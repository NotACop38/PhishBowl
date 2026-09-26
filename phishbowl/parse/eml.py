"""``.eml`` parsing — RFC 822 / MIME via the stdlib ``email`` package.

Turns raw ``.eml`` bytes into a fully populated
:class:`~phishbowl.models.ParsedEmail` (PRD §6.1). All charset / encoding
handling is delegated to :mod:`phishbowl.parse.charset`, so this module never
decodes bytes itself.

Robustness is load-bearing: the analyzed email is hostile input end to end
(PRD §13). Every section is parsed under guard — a failure in one (a malformed
address list, an unparseable hop) is recorded as an :class:`Anomaly` and the
rest of the parse continues. A malformed message degrades into a noted partial
result; it never crashes the run (PRD §11).

Defensive invariants honored here: we read attachment bytes only to hash and
sniff them — never execute, never extract an archive (AGENTS.md).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime
from email import errors
from email.message import Message
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import TypeVar

from phishbowl import __version__
from phishbowl.models import (
    Address,
    Addresses,
    Anomaly,
    Attachment,
    Auth,
    Body,
    EmailFormat,
    Header,
    Headers,
    ParsedEmail,
    Routing,
    Source,
    TextPart,
)

from .addresses import parse_address_list, parse_single_address
from .attachments import build_attachment, is_attachment, is_other_inline_text, iter_parts
from .auth import parse_auth
from .charset import decode_mime_words, decode_payload, header_text
from .limits import MAX_INPUT_BYTES, read_within_limit
from .mime import MIMEBudgetError, bounded_message, headers_only
from .routing import parse_routing

T = TypeVar("T")

# Collapse RFC 5322 header folding (CRLF + leading whitespace) back to a space,
# so each header value is a single logical line for downstream regexes.
_FOLD = re.compile(r"\r?\n[ \t]+")

# RFC 5545 content-line folding: CRLF followed by one space or tab is removed
# outright (not replaced by a space), so a URL folded across lines rejoins.
_ICAL_FOLD = re.compile(r"\r?\n[ \t]")

# MIME defects that make the message *structure* ambiguous: the stdlib parser
# recovered one reading, but a mail client may split parts or headers
# differently and display content that was not analyzed. These are coverage
# gaps. Other defects (undecodable bytes, bad base64 padding, malformed header
# values) affect a single value, which is still analyzed, so they are notices.
_STRUCTURAL_DEFECTS = (
    errors.StartBoundaryNotFoundDefect,
    errors.CloseBoundaryNotFoundDefect,
    errors.NoBoundaryInMultipartDefect,
    errors.MultipartInvariantViolationDefect,
    errors.InvalidMultipartContentTransferEncodingDefect,
    errors.FirstHeaderLineIsContinuationDefect,
    errors.MissingHeaderBodySeparatorDefect,
)


# Unstructured headers (RFC 5322 §3.6.5) whose text may carry RFC 2047
# encoded-words. Every other header is kept exactly as written: decoding
# encoded-words inside a structured header such as Authentication-Results would
# let an attacker-chosen envelope address inject "; dkim=pass" into it.
_UNSTRUCTURED_HEADERS = frozenset({"subject", "comments", "keywords", "thread-topic"})


def _unfold(value: str) -> str:
    return _FOLD.sub(" ", value)


def parse_eml(data: bytes, filename: str | None = None) -> ParsedEmail:
    """Parse raw ``.eml`` bytes into a :class:`ParsedEmail`.

    Always returns a model: anything that goes wrong is captured as an anomaly
    rather than raised (PRD §11).
    """
    parsed = ParsedEmail(
        source=Source(filename=filename, format=EmailFormat.EML, parser_version=__version__),
    )

    # Defensive input cap: refuse to deep-parse an oversized blob (the bytes path
    # has no file to stat, so we check the length here). Degrades to a noted
    # partial result rather than raising, matching the bytes-path contract.
    if len(data) > MAX_INPUT_BYTES:
        parsed.anomalies.append(
            Anomaly(
                code="input_too_large",
                message=f"input is {len(data)} bytes, exceeding the {MAX_INPUT_BYTES}-byte limit",
            )
        )
        return parsed

    whole = True
    try:
        msg = bounded_message(data)
    except Exception as exc:
        # Over budget, or a structure the parser cannot build: keep the header
        # evidence (sender, authentication, routing) rather than discarding
        # the whole message.
        whole = False
        code = "mime_budget" if isinstance(exc, MIMEBudgetError) else "parse_error"
        parsed.anomalies.append(
            Anomaly(code=code, message=f"{exc}; only the headers were analyzed")
        )
        try:
            msg = headers_only(data)
        except Exception as inner:  # a header block the stdlib cannot read at all
            parsed.anomalies.append(
                Anomaly(code="parse_error", message=f"could not parse headers: {inner}")
            )
            return parsed

    populate_headers(parsed, msg)
    if whole:
        parsed.body = _guard(parsed, "body_error", lambda: _build_body(msg, parsed), Body())
        parsed.attachments = _guard(
            parsed, "attachment_error", lambda: _build_attachments(msg, parsed), []
        )
        _guard(parsed, "structure_error", lambda: _note_structural_anomalies(msg, parsed), None)
    if parsed.addresses.from_ is None:
        parsed.anomalies.append(
            Anomaly.notice("missing_from", "message has no parseable From address")
        )
    return parsed


def populate_headers(parsed: ParsedEmail, msg: Message) -> None:
    """Fill the header-derived fields (shared by the ``.eml`` and ``.msg`` paths).

    Addresses come first so authentication can prefer the DKIM result that
    speaks for the From domain.
    """
    headers = _guard(parsed, "headers_error", lambda: _build_headers(msg), Headers())
    parsed.headers = headers
    parsed.addresses = _guard(
        parsed, "address_error", lambda: _build_addresses(msg, parsed), Addresses()
    )
    from_domain = parsed.addresses.from_.domain if parsed.addresses.from_ else None
    auth, notes = _guard(
        parsed, "auth_error", lambda: parse_auth(headers, from_domain=from_domain), (Auth(), [])
    )
    parsed.auth = auth
    parsed.anomalies.extend(notes)
    parsed.routing = _guard(parsed, "routing_error", lambda: parse_routing(headers), Routing())
    parsed.subject = _guard(parsed, "subject_error", lambda: _subject(msg), None)
    parsed.date = _guard(parsed, "date_error", lambda: _date(msg), None)


def parse_file(path: str | Path) -> ParsedEmail:
    """Read ``path`` and parse it as ``.eml`` (refusing oversized input)."""
    p = Path(path)
    return parse_eml(read_within_limit(p), filename=p.name)


def _guard(parsed: ParsedEmail, code: str, fn: Callable[[], T], default: T) -> T:
    """Run ``fn`` and return its result; on any error, note it and return ``default``."""
    try:
        return fn()
    except Exception as exc:
        parsed.anomalies.append(Anomaly(code=code, message=f"{code}: {exc}"))
        return default


def _build_headers(msg: Message) -> Headers:
    """Every header in order, unfolded; encoded-words decoded in unstructured ones only."""
    items: list[Header] = []
    for name, value in msg.items():
        try:
            if name.casefold() in _UNSTRUCTURED_HEADERS:
                text = decode_mime_words(value)
            else:
                text = header_text(value)
        except Exception:  # never lose the header; keep it undecoded instead
            text = header_text(str(value))
        items.append(Header(name=name, value=_unfold(text or "")))
    return Headers(items=items)


def _build_addresses(msg: Message, parsed: ParsedEmail) -> Addresses:
    """Parse the address headers from their raw values.

    Raw values (not the RFC 2047-decoded copies) keep an encoded display name
    containing a comma from confusing address splitting; ``header_text`` still
    recovers raw 8-bit (SMTPUTF8) headers. A malformed single-mailbox header is
    read the way mail clients display it, with a notice for the analyst.
    """

    def values(name: str) -> list[str]:
        return [header_text(v) or "" for v in msg.get_all(name, [])]

    # Each header is guarded on its own: one unreadable header never costs
    # the others (least of all From).
    singles: dict[str, Address | None] = {}
    for name in ("From", "Reply-To", "Return-Path", "Sender"):
        address, lenient = _guard(
            parsed,
            "address_error",
            lambda name=name: parse_single_address(values(name)),
            (None, False),
        )
        singles[name] = address
        if lenient:
            shown = address.addr_spec if address and address.addr_spec else "no address"
            parsed.anomalies.append(
                Anomaly.notice(
                    "malformed_address",
                    f"{name} header is not a valid RFC 5322 mailbox; read as {shown!r}",
                )
            )
    return Addresses(
        from_=singles["From"],
        reply_to=singles["Reply-To"],
        return_path=singles["Return-Path"],
        sender=singles["Sender"],
        to=_guard(parsed, "address_error", lambda: parse_address_list(values("To")), []),
        cc=_guard(parsed, "address_error", lambda: parse_address_list(values("Cc")), []),
    )


def _subject(msg: Message) -> str | None:
    raw = msg.get("Subject")
    if raw is None:
        return None
    return _unfold(decode_mime_words(raw) or "")


def _date(msg: Message) -> datetime | None:
    raw = header_text(msg.get("Date"))
    if not raw:
        return None
    try:
        return parsedate_to_datetime(raw)
    except (TypeError, ValueError, OverflowError):
        return None


def _build_body(msg: Message, parsed: ParsedEmail) -> Body:
    """Collect every inline body part: text/plain, text/html, and other text.

    ``html_raw`` is stored for analysis only and is NEVER rendered (PRD §10).
    Inline parts in other text formats (``text/calendar`` invitations, …) are
    kept in ``other_text`` so their links are scanned too. So is the raw content
    of a multipart part the parser could not split: it is scanned as text rather
    than silently dropped. A text/plain or text/html part that merely carries a
    file name (without ``Content-Disposition: attachment``) is displayed inline
    by mail clients, so it is read as body text as well as listed. One
    unreadable part is noted and skipped; it never costs the others.
    """
    text: list[str] = []
    html: list[str] = []
    other: list[TextPart] = []
    has_html = False
    for part in iter_parts(msg):
        try:
            if part.is_multipart():
                continue
            ctype = part.get_content_type()
            if is_other_inline_text(part) or part.get_content_maintype() == "multipart":
                content = decode_payload(part) or ""
                if ctype == "text/calendar":
                    content = _ICAL_FOLD.sub("", content)
                if content.strip():
                    other.append(TextPart(content_type=ctype, text=content))
                continue
            if is_attachment(part) and part.get_content_disposition() == "attachment":
                continue
            if ctype == "text/plain":
                text.append(decode_payload(part) or "")
            elif ctype == "text/html":
                has_html = True
                html.append(decode_payload(part) or "")
        except Exception as exc:
            parsed.anomalies.append(
                Anomaly(code="body_part_error", message=f"a body part could not be read: {exc}")
            )
    return Body(
        text="\n".join(text) or None,
        html_raw="\n".join(html) or None,
        has_html=has_html,
        other_text=other,
    )


def _build_attachments(msg: Message, parsed: ParsedEmail) -> list[Attachment]:
    attachments: list[Attachment] = []
    for part in iter_parts(msg):
        try:
            if is_attachment(part):
                attachments.append(build_attachment(part))
        except Exception as exc:
            parsed.anomalies.append(
                Anomaly(code="attachment_error", message=f"an attachment could not be read: {exc}")
            )
    return attachments


def _note_structural_anomalies(msg: Message, parsed: ParsedEmail) -> None:
    """Surface MIME defects and obvious missing pieces as anomaly notes."""
    for part in iter_parts(msg, include_containers=True):
        if is_other_inline_text(part):
            parsed.anomalies.append(
                Anomaly.notice(
                    "other_body_type",
                    f"{part.get_content_type()} body part scanned as plain text for "
                    "indicators and listed with the attachments",
                )
            )
        for defect in getattr(part, "defects", []) or []:
            # Some defects quote the offending raw line, surrogate escapes and all.
            message = header_text(f"{type(defect).__name__}: {defect}") or ""
            if isinstance(defect, _STRUCTURAL_DEFECTS):
                parsed.anomalies.append(
                    Anomaly(
                        code="mime_defect",
                        message=f"{message} (ambiguous MIME structure: a mail client may "
                        "display content the parser did not separate)",
                    )
                )
            else:
                parsed.anomalies.append(Anomaly.notice("mime_defect", message))
