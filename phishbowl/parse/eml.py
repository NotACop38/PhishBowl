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
sniff them — never execute, never extract an archive (CLAUDE.md).
"""

from __future__ import annotations

import email
import re
from collections.abc import Callable
from datetime import datetime
from email.message import Message
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import TypeVar

from phishbowl import __version__
from phishbowl.models import (
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
)

from .addresses import parse_address_list, parse_single_address
from .attachments import build_attachment, is_attachment, iter_parts
from .auth import parse_auth
from .charset import decode_mime_words, decode_payload
from .routing import parse_routing

T = TypeVar("T")

# Collapse RFC 5322 header folding (CRLF + leading whitespace) back to a space,
# so each header value is a single logical line for downstream regexes.
_FOLD = re.compile(r"\r?\n[ \t]+")


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

    try:
        msg = email.message_from_bytes(data)
    except Exception as exc:  # pragma: no cover - message_from_bytes is very tolerant
        parsed.anomalies.append(
            Anomaly(code="parse_error", message=f"could not parse message: {exc}")
        )
        return parsed

    headers = _guard(parsed, "headers_error", lambda: _build_headers(msg), Headers())
    parsed.headers = headers
    parsed.auth = _guard(parsed, "auth_error", lambda: parse_auth(headers), Auth())
    parsed.routing = _guard(parsed, "routing_error", lambda: parse_routing(headers), Routing())
    parsed.addresses = _guard(parsed, "address_error", lambda: _build_addresses(msg), Addresses())
    parsed.subject = _guard(parsed, "subject_error", lambda: _subject(msg), None)
    parsed.date = _guard(parsed, "date_error", lambda: _date(msg), None)
    parsed.body = _guard(parsed, "body_error", lambda: _build_body(msg), Body())
    parsed.attachments = _guard(parsed, "attachment_error", lambda: _build_attachments(msg), [])

    _note_structural_anomalies(msg, parsed)
    return parsed


def parse_file(path: str | Path) -> ParsedEmail:
    """Read ``path`` and parse it as ``.eml``."""
    p = Path(path)
    return parse_eml(p.read_bytes(), filename=p.name)


def _guard(parsed: ParsedEmail, code: str, fn: Callable[[], T], default: T) -> T:
    """Run ``fn`` and return its result; on any error, note it and return ``default``."""
    try:
        return fn()
    except Exception as exc:
        parsed.anomalies.append(Anomaly(code=code, message=f"{code}: {exc}"))
        return default


def _build_headers(msg: Message) -> Headers:
    items: list[Header] = []
    for name, value in msg.items():
        # Decode first (handles RFC 2047 and raw 8-bit / SMTPUTF8 headers), then
        # unfold. Stringifying ``value`` before decoding would mangle 8-bit bytes.
        decoded = _unfold(decode_mime_words(value) or "")
        items.append(Header(name=name, value=decoded))
    return Headers(items=items)


def _header_text(value: object) -> str:
    """Raw header value as a string suitable for address splitting.

    A plain ``str`` (ASCII / RFC 2047) is returned unchanged so encoded-words —
    which may hide a comma inside a display name — stay intact for
    ``getaddresses``. An ``email.header.Header`` (raw 8-bit / SMTPUTF8) is
    decoded to proper text instead of being mangled by ``str()``.
    """
    if isinstance(value, str):
        return value
    return decode_mime_words(value) or ""


def _build_addresses(msg: Message) -> Addresses:
    # Parse from the raw header values (not the fully RFC 2047-decoded stored
    # copy) so an encoded display name containing a comma can't confuse address
    # splitting; _header_text still recovers raw 8-bit (SMTPUTF8) headers.
    def values(name: str) -> list[str]:
        return [_header_text(v) for v in msg.get_all(name, [])]

    return Addresses(
        from_=parse_single_address(values("From")),
        reply_to=parse_single_address(values("Reply-To")),
        return_path=parse_single_address(values("Return-Path")),
        sender=parse_single_address(values("Sender")),
        to=parse_address_list(values("To")),
        cc=parse_address_list(values("Cc")),
    )


def _subject(msg: Message) -> str | None:
    raw = msg.get("Subject")
    if raw is None:
        return None
    return _unfold(decode_mime_words(raw) or "")


def _date(msg: Message) -> datetime | None:
    raw = msg.get("Date")
    if not raw:
        return None
    try:
        return parsedate_to_datetime(str(raw))
    except (TypeError, ValueError):
        return None


def _build_body(msg: Message) -> Body:
    """Collect the first text/plain and text/html body parts.

    ``html_raw`` is stored for analysis only and is NEVER rendered (PRD §10).
    """
    text: str | None = None
    html: str | None = None
    has_html = False
    for part in iter_parts(msg):
        if part.is_multipart() or is_attachment(part):
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain" and text is None:
            text = decode_payload(part)
        elif ctype == "text/html":
            has_html = True
            if html is None:
                html = decode_payload(part)
    return Body(text=text, html_raw=html, has_html=has_html)


def _build_attachments(msg: Message) -> list[Attachment]:
    return [build_attachment(part) for part in iter_parts(msg) if is_attachment(part)]


def _note_structural_anomalies(msg: Message, parsed: ParsedEmail) -> None:
    """Surface MIME defects and obvious missing pieces as anomaly notes."""
    for part in msg.walk():
        for defect in getattr(part, "defects", []) or []:
            parsed.anomalies.append(
                Anomaly(code="mime_defect", message=f"{type(defect).__name__}: {defect}")
            )
    if parsed.addresses.from_ is None:
        parsed.anomalies.append(
            Anomaly(code="missing_from", message="message has no parseable From address")
        )
