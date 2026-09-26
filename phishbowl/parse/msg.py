"""``.msg`` parsing — Outlook/MAPI compound files via ``extract-msg``.

Turns a ``.msg`` (an OLE/CFB compound document of MAPI property streams) into the
**same** :class:`~phishbowl.models.ParsedEmail` the ``.eml`` path produces, so
everything downstream of parsing stays format-agnostic (PRD §5 / §6.1). Nothing
here is format-specific past this module: we normalize MAPI into the one shared
contract and hand it off.

Reuse over reimplementation: a ``.msg`` keeps the original internet
``Authentication-Results`` / ``Received`` / address headers in its transport
message-headers stream (PR_TRANSPORT_MESSAGE_HEADERS, ``0x007D``) whenever they
were preserved. When that stream is present we parse it with the very same
helpers the ``.eml`` path uses (:func:`parse_auth`, :func:`parse_routing`,
address/subject/date builders), so the two formats converge byte-for-byte on
those fields. Body and attachments, which a ``.msg`` stores as MAPI streams
rather than MIME parts, are pulled from MAPI and fed through the shared
attachment inspector so hashes and structural flags match the ``.eml`` path too.

**Auth is lossier from ``.msg``.** Outlook frequently saves a message *without*
its transport headers (or with the auth results stripped), so SPF/DKIM/DMARC
simply aren't recoverable. That is a property of the format, not a parse error:
when it happens we still return a complete model and record an
:class:`Anomaly` noting the auth results couldn't be recovered, rather than
silently presenting "no result" as if the headers had been checked.

Defensive invariants honored here mirror the ``.eml`` path: attachment bytes are
read only to hash and sniff them — never executed, never extracted (AGENTS.md).
Robustness is load-bearing: any section that fails is recorded as an anomaly and
the rest of the parse continues; a malformed ``.msg`` degrades into a noted
partial result, never a crash (PRD §11).
"""

from __future__ import annotations

import io
import re
from datetime import datetime
from email.parser import HeaderParser
from pathlib import Path

from phishbowl import __version__
from phishbowl.models import (
    Address,
    Addresses,
    Anomaly,
    Attachment,
    Body,
    EmailFormat,
    ParsedEmail,
    Source,
)

from .addresses import parse_single_address
from .attachments import build_attachment_from_bytes
from .charset import _decode_bytes
from .eml import _guard, populate_headers
from .limits import MAX_INPUT_BYTES, read_within_limit
from .mime import SafeMessage

# The PR_TRANSPORT_MESSAGE_HEADERS stream — the original RFC 822 header block as
# received, when Outlook preserved it. Read sans the type suffix per extract-msg.
_TRANSPORT_HEADERS_ID = "__substg1.0_007D"

# PR_HTML — the real HTML body part, as raw bytes in the message's code page.
_HTML_BODY_ID = "__substg1.0_10130102"

# MAPI property/stream ids we fall back to when transport headers are absent.
_SENDER_NAME_ID = "__substg1.0_0C1A"
_SENDER_SMTP_ID = "__substg1.0_5D01"
_SENDER_EMAIL_ID = "__substg1.0_0C1F"
_DELIVERY_TIME_PROP = "0E060040"  # PR_MESSAGE_DELIVERY_TIME
_SUBMIT_TIME_PROP = "00390040"  # PR_CLIENT_SUBMIT_TIME
_INTERNET_CPID_PROP = "3FDE0003"  # PR_INTERNET_CPID (code page of the HTML body)


def parse_msg(data: bytes, filename: str | None = None) -> ParsedEmail:
    """Parse raw ``.msg`` bytes into a :class:`ParsedEmail`.

    Always returns a model: anything that goes wrong is captured as an anomaly
    rather than raised (PRD §11), matching the ``.eml`` path's contract.
    """
    parsed = ParsedEmail(
        source=Source(filename=filename, format=EmailFormat.MSG, parser_version=__version__),
    )

    # Defensive input cap: refuse to deep-parse an oversized blob (the bytes path
    # has no file to stat, so we check the length here). Degrades to a noted
    # partial result rather than raising, matching the .eml path's contract.
    if len(data) > MAX_INPUT_BYTES:
        parsed.anomalies.append(
            Anomaly(
                code="input_too_large",
                message=f"input is {len(data)} bytes, exceeding the {MAX_INPUT_BYTES}-byte limit",
            )
        )
        return parsed

    # Imported lazily so importing the parse layer never hard-requires the
    # optional ``.msg`` dependency just to handle ``.eml`` files.
    try:
        import extract_msg
    except ImportError as exc:  # pragma: no cover - extract-msg is a declared dep
        parsed.anomalies.append(
            Anomaly(code="msg_dependency_missing", message=f"extract-msg unavailable: {exc}")
        )
        return parsed

    try:
        msg = _open(extract_msg, data)
    except Exception as exc:
        parsed.anomalies.append(Anomaly(code="parse_error", message=f"could not parse .msg: {exc}"))
        return parsed

    try:
        _populate(parsed, msg)
    finally:
        try:
            msg.close()
        except Exception:  # pragma: no cover - close is best-effort  # nosec B110
            pass  # releasing the parser handle must never mask the real result
    return parsed


def _open(extract_msg, data: bytes):
    """Open ``.msg`` bytes, tolerating the container defects extract-msg can skip.

    Suppressing attachment and standards errors keeps one malformed recipient
    or attachment from taking the whole message down with it.
    """
    options: dict = {"delayAttachments": True}
    behavior = getattr(getattr(extract_msg, "enums", None), "ErrorBehavior", None)
    if behavior is not None and hasattr(behavior, "SUPPRESS_ALL"):
        options["errorBehavior"] = behavior.SUPPRESS_ALL
    return extract_msg.openMsg(io.BytesIO(data), **options)


def parse_file(path: str | Path) -> ParsedEmail:
    """Read ``path`` and parse it as ``.msg`` (refusing oversized input)."""
    p = Path(path)
    return parse_msg(read_within_limit(p), filename=p.name)


def _populate(parsed: ParsedEmail, msg) -> None:
    """Fill ``parsed`` from an open ``extract-msg`` message, section by section."""
    # Transport headers are the bridge to the .eml machinery: when present, the
    # original auth/routing/address/subject/date headers are parsed with the
    # exact same helpers, so both formats agree on these fields.
    header_msg = _guard(parsed, "headers_error", lambda: _transport_headers(msg), None)

    if header_msg is not None:
        populate_headers(parsed, header_msg)

    # MAPI fallbacks for anything the transport headers didn't (or couldn't)
    # supply. A .msg authored in Outlook may carry no transport headers at all,
    # or carry a From but a stripped/mangled recipient block — in either case the
    # MAPI sender/recipient table is the only source. We fill each gap (sender,
    # To, Cc) independently and only when empty, so a header that supplied just
    # one of them still gets the others from MAPI, and nothing already present is
    # overwritten.
    need_sender = parsed.addresses.from_ is None
    need_to = not parsed.addresses.to
    need_cc = not parsed.addresses.cc
    if need_sender or need_to or need_cc:
        current = parsed.addresses
        parsed.addresses = _guard(
            parsed,
            "address_error",
            lambda: _mapi_addresses(msg, current, need_sender, need_to, need_cc),
            current,
        )
    if parsed.subject is None:
        parsed.subject = _guard(parsed, "subject_error", lambda: msg.subject, None)
    if parsed.date is None:
        parsed.date = _guard(parsed, "date_error", lambda: _mapi_date(msg), None)

    parsed.body = _guard(parsed, "body_error", lambda: _build_body(msg), Body())
    if not parsed.body.text and not parsed.body.html_raw:
        parsed.anomalies.append(
            Anomaly(
                code="msg_body_unavailable",
                message="No plain text or PR_HTML body recovered; compressed RTF is not expanded",
            )
        )
    parsed.attachments = _guard(
        parsed, "attachment_error", lambda: _build_attachments(msg, parsed), []
    )

    _note_msg_anomalies(parsed, header_msg)


def _transport_headers(msg):
    """The original RFC 822 header block as an :class:`email.message.Message`, or ``None``.

    Read straight from the PR_TRANSPORT_MESSAGE_HEADERS stream so we know whether
    *real* headers were preserved — ``extract-msg``'s ``.header`` would otherwise
    fabricate one from MAPI fields (inventing a placeholder
    ``Authentication-Results``), which we must not mistake for received auth data.
    """
    text = _string_stream(msg, _TRANSPORT_HEADERS_ID)
    if not text:
        return None
    # Headers only: whatever follows the first blank line is never parsed as
    # MIME (a hostile stream could otherwise smuggle an unbounded part tree).
    return HeaderParser(_class=SafeMessage).parsestr(text, headersonly=True)


def _string_stream(msg, stream_id: str) -> str | None:
    """Read a MAPI string stream, preferring extract-msg's public accessor.

    ``extract-msg`` >= 0.48 (the declared dependency) exposes ``getStringStream``;
    older releases only had the private ``_getStringStream``. We prefer the
    public name and fall back to the private one so a stream isn't silently
    dropped on either API.
    """
    getter = getattr(msg, "getStringStream", None) or getattr(msg, "_getStringStream", None)
    return getter(stream_id) if getter is not None else None


def _mapi_addresses(
    msg, current: Addresses, fill_sender: bool, fill_to: bool, fill_cc: bool
) -> Addresses:
    """Fill the requested gaps in :class:`Addresses` from MAPI streams.

    Each of sender / To / Cc is filled independently and only when requested, so
    header-derived values are never clobbered and a header that supplied only one
    recipient field still gets the others. ``from_`` comes from the sender name +
    SMTP address; ``to``/``cc`` from the recipient table.
    """
    update: dict = {}
    if fill_sender:
        update["from_"] = _mapi_sender(msg)
    if fill_to or fill_cc:
        to: list[Address] = []
        cc: list[Address] = []
        for recip in msg.recipients or []:
            addr = _recipient_address(recip)
            if addr is None:
                continue
            # Map only To (1) and Cc (2). Bcc (3) and other types are deliberately
            # omitted: the ParsedEmail model has no Bcc field, and a saved Bcc
            # must not masquerade as a To recipient (it would mislead the report).
            recip_type = int(getattr(recip.type, "value", recip.type))
            if recip_type == 1:
                to.append(addr)
            elif recip_type == 2:
                cc.append(addr)
        if fill_to:
            update["to"] = to
        if fill_cc:
            update["cc"] = cc
    return current.model_copy(update=update)


def _mapi_sender(msg) -> Address | None:
    name = _string_stream(msg, _SENDER_NAME_ID)
    email_addr = _string_stream(msg, _SENDER_SMTP_ID) or _string_stream(msg, _SENDER_EMAIL_ID)
    if not name and not email_addr:
        return None
    return _address(name, email_addr)


def _recipient_address(recip) -> Address | None:
    return _address(getattr(recip, "name", None), getattr(recip, "email", None))


def _address(display: str | None, addr_spec: str | None) -> Address | None:
    """Build an :class:`Address`, reusing the shared address parser for the spec.

    Routing the address spec back through ``parse_single_address`` keeps the
    domain-splitting (and thus the mismatch comparisons) identical to the .eml
    path rather than re-deriving the domain here.
    """
    display = (display or "").strip() or None
    addr_spec = (addr_spec or "").strip() or None
    if addr_spec:
        parsed, _lenient = parse_single_address([addr_spec])
        if parsed is not None:
            parsed.display_name = display or parsed.display_name
            return parsed
    if display is None:
        return None
    return Address(display_name=display)


def _mapi_date(msg) -> datetime | None:
    """Send/receive time from the MAPI property stream (transport-header fallback)."""
    for prop_id in (_SUBMIT_TIME_PROP, _DELIVERY_TIME_PROP):
        prop = msg.props.get(prop_id)
        value = getattr(prop, "value", None)
        if isinstance(value, datetime):
            return value
    return None


def _build_body(msg) -> Body:
    """Collect the plain-text and HTML bodies from MAPI streams.

    ``html_raw`` is stored for analysis only and is NEVER rendered (PRD §10),
    exactly as on the .eml path. ``has_html`` reflects whether a *real* HTML part
    was present (matching the .eml parser's semantics).
    """
    text = _string_stream(msg, "__substg1.0_1000")
    html = _real_html(msg)
    return Body(text=text, html_raw=html, has_html=html is not None)


def _real_html(msg) -> str | None:
    """Read genuine PR_HTML only; do not expand compressed RTF or synthesize HTML."""
    raw = _get_stream(msg, _HTML_BODY_ID)
    if raw is not None:
        return _decode_html(bytes(raw), msg)
    return None


def _get_stream(msg, stream_id: str) -> bytes | None:
    """Read a raw MAPI stream, preferring extract-msg's public accessor."""
    getter = getattr(msg, "getStream", None) or getattr(msg, "_getStream", None)
    return getter(stream_id) if getter is not None else None


# Scan the leading bytes of an HTML part for a declared charset (``<meta>``),
# matching how the .eml path honours the part's declared charset.
_META_CHARSET = re.compile(rb"""charset\s*=\s*["']?\s*([A-Za-z0-9_\-]+)""", re.IGNORECASE)


def _decode_html(raw: bytes, msg) -> str:
    """Decode PR_HTML bytes using the message's actual charset, leniently.

    The PR_HTML stream is bytes in the message's code page (commonly
    Windows-1252 or UTF-16, not UTF-8). We resolve the charset from a declared
    ``<meta charset>`` first, then the message's internet code page, and decode
    through the same lenient helper the .eml path uses — so non-ASCII text and
    URLs survive intact for downstream IOC analysis instead of being mangled by
    an unconditional UTF-8 decode.
    """
    return _decode_bytes(raw, _html_charset(raw, msg))


def _html_charset(raw: bytes, msg) -> str | None:
    match = _META_CHARSET.search(raw[:2048])
    if match:
        return match.group(1).decode("ascii", errors="replace")
    cpid = getattr(msg.props.get(_INTERNET_CPID_PROP), "value", None)
    if isinstance(cpid, int):
        return _codepage_charset(cpid)
    return None


def _codepage_charset(cpid: int) -> str:
    """Map a Windows code-page id (PR_INTERNET_CPID) to a Python codec name."""
    special = {
        65001: "utf-8",
        65000: "utf-7",
        1200: "utf-16-le",
        1201: "utf-16-be",
        20127: "ascii",
        12000: "utf-32-le",
        12001: "utf-32-be",
        50220: "iso2022_jp",
        50221: "iso2022_jp",
        50222: "iso2022_jp",
        51932: "euc_jp",
        51936: "gb2312",
        51949: "euc_kr",
        54936: "gb18030",
        20866: "koi8_r",
        21866: "koi8_u",
        10000: "mac_roman",
        10007: "mac_cyrillic",
    }
    if cpid in special:
        return special[cpid]
    if 28591 <= cpid <= 28605:
        return f"iso-8859-{cpid - 28590}"
    return f"cp{cpid}"


def _build_attachments(msg, parsed: ParsedEmail) -> list[Attachment]:
    """Inspect MAPI attachments through the shared, format-agnostic inspector.

    Each attachment is guarded on its own: a by-reference or cloud attachment
    (whose bytes are not in the file) is recorded by name with a notice, and an
    unreadable one is noted — neither costs the other attachments.
    """
    attachments: list[Attachment] = []
    for att in msg.attachments or []:
        filename = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None)
        declared_type = getattr(att, "mimetype", None)
        try:
            data = att.data
        except Exception as exc:
            parsed.anomalies.append(
                Anomaly.notice(
                    "msg_attachment_external",
                    f"attachment {filename or '(unnamed)'!r} has no embedded content: {exc}",
                )
            )
            continue
        try:
            if data is None:
                continue
            if not isinstance(data, (bytes, bytearray)):
                # An embedded message attachment surfaces as a nested message
                # object, not bytes. We don't descend into it (no extraction, no
                # detonation), but we DO serialize the container back to bytes
                # and hash it — so a reported phishing email attached as a .msg
                # keeps real size/hashes/type as evidence.
                data = _embedded_message_bytes(data)
                if not declared_type:
                    declared_type = "application/vnd.ms-outlook"
                if not filename:
                    filename = "embedded-message.msg"
            attachments.append(build_attachment_from_bytes(filename, declared_type, bytes(data)))
        except Exception as exc:
            parsed.anomalies.append(
                Anomaly(
                    code="attachment_error",
                    message=f"attachment {filename or '(unnamed)'!r} could not be read: {exc}",
                )
            )
    return attachments


def _embedded_message_bytes(embedded) -> bytes:
    """Serialize an embedded ``.msg`` attachment to its container bytes for hashing.

    Re-serializes the compound-file container only (``extract-msg``'s
    ``exportBytes``); it never extracts or runs the embedded message's contents.
    Best-effort: if serialization isn't available or fails, returns empty bytes
    rather than raising.
    """
    exporter = getattr(embedded, "exportBytes", None)
    if exporter is None:
        return b""
    try:
        return exporter() or b""
    except Exception:
        return b""


def embedded_emails(data: bytes) -> list[tuple[str, bytes]]:
    """``(filename, bytes)`` for each email attached to raw ``.msg`` bytes, in order.

    Embedded Outlook items (the "forward as attachment" hand-off) are
    re-serialized as standalone ``.msg`` containers; ``.eml`` / ``message/rfc822``
    file attachments are returned byte-for-byte. Nothing is executed or
    extracted beyond that serialization. Never raises: an unreadable container
    yields no emails.
    """
    if len(data) > MAX_INPUT_BYTES:
        return []
    try:
        import extract_msg

        msg = extract_msg.openMsg(io.BytesIO(data), delayAttachments=True)
    except Exception:
        return []
    found: list[tuple[str, bytes]] = []
    try:
        for att in msg.attachments or []:
            filename = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None)
            payload = att.data
            if not isinstance(payload, (bytes, bytearray)):
                blob = _embedded_message_bytes(payload)
                if blob:
                    name = filename or "embedded-message.msg"
                    if not name.casefold().endswith(".msg"):
                        name += ".msg"
                    found.append((name, blob))
                continue
            declared = (getattr(att, "mimetype", None) or "").casefold()
            if (filename or "").casefold().endswith(".eml") or declared == "message/rfc822":
                name = filename or "attached.eml"
                if not name.casefold().endswith(".eml"):
                    name += ".eml"
                found.append((name, bytes(payload)))
    except Exception:
        return found
    finally:
        try:
            msg.close()
        except Exception:  # pragma: no cover - close is best-effort  # nosec B110
            pass
    return found


def _note_msg_anomalies(parsed: ParsedEmail, header_msg) -> None:
    """Record the .msg-specific lossiness so the report never overstates the data."""
    if header_msg is None:
        parsed.anomalies.append(
            Anomaly.notice(
                "msg_no_transport_headers",
                "no transport headers in .msg; routing path and "
                "authentication results are unavailable (lossy format)",
            )
        )

    # Auth is the classic .msg loss: even when transport headers survive, Outlook
    # often strips Authentication-Results, so SPF/DKIM/DMARC read as NONE not
    # because they failed a check but because no result was recoverable.
    if header_msg is None or not (
        "Authentication-Results" in parsed.headers or "Received-SPF" in parsed.headers
    ):
        parsed.anomalies.append(
            Anomaly.notice(
                "msg_auth_unavailable",
                "no SPF/DKIM/DMARC results recoverable from .msg "
                "(authentication results are commonly absent in this format)",
            )
        )

    if parsed.addresses.from_ is None and not any(
        a.code == "missing_from" for a in parsed.anomalies
    ):
        parsed.anomalies.append(
            Anomaly.notice("missing_from", "message has no parseable From address")
        )
