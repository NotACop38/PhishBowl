"""Extract attached emails for inner-message triage.

SOC triage often arrives as ``Fwd: reported message`` with the suspicious mail
attached as ``message/rfc822`` (or a ``.eml``/``.msg`` file attachment). The
outer wrapper is usually benign infrastructure mail; the analyst needs the
**inner** message scored. This module finds those embedded emails as a pure
byte-level walk — never executing, never fetching, never writing to disk.

The outer parse still captures each attached email as one opaque
:class:`~phishbowl.models.Attachment` (hashes + metadata only). Callers that
want to *triage* the enclosed message re-read the original bytes here and hand
the result to :func:`~phishbowl.parse.parse_bytes`.
"""

from __future__ import annotations

import email
import io
from dataclasses import dataclass
from email.generator import BytesGenerator
from email.message import Message
from pathlib import Path

from .attachments import iter_parts
from .charset import decode_mime_words


@dataclass(frozen=True)
class EmbeddedEmail:
    """One attached email found inside an outer message."""

    index: int
    filename: str
    data: bytes
    declared_type: str | None = None


def list_embedded_emails(data: bytes, *, filename: str | None = None) -> list[EmbeddedEmail]:
    """Return attached emails found in raw ``.eml`` (or message-like) bytes.

    Finds ``message/rfc822`` / ``message/news`` parts and leaf attachments whose
    filename ends in ``.eml``. ``.msg`` containers are not walked here (OLE
    embedding is lossier and uncommon for the "user forwarded this" path); pass
    a standalone ``.msg`` straight to :func:`~phishbowl.parse.parse_bytes`.

    Parts are returned in document order, 0-indexed. Each ``data`` blob is a
    wire-faithful serialization suitable for :func:`~phishbowl.parse.parse_bytes`.
    """
    # OLE2 / .msg — not an RFC 822 tree; no message/rfc822 walk applies.
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return []

    try:
        msg = email.message_from_bytes(data)
    except Exception:
        return []

    found: list[EmbeddedEmail] = []
    for part in iter_parts(msg):
        embedded = _maybe_embedded(part)
        if embedded is None:
            continue
        name, payload, declared = embedded
        found.append(
            EmbeddedEmail(
                index=len(found),
                filename=name or f"attached-{len(found) + 1}.eml",
                data=payload,
                declared_type=declared,
            )
        )
    # Hint unused on purpose — kept so callers can pass the outer filename for
    # future format-specific heuristics without an API break.
    _ = filename
    return found


def _maybe_embedded(part: Message) -> tuple[str | None, bytes, str | None] | None:
    """Return ``(filename, bytes, declared_type)`` if ``part`` is an attached email."""
    maintype = part.get_content_maintype()
    declared = part.get_content_type()
    filename = decode_mime_words(part.get_filename())
    suffix = Path(filename).suffix.casefold() if filename else ""

    if maintype == "message":
        payload = _serialize_message_part(part)
        if not payload.strip():
            return None
        return filename or "attached.eml", payload, declared

    # A leaf ``.eml`` file attachment (not message/rfc822) — common when a user
    # saves-and-forwards rather than attaching the message object itself.
    if suffix == ".eml":
        try:
            raw = part.get_payload(decode=True)
        except Exception:
            raw = None
        if isinstance(raw, bytes) and raw.strip():
            return filename, raw, declared

    return None


def _serialize_message_part(part: Message) -> bytes:
    """Wire-faithful bytes of an enclosed message (same approach as attachments)."""
    try:
        payload = part.get_payload()
        if isinstance(payload, list) and payload:
            buf = io.BytesIO()
            BytesGenerator(buf, mangle_from_=False, maxheaderlen=0).flatten(
                payload[0], linesep="\r\n"
            )
            return buf.getvalue()
        if isinstance(payload, Message):
            buf = io.BytesIO()
            BytesGenerator(buf, mangle_from_=False, maxheaderlen=0).flatten(payload, linesep="\r\n")
            return buf.getvalue()
        if isinstance(payload, str):
            return payload.encode("utf-8", errors="replace")
        if isinstance(payload, bytes):
            return payload
    except Exception:
        return b""
    return b""
