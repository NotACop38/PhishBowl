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

from dataclasses import dataclass
from email.message import Message
from pathlib import Path

from .attachments import OLE_MAGIC, iter_parts, message_part_bytes
from .charset import decode_mime_words
from .mime import bounded_message
from .msg import embedded_emails as msg_embedded_emails


@dataclass(frozen=True)
class EmbeddedEmail:
    """One attached email found inside an outer message."""

    index: int
    filename: str
    data: bytes
    declared_type: str | None = None


def list_embedded_emails(data: bytes) -> list[EmbeddedEmail]:
    """Return the emails attached to raw ``.eml`` or ``.msg`` bytes.

    For RFC 822 input: ``message/rfc822`` / ``message/news`` parts and leaf
    attachments whose filename ends in ``.eml``. For an Outlook ``.msg``:
    embedded Outlook items (re-serialized as ``.msg``) and attached ``.eml``
    files. Results are in document order, 0-indexed, and each ``data`` blob is
    suitable for :func:`~phishbowl.parse.parse_bytes` (its filename's suffix
    selects the parser).
    """
    if data.startswith(OLE_MAGIC):
        return [
            EmbeddedEmail(index=index, filename=name, data=blob)
            for index, (name, blob) in enumerate(msg_embedded_emails(data))
        ]

    try:
        msg = bounded_message(data)
    except Exception:
        return []

    found: list[EmbeddedEmail] = []
    for part in iter_parts(msg):
        try:
            embedded = _maybe_embedded(part)
        except Exception:  # one unreadable part never hides the others
            continue
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
    return found


# Parts whose payload is a whole email. message/delivery-status and friends are
# message/* too, but hold report fields, not a message to triage.
_EMAIL_TYPES = frozenset({"message/rfc822", "message/global", "message/news"})


def _maybe_embedded(part: Message) -> tuple[str | None, bytes, str | None] | None:
    """Return ``(filename, bytes, declared_type)`` if ``part`` is an attached email."""
    declared = part.get_content_type()
    filename = decode_mime_words(part.get_filename())
    suffix = Path(filename).suffix.casefold() if filename else ""

    if declared in _EMAIL_TYPES:
        payload = message_part_bytes(part)
        if not payload.strip():
            return None
        return filename, payload, declared

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
