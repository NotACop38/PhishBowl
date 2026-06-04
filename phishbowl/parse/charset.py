"""Centralized charset / encoding handling for the parse layer (PRD §7).

Every decode in Phishbowl goes through here, so charset and RFC 2047
encoded-word handling happens **exactly once**, in one place. Downstream code
(extract, score, report) never re-decodes — it consumes already-decoded
``str`` from the :class:`~phishbowl.models.ParsedEmail`.

Two jobs:

- :func:`decode_mime_words` — RFC 2047 encoded-words in headers (subject,
  display names, filenames). ``=?utf-8?b?...?=`` → plain text.
- :func:`decode_payload` — a body part's transfer-decoded bytes → ``str`` using
  the part's declared charset.

Both are deliberately total: hostile input must never raise out of here. An
unknown charset, a malformed encoded-word, or undecodable bytes degrade to a
replacement-character decode rather than crashing the run (PRD §11).
"""

from __future__ import annotations

from email.header import Header, decode_header
from email.message import Message

# Fallback when a part declares no charset or declares one Python can't load.
_FALLBACK_CHARSET = "utf-8"


def decode_mime_words(value: str | Header | None) -> str | None:
    """Decode any RFC 2047 encoded-words in a header value into plain text.

    Handles mixed runs of encoded and literal text (``Re: =?utf-8?q?...?=``)
    and per-word charsets. Accepts the raw header value as returned by the
    stdlib ``email`` package — a ``str`` for ASCII / RFC 2047 headers, or an
    ``email.header.Header`` when raw 8-bit bytes are present (SMTPUTF8 /
    RFC 6532). Passing such a ``Header`` through ``str()`` first would mangle
    those bytes, so callers should hand the raw value straight here.

    Never raises: a malformed encoded-word or an unknown charset falls back to
    a lenient decode so a hostile header can't crash the parser.
    """
    if value is None:
        return None
    try:
        fragments = decode_header(value)
    except Exception:
        # Malformed encoded-word syntax — keep the raw text rather than crash.
        return str(value)

    out: list[str] = []
    for text, charset in fragments:
        if isinstance(text, bytes):
            out.append(_decode_bytes(text, charset))
        else:
            out.append(text)
    return "".join(out)


def decode_payload(part: Message) -> str | None:
    """Transfer-decode a body part and decode its bytes to ``str``.

    ``get_payload(decode=True)`` reverses the Content-Transfer-Encoding
    (base64 / quoted-printable / …); we then decode the resulting bytes with
    the part's declared charset. Returns ``None`` when the part has no payload.
    Never raises.
    """
    try:
        raw = part.get_payload(decode=True)
    except Exception:
        return None
    if raw is None:
        return None
    charset = part.get_content_charset() or _FALLBACK_CHARSET
    return _decode_bytes(raw, charset)


def _decode_bytes(raw: bytes, charset: str | None) -> str:
    """Decode bytes with ``charset``, falling back leniently on any failure."""
    for candidate in (charset, _FALLBACK_CHARSET):
        if not candidate:
            continue
        try:
            return raw.decode(candidate)
        except (LookupError, ValueError):
            continue
    # Last resort: never lose the content, never raise.
    return raw.decode(_FALLBACK_CHARSET, errors="replace")
