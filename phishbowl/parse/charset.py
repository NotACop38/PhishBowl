"""Centralized charset / encoding handling for the parse layer (PRD §7).

Every decode in PhishBowl goes through here, so charset and RFC 2047
encoded-word handling happens **exactly once**, in one place. Downstream code
(extract, score, report) never re-decodes — it consumes already-decoded
``str`` from the :class:`~phishbowl.models.ParsedEmail`.

Three jobs:

- :func:`decode_mime_words` — RFC 2047 encoded-words in unstructured header
  text (subject, display names, filenames). ``=?utf-8?b?...?=`` → plain text.
- :func:`header_text` — a raw header value as text, *without* interpreting
  encoded-words (structured headers such as ``Authentication-Results`` must be
  parsed exactly as the receiving server wrote them).
- :func:`decode_payload` — a body part's transfer-decoded bytes → ``str`` using
  the part's declared charset.

All are deliberately total and linear-time: hostile input must never raise out
of here or make decoding quadratic. An unknown charset, a malformed
encoded-word, or undecodable bytes degrade to a replacement-character decode
rather than crashing the run (PRD §11), and decoded text never carries lone
UTF-16 surrogates (which some codecs produce and JSON/terminal output rejects).
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from email.header import Header, decode_header
from email.message import Message

# Fallback when a part declares no charset or declares one Python can't load.
_FALLBACK_CHARSET = "utf-8"

# Labels mail software uses that Python's codec registry does not know (or maps
# to a narrower codec), per the WHATWG Encoding Standard.
_CHARSET_ALIASES = {
    "iso-8859-8-i": "iso-8859-8",
    "windows-874": "cp874",
    "x-sjis": "shift_jis",
    "ms_kanji": "shift_jis",
    "x-gbk": "gbk",
    "cn-gb": "gb2312",
    "x-euc-jp": "euc_jp",
    "x-mac-cyrillic": "mac_cyrillic",
    "x-mac-roman": "mac_roman",
    "ks_c_5601-1987": "cp949",
    "ks_c_5601-1989": "cp949",
    "x-user-defined": "latin-1",
}

# Codecs that are not mail text encodings: punycode/idna decode in quadratic
# time, the escape codecs interpret backslashes, "undefined" always fails.
_REFUSED_CODECS = frozenset(
    {"punycode", "idna", "unicode-escape", "raw-unicode-escape", "undefined"}
)

# An RFC 2047 encoded-word, with an optional RFC 2231 language tag after "*".
# No part can contain "?" or whitespace, and the charset cannot contain "*", so
# every character is consumed by exactly one part and the pattern is linear
# (the stdlib's lazy ``.*?`` rescans the rest of the line for every
# unterminated "=?", which is quadratic on hostile headers).
_ENCODED_WORD = re.compile(r"=\?([^?\s*]+)(?:\*[^?\s]*)?\?([bBqQ])\?([^?\s]*)\?=")

_SURROGATES = re.compile(r"[\ud800-\udfff]")


def _codec(charset: str | None) -> str | None:
    """A safe Python codec name for a declared charset, or ``None``."""
    if not charset:
        return None
    label = charset.strip().strip("\"'").casefold()
    label = _CHARSET_ALIASES.get(label, label)
    try:
        name = codecs.lookup(label).name
    except (LookupError, ValueError, TypeError):  # unknown, or e.g. an embedded NUL
        return None
    return None if name in _REFUSED_CODECS else name


def _decode_bytes(raw: bytes, charset: str | None) -> str:
    """Decode bytes with ``charset``, falling back leniently on any failure."""
    for candidate in (_codec(charset), _FALLBACK_CHARSET):
        if not candidate:
            continue
        try:
            text = raw.decode(candidate)
        except (LookupError, ValueError):
            continue
        return _SURROGATES.sub("�", text)
    # Last resort: never lose the content, never raise.
    return raw.decode(_FALLBACK_CHARSET, errors="replace")


def _word_bytes(encoding: str, text: str) -> bytes | None:
    """The bytes one encoded-word carries, or ``None`` if it is malformed."""
    try:
        if encoding in "bB":
            return base64.b64decode(text + "=" * (-len(text) % 4))
        return binascii.a2b_qp(text.encode("ascii"), header=True)
    except (ValueError, binascii.Error, UnicodeError):
        return None


def header_text(value: str | Header | None) -> str | None:
    """A raw header value as text, without interpreting RFC 2047 encoded-words.

    The stdlib returns a ``str`` for ASCII headers and an
    :class:`email.header.Header` when raw 8-bit bytes are present (SMTPUTF8 /
    RFC 6532); ``str()`` would mangle the latter, so its bytes are decoded
    leniently instead (UTF-8, with replacement).
    """
    if value is None:
        return None
    if isinstance(value, str):
        return _SURROGATES.sub("�", value)
    try:
        fragments = decode_header(value)
    except Exception:
        return _SURROGATES.sub("�", str(value))
    return "".join(
        _decode_bytes(text, charset) if isinstance(text, bytes) else text
        for text, charset in fragments
    )


def decode_mime_words(value: str | Header | None) -> str | None:
    """Decode RFC 2047 encoded-words in unstructured header text.

    Handles runs of encoded and literal text (``Re: =?utf-8?q?...?=``),
    per-word charsets, and raw 8-bit text beside encoded-words. Whitespace
    between two adjacent encoded-words is dropped (RFC 2047 §6.2), and the bytes
    of adjacent words in the same charset are decoded together, so a character
    split across two words (common, though RFC 2047 forbids it) survives. A
    malformed encoded-word is kept verbatim. Never raises; linear in the input.
    """
    text = header_text(value)
    if text is None:
        return None
    out: list[str] = []
    run: bytearray = bytearray()  # bytes of the current run of adjacent words
    run_charset: str | None = None

    def flush() -> None:
        nonlocal run_charset
        if run_charset is not None:
            out.append(_decode_bytes(bytes(run), run_charset))
            run.clear()
            run_charset = None

    position = 0
    for match in _ENCODED_WORD.finditer(text):
        gap = text[position : match.start()]
        charset, encoding, payload = match.groups()
        raw = _word_bytes(encoding, payload)
        adjacent = run_charset is not None and not gap.strip()
        if raw is None:
            flush()
            out.append(gap + match.group(0))
        elif adjacent and charset.casefold() == run_charset:
            run.extend(raw)
        else:
            flush()
            if not adjacent:
                out.append(gap)
            run.extend(raw)
            run_charset = charset.casefold()
        position = match.end()
    flush()
    out.append(text[position:])
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
    try:
        charset = part.get_content_charset()
    except Exception:
        charset = None  # an unreadable charset parameter must not cost the body
    return _decode_bytes(raw, charset or _FALLBACK_CHARSET)
