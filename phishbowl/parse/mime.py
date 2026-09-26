"""Bounded, hostile-input-safe MIME construction.

The stdlib ``email`` parser is tolerant of malformed structure, but two things
need guarding before it is handed attacker-controlled bytes:

* **Budgets.** Part count and nesting depth are checked as each node is
  allocated, and line length/count before parsing starts, so a "MIME bomb"
  is refused rather than chased. :func:`headers_only` then recovers the header
  block alone, so an over-budget message still yields its sender,
  authentication and routing evidence.
* **Parameter decoding.** RFC 2231 parameters name their own charset
  (``filename*=idna''…``). The stdlib decodes them with whatever codec is named:
  ``idna`` raises an exception the parser does not catch, and ``punycode``
  decodes in quadratic time. :class:`SafeMessage` routes every such decode
  through :mod:`phishbowl.parse.charset`, which refuses non-mail codecs and
  never raises.
"""

from __future__ import annotations

from email import utils
from email.feedparser import BytesFeedParser
from email.message import Message
from email.parser import BytesHeaderParser

from . import limits
from .charset import _codec, _decode_bytes

MAX_DEPTH = 30

# Longest line and most lines accepted before parsing. The line cap follows the
# byte cap: 50 MiB of standard 76-column base64 is about 690,000 lines.
MAX_LINE_BYTES = 64 * 1024
MAX_LINES = 1_000_000

# The most header bytes :func:`headers_only` reads.
_MAX_HEADER_BYTES = 1024 * 1024


class MIMEBudgetError(ValueError):
    """The message's MIME structure exceeds the parser's budgets."""


def _collapse(value: object) -> str:
    """Decode an RFC 2231 parameter value (``(charset, language, text)``) safely."""
    if isinstance(value, tuple) and len(value) == 3:
        charset, _language, text = value
        raw = str(text).encode("raw-unicode-escape")
        return _decode_bytes(raw, _codec(charset) or "us-ascii")
    return utils.unquote(str(value))


class SafeMessage(Message):
    """A :class:`~email.message.Message` whose parameter accessors never raise.

    The stdlib raises ``TypeError`` for some malformed RFC 2231 parameters (a
    ``name*`` mixed with ``name*0`` continuations) and mishandles charsets; here
    an unreadable parameter reads as absent, and RFC 2231 values are decoded
    leniently. Everything else is inherited unchanged.
    """

    def get_params(self, failobj=None, header="content-type", unquote=True):
        try:
            return super().get_params(failobj, header, unquote)
        except Exception:
            return failobj

    def get_param(self, param, failobj=None, header="content-type", unquote=True):
        try:
            return super().get_param(param, failobj, header, unquote)
        except Exception:
            return failobj

    def get_filename(self, failobj=None):
        missing = object()
        filename = self.get_param("filename", missing, "content-disposition")
        if filename is missing:
            filename = self.get_param("name", missing, "content-type")
        if filename is missing:
            return failobj
        return _collapse(filename).strip()

    def get_boundary(self, failobj=None):
        missing = object()
        boundary = self.get_param("boundary", missing)
        if boundary is missing:
            return failobj
        # RFC 2046 says boundaries may begin but not end in whitespace.
        return _collapse(boundary).rstrip()

    def get_content_charset(self, failobj=None):
        missing = object()
        charset = self.get_param("charset", missing)
        if charset is missing:
            return failobj
        charset = _collapse(charset)
        if not charset.isascii():
            return failobj
        return charset.lower()


def _check_lines(data: bytes) -> None:
    start = 0
    lines = 0
    while start < len(data):
        end = data.find(b"\n", start)
        end = len(data) if end < 0 else end
        lines += 1
        if end - start > MAX_LINE_BYTES or lines > MAX_LINES:
            raise MIMEBudgetError("MIME line length or line count limit exceeded")
        start = end + 1


def bounded_message(data: bytes) -> Message:
    """Parse ``data`` into a :class:`SafeMessage` tree, enforcing the budgets."""
    if len(data) > limits.MAX_INPUT_BYTES:
        raise MIMEBudgetError("message exceeds the input byte limit")
    _check_lines(data)
    count = 0

    # FeedParser's message factory is called before each MIME node is allocated.
    # The factory also sees the active stack, so depth is checked before recursion.
    def factory():
        nonlocal count
        count += 1
        if count > limits.MAX_PARTS or len(parser._msgstack) >= MAX_DEPTH:
            raise MIMEBudgetError(
                f"MIME structure exceeds {limits.MAX_PARTS} parts or {MAX_DEPTH} levels"
            )
        return SafeMessage()

    parser = BytesFeedParser(_factory=factory)
    for start in range(0, len(data), 64 * 1024):
        parser.feed(data[start : start + 64 * 1024])
    return parser.close()


def headers_only(data: bytes) -> Message:
    """Parse just the header block of ``data`` (at most 1 MiB); the body is ignored."""
    head = data[:_MAX_HEADER_BYTES]
    for separator in (b"\r\n\r\n", b"\n\n"):
        end = head.find(separator)
        if end >= 0:
            head = head[: end + len(separator)]
            break
    return BytesHeaderParser(_class=SafeMessage).parsebytes(head)
