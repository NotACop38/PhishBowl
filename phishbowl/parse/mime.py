"""Reject excessive MIME trees while constructing them, including embedded mail."""

from email.feedparser import BytesFeedParser
from email.message import Message

from . import limits

MAX_DEPTH = 30


class MIMEBudgetError(ValueError):
    pass


def bounded_message(data: bytes) -> Message:
    if len(data) > limits.MAX_INPUT_BYTES:
        raise MIMEBudgetError("Message exceeds the input byte limit")
    start = 0
    lines = 0
    while start < len(data):
        end = data.find(b"\n", start)
        end = len(data) if end < 0 else end
        lines += 1
        if end - start > 64 * 1024 or lines > 100_000:
            raise MIMEBudgetError("MIME line length or line count limit exceeded")
        start = end + 1
    count = 0

    # FeedParser's message factory is called before each MIME node is allocated.
    # The factory also sees the active stack, so depth is checked before recursion.
    def factory():
        nonlocal count
        count += 1
        if count > limits.MAX_PARTS or len(parser._msgstack) >= MAX_DEPTH:
            raise MIMEBudgetError("MIME part or nesting limit exceeded; analysis incomplete")
        return Message()

    parser = BytesFeedParser(_factory=factory)
    for start in range(0, len(data), 64 * 1024):
        parser.feed(data[start : start + 64 * 1024])
    return parser.close()
