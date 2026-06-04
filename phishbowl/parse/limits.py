"""Input-validation limits for the parse layer (defensive hardening, PRD §13).

The analyzed email is hostile input end to end: a `.eml`/`.msg` can be
maliciously oversized or pathologically structured (a deeply nested or
fan-out multipart "MIME bomb"). These caps bound the work the parser will do
on a single message so abusive input can't exhaust memory or wedge the
pipeline. They are deliberately generous — far above any legitimate email — so
they never trip on real mail, only on abuse.

Two complementary guards:

* :data:`MAX_INPUT_BYTES` — the largest file/byte string we will parse at all.
  Enforced *before* reading the whole file into memory (via ``stat``), so a
  multi-gigabyte input is rejected without ever being slurped.
* :data:`MAX_PARTS` — the most MIME parts we will walk in one message, so a
  multipart tree engineered to explode into millions of parts is truncated
  rather than chased unbounded.
"""

from __future__ import annotations

from pathlib import Path

# Largest message we will read/parse. 50 MiB comfortably exceeds real-world mail
# (providers cap attachments around 25–35 MB) while refusing the multi-gigabyte
# inputs that would blow up memory.
MAX_INPUT_BYTES = 50 * 1024 * 1024

# Most MIME parts we will walk in one message. A multipart tree far larger than
# this is structural abuse, not legitimate mail; the walker stops here rather
# than chase an unbounded part explosion.
MAX_PARTS = 2000


class InputTooLargeError(ValueError):
    """Raised when an input exceeds :data:`MAX_INPUT_BYTES`.

    Subclasses :class:`ValueError` so the CLI's existing input-error handling
    (``parse`` → ``typer.BadParameter``) reports it as a clean message rather
    than an internal traceback.
    """


def _too_large(size: int) -> InputTooLargeError:
    return InputTooLargeError(
        f"input is {size} bytes, exceeding the {MAX_INPUT_BYTES}-byte "
        f"({MAX_INPUT_BYTES // (1024 * 1024)} MiB) limit"
    )


def read_within_limit(path: Path) -> bytes:
    """Read ``path`` as bytes, refusing anything over :data:`MAX_INPUT_BYTES`.

    The size is checked from ``stat`` *before* the file is read, so an
    oversized input is rejected without being loaded into memory. The decoded
    length is re-checked after reading to close any stat/read race (e.g. a
    symlinked or growing file).
    """
    size = path.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise _too_large(size)
    data = path.read_bytes()
    if len(data) > MAX_INPUT_BYTES:
        raise _too_large(len(data))
    return data
