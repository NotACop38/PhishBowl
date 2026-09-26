"""Defensive readers for fields of an untrusted vendor JSON document.

A vendor response is input like any other: a field can be missing, ``null``,
the wrong type, negative, or a float where a count belongs. These readers turn
anything unexpected into "no data" so a connector reports *unknown* rather than
crashing or inventing a number.
"""

from __future__ import annotations

import math
from typing import Any


def mapping(value: Any) -> dict[str, Any]:
    """``value`` if it is a JSON object, else an empty one."""
    return value if isinstance(value, dict) else {}


# Larger than any real count; beyond it a number is garbage, not data (and
# arbitrarily large JSON integers are expensive to carry around and print).
_MAX_COUNT = 2**53


def count(value: Any) -> int | None:
    """A non-negative whole number, or ``None`` when missing or malformed."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if not 0 <= value <= _MAX_COUNT:
        return None
    return int(value)


def text(value: Any) -> str | None:
    """``value`` if it is a JSON string, else ``None``."""
    return value if isinstance(value, str) else None
