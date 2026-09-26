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


def count(value: Any) -> int | None:
    """A non-negative whole number, or ``None`` when missing or malformed."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or value < 0:
        return None
    return int(value)
