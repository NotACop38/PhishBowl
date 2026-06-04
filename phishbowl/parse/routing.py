"""``Received`` hop parsing (PRD §6.1 / §7 — *Routing*).

Each ``Received`` header is reconstructed into the delivery path, top-to-bottom
as it appears (``hops[0]`` is the most recent / closest to us). The raw value
is always retained; ``from`` / ``by`` / ``with`` / timestamp are best-effort and
may be ``None`` when a hop doesn't parse cleanly — a malformed hop is recorded
raw, never dropped, never fatal.
"""

from __future__ import annotations

import re
from datetime import datetime
from email.utils import parsedate_to_datetime

from phishbowl.models import ReceivedHop, Routing
from phishbowl.models.headers import Headers

# ``from <token>`` / ``by <token>`` / ``with <token>`` — grab the first token
# after each keyword, stopping at whitespace, ``;`` or an opening paren.
_FROM = re.compile(r"\bfrom\s+([^\s;(]+)", re.IGNORECASE)
_BY = re.compile(r"\bby\s+([^\s;(]+)", re.IGNORECASE)
_WITH = re.compile(r"\bwith\s+([^\s;(]+)", re.IGNORECASE)


def _first(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(1) if match else None


def _timestamp(raw: str) -> datetime | None:
    """Parse the trailing ``; <date>`` of a Received header, if present."""
    if ";" not in raw:
        return None
    date_part = raw.rsplit(";", 1)[1].strip()
    if not date_part:
        return None
    try:
        return parsedate_to_datetime(date_part)
    except (TypeError, ValueError):
        return None


def _parse_hop(raw: str) -> ReceivedHop:
    return ReceivedHop(
        raw=raw,
        from_=_first(_FROM, raw),
        by=_first(_BY, raw),
        with_=_first(_WITH, raw),
        timestamp=_timestamp(raw),
    )


def parse_routing(headers: Headers) -> Routing:
    """Build the ordered :class:`Routing` path from all ``Received`` headers."""
    return Routing(hops=[_parse_hop(raw) for raw in headers.get_all("Received")])
