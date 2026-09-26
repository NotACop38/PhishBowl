"""``Received`` hop parsing (PRD §6.1 / §7 — *Routing*).

Each ``Received`` header is reconstructed into the delivery path, top-to-bottom
as it appears (``hops[0]`` is the most recent / closest to us). The raw value
(unfolded, never RFC 2047-decoded) is always retained; ``from`` / ``by`` /
``with`` / timestamp are best-effort and may be ``None`` when a hop doesn't
parse cleanly — a malformed hop is recorded raw, never dropped, never fatal.

Clause keywords are matched only outside comments, so the ``from`` in
``(envelope-from <…>)`` or the ``with`` in ``(using TLSv1.3 with cipher …)`` is
never mistaken for the hop's own ``from`` host or ``with`` protocol.
"""

from __future__ import annotations

import re
from datetime import datetime
from email.utils import parsedate_to_datetime

from phishbowl.models import ReceivedHop, Routing
from phishbowl.models.headers import Headers

from .auth import strip_comments

# ``from <token>`` / ``by <token>`` / ``with <token>`` at a clause boundary
# (start of the value or after whitespace), capturing up to whitespace, ";",
# or a parenthesis.
_FROM = re.compile(r"(?:^|\s)from\s+([^\s;()]+)", re.IGNORECASE)
_BY = re.compile(r"(?:^|\s)by\s+([^\s;()]+)", re.IGNORECASE)
_WITH = re.compile(r"(?:^|\s)with\s+([^\s;()]+)", re.IGNORECASE)


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
    except (TypeError, ValueError, OverflowError):
        # A hostile offset can overflow datetime arithmetic; the hop stays.
        return None


def _parse_hop(raw: str) -> ReceivedHop:
    clauses = strip_comments(raw.rsplit(";", 1)[0] if ";" in raw else raw)
    return ReceivedHop(
        raw=raw,
        from_=_first(_FROM, clauses),
        by=_first(_BY, clauses),
        with_=_first(_WITH, clauses),
        timestamp=_timestamp(raw),
    )


def parse_routing(headers: Headers) -> Routing:
    """Build the ordered :class:`Routing` path from all ``Received`` headers."""
    return Routing(hops=[_parse_hop(raw) for raw in headers.get_all("Received")])
