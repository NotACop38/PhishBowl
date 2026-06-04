"""Delivery path (PRD §7 — *Routing*).

The ordered list of ``Received`` hops, reconstructed top-to-bottom as parsed
from the headers (PRD §6.1). The raw value is always retained; the parsed
``from``/``by``/``with``/timestamp fields are best-effort and may be ``None``
when a hop doesn't parse cleanly.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from ._base import PhishbowlModel


class ReceivedHop(PhishbowlModel):
    """A single ``Received`` header, both raw and best-effort parsed.

    ``from_`` / ``with_`` carry ``from`` / ``with`` aliases since both are
    Python keywords; ``populate_by_name`` lets either spelling validate.
    """

    raw: str
    from_: str | None = Field(default=None, alias="from")
    by: str | None = None
    with_: str | None = Field(default=None, alias="with")
    timestamp: datetime | None = None


class Routing(PhishbowlModel):
    """Ordered ``Received`` hops; ``hops[0]`` is the topmost (most recent)."""

    hops: list[ReceivedHop] = Field(default_factory=list)

    def __len__(self) -> int:
        return len(self.hops)
