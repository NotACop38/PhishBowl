"""Raw header capture (PRD §7 — *Headers*).

Headers are stored as an **ordered** list of ``(name, value)`` pairs that
**preserves duplicates** — ``Received`` hops and others legitimately repeat,
and the order carries analytic meaning (PRD §6.1). Lookups are
case-insensitive per RFC 5322.
"""

from __future__ import annotations

from collections.abc import Iterator

from pydantic import Field

from ._base import PhishbowlModel


class Header(PhishbowlModel):
    """A single header occurrence, exactly as parsed (after RFC 2047 decode)."""

    name: str
    value: str


class Headers(PhishbowlModel):
    """Ordered, duplicate-preserving header list with convenience accessors."""

    items: list[Header] = Field(default_factory=list)

    def get(self, name: str) -> str | None:
        """First value for ``name`` (case-insensitive), or ``None``."""
        folded = name.casefold()
        for header in self.items:
            if header.name.casefold() == folded:
                return header.value
        return None

    def get_all(self, name: str) -> list[str]:
        """Every value for ``name`` (case-insensitive), in original order."""
        folded = name.casefold()
        return [h.value for h in self.items if h.name.casefold() == folded]

    def names(self) -> list[str]:
        """Header names in original order, including duplicates."""
        return [h.name for h in self.items]

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        folded = name.casefold()
        return any(h.name.casefold() == folded for h in self.items)

    def __iter__(self) -> Iterator[Header]:  # type: ignore[override]
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)
