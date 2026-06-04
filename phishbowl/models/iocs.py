"""Indicators of compromise (PRD §7 — *IOCs*).

The extracted-and-defanged indicator collection, with provenance. Every IOC
keeps both a normalized ``value`` and its ``defanged`` form (PRD §6.2): all
human-facing output uses the defanged form by default, while ``value`` is for
tool interchange (clearly labeled raw). ``provenance`` records which
header/part each indicator came from.

Protective link wrappers (Microsoft Safelinks, Proofpoint URL Defense) are
unwrapped as a pure **string transform** — Phishbowl never fetches anything
(CLAUDE.md). Both forms are retained: ``value`` holds the unwrapped target and
``wrapped`` the original on-wire wrapper string. ``wrapper`` names the detected
wrapper, and ``unresolved`` is set for wrappers we can detect but cannot reverse
offline (Mimecast / Barracuda / Cisco), whose ``value`` stays the wrapped form.
"""

from __future__ import annotations

from collections.abc import Iterator

from pydantic import Field

from ._base import PhishbowlModel
from .enums import IOCType


class IOC(PhishbowlModel):
    """A single indicator, normalized and defanged, with its provenance."""

    type: IOCType
    value: str
    defanged: str
    # Header/part(s) the indicator was seen in (e.g. "header:From", "body:html").
    provenance: list[str] = Field(default_factory=list)
    # Original protective-wrapper form, retained whenever a wrapper was detected.
    wrapped: str | None = None
    # Detected protective-wrapper name (e.g. "safelinks", "proofpoint",
    # "mimecast"); ``None`` when the indicator was not wrapped.
    wrapper: str | None = None
    # True for a wrapper we detected but cannot reverse offline (Mimecast /
    # Barracuda / Cisco): the wrapped form is kept and flagged "wrapped, unresolved".
    unresolved: bool = False


class IOCs(PhishbowlModel):
    """Deduplicated indicator collection."""

    items: list[IOC] = Field(default_factory=list)

    def by_type(self, ioc_type: IOCType) -> list[IOC]:
        """All indicators of a given type, in collection order."""
        return [ioc for ioc in self.items if ioc.type == ioc_type]

    def __iter__(self) -> Iterator[IOC]:  # type: ignore[override]
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)
