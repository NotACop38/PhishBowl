"""Parsed message addresses (PRD §7 — *Addresses*).

Every address is split into ``{display_name, addr_spec, domain}`` (PRD §6.1).
Crucially, ``From`` / ``Return-Path`` / ``Reply-To`` must be **trivially
comparable**: a domain mismatch between them is a core offline scoring signal
(PRD §8). The comparison helpers here are deliberately conservative — they
fire only when both domains are known and differ — so the scorer never raises
a mismatch on missing data.
"""

from __future__ import annotations

from pydantic import Field

from ._base import PhishbowlModel


class Address(PhishbowlModel):
    """A single mailbox: display name, ``local@domain``, and bare domain.

    ``domain`` is stored separately (rather than re-derived downstream) so
    comparisons are cheap and charset/encoding is resolved once, here.
    """

    display_name: str | None = None
    addr_spec: str | None = None
    domain: str | None = None

    def domain_matches(self, other: Address | None) -> bool:
        """True iff both addresses have a domain and they're equal.

        Case-insensitive. Returns ``False`` when either domain is missing —
        absence is not a match.
        """
        if other is None or not self.domain or not other.domain:
            return False
        return self.domain.casefold() == other.domain.casefold()


def _domains_differ(a: Address | None, b: Address | None) -> bool:
    """True only when both addresses have a domain and the two differ."""
    if a is None or b is None or not a.domain or not b.domain:
        return False
    return a.domain.casefold() != b.domain.casefold()


class Addresses(PhishbowlModel):
    """The message's address fields.

    ``from_`` carries a ``from`` alias (``from`` is a Python keyword);
    ``populate_by_name`` accepts either spelling on input.
    """

    from_: Address | None = Field(default=None, alias="from")
    reply_to: Address | None = None
    return_path: Address | None = None
    sender: Address | None = None
    to: list[Address] = Field(default_factory=list)
    cc: list[Address] = Field(default_factory=list)

    @property
    def return_path_mismatch(self) -> bool:
        """Return-Path domain present and ≠ From domain (PRD §8)."""
        return _domains_differ(self.from_, self.return_path)

    @property
    def reply_to_mismatch(self) -> bool:
        """Reply-To domain present and ≠ From domain (PRD §8)."""
        return _domains_differ(self.from_, self.reply_to)

    @property
    def sender_mismatch(self) -> bool:
        """Envelope Sender domain present and ≠ From domain (PRD §8)."""
        return _domains_differ(self.from_, self.sender)
