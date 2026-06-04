"""Address-header parsing (PRD §6.1 / §7 — *Addresses*).

Splits each address into ``{display_name, addr_spec, domain}``. Display names
are RFC 2047 decoded (a common obfuscation vector). ``domain`` is derived once,
here, so downstream mismatch comparisons (From vs Return-Path vs Reply-To — a
core scoring signal, PRD §8) stay trivial.
"""

from __future__ import annotations

from email.utils import getaddresses

from phishbowl.models import Address

from .charset import decode_mime_words


def _domain_of(addr_spec: str | None) -> str | None:
    """Bare domain (everything after the last ``@``), or ``None``."""
    if not addr_spec or "@" not in addr_spec:
        return None
    domain = addr_spec.rsplit("@", 1)[1].strip()
    return domain or None


def _to_address(display: str, addr_spec: str) -> Address | None:
    """Build an :class:`Address` from a ``(display, addr_spec)`` pair.

    Returns ``None`` only when both halves are empty (nothing to record).
    """
    display = decode_mime_words(display) or ""
    display = display.strip()
    addr_spec = (addr_spec or "").strip()
    if not display and not addr_spec:
        return None
    return Address(
        display_name=display or None,
        addr_spec=addr_spec or None,
        domain=_domain_of(addr_spec),
    )


def parse_address_list(raw_values: list[str]) -> list[Address]:
    """Parse one-or-more address header values into a flat list of addresses.

    ``getaddresses`` accepts the list directly and splits comma-separated
    mailboxes, tolerating the malformed input phishing headers routinely carry.
    """
    addresses: list[Address] = []
    for display, addr_spec in getaddresses(raw_values):
        address = _to_address(display, addr_spec)
        if address is not None:
            addresses.append(address)
    return addresses


def parse_single_address(raw_values: list[str]) -> Address | None:
    """First address from ``raw_values`` (for single-mailbox headers)."""
    parsed = parse_address_list(raw_values)
    return parsed[0] if parsed else None
