"""Address-header parsing (PRD §6.1 / §7 — *Addresses*).

Splits each address into ``{display_name, addr_spec, domain}``. Display names
are RFC 2047 decoded (a common obfuscation vector). ``domain`` is derived once,
here, so downstream mismatch comparisons (From vs Return-Path vs Reply-To — a
core scoring signal, PRD §8) stay trivial.

Phishing headers are routinely malformed, and on purpose: an unquoted display
name that is itself an address (``security@bank.example <attacker@evil.example>``)
or contains a comma (``Doe, John <jd@example.com>``). Python's strict parser
rejects such values outright, which would silently lose the sender. So a
single-mailbox header with an angle address is read the way mail clients
display it — the text before ``<…>`` is the display name — and the caller is
told when a value needed that lenient reading, so it can note it.
"""

from __future__ import annotations

import re
from email.utils import getaddresses

from phishbowl.models import Address

from .charset import decode_mime_words

# "display text <addr-spec>" — the angle address is the last <…> in the value.
_ANGLE_ADDR = re.compile(r"^(?P<display>.*)<(?P<addr>[^<>]*)>\s*$", re.DOTALL)


def _lenient_pairs(raw: str) -> list[tuple[str, str]]:
    """``getaddresses`` without strict RFC 5322 checking.

    Python releases since the CVE-2023-27043 fix parse strictly by default and
    take ``strict=False`` for the old behaviour; earlier releases are lenient
    already and do not accept the keyword.
    """
    try:
        return getaddresses([raw], strict=False)
    except TypeError:
        return getaddresses([raw])


def _domain_of(addr_spec: str | None) -> str | None:
    """Bare domain (everything after the last ``@``), or ``None``."""
    if not addr_spec or "@" not in addr_spec:
        return None
    domain = addr_spec.rsplit("@", 1)[1].strip().rstrip(">").strip()
    return domain or None


def _to_address(display: str, addr_spec: str) -> Address | None:
    """Build an :class:`Address` from a ``(display, addr_spec)`` pair.

    Returns ``None`` only when both halves are empty (nothing to record).
    """
    display = (decode_mime_words(display) or "").strip()
    if len(display) >= 2 and display[0] == display[-1] == '"':
        display = display[1:-1].replace('\\"', '"').strip()
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

    ``getaddresses`` splits comma-separated mailboxes. When the strict parser
    rejects a value outright it returns an empty pair; the non-strict parser is
    then used for that value instead, so a malformed recipient list still
    yields its addresses.
    """
    addresses: list[Address] = []
    for raw in raw_values:
        pairs = getaddresses([raw])
        if not any(addr for _display, addr in pairs):
            pairs = _lenient_pairs(raw)
        for display, addr_spec in pairs:
            address = _to_address(display, addr_spec)
            if address is not None:
                addresses.append(address)
    return addresses


def parse_single_address(raw_values: list[str]) -> tuple[Address | None, bool]:
    """The mailbox of a single-mailbox header, and whether it was read leniently.

    The first value is used (a second copy of the header is scored separately
    as a spoofing signal). A value with an angle address is split at the
    ``<…>`` exactly as a mail client displays it; otherwise the first parsed
    mailbox that has an address wins. ``lenient`` is ``True`` when the strict
    RFC 5322 reading differs, i.e. the header is malformed.
    """
    if not raw_values:
        return None, False
    raw = raw_values[0]
    strict = [pair for pair in getaddresses([raw]) if pair[1]]
    angle = _ANGLE_ADDR.match(raw.strip())
    if angle and "@" in angle.group("addr"):
        address = _to_address(angle.group("display"), angle.group("addr"))
        lenient = len(strict) != 1 or strict[0][1].strip() != angle.group("addr").strip()
        return address, lenient
    with_at = [pair for pair in strict if "@" in pair[1]]
    if with_at:
        return _to_address(*with_at[0]), len(strict) != 1
    loose = [pair for pair in _lenient_pairs(raw) if pair[0] or pair[1]]
    if loose:
        return _to_address(*loose[0]), True
    return None, bool(raw.strip())
