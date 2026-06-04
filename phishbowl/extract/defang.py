"""Defanging — render indicators inert for human-facing output (PRD §6.2).

Every URL, IP, email, and domain shown to an analyst is *defanged* by default so
a report or terminal can never auto-link or one-click an attacker's indicator
(``hxxps://evil[.]com``, ``1[.]2[.]3[.]4``, ``user[at]evil[.]com``). This is a
pure string transform — like everything in :mod:`phishbowl.extract`, it never
touches the network.

The JSON output keeps the raw ``value`` alongside the ``defanged`` form for tool
interchange (PRD §6.2); :func:`refang` reverses the transform so a round-trip is
lossless for the indicators we produce.
"""

from __future__ import annotations

import re

from phishbowl.models import IOCType

# http -> hxxp, https -> hxxps, only when it's a real scheme (followed by "://").
_SCHEME_RE = re.compile(r"^(https?)(?=://)", re.IGNORECASE)


def defang_url(value: str) -> str:
    """Defang a URL: neuter the scheme and bracket every dot."""
    out = _SCHEME_RE.sub(lambda m: "hxxp" + m.group(1)[4:], value)
    return out.replace(".", "[.]")


def defang_ipv4(value: str) -> str:
    """Defang an IPv4 literal: ``1.2.3.4`` -> ``1[.]2[.]3[.]4``."""
    return value.replace(".", "[.]")


def defang_ipv6(value: str) -> str:
    """Defang an IPv6 literal by bracketing its separators."""
    return value.replace(":", "[:]")


def defang_email(value: str) -> str:
    """Defang an address: ``user@evil.com`` -> ``user[at]evil[.]com``."""
    return value.replace("@", "[at]").replace(".", "[.]")


def defang_domain(value: str) -> str:
    """Defang a bare domain: ``evil.com`` -> ``evil[.]com``."""
    return value.replace(".", "[.]")


def defang(value: str, ioc_type: IOCType) -> str:
    """Defang ``value`` according to its IOC type (PRD §6.2)."""
    if ioc_type is IOCType.URL:
        return defang_url(value)
    if ioc_type is IOCType.IPV4:
        return defang_ipv4(value)
    if ioc_type is IOCType.IPV6:
        return defang_ipv6(value)
    if ioc_type is IOCType.EMAIL:
        return defang_email(value)
    if ioc_type is IOCType.DOMAIN:
        return defang_domain(value)
    # Hashes carry no auto-linkable punctuation; nothing to defang.
    return value


def refang(value: str) -> str:
    """Reverse :func:`defang` — restore a live indicator from its defanged form.

    Covers the brackets and scheme swaps Phishbowl emits, plus the common
    ``[at]`` / ``(.)`` variants seen in the wild, so a defang round-trip is
    lossless for the indicators we produce.
    """
    out = (
        value.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
        .replace("[:]", ":")
        .replace("[at]", "@")
        .replace("[@]", "@")
    )
    return out.replace("hxxps://", "https://").replace("hxxp://", "http://")
