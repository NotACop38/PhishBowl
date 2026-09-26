"""Build the indicator set an enrichment pass works over (PRD §9).

Connectors enrich *indicators*, and the natural source is the extracted IOC
collection — every URL, domain, IP, and hash PhishBowl already found (PRD §6.2).
One thing the IOC pass doesn't surface is the **sending IP**: it lives in the
``Received`` routing chain, and AbuseIPDB/Shodan want it (PRD §8). So this
builder unions the IOC indicators with the public IPs parsed out of the routing
hops, de-duplicated and ordered by pivot value: routing IPs first, then
attachment hashes, then everything else in collection order. Per-connector caps
therefore drop body padding before they drop the sending IP or a file hash.

What is never sent to a third party, as an indicator or as a URL's host:

* non-public IP addresses, however they are written — including the legacy
  notations browsers still accept as IPv4 (``127.1``, ``0x7f.0.0.1``, a
  trailing dot);
* local host names (no dot, or ``.localhost`` / ``.local`` / ``.internal`` /
  ``.home.arpa``) and anything that is not a syntactically valid DNS name;
* hosts under a configured organization domain (``excluded_domains``), compared
  in IDNA form and with backslashes read as browsers read them;
* domains seen only in recipient headers, and email addresses (often PII).

A URL whose host passes is sent whole to URL-reputation services, so its path
and query travel with it.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from phishbowl.domains import in_domain, is_public_ip, normalize_domain_pattern, public_host
from phishbowl.models import IOCs, IOCType, ParsedEmail

from .base import Indicator

# Indicator types a connector might enrich. Email addresses are deliberately
# excluded — no bundled connector consumes them, and they are often recipient PII.
_ENRICHABLE = (IOCType.URL, IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6, IOCType.HASH)

# Provenance of an attachment's SHA-256 (see phishbowl.extract).
_ATTACHMENT_HASH = "attachment:sha256"

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Bracketed IPv6 as it appears in Received hops, e.g. "[2001:db8::1]".
_IPV6_RE = re.compile(r"\[([0-9A-Fa-f:]{2,}:[0-9A-Fa-f:]+)\]")


def _defang_ip(value: str) -> str:
    # Match the IOC defanger's convention without importing it here.
    return value.replace(".", "[.]") if ":" not in value else value.replace(":", "[:]")


def _ip_indicator(value: str) -> Indicator:
    ip_type = IOCType.IPV6 if ":" in value else IOCType.IPV4
    return Indicator(type=ip_type.value, value=value, defanged=_defang_ip(value))


def sending_ips(parsed: ParsedEmail) -> list[Indicator]:
    """Public IPs from the ``Received`` chain, most-recent hop first (PRD §8).

    The topmost hop is closest to the receiving infrastructure; reading downward
    walks back toward the origin. We scan each hop's raw text for IPv4/IPv6
    literals and keep the public ones in first-seen order — ``[0]`` is the best
    "sending IP" candidate for IP reputation lookups. Received headers can be
    forged below the receiving server's own hop, so this is a candidate list,
    not a verified origin.
    """
    seen: set[str] = set()
    out: list[Indicator] = []
    for hop in parsed.routing.hops:
        text = hop.raw or ""
        candidates = list(_IPV4_RE.findall(text)) + list(_IPV6_RE.findall(text))
        for raw in candidates:
            try:
                canonical = str(ipaddress.ip_address(raw.strip()))
            except ValueError:
                continue
            if canonical in seen or not is_public_ip(canonical):
                continue
            seen.add(canonical)
            out.append(_ip_indicator(canonical))
    return out


def build_targets(
    parsed: ParsedEmail, iocs: IOCs, *, excluded_domains: frozenset[str] = frozenset()
) -> list[Indicator]:
    """Union of enrichable IOCs and routing sending-IPs, de-duplicated (PRD §9).

    Order: routing sending IPs, then attachment SHA-256 hashes, then the
    remaining IOCs (hash-shaped strings from text included) in collection
    order. De-duplication is by ``(type, value)`` so an IP that appears both in
    a hop and in the body is enriched once.
    """
    excluded = frozenset(normalize_domain_pattern(d) for d in excluded_domains if d.strip())
    seen: set[tuple[str, str]] = set()
    targets: list[Indicator] = []

    def add(indicator: Indicator) -> None:
        key = (indicator.type, indicator.value)
        if key not in seen:
            seen.add(key)
            targets.append(indicator)

    def sendable_name(name: str) -> bool:
        return not in_domain(name, excluded)

    for ip in sending_ips(parsed):
        add(ip)

    # Attachment hashes go ahead of everything else, but only those: a
    # hash-shaped string in the body is attacker-controlled text, and letting it
    # jump the queue would let a sender push real links past a connector's cap.
    iocs_in_order = sorted(iocs, key=lambda ioc: _ATTACHMENT_HASH not in ioc.provenance)
    for ioc in iocs_in_order:
        if ioc.type not in _ENRICHABLE:
            continue
        if ioc.type is IOCType.HASH:
            add(Indicator(type=ioc.type.value, value=ioc.value, defanged=ioc.defanged))
        elif ioc.type in (IOCType.IPV4, IOCType.IPV6):
            if is_public_ip(ioc.value):
                add(_ip_indicator(str(ipaddress.ip_address(ioc.value))))
        elif ioc.type is IOCType.DOMAIN:
            if set(ioc.provenance) <= {"header:To", "header:Cc"}:
                continue  # a recipient's domain is theirs, not the attacker's
            host = public_host(ioc.value)
            if host is None:
                continue
            kind, value = host
            if kind == "ip":
                add(_ip_indicator(value))  # an IP literal mislabelled as a domain
            elif sendable_name(value):
                add(Indicator(type="domain", value=value, defanged=value.replace(".", "[.]")))
        elif ioc.type is IOCType.URL:
            try:
                # Browsers read "\" as "/" in web URLs; judge the host they would.
                parts = urlsplit(ioc.value.replace("\\", "/"))
                hostname = parts.hostname
            except ValueError:
                continue
            if parts.scheme not in {"http", "https"} or not hostname:
                continue
            host = public_host(hostname)
            if host is None or (host[0] == "name" and not sendable_name(host[1])):
                continue
            add(Indicator(type=ioc.type.value, value=ioc.value, defanged=ioc.defanged))
    return targets
