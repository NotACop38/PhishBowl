"""Build the indicator set an enrichment pass works over (PRD §9).

Connectors enrich *indicators*, and the natural source is the extracted IOC
collection — every URL, domain, IP, and hash PhishBowl already found and
defanged (PRD §6.2). One thing the IOC pass doesn't surface is the **sending
IP**: it lives in the ``Received`` routing chain, and AbuseIPDB/Shodan want it
(PRD §8). So this builder unions the IOC indicators with the public IPs parsed
out of the routing hops, de-duplicated and ordered (routing IPs first, since the
sending infrastructure is the highest-value pivot).

Only *public* IPs are emitted — private/loopback/link-local addresses are
internal topology, never sent to a third party (consistent with PII redaction,
PRD §10). Email-address indicators are not enriched by any bundled connector and
are omitted.
"""

from __future__ import annotations

import ipaddress
import re

from phishbowl.models import IOCs, IOCType, ParsedEmail

from .base import Indicator

# Indicator types a connector might enrich. Email addresses are deliberately
# excluded — no bundled connector consumes them, and they are often recipient PII.
_ENRICHABLE = (IOCType.URL, IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6, IOCType.HASH)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Bracketed IPv6 as it appears in Received hops, e.g. "[2001:db8::1]".
_IPV6_RE = re.compile(r"\[([0-9A-Fa-f:]{2,}:[0-9A-Fa-f:]+)\]")


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    )


def _defang_ip(value: str) -> str:
    # Match the IOC defanger's convention without importing it here.
    return value.replace(".", "[.]") if ":" not in value else value.replace(":", "[:]")


def sending_ips(parsed: ParsedEmail) -> list[Indicator]:
    """Public IPs from the ``Received`` chain, most-recent hop first (PRD §8).

    The topmost hop is closest to the receiving infrastructure; reading downward
    walks back toward the origin. We scan each hop's raw text for IPv4/IPv6
    literals and keep the public ones in first-seen order — ``[0]`` is the best
    "sending IP" candidate for IP reputation lookups.
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
            if canonical in seen or not _is_public_ip(canonical):
                continue
            seen.add(canonical)
            ip_type = IOCType.IPV6 if ":" in canonical else IOCType.IPV4
            out.append(
                Indicator(type=ip_type.value, value=canonical, defanged=_defang_ip(canonical))
            )
    return out


def build_targets(parsed: ParsedEmail, iocs: IOCs) -> list[Indicator]:
    """Union of enrichable IOCs and routing sending-IPs, de-duplicated (PRD §9).

    Routing-derived sending IPs come first (highest-value pivot), then the
    extracted IOCs in collection order. De-duplication is by ``(type, value)`` so
    an IP that appears both in a hop and in the body is enriched once.
    """
    seen: set[tuple[str, str]] = set()
    targets: list[Indicator] = []

    def _add(ind: Indicator) -> None:
        key = (ind.type, ind.value)
        if key not in seen:
            seen.add(key)
            targets.append(ind)

    for ip in sending_ips(parsed):
        _add(ip)

    for ioc in iocs:
        if ioc.type in _ENRICHABLE:
            _add(Indicator(type=ioc.type.value, value=ioc.value, defanged=ioc.defanged))

    return targets
