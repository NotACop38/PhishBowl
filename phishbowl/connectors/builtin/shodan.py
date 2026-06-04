"""Shodan connector (PRD §8, §9).

Exposed-service context for an IP — a contextual signal (PRD §8 weight 6): a
sending IP exposing remote-access or admin services is mildly corroborating, not
decisive. Key-gated (``SHODAN_API_KEY``), reaches only ``api.shodan.io``, and
never logs or returns the key. The key travels as a query parameter to Shodan
only; it is never placed in a reference link or the retained raw response.
"""

from __future__ import annotations

from phishbowl.models import IOCType

from ..base import (
    Connector,
    EnrichContext,
    EnrichmentResult,
    EnrichmentSignal,
    EnrichmentVerdict,
    Indicator,
)
from ..errors import ConnectorError
from ..registry import register

_SIGNAL_ID = "enrichment.shodan.exposed"

# Remote-access / admin / file-share services that are notable on a host that is
# *sending mail*. Port → short label for the evidence line.
_NOTABLE_PORTS = {
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


@register
class ShodanConnector(Connector):
    name = "shodan"
    version = "1.0.0"
    supported_ioc_types = frozenset({IOCType.IPV4.value, IOCType.IPV6.value})
    requires_api_key = True
    allowed_hosts = frozenset({"api.shodan.io"})
    base_url = "https://api.shodan.io"
    cache_ttl = 12 * 3600
    rate_limit_per_min = 60
    max_indicators = 8

    async def enrich(self, indicator: Indicator, ctx: EnrichContext) -> EnrichmentResult:
        # Key is a query parameter for Shodan; httpx attaches it to the request to
        # api.shodan.io only. It never appears in the reference or raw below.
        response = await ctx.http.get(
            f"{self.base_url}/shodan/host/{indicator.value}",
            params={"key": ctx.api_key or ""},
        )
        if response.status_code == 404:
            # Shodan has no record for this IP — nothing exposed that it can see.
            return self._result(indicator, EnrichmentVerdict.BENIGN, None, [])
        if response.status_code != 200:
            raise ConnectorError(f"Shodan returned HTTP {response.status_code}")

        body = response.json()
        ports = sorted({int(p) for p in body.get("ports", []) if isinstance(p, int)})
        notable = [p for p in ports if p in _NOTABLE_PORTS]
        if not notable:
            return self._result(indicator, EnrichmentVerdict.UNKNOWN, None, ports)

        labels = ", ".join(f"{p} ({_NOTABLE_PORTS[p]})" for p in notable)
        signal = EnrichmentSignal(
            id=_SIGNAL_ID,
            description="Shodan shows exposed services on the related IP",
            magnitude=min(1.0, len(notable) / 3.0),
            evidence=f"Shodan: {indicator.defanged} exposes {labels}",
        )
        return self._result(indicator, EnrichmentVerdict.SUSPICIOUS, signal, ports)

    def _result(
        self,
        indicator: Indicator,
        verdict: EnrichmentVerdict,
        signal: EnrichmentSignal | None,
        ports: list[int],
    ) -> EnrichmentResult:
        return EnrichmentResult(
            connector=self.name,
            ioc_type=indicator.type,
            indicator=indicator.value,
            verdict=verdict,
            signals=(signal,) if signal else (),
            references=(f"https://www.shodan.io/host/{indicator.value}",),
            raw={"ports": ports} if ports else None,
        )
