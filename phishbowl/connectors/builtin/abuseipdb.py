"""AbuseIPDB connector (PRD §8, §9).

Abuse-confidence lookup for an IP — most usefully the **sending IP** lifted from
the routing chain (PRD §8). The contribution scales with AbuseIPDB's confidence
score, and only fires past a noise threshold so a single stale report doesn't
move the verdict. Key-gated (``ABUSEIPDB_API_KEY``), reaches only
``api.abuseipdb.com``, and never logs or returns the key.
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

_SIGNAL_ID = "enrichment.abuseipdb.confidence"
# Below this confidence the result is reported but contributes no score (PRD §8
# scales by confidence; this just suppresses low-confidence noise).
_MIN_CONFIDENCE = 25


@register
class AbuseIPDBConnector(Connector):
    name = "abuseipdb"
    version = "1.0.0"
    supported_ioc_types = frozenset({IOCType.IPV4.value, IOCType.IPV6.value})
    requires_api_key = True
    allowed_hosts = frozenset({"api.abuseipdb.com"})
    base_url = "https://api.abuseipdb.com/api/v2"
    cache_ttl = 6 * 3600
    rate_limit_per_min = 60
    max_indicators = 8

    async def enrich(self, indicator: Indicator, ctx: EnrichContext) -> EnrichmentResult:
        response = await ctx.http.get(
            f"{self.base_url}/check",
            headers={"Key": ctx.api_key or "", "Accept": "application/json"},
            params={"ipAddress": indicator.value, "maxAgeInDays": "90"},
        )
        if response.status_code != 200:
            raise ConnectorError(f"AbuseIPDB returned HTTP {response.status_code}")

        data = response.json().get("data", {})
        confidence = int(data.get("abuseConfidenceScore", 0) or 0)
        reports = int(data.get("totalReports", 0) or 0)
        raw = {
            "abuseConfidenceScore": confidence,
            "totalReports": reports,
            "countryCode": data.get("countryCode"),
            "isWhitelisted": data.get("isWhitelisted"),
        }

        signal: EnrichmentSignal | None = None
        if confidence >= _MIN_CONFIDENCE:
            verdict = (
                EnrichmentVerdict.MALICIOUS if confidence >= 75 else EnrichmentVerdict.SUSPICIOUS
            )
            signal = EnrichmentSignal(
                id=_SIGNAL_ID,
                description="AbuseIPDB reports the sending IP as abusive",
                magnitude=min(1.0, confidence / 100.0),
                evidence=(
                    f"AbuseIPDB: {confidence}% abuse confidence for {indicator.defanged} "
                    f"({reports} report(s))"
                ),
            )
        else:
            verdict = EnrichmentVerdict.BENIGN if confidence == 0 else EnrichmentVerdict.UNKNOWN

        return EnrichmentResult(
            connector=self.name,
            ioc_type=indicator.type,
            indicator=indicator.value,
            verdict=verdict,
            signals=(signal,) if signal else (),
            references=(f"https://www.abuseipdb.com/check/{indicator.value}",),
            raw=raw,
        )
