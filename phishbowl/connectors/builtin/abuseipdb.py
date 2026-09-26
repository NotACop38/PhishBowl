"""AbuseIPDB connector (PRD §8, §9).

Abuse-confidence lookup for an IP — most usefully the **sending IP** lifted from
the routing chain (PRD §8). The contribution scales with AbuseIPDB's confidence
score, and only fires past a noise threshold so a single stale report doesn't
move the verdict. Key-gated (``ABUSEIPDB_API_KEY``), reaches only
``api.abuseipdb.com``, and never logs or returns the key.
"""

from __future__ import annotations

from urllib.parse import quote

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
from ..http import json_object
from ..registry import register
from ._fields import count, mapping

_SIGNAL_ID = "enrichment.abuseipdb.confidence"
# Below this confidence the result is reported but contributes no score (PRD §8
# scales by confidence; this just suppresses low-confidence noise).
_MIN_CONFIDENCE = 25


@register
class AbuseIPDBConnector(Connector):
    name = "abuseipdb"
    version = "1.1.0"
    supported_ioc_types = frozenset({IOCType.IPV4.value, IOCType.IPV6.value})
    requires_api_key = True
    api_key_env = "ABUSEIPDB_API_KEY"
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

        data = mapping(json_object(response, "AbuseIPDB").get("data"))
        score = count(data.get("abuseConfidenceScore"))
        if score is None:
            # No confidence score in the answer: nothing to assert either way.
            return self._result(indicator, EnrichmentVerdict.UNKNOWN, None, None)
        confidence = min(score, 100)
        reports = count(data.get("totalReports")) or 0
        country = data.get("countryCode")
        whitelisted = data.get("isWhitelisted")
        raw = {
            "abuseConfidenceScore": confidence,
            "totalReports": reports,
            "countryCode": country[:8] if isinstance(country, str) else None,
            "isWhitelisted": whitelisted if isinstance(whitelisted, bool) else None,
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
        return self._result(indicator, verdict, signal, raw)

    def _result(
        self,
        indicator: Indicator,
        verdict: EnrichmentVerdict,
        signal: EnrichmentSignal | None,
        raw: dict | None,
    ) -> EnrichmentResult:
        return EnrichmentResult(
            connector=self.name,
            ioc_type=indicator.type,
            indicator=indicator.value,
            verdict=verdict,
            signals=(signal,) if signal else (),
            references=(f"https://www.abuseipdb.com/check/{quote(indicator.value, safe=':')}",),
            raw=raw,
        )
