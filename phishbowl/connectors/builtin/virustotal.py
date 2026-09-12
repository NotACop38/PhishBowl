"""VirusTotal connector (PRD §8, §9).

Passive reputation lookup for URLs, domains, and file hashes against the
VirusTotal v3 API. The contribution scales with the **detection ratio** — how
many engines flagged the indicator — so a couple of detections nudge the score
while a broad consensus pushes it hard (PRD §8). Key-gated (``VIRUSTOTAL_API_KEY``),
reaches only ``www.virustotal.com``, and never logs or returns the key.

Free-tier friendly: a conservative request rate and a generous cache TTL keep
repeat runs and the demo from burning the ~4 req/min public quota.
"""

from __future__ import annotations

import base64

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

_SIGNAL_ID = "enrichment.virustotal.detections"


def _vt_url_id(url: str) -> str:
    """VirusTotal v3 URL identifier: unpadded base64url of the raw URL."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


@register
class VirusTotalConnector(Connector):
    name = "virustotal"
    version = "1.0.0"
    supported_ioc_types = frozenset({IOCType.URL.value, IOCType.DOMAIN.value, IOCType.HASH.value})
    requires_api_key = True
    allowed_hosts = frozenset({"www.virustotal.com"})
    base_url = "https://www.virustotal.com/api/v3"
    cache_ttl = 6 * 3600
    rate_limit_per_min = 4  # VT public free tier
    max_indicators = 12

    async def enrich(self, indicator: Indicator, ctx: EnrichContext) -> EnrichmentResult:
        endpoint, gui_kind, gui_id = self._route(indicator)
        response = await ctx.http.get(
            f"{self.base_url}/{endpoint}",
            headers={"x-apikey": ctx.api_key or ""},
        )
        if response.status_code == 404:
            # VT has never seen this indicator — not evidence of anything.
            return self._result(indicator, EnrichmentVerdict.UNKNOWN, None, gui_kind, gui_id, {})
        if response.status_code != 200:
            raise ConnectorError(f"VirusTotal returned HTTP {response.status_code}")

        stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        total = sum(int(v or 0) for v in stats.values())

        if malicious == 0 and suspicious == 0:
            return self._result(
                indicator,
                EnrichmentVerdict.BENIGN if sum(stats.values()) > 0 else EnrichmentVerdict.UNKNOWN,
                None,
                gui_kind,
                gui_id,
                stats,
            )

        # Magnitude = detection ratio (PRD §8 "scaled by detection ratio").
        ratio = (malicious + suspicious) / total if total else 0.0
        verdict = EnrichmentVerdict.MALICIOUS if malicious else EnrichmentVerdict.SUSPICIOUS
        signal = EnrichmentSignal(
            id=_SIGNAL_ID,
            description="VirusTotal engines flagged the indicator",
            magnitude=min(1.0, ratio),
            evidence=(
                f"VirusTotal: {malicious + suspicious}/{total} engines flagged "
                f"{indicator.defanged} ({malicious} malicious, {suspicious} suspicious)"
            ),
        )
        return self._result(indicator, verdict, signal, gui_kind, gui_id, stats)

    def _route(self, indicator: Indicator) -> tuple[str, str, str]:
        """API endpoint + GUI (kind, id) for an indicator type."""
        if indicator.type == IOCType.DOMAIN.value:
            return f"domains/{indicator.value}", "domain", indicator.value
        if indicator.type == IOCType.HASH.value:
            return f"files/{indicator.value}", "file", indicator.value
        if indicator.type == IOCType.URL.value:
            url_id = _vt_url_id(indicator.value)
            return f"urls/{url_id}", "url", url_id
        raise ConnectorError(f"VirusTotal does not support {indicator.type!r}")

    def _result(
        self,
        indicator: Indicator,
        verdict: EnrichmentVerdict,
        signal: EnrichmentSignal | None,
        gui_kind: str,
        gui_id: str,
        stats: dict,
    ) -> EnrichmentResult:
        return EnrichmentResult(
            connector=self.name,
            ioc_type=indicator.type,
            indicator=indicator.value,
            verdict=verdict,
            signals=(signal,) if signal else (),
            references=(f"https://www.virustotal.com/gui/{gui_kind}/{gui_id}",),
            raw={"last_analysis_stats": stats} if stats else None,
        )
