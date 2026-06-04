"""urlscan.io connector (PRD §9 — the operational-security-sensitive one).

urlscan is special, and treated specially. Active submission causes the email's
URL to be **visited** (on urlscan's infrastructure) — which can tip off an
attacker and, since phishing URLs often carry a per-victim token, can leak
victim-specific data to a third party (PRD §9). So:

* It defaults to a **passive search** by *domain* (never the full, possibly
  tokened URL), which answers "has urlscan seen this host, and how was it judged?"
  without visiting anything.
* Active submission is strictly opt-in (``--urlscan-submit`` / ``urlscan_submit``)
  and defaults to **private** visibility (``urlscan_visibility``). Private hides
  only the result page — the fetch still happens — so it stays a deliberate,
  per-run choice.

Either way the connector reaches **only ``urlscan.io``**: the email's URL is
sent as request *data*, never used as a request target (the SSRF guarantee).
Key-gated (``URLSCAN_API_KEY``); never logs or returns the key.
"""

from __future__ import annotations

from urllib.parse import urlsplit

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

_SIGNAL_ID = "enrichment.urlscan.malicious"


def _host_of(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.casefold() if host else None


@register
class UrlscanConnector(Connector):
    name = "urlscan"
    version = "1.0.0"
    supported_ioc_types = frozenset({IOCType.URL.value})
    requires_api_key = True
    allowed_hosts = frozenset({"urlscan.io"})
    base_url = "https://urlscan.io/api/v1"
    cache_ttl = 6 * 3600
    rate_limit_per_min = 60
    max_indicators = 8

    async def enrich(self, indicator: Indicator, ctx: EnrichContext) -> EnrichmentResult:
        if ctx.settings.urlscan_submit:
            return await self._submit(indicator, ctx)
        return await self._search(indicator, ctx)

    async def _search(self, indicator: Indicator, ctx: EnrichContext) -> EnrichmentResult:
        """Passive search by domain — no fetch of the email's URL (PRD §9)."""
        host = _host_of(indicator.value)
        if not host:
            return self._result(indicator, EnrichmentVerdict.UNKNOWN, None, ())
        response = await ctx.http.get(
            f"{self.base_url}/search/",
            headers={"API-Key": ctx.api_key or ""},
            params={"q": f"page.domain:{host}", "size": "10"},
        )
        if response.status_code != 200:
            raise ConnectorError(f"urlscan search returned HTTP {response.status_code}")

        body = response.json()
        results = body.get("results", []) or []
        worst = _worst_verdict(results)
        references = tuple(
            r["result"] for r in results[:3] if isinstance(r, dict) and r.get("result")
        )

        if worst is not None and worst.get("malicious"):
            signal = EnrichmentSignal(
                id=_SIGNAL_ID,
                description="urlscan judged a prior scan of this host malicious",
                magnitude=1.0,
                evidence=(
                    f"urlscan: prior scan of {indicator.defanged} judged malicious "
                    f"(score {worst.get('score', '?')})"
                ),
            )
            return self._result(indicator, EnrichmentVerdict.MALICIOUS, signal, references)

        verdict = EnrichmentVerdict.UNKNOWN if results else EnrichmentVerdict.BENIGN
        return self._result(indicator, verdict, None, references)

    async def _submit(self, indicator: Indicator, ctx: EnrichContext) -> EnrichmentResult:
        """Active submission (opt-in, private by default). The URL is *data*, not a target."""
        response = await ctx.http.post(
            f"{self.base_url}/scan/",
            headers={"API-Key": ctx.api_key or ""},
            json={"url": indicator.value, "visibility": ctx.settings.urlscan_visibility},
        )
        if response.status_code not in (200, 201):
            raise ConnectorError(f"urlscan submission returned HTTP {response.status_code}")
        body = response.json()
        result_link = body.get("result")
        references = (result_link,) if result_link else ()
        # A submission kicks off an async scan; no verdict is available yet.
        return self._result(indicator, EnrichmentVerdict.UNKNOWN, None, references)

    def _result(
        self,
        indicator: Indicator,
        verdict: EnrichmentVerdict,
        signal: EnrichmentSignal | None,
        references: tuple[str, ...],
    ) -> EnrichmentResult:
        return EnrichmentResult(
            connector=self.name,
            ioc_type=indicator.type,
            indicator=indicator.value,
            verdict=verdict,
            signals=(signal,) if signal else (),
            references=references,
            raw=None,
        )


def _worst_verdict(results: list) -> dict | None:
    """The most-severe ``verdicts.overall`` block across search results, if any."""
    worst: dict | None = None
    for entry in results:
        if not isinstance(entry, dict):
            continue
        overall = entry.get("verdicts", {}).get("overall")
        if not isinstance(overall, dict):
            continue
        if worst is None or int(overall.get("score", 0) or 0) > int(worst.get("score", 0) or 0):
            worst = overall
    return worst
