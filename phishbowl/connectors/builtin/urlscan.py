"""urlscan.io connector (PRD §9 — the operational-security-sensitive one).

urlscan is special, and treated specially. Active submission causes the email's
URL to be **visited** (on urlscan's infrastructure) — which can tip off an
attacker and, since phishing URLs often carry a per-victim token, can leak
victim-specific data to a third party (PRD §9). So:

* It defaults to a **passive search** by *domain* (never the full, possibly
  tokened URL), which answers "has urlscan seen this host, and how was it judged?"
  without visiting anything. A malicious prior scan of the *same URL* counts in
  full; one of another page on the host counts half, because shared hosting
  puts unrelated pages under one domain.
* Active submission is strictly opt-in (``--urlscan-submit`` / ``urlscan_submit``)
  and defaults to **private** visibility (``urlscan_visibility``). Private hides
  only the result page — the fetch still happens — so it stays a deliberate,
  per-run choice.

Either way the connector reaches **only ``urlscan.io``**: the email's URL is
sent as request *data*, never used as a request target (the SSRF guarantee).
Key-gated (``URLSCAN_API_KEY``); never logs or returns the key.
"""

from __future__ import annotations

from typing import NamedTuple
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
from ..http import json_object
from ..registry import register
from ._fields import count, mapping

_SIGNAL_ID = "enrichment.urlscan.malicious"
# Evidence about another page on the same host is weaker than about the URL itself.
_SAME_HOST_MAGNITUDE = 0.5


def _host_of(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.casefold() if host else None


def _result_link(value: object) -> str | None:
    """``value`` if it is an https link to a urlscan.io page, else ``None``."""
    if not isinstance(value, str):
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if parts.scheme != "https" or parts.hostname != "urlscan.io":
        return None
    return value


class _Scan(NamedTuple):
    """One prior scan's overall verdict, ordered so ``max`` picks the worst."""

    malicious: bool
    same_url: bool
    score: int


@register
class UrlscanConnector(Connector):
    name = "urlscan"
    version = "1.1.0"
    supported_ioc_types = frozenset({IOCType.URL.value})
    requires_api_key = True
    api_key_env = "URLSCAN_API_KEY"
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
            params={"q": f'page.domain:"{host}"', "size": "10"},
        )
        if response.status_code != 200:
            raise ConnectorError(f"urlscan search returned HTTP {response.status_code}")

        listed = json_object(response, "urlscan").get("results")
        results = [r for r in listed if isinstance(r, dict)] if isinstance(listed, list) else []
        references = tuple(
            link for r in results[:3] if (link := _result_link(r.get("result"))) is not None
        )
        worst = max((_scan(r, indicator.value) for r in results), default=None)
        if worst is None or not worst.malicious:
            return self._result(indicator, EnrichmentVerdict.UNKNOWN, None, references)

        if worst.same_url:
            subject = f"a prior scan of {indicator.defanged}"
            magnitude = 1.0
        else:
            subject = f"a prior scan of another page on {host.replace('.', '[.]')}"
            magnitude = _SAME_HOST_MAGNITUDE
        signal = EnrichmentSignal(
            id=_SIGNAL_ID,
            description="urlscan judged a prior scan of this URL or host malicious",
            magnitude=magnitude,
            evidence=f"urlscan: {subject} was judged malicious (score {worst.score})",
        )
        return self._result(indicator, EnrichmentVerdict.MALICIOUS, signal, references)

    async def _submit(self, indicator: Indicator, ctx: EnrichContext) -> EnrichmentResult:
        """Active submission (opt-in, private by default). The URL is *data*, not a target."""
        response = await ctx.http.post(
            f"{self.base_url}/scan/",
            headers={"API-Key": ctx.api_key or ""},
            json={"url": indicator.value, "visibility": ctx.settings.urlscan_visibility},
        )
        if response.status_code not in (200, 201):
            raise ConnectorError(f"urlscan submission returned HTTP {response.status_code}")
        result_link = _result_link(json_object(response, "urlscan").get("result"))
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


def _scan(entry: dict, url: str) -> _Scan:
    """A search result's overall verdict, and whether it scanned ``url`` itself."""
    overall = mapping(mapping(entry.get("verdicts")).get("overall"))
    scanned = {mapping(entry.get(section)).get("url") for section in ("task", "page")} - {None}
    return _Scan(
        malicious=overall.get("malicious") is True,
        same_url=url in scanned,
        score=min(count(overall.get("score")) or 0, 100),
    )
