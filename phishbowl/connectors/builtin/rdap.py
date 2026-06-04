"""WHOIS/RDAP connector — domain age (PRD §8, §9).

A newly-registered domain is one of the strongest single phishing signals
(PRD §8, weight 18): legitimate brands don't email you from a domain registered
last week. This connector reads a domain's **registration date** from RDAP — the
modern, structured, JSON successor to WHOIS — and flags domains younger than 30
days.

RDAP is **keyless** and a *passive registry lookup*: it queries the registry's
RDAP service for the domain, never the suspicious site itself. Discovery goes
through ``rdap.org``, the community RDAP redirector, which forwards to the
authoritative registry for the TLD. Because RDAP bootstrapping is inherently a
cross-host redirect to the *registry* (never the registrant), this is the one
connector that follows redirects — but the request target is always an RDAP
service with the domain only in the URL *path*; the email's own URL is never
fetched, so the SSRF guarantee holds (PRD §9).
"""

from __future__ import annotations

from datetime import datetime

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

_SIGNAL_ID = "enrichment.rdap.young_domain"
_YOUNG_DOMAIN_DAYS = 30


def _parse_rdap_date(value: str) -> datetime | None:
    raw = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _registration_date(events: list) -> datetime | None:
    for event in events:
        if not isinstance(event, dict):
            continue
        if str(event.get("eventAction", "")).strip().casefold() == "registration":
            date = event.get("eventDate")
            if isinstance(date, str):
                return _parse_rdap_date(date)
    return None


@register
class RDAPConnector(Connector):
    name = "rdap"
    version = "1.0.0"
    supported_ioc_types = frozenset({IOCType.DOMAIN.value})
    requires_api_key = False
    allowed_hosts = frozenset({"rdap.org"})
    base_url = "https://rdap.org"
    cache_ttl = 24 * 3600  # registration dates change slowly — cache generously
    rate_limit_per_min = 30
    max_indicators = 12
    follow_redirects = True  # RDAP bootstrap redirects to the authoritative registry

    async def enrich(self, indicator: Indicator, ctx: EnrichContext) -> EnrichmentResult:
        response = await ctx.http.get(f"{self.base_url}/domain/{indicator.value}")
        if response.status_code == 404:
            # No RDAP record (unregistered / unsupported TLD) — nothing to assert.
            return self._result(indicator, EnrichmentVerdict.UNKNOWN, None, None)
        if response.status_code != 200:
            raise ConnectorError(f"RDAP returned HTTP {response.status_code}")

        registered = _registration_date(response.json().get("events", []))
        if registered is None:
            return self._result(indicator, EnrichmentVerdict.UNKNOWN, None, None)

        age_days = (ctx.now() - registered).days
        if age_days < _YOUNG_DOMAIN_DAYS:
            signal = EnrichmentSignal(
                id=_SIGNAL_ID,
                description="Domain was registered very recently",
                magnitude=1.0,
                evidence=(
                    f"RDAP: {indicator.defanged} registered {max(age_days, 0)} day(s) ago "
                    f"({registered.date().isoformat()})"
                ),
            )
            return self._result(indicator, EnrichmentVerdict.SUSPICIOUS, signal, registered)
        return self._result(indicator, EnrichmentVerdict.BENIGN, None, registered)

    def _result(
        self,
        indicator: Indicator,
        verdict: EnrichmentVerdict,
        signal: EnrichmentSignal | None,
        registered: datetime | None,
    ) -> EnrichmentResult:
        return EnrichmentResult(
            connector=self.name,
            ioc_type=indicator.type,
            indicator=indicator.value,
            verdict=verdict,
            signals=(signal,) if signal else (),
            references=(f"https://rdap.org/domain/{indicator.value}",),
            raw={"registration": registered.isoformat()} if registered else None,
        )
