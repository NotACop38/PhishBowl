"""Enrichment orchestration (PRD §9).

The layer that turns a set of indicators and a pile of registered connectors into
an :class:`EnrichmentReport`, upholding every cross-cutting connector requirement
in one place so individual connectors stay small:

* **Discovery** — registry + entry-points (:mod:`.registry`).
* **Key-gating** — a connector that ``requires_api_key`` with no key is *skipped*
  with a clear note; it is never invoked (PRD §9 graceful degrade).
* **Caching** — every lookup checks the on-disk cache first, keyed by
  ``(connector, ioc_type, value)`` with the connector's TTL (:mod:`.cache`).
* **Rate limiting** — proactive per-connector spacing (:mod:`.ratelimit`) plus a
  **global concurrency cap** (an :class:`asyncio.Semaphore`) shared by all
  connectors.
* **SSRF guard** — every connector gets an :class:`AllowlistedClient` bound to its
  own ``allowed_hosts`` and can reach nothing else (:mod:`.http`).
* **Graceful degrade** — any connector error (missing data, network/API failure,
  rate-limit exhaustion, even an unexpected bug) is caught and recorded as a
  soft-fail note; it never crashes the run.
* **Secret hygiene** — known key values are scrubbed from every retained raw
  response defensively (:mod:`.secrets`).

The offline verdict never depends on any of this: with enrichment disabled (the
default) :func:`run_enrichment` returns an empty, ``enabled=False`` report and the
scorer is untouched (PRD §5, §8).
"""

from __future__ import annotations

import asyncio
import logging
import traceback
from contextlib import contextmanager

import httpx

from phishbowl.models import IOCs, ParsedEmail

from .base import (
    Connector,
    ConnectorOutcome,
    ConnectorStatus,
    EnrichContext,
    EnrichmentReport,
    EnrichmentResult,
    EnrichmentSettings,
    Indicator,
)
from .cache import EnrichmentCache
from .errors import ConnectorError
from .http import AllowlistedClient
from .ratelimit import RateLimiter
from .registry import discover
from .secrets import active_key_values, env_var_for, scrub_secrets
from .targets import build_targets

log = logging.getLogger(__name__)

# Loggers that can see a full request URL: httpx logs every request line at
# INFO/DEBUG, httpcore traces at DEBUG. Shodan's API key rides in the query
# string, so with debug logging enabled these would otherwise print the key.
_HTTP_LOGGERS = ("httpx", "httpcore")


class _SecretScrubFilter(logging.Filter):
    """Rewrites known key values out of a log record before it is emitted.

    Secrets are never logged (PRD §11) — but third-party HTTP libraries log
    request URLs, and some vendors (Shodan) require the key as a query
    parameter. This filter is attached to those loggers for the duration of an
    enrichment run so the operator can debug at any verbosity without a key
    landing in their logs.
    """

    def __init__(self, secrets: frozenset[str]) -> None:
        super().__init__()
        self._secrets = secrets

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - a malformed record must not break the caller
            return True
        scrubbed = scrub_secrets(message, self._secrets)
        if scrubbed != message:
            record.msg = scrubbed
            record.args = None
        return True


def _http_logger_names() -> set[str]:
    """The HTTP loggers to scrub: the parents plus every existing descendant.

    A :class:`logging.Filter` on a parent logger does **not** apply to records
    emitted through child loggers (``httpcore.http11``, ``httpcore.connection``,
    …) — propagation runs ancestor *handlers*, not ancestor filters — so each
    descendant needs the filter too. Both libraries create their loggers at
    import time, which has happened by the time enrichment runs.
    """
    prefixes = tuple(f"{name}." for name in _HTTP_LOGGERS)
    names = set(_HTTP_LOGGERS)
    names.update(n for n in logging.Logger.manager.loggerDict if n.startswith(prefixes))
    return names


@contextmanager
def _scrubbed_http_logs(secrets: frozenset[str]):
    """Attach the secret-scrub filter to the HTTP loggers; always detach after."""
    pairs = [
        (logging.getLogger(name), _SecretScrubFilter(secrets)) for name in _http_logger_names()
    ]
    for logger, filt in pairs:
        logger.addFilter(filt)
    try:
        yield
    finally:
        for logger, filt in pairs:
            logger.removeFilter(filt)


def enrich_email(
    parsed: ParsedEmail,
    iocs: IOCs,
    settings: EnrichmentSettings | None = None,
) -> EnrichmentReport:
    """Run enrichment over an email's indicators (PRD §9) — the pipeline entry point.

    Builds the indicator set (IOCs + routing sending-IPs) and delegates to
    :func:`run_enrichment`. With ``settings.enabled`` false (the default) this is
    a no-op returning an ``enabled=False`` report, so the offline pipeline is
    entirely unaffected.
    """
    settings = settings or EnrichmentSettings()
    if not settings.enabled:
        return EnrichmentReport(enabled=False)
    return run_enrichment(
        build_targets(parsed, iocs, excluded_domains=settings.excluded_domains), settings
    )


def run_enrichment(
    targets: list[Indicator],
    settings: EnrichmentSettings | None = None,
) -> EnrichmentReport:
    """Synchronous wrapper around :func:`run_enrichment_async` (drives the event loop)."""
    settings = settings or EnrichmentSettings()
    if not settings.enabled:
        return EnrichmentReport(enabled=False)
    return asyncio.run(run_enrichment_async(targets, settings))


async def run_enrichment_async(
    targets: list[Indicator],
    settings: EnrichmentSettings,
) -> EnrichmentReport:
    """Enrich ``targets`` across all selected connectors, concurrently and safely."""
    connectors = _select_connectors(settings)
    cache = EnrichmentCache(settings.cache_dir, enabled=settings.cache_enabled, now=settings.now)
    # Everything key-shaped we know about — env vars *and* programmatic
    # overrides — so the defensive scrub covers the library-use path too.
    secrets = active_key_values() | frozenset(v for v in settings.api_keys.values() if v)
    semaphore = asyncio.Semaphore(max(1, settings.concurrency))

    with _scrubbed_http_logs(secrets):
        statuses = await asyncio.gather(
            *(
                _run_one_connector(cls(), targets, settings, cache, semaphore, secrets)
                for cls in connectors
            )
        )
    # Stable, name-sorted ordering so reports read the same run to run.
    statuses = tuple(sorted(statuses, key=lambda s: s.connector))
    return EnrichmentReport(enabled=True, statuses=statuses)


def _select_connectors(settings: EnrichmentSettings) -> list[type[Connector]]:
    """Resolve which connector classes to run, honoring select/disable filters."""
    classes = discover()
    selected: list[type[Connector]] = []
    for name, cls in sorted(classes.items()):
        if settings.select is not None and name not in settings.select:
            continue
        if name in settings.disable:
            continue
        selected.append(cls)
    return selected


async def _run_one_connector(
    connector: Connector,
    targets: list[Indicator],
    settings: EnrichmentSettings,
    cache: EnrichmentCache,
    semaphore: asyncio.Semaphore,
    secrets: frozenset[str],
) -> ConnectorStatus:
    """Run a single connector over its indicators, degrading gracefully throughout."""
    name = connector.name

    api_key = settings.api_key_for(name) if connector.requires_api_key else None
    if connector.requires_api_key and not api_key:
        var = env_var_for(name) or "its API key"
        return _status(connector, ConnectorOutcome.SKIPPED, f"skipped — no API key (set {var})")

    indicators = [t for t in targets if t.type in connector.supported_ioc_types]
    indicators = indicators[: min(connector.max_indicators, settings.max_indicators)]
    if not indicators:
        return _status(connector, ConnectorOutcome.SKIPPED, "skipped — no matching indicators")

    limiter = RateLimiter(connector.rate_limit_per_min, sleep=settings.sleep)
    client = AllowlistedClient(
        allowed_hosts=connector.allowed_hosts,
        timeout=settings.timeout,
        max_retries=settings.max_retries,
        transport=settings.transport,
        sleep=settings.sleep,
        follow_redirects=connector.follow_redirects,
        bootstrap_redirect=connector.bootstrap_redirect,
    )
    ctx = EnrichContext(http=client, settings=settings, api_key=api_key, now=settings.clock())

    results: list[EnrichmentResult] = []
    failures: list[str] = []
    cache_hits = 0
    try:
        for indicator in indicators:
            cached = cache.get(name, indicator.type, indicator.value, ttl=connector.cache_ttl)
            if cached is not None:
                results.append(_sanitize(cached, secrets).as_cached())
                cache_hits += 1
                continue
            result = await _enrich_one(
                connector, indicator, ctx, limiter, semaphore, failures, secrets
            )
            if result is not None:
                result = _sanitize(result, secrets)
                cache.put(result)
                results.append(result)
    finally:
        await client.aclose()

    return _summarize(connector, indicators, results, cache_hits, failures)


async def _enrich_one(
    connector: Connector,
    indicator: Indicator,
    ctx: EnrichContext,
    limiter: RateLimiter,
    semaphore: asyncio.Semaphore,
    failures: list[str],
    secrets: frozenset[str],
) -> EnrichmentResult | None:
    """One guarded enrichment call: rate-limited, concurrency-capped, soft-failing."""
    await limiter.acquire()
    async with semaphore:
        try:
            return await connector.enrich(indicator, ctx)
        except ConnectorError as exc:
            failures.append(scrub_secrets(str(exc), secrets) or exc.__class__.__name__)
        except httpx.HTTPError as exc:
            # Network/transport failure (timeout, DNS, connection reset, …).
            failures.append(f"network error: {exc.__class__.__name__}")
        except Exception:  # noqa: BLE001 - last-resort guard: a connector bug must not crash the run
            # Keep the traceback for debuggability, but scrub known key values
            # first — a buggy connector could embed its API key in an exception
            # message, and secrets are never logged (PRD §11).
            detail = scrub_secrets(traceback.format_exc(), secrets)
            log.warning("connector %r raised an unexpected error\n%s", connector.name, detail)
            failures.append("unexpected connector error")
    return None


def _sanitize(result: EnrichmentResult, secrets: frozenset[str]) -> EnrichmentResult:
    """Defensively scrub any known key value out of a result's retained raw data."""
    from dataclasses import replace

    return replace(
        result,
        raw=scrub_secrets(result.raw, secrets),
        indicator=scrub_secrets(result.indicator, secrets),
        references=scrub_secrets(result.references, secrets),
        signals=tuple(
            replace(
                signal,
                description=scrub_secrets(signal.description, secrets),
                evidence=scrub_secrets(signal.evidence, secrets),
            )
            for signal in result.signals
        ),
    )


def _status(connector: Connector, outcome: ConnectorOutcome, note: str) -> ConnectorStatus:
    return ConnectorStatus(
        connector=connector.name,
        version=connector.version,
        outcome=outcome,
        note=note,
    )


def _summarize(
    connector: Connector,
    indicators: list[Indicator],
    results: list[EnrichmentResult],
    cache_hits: int,
    failures: list[str],
) -> ConnectorStatus:
    """Fold a connector's per-indicator outcomes into one status line."""
    if results:
        note = f"{len(results)} indicator(s) enriched"
        if cache_hits:
            note += f" ({cache_hits} from cache)"
        flagged = sum(1 for r in results if r.signals)
        if flagged:
            note += f"; {flagged} flagged"
        if failures:
            note += f"; {len(failures)} soft-failed"
        outcome = ConnectorOutcome.USED
    elif failures:
        note = f"failed — {failures[0]}"
        if len(failures) > 1:
            note += f" (+{len(failures) - 1} more)"
        outcome = ConnectorOutcome.FAILED
    else:
        note = "skipped — nothing to do"
        outcome = ConnectorOutcome.SKIPPED
    return ConnectorStatus(
        connector=connector.name,
        version=connector.version,
        outcome=outcome,
        note=note,
        queried=len(indicators),
        cache_hits=cache_hits,
        results=tuple(results),
    )
