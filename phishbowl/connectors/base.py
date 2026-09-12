"""The connector interface & normalized enrichment types (PRD §9).

This is PhishBowl's community contribution surface, so the *interface* is
designed to be stable and is documented in ``docs/CONNECTORS.md``. A connector
declares what it can enrich and how to reach its vendor, then implements one
``async def enrich(indicator, ctx)`` that returns a **normalized**
:class:`EnrichmentResult`. The scorer needs no per-vendor logic: it consumes the
normalized :class:`EnrichmentSignal`\\s every connector emits.

Key shapes:

* :class:`Connector` — the ABC a connector subclasses (registry + entry-point
  discoverable). Metadata (``name``, ``supported_ioc_types``, ``requires_api_key``,
  ``allowed_hosts``, cache TTL, rate limit) is declarative so the orchestrator
  can cache, rate-limit, key-gate, and SSRF-guard it uniformly.
* :class:`Indicator` — one thing to enrich (``type``/``value``/``defanged``).
* :class:`EnrichmentResult` — the normalized return: a vendor verdict, scored
  :class:`EnrichmentSignal` contributions, reference links, and a retained,
  secret-free raw response.
* :class:`EnrichContext` — what a connector gets at call time: the SSRF-guarded
  HTTP client, settings, the resolved API key (env-only), and a clock.

Nothing here imports the scorer or the report layer — enrichment is a one-way
dependency, so a connector package can depend on this module alone.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from .secrets import api_key_from_env

if TYPE_CHECKING:
    from .http import AllowlistedClient


def utcnow() -> datetime:
    """Timezone-aware UTC now — the default clock connectors compute ages against."""
    return datetime.now(UTC)


class EnrichmentVerdict(StrEnum):
    """A connector's normalized opinion on one indicator.

    Deliberately coarse: the *numeric* contribution to the score is carried by
    :class:`EnrichmentSignal`\\s; this is the at-a-glance label shown per result.
    """

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class ConnectorOutcome(StrEnum):
    """How a connector fared over a run, surfaced per-connector in every output."""

    USED = "used"  # produced at least one result (live or from cache)
    SKIPPED = "skipped"  # no key / no matching indicators / disabled
    FAILED = "failed"  # had work to do but every attempt soft-failed


@dataclass(frozen=True)
class Indicator:
    """One indicator handed to a connector: its type, raw value, and defanged form.

    ``type`` is one of the :class:`~phishbowl.models.IOCType` values
    (``ip``-family / ``domain`` / ``url`` / ``hash`` / ``email``). ``defanged``
    is provided so a connector can build human-facing evidence without ever
    re-fanging an indicator in output.
    """

    type: str
    value: str
    defanged: str


@dataclass(frozen=True)
class EnrichmentSignal:
    """One scored contribution from a connector, tagged ``[enrichment]`` by the scorer.

    The connector supplies a stable ``id`` (whose **base weight lives in the
    editable scoring YAML**, like every offline rule) and a ``magnitude`` in
    ``0..1`` that scales it — ``1.0`` for a fixed signal, or e.g. a VirusTotal
    detection ratio / an AbuseIPDB confidence fraction. The scorer's contribution
    is ``base_weight(id) * magnitude``, keeping enrichment weights as transparent
    and tunable as offline ones (PRD §8). ``evidence`` is a human-readable,
    already-defanged one-liner.
    """

    id: str
    description: str
    magnitude: float
    evidence: str


@dataclass(frozen=True)
class EnrichmentResult:
    """A connector's normalized answer for one indicator (PRD §9).

    Carries the vendor ``verdict``, the scored ``signals`` the scorer folds in,
    ``references`` (links an analyst can pivot to), and the retained ``raw``
    response (secret-free — the orchestrator scrubs known key values defensively).
    ``cached`` marks a result served from the on-disk cache.
    """

    connector: str
    ioc_type: str
    indicator: str
    verdict: EnrichmentVerdict = EnrichmentVerdict.UNKNOWN
    signals: tuple[EnrichmentSignal, ...] = ()
    references: tuple[str, ...] = ()
    raw: dict[str, Any] | None = None
    cached: bool = False

    def as_cached(self) -> EnrichmentResult:
        """A copy flagged as served from cache (for the report's cache-hit note)."""
        if self.cached:
            return self
        return EnrichmentResult(
            connector=self.connector,
            ioc_type=self.ioc_type,
            indicator=self.indicator,
            verdict=self.verdict,
            signals=self.signals,
            references=self.references,
            raw=self.raw,
            cached=True,
        )


@dataclass(frozen=True)
class ConnectorStatus:
    """Per-connector outcome for one run, shown in every output (PRD §9).

    ``note`` is the human-readable status line ("skipped — no API key",
    "2 indicators enriched (1 from cache)", "rate limited"). ``results`` holds the
    successful :class:`EnrichmentResult`\\s so the report can list references.
    """

    connector: str
    version: str
    outcome: ConnectorOutcome
    note: str
    queried: int = 0
    cache_hits: int = 0
    results: tuple[EnrichmentResult, ...] = ()


@dataclass(frozen=True)
class EnrichmentReport:
    """The outcome of an enrichment pass: per-connector statuses + their results.

    ``enabled`` is ``False`` for a run where enrichment was never requested — the
    default, key-free, fully-offline path (PRD §5). ``signals`` flattens every
    result's contributions for the scorer to fold in and tag ``[enrichment]``.
    """

    enabled: bool
    statuses: tuple[ConnectorStatus, ...] = ()

    @property
    def results(self) -> tuple[EnrichmentResult, ...]:
        return tuple(r for s in self.statuses for r in s.results)

    @property
    def signals(self) -> tuple[EnrichmentSignal, ...]:
        return tuple(sig for r in self.results for sig in r.signals)

    def status_for(self, connector: str) -> ConnectorStatus | None:
        for s in self.statuses:
            if s.connector == connector:
                return s
        return None


@dataclass(frozen=True)
class EnrichmentSettings:
    """Operator + run configuration for an enrichment pass (PRD §9, §11).

    Sane, safe defaults: enrichment is **off** unless asked for, urlscan defaults
    to **private** and to passive search (never an active submission unless
    ``urlscan_submit`` is set), and a small global concurrency cap protects free
    tiers. ``api_keys`` lets a caller inject keys (tests/embedding) ahead of the
    env; production leaves it empty and keys are read from the environment only.
    ``transport``/``sleep``/``now`` are seams for deterministic, offline tests
    (a mocked HTTP transport, a no-wait sleep, a fixed clock).
    """

    enabled: bool = False
    select: frozenset[str] | None = None
    disable: frozenset[str] = frozenset()
    urlscan_visibility: str = "private"
    excluded_domains: frozenset[str] = frozenset()
    urlscan_submit: bool = False
    concurrency: int = 4
    timeout: float = 10.0
    max_retries: int = 3
    max_indicators: int = 16
    cache_enabled: bool = True
    cache_dir: Any = None
    api_keys: Mapping[str, str] = field(default_factory=dict)
    transport: Any = None
    sleep: Callable[[float], Awaitable[None]] | None = None
    now: Callable[[], datetime] | None = None

    def api_key_for(self, name: str) -> str | None:
        """Resolve a connector's key: explicit override first, then env (PRD §11)."""
        if name in self.api_keys:
            return self.api_keys[name] or None
        return api_key_from_env(name)

    def clock(self) -> Callable[[], datetime]:
        return self.now or utcnow


@dataclass(frozen=True)
class EnrichContext:
    """Everything a connector gets at call time (PRD §9).

    ``http`` is the SSRF-guarded client, pre-bound to the connector's allowlist —
    a connector simply calls ``ctx.http.get(...)`` and physically cannot reach a
    non-allowlisted host. ``api_key`` is the resolved secret (or ``None``); the
    connector decides how to present it (header/param) and must never log or
    return it. ``now`` is the clock for age math (e.g. RDAP domain age).
    """

    http: AllowlistedClient
    settings: EnrichmentSettings
    api_key: str | None = None
    now: Callable[[], datetime] = utcnow


class Connector(ABC):
    """Base class for an enrichment connector (PRD §9).

    Subclass it, set the declarative metadata, and implement :meth:`enrich`. The
    orchestrator uses the metadata to key-gate (``requires_api_key``), route
    indicators (``supported_ioc_types``), cache (``cache_ttl``), rate-limit
    (``rate_limit_per_min``), bound work (``max_indicators``), and — crucially —
    SSRF-guard every request to ``allowed_hosts`` only.

    Discovery is via the in-repo registry (the :func:`~phishbowl.connectors.registry.register`
    decorator) **and** the ``phishbowl.connectors`` entry-point group, so a third
    party can ship a connector as a pip package without forking.
    """

    #: Unique, stable connector id (also the cache namespace and key-env lookup).
    name: str = ""
    version: str = "0.1.0"
    #: Which IOC types this connector enriches (``ipv4``/``ipv6``/``domain``/``url``/``hash``).
    supported_ioc_types: frozenset[str] = frozenset()
    #: When ``True`` the connector is skipped (with a note) unless its env key is set.
    requires_api_key: bool = True
    #: Hosts the connector may reach. Egress to anything else is refused (SSRF guard).
    allowed_hosts: frozenset[str] = frozenset()
    #: The vendor's documented API base URL.
    base_url: str = ""
    #: Per-connector cache TTL in seconds (repeat runs/demos stay fast, quota is spared).
    cache_ttl: int = 3600
    #: Proactive request spacing — at most this many requests per minute.
    rate_limit_per_min: float = 60.0
    #: Cap on indicators enriched per run (protects free tiers from a big mailbox).
    max_indicators: int = 16
    #: Whether the HTTP client may follow redirects. Every hop is re-checked
    #: against ``allowed_hosts`` before any connection (the SSRF guard holds
    #: across the whole chain).
    follow_redirects: bool = False
    #: Whether the vendor's allowlisted host is a *bootstrap redirector* whose
    #: documented job is to designate the real host (RDAP's ``rdap.org`` →
    #: authoritative registry). When ``True``, exactly one redirect issued by an
    #: allowlisted host may leave the allowlist — https only — and the
    #: designated host gets exactly one request: any further redirect soft-fails.
    #: Implies ``follow_redirects``. The redirect target is chosen by the
    #: allowlisted vendor, never by email content.
    bootstrap_redirect: bool = False

    @abstractmethod
    async def enrich(self, indicator: Indicator, ctx: EnrichContext) -> EnrichmentResult:
        """Enrich one indicator into a normalized :class:`EnrichmentResult`.

        Implementations must reach **only** their vendor via ``ctx.http`` (the
        SSRF guard enforces this), must not log or return the API key, and should
        raise a :class:`~phishbowl.connectors.errors.ConnectorError` (or let an
        HTTP error propagate) on failure — the orchestrator soft-fails it with a
        note rather than crashing the run.
        """
        raise NotImplementedError
