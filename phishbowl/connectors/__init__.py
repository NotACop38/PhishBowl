"""Enrichment connectors (PRD §6.5, §9).

Pluggable, key-gated OSINT enrichment that augments — never gates — the verdict
(PRD §5). The offline pipeline always produces a complete verdict first; with no
API keys the experience is unchanged, and enrichment only ever *adds*
source-tagged ``[enrichment]`` signals on top.

The public surface a connector author depends on:

* :class:`Connector` — the ABC to subclass (registry- and entry-point-discoverable).
* :class:`Indicator`, :class:`EnrichContext` — what ``enrich`` receives.
* :class:`EnrichmentResult` / :class:`EnrichmentSignal` — the normalized return.
* :func:`register` — the in-repo registry decorator (third parties use the
  ``phishbowl.connectors`` entry-point group instead — no fork required).

The pipeline entry points:

* :func:`enrich_email` — run enrichment over a parsed message + its IOCs.
* :class:`EnrichmentSettings` / :class:`EnrichmentReport` — run config and result.

Cross-cutting guarantees live in the orchestrator (:mod:`.engine`), not in each
connector: on-disk caching keyed by ``(connector, ioc_type, value)`` with a
per-connector TTL, proactive rate limiting + reactive backoff + a global
concurrency cap, graceful degrade (missing key → skipped; error → soft-fail;
never crash), an SSRF guard (a connector reaches only its vendor's allowlisted
host, never a URL taken from the email), and env-only secrets that never reach an
output. See ``docs/CONNECTORS.md`` for the authoring guide.
"""

from __future__ import annotations

from .base import (
    Connector,
    ConnectorOutcome,
    ConnectorStatus,
    EnrichContext,
    EnrichmentReport,
    EnrichmentResult,
    EnrichmentSettings,
    EnrichmentSignal,
    EnrichmentVerdict,
    Indicator,
)
from .engine import enrich_email, run_enrichment, run_enrichment_async
from .errors import ConnectorError, RateLimitedError, SSRFGuardError
from .registry import ENTRY_POINT_GROUP, discover, register
from .targets import build_targets, sending_ips

__all__ = [
    # Connector interface
    "Connector",
    "Indicator",
    "EnrichContext",
    "EnrichmentResult",
    "EnrichmentSignal",
    "EnrichmentVerdict",
    # Discovery
    "register",
    "discover",
    "ENTRY_POINT_GROUP",
    # Orchestration
    "enrich_email",
    "run_enrichment",
    "run_enrichment_async",
    "build_targets",
    "sending_ips",
    "EnrichmentSettings",
    "EnrichmentReport",
    "ConnectorStatus",
    "ConnectorOutcome",
    # Errors
    "ConnectorError",
    "SSRFGuardError",
    "RateLimitedError",
]
