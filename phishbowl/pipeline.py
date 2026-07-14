"""Shared triage pipeline used by the CLI and the upload UI.

Keeps a single parse → extract → (optional enrich) → score → report path so the
web UI and ``phishbowl analyze`` can never diverge (PRD §15). Callers supply an
already-parsed :class:`~phishbowl.models.ParsedEmail` (and optional enrichment /
redaction settings); this module never opens files or reaches the network on its
own — enrichment only runs when the caller opts in with settings.
"""

from __future__ import annotations

from phishbowl.connectors import EnrichmentReport, EnrichmentSettings, enrich_email
from phishbowl.extract import extract_iocs
from phishbowl.models import ParsedEmail
from phishbowl.report import RedactionPolicy, ReportView, build_report
from phishbowl.score import ScoreResult, ScoringConfig, load_config, score_email


def triage(
    parsed: ParsedEmail,
    *,
    config: ScoringConfig | None = None,
    policy: RedactionPolicy | None = None,
    enrichment_settings: EnrichmentSettings | None = None,
    enrichment: EnrichmentReport | None = None,
) -> tuple[ReportView, ScoreResult]:
    """Run extract → optional enrich → score → report on ``parsed``.

    If ``enrichment`` is already computed, it is used as-is. Otherwise, when
    ``enrichment_settings`` is provided and enabled, connectors run against the
    extracted IOCs. The offline score is always computed; enrichment only adds
    source-tagged points on top.
    """
    config = config or load_config()
    policy = policy or RedactionPolicy.disabled()
    iocs = extract_iocs(parsed)

    report = enrichment
    if report is None and enrichment_settings is not None and enrichment_settings.enabled:
        report = enrich_email(parsed, iocs, enrichment_settings)

    result = score_email(parsed, iocs, config, enrichment=report)
    view = build_report(parsed, iocs, result, policy=policy, config=config, enrichment=report)
    return view, result
