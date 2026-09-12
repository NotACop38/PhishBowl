"""Shared triage pipeline used by the CLI and the upload UI.

Keeps a single parse → extract → (optional enrich) → score → report path so the
web UI and ``phishbowl analyze`` can never diverge (PRD §15). Callers supply an
already-parsed :class:`~phishbowl.models.ParsedEmail` (and optional enrichment /
redaction settings); this module never opens files or reaches the network on its
own — enrichment only runs when the caller opts in with settings.
"""

from __future__ import annotations

from dataclasses import replace

from phishbowl.connectors import EnrichmentReport, EnrichmentSettings, enrich_email
from phishbowl.extract import extract_iocs
from phishbowl.html_analysis import MAX_TEXT_CHARS
from phishbowl.models import Anomaly, ParsedEmail
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
    parsed = parsed.model_copy(deep=True)
    for field in ("text", "html_raw"):
        value = getattr(parsed.body, field)
        if value and len(value) > MAX_TEXT_CHARS:
            setattr(parsed.body, field, value[:MAX_TEXT_CHARS])
            parsed.anomalies.append(
                Anomaly(
                    code="analysis_truncated",
                    message=(
                        f"{field} exceeds the {MAX_TEXT_CHARS}-character analysis limit; "
                        "later content was not analyzed"
                    ),
                )
            )
    if parsed.subject and len(parsed.subject) > MAX_TEXT_CHARS:
        parsed.subject = parsed.subject[:MAX_TEXT_CHARS]
        parsed.anomalies.append(
            Anomaly(code="analysis_truncated", message="Subject analysis truncated")
        )
    iocs = extract_iocs(parsed)

    result = score_email(parsed, iocs, config)

    report = enrichment
    if report is None and enrichment_settings is not None and enrichment_settings.enabled:
        try:
            report = enrich_email(
                parsed,
                iocs,
                replace(
                    enrichment_settings,
                    excluded_domains=enrichment_settings.excluded_domains | config.org_domains,
                ),
            )
        except Exception:
            from phishbowl.connectors.base import ConnectorOutcome, ConnectorStatus

            report = EnrichmentReport(
                enabled=True,
                statuses=(
                    ConnectorStatus(
                        connector="enrichment",
                        version="",
                        outcome=ConnectorOutcome.FAILED,
                        note="Enrichment failed; offline analysis retained",
                    ),
                ),
            )

    if report is not None:
        result = score_email(parsed, iocs, config, enrichment=report)
    view = build_report(parsed, iocs, result, policy=policy, config=config, enrichment=report)
    return view, result
