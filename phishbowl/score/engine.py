"""The scorer (PRD §8).

Binds the offline detector catalog to the configured weights, runs every rule
over a :class:`ScoringContext`, sums the weights of the rules that fired, clamps
to 0-100, and maps the total to a verdict band. Each fired rule keeps its
evidence and source tag, so every point of the score traces to a named,
human-readable reason (PRD §8 "transparent over clever").

The offline verdict is **always** computed from offline rules alone — it never
depends on enrichment, and no single connector can zero it out (PRD §8
combination rule). When enrichment results are supplied they only ever *add*
``[enrichment]``-tagged points on top of that offline base, and the email is
re-scored to a fresh total. Weights — offline and enrichment alike — come from
editable YAML, so analysts retune without touching this code.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from phishbowl.models import IOCs, ParsedEmail

from .config import ScoringConfig, load_config
from .detectors import OFFLINE_DETECTORS, ScoringContext
from .rules import FiredRule, Rule, RuleSource, ScoreResult

if TYPE_CHECKING:
    from phishbowl.connectors import EnrichmentReport


def build_rules(config: ScoringConfig) -> list[Rule]:
    """Bind every detector in the offline catalog to its configured weight."""
    return [Rule(spec=spec, weight=config.weight(spec.id)) for spec in OFFLINE_DETECTORS]


def verdict_for(score: int, config: ScoringConfig) -> str:
    """Map a 0-100 score to its verdict band (PRD §8)."""
    for band in config.bands:
        if score <= band.max:
            return band.verdict
    # Bands are validated to end at 100, but clamp defensively to the last one.
    return config.bands[-1].verdict if config.bands else "Unknown"


def _clamp(value: float) -> int:
    """Normalize a raw weight sum to an integer 0-100 (PRD §8).

    Clamping (not rescaling) keeps the model additive and transparent: each rule
    contributes its literal weight, and a pile-up of strong signals simply
    saturates at 100 rather than diluting any single reason.
    """
    return max(0, min(100, round(value)))


def _dedup(items: list[str]) -> list[str]:
    """Order-preserving de-duplication of evidence strings."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _fold_enrichment(
    enrichment: EnrichmentReport,
    config: ScoringConfig,
) -> list[FiredRule]:
    """Turn normalized enrichment signals into ``[enrichment]``-tagged fired rules.

    Signals are aggregated by their stable ``id`` so one connector finding the
    same condition across several indicators contributes its weight **once** (the
    enrichment counterpart of the offline no-double-counting guard, PRD §8): the
    rule's weight uses the strongest magnitude seen, and every indicator's
    evidence line is listed. Each signal's base weight comes from the editable
    YAML — an enrichment rule is as tunable (and as disableable, by setting its
    weight to 0) as any offline rule.
    """
    grouped: dict[str, list] = {}
    order: list[str] = []
    for signal in enrichment.signals:
        if signal.id not in grouped:
            grouped[signal.id] = []
            order.append(signal.id)
        grouped[signal.id].append(signal)

    fired: list[FiredRule] = []
    for signal_id in order:
        signals = grouped[signal_id]
        base = config.weight(signal_id)
        magnitude = max(s.magnitude for s in signals)
        weight = base * magnitude
        fired.append(
            FiredRule(
                id=signal_id,
                description=signals[0].description,
                weight=weight,
                source=RuleSource.ENRICHMENT,
                evidence=_dedup([s.evidence for s in signals]),
            )
        )
    return fired


def score_email(
    parsed: ParsedEmail,
    iocs: IOCs,
    config: ScoringConfig | None = None,
    *,
    enrichment: EnrichmentReport | None = None,
) -> ScoreResult:
    """Score a parsed message and its IOCs into a :class:`ScoreResult` (PRD §8).

    Runs the offline rule catalog, summing each *fired* rule's weight exactly
    once (a rule that several indicators trigger still counts once — the guard
    against double-counting), then clamps to 0-100 and assigns a verdict band.
    Every fired rule carries its evidence and ``offline`` source tag.

    The ``offline_score`` is always computed from offline rules alone. When an
    ``enrichment`` report is supplied, its normalized signals are folded in as
    ``[enrichment]``-tagged rules and the email is re-scored to a higher total;
    with no enrichment (the default) the total equals the offline score, so the
    offline-only path is entirely unchanged (PRD §5, §8 combination rule).
    """
    config = config or load_config()
    ctx = ScoringContext(parsed=parsed, iocs=iocs, config=config)

    fired: list[FiredRule] = []
    for rule in build_rules(config):
        result = rule.evaluate(ctx)
        if result is not None:
            fired.append(result)

    offline_total = sum(f.weight for f in fired if f.source is RuleSource.OFFLINE)
    offline_score = _clamp(offline_total)

    enrichment_fired: list[FiredRule] = []
    if enrichment is not None and enrichment.enabled:
        enrichment_fired = _fold_enrichment(enrichment, config)
    fired.extend(enrichment_fired)

    enrichment_total = sum(f.weight for f in enrichment_fired)
    total_score = _clamp(offline_total + enrichment_total)

    return ScoreResult(
        score=total_score,
        verdict=(
            verdict_for(total_score, config)
            if not parsed.anomalies
            else "Incomplete — analyst review required"
        ),
        fired=tuple(fired),
        offline_score=offline_score,
        analysis_complete=not parsed.anomalies,
    )
