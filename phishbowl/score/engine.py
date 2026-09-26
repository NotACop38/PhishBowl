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

import math
from typing import TYPE_CHECKING

from phishbowl.models import IOCs, ParsedEmail

from .config import ScoringConfig, load_config
from .detectors import OFFLINE_DETECTORS, ScoringContext
from .rules import FiredRule, Rule, RuleSource, ScoreResult

if TYPE_CHECKING:
    from phishbowl.connectors import EnrichmentReport

# Appended to the verdict band when some of the message's evidence was not
# analyzed: the score is then a lower bound, not a full assessment.
INCOMPLETE_SUFFIX = "(incomplete analysis)"


def build_rules(config: ScoringConfig) -> list[Rule]:
    """Bind every detector in the offline catalog to its configured weight."""
    return [Rule(spec=spec, weight=config.weight(spec.id)) for spec in OFFLINE_DETECTORS]


def verdict_for(score: int, config: ScoringConfig) -> str:
    """Map a 0-100 score to its verdict band (PRD §8)."""
    for band in config.bands:
        if score <= band.max:
            return band.verdict
    # Bands are validated to end at 100, so this only guards a hand-built config.
    return config.bands[-1].verdict


def _clamp(value: float) -> int:
    """Normalize a raw weight sum to an integer 0-100 (PRD §8).

    Clamping (not rescaling) keeps the model additive and transparent: each rule
    contributes its literal weight, and a pile-up of strong signals simply
    saturates at 100 rather than diluting any single reason. Halves round up,
    so a band edge means the same thing for every fractional enrichment weight.
    """
    return max(0, min(100, math.floor(value + 0.5)))


def _magnitude(value: float) -> float:
    """A connector-supplied magnitude, forced into 0..1 (non-finite counts as 0)."""
    return min(1.0, max(0.0, value)) if math.isfinite(value) else 0.0


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
    YAML — an enrichment rule is as tunable as any offline rule, and a weight
    of 0 (or none configured) keeps it visible as information at +0.
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
        # Enrichment only ever adds: a negative, oversized or NaN magnitude from
        # a connector (or a tampered cache entry) cannot subtract or overflow.
        weight = base * max(_magnitude(s.magnitude) for s in signals)
        fired.append(
            FiredRule(
                id=signal_id,
                description=signals[0].description,
                weight=weight,
                source=RuleSource.ENRICHMENT,
                evidence=list(dict.fromkeys(s.evidence for s in signals)),
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

    # An incomplete analysis keeps its band — the rules that fired are real
    # evidence — but says so in the verdict itself, so no consumer that reads
    # only the verdict text can mistake a partial result for a complete one.
    complete = parsed.analysis_complete
    verdict = verdict_for(total_score, config)
    if not complete:
        verdict = f"{verdict} {INCOMPLETE_SUFFIX}"
    return ScoreResult(
        score=total_score,
        verdict=verdict,
        fired=tuple(fired),
        offline_score=offline_score,
        analysis_complete=complete,
    )
