"""The scorer (PRD §8).

Binds the offline detector catalog to the configured weights, runs every rule
over a :class:`ScoringContext`, sums the weights of the rules that fired, clamps
to 0-100, and maps the total to a verdict band. Each fired rule keeps its
evidence and source tag, so every point of the score traces to a named,
human-readable reason (PRD §8 "transparent over clever").

The offline verdict is **always** computed from offline rules alone — it never
depends on enrichment, and no single connector (when Phase 5 lands) can zero it
out (PRD §8 combination rule). Weights come from editable YAML, so analysts
retune without touching this code.
"""

from __future__ import annotations

from phishbowl.models import IOCs, ParsedEmail

from .config import ScoringConfig, load_config
from .detectors import OFFLINE_DETECTORS, ScoringContext
from .rules import FiredRule, Rule, RuleSource, ScoreResult


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


def score_email(
    parsed: ParsedEmail,
    iocs: IOCs,
    config: ScoringConfig | None = None,
) -> ScoreResult:
    """Score a parsed message and its IOCs into a :class:`ScoreResult` (PRD §8).

    Runs the offline rule catalog, summing each *fired* rule's weight exactly
    once (a rule that several indicators trigger still counts once — the guard
    against double-counting), then clamps to 0-100 and assigns a verdict band.
    Every fired rule carries its evidence and ``offline`` source tag.
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

    # Phase 3 is offline-only; the total equals the offline score. The split is
    # preserved so Phase 5 enrichment can add on top without hiding the base.
    total_score = offline_score

    return ScoreResult(
        score=total_score,
        verdict=verdict_for(total_score, config),
        fired=tuple(fired),
        offline_score=offline_score,
    )
