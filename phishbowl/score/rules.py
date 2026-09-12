"""Rule-engine data types (PRD §8).

A *rule* is the unit of scoring: ``{id, description, weight, source, detector}``.
Detectors live in :mod:`phishbowl.score.detectors` and weights in the editable
YAML (:mod:`phishbowl.score.config`); a :class:`Rule` binds a detector to its
configured weight. When a detector fires it yields a :class:`FiredRule` carrying
the human-readable reason and the evidence that triggered it, tagged by source
so a reader can always tell offline heuristics from enrichment (PRD §8).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .detectors import ScoringContext


class RuleSource(StrEnum):
    """Where a rule's signal comes from (PRD §8).

    The offline verdict is always computed from ``OFFLINE`` rules alone,
    independent of any enrichment (PRD §8 combination rule).
    """

    OFFLINE = "offline"
    ENRICHMENT = "enrichment"


# A detector inspects the scoring context and returns a list of evidence
# strings. A non-empty list means the rule FIRED (each entry is a concrete piece
# of evidence to show the analyst); an empty list means it stayed silent.
Detector = Callable[["ScoringContext"], list[str]]


@dataclass(frozen=True)
class DetectorSpec:
    """A detector and its identity, defined in code (weight comes from config).

    Keeping id/description/source with the detector — and the *weight* out in
    YAML — is what lets analysts retune without touching code (PRD §8).
    """

    id: str
    description: str
    source: RuleSource
    detector: Detector


@dataclass(frozen=True)
class Rule:
    """A :class:`DetectorSpec` bound to its configured weight."""

    spec: DetectorSpec
    weight: float

    @property
    def id(self) -> str:
        return self.spec.id

    @property
    def description(self) -> str:
        return self.spec.description

    @property
    def source(self) -> RuleSource:
        return self.spec.source

    def evaluate(self, ctx: ScoringContext) -> FiredRule | None:
        """Run the detector; return a :class:`FiredRule` iff it fired."""
        evidence = self.spec.detector(ctx)
        if not evidence:
            return None
        return FiredRule(
            id=self.id,
            description=self.description,
            weight=self.weight,
            source=self.source,
            evidence=list(evidence),
        )


@dataclass(frozen=True)
class FiredRule:
    """One rule that fired: its identity, weight, source, and evidence."""

    id: str
    description: str
    weight: float
    source: RuleSource
    evidence: list[str] = field(default_factory=list)

    @property
    def reason(self) -> str:
        """Human-readable one-liner: description, evidence, weight, and source.

        Example: ``"DMARC authentication failed (dmarc=fail; header.from=…) [+18, offline]"``.
        """
        detail = f" ({'; '.join(self.evidence)})" if self.evidence else ""
        return f"{self.description}{detail} [+{self.weight:g}, {self.source.value}]"


@dataclass(frozen=True)
class ScoreResult:
    """The outcome of scoring one message (PRD §8).

    ``score`` is the final 0-100 value and ``verdict`` its band. ``offline_score``
    is the score from offline rules alone — always computed and always meaningful
    even with zero enrichment (PRD §8). For Phase 3 (offline only) the two are
    equal; the split is kept so Phase 5 enrichment can add on top without
    obscuring the offline base.
    """

    score: int
    verdict: str
    fired: tuple[FiredRule, ...]
    offline_score: int
    analysis_complete: bool = True

    def by_source(self, source: RuleSource) -> tuple[FiredRule, ...]:
        """The fired rules from a given source, in fire order."""
        return tuple(f for f in self.fired if f.source is source)

    @property
    def reasons(self) -> list[str]:
        """Every fired rule's human-readable reason (PRD §8)."""
        return [f.reason for f in self.fired]
