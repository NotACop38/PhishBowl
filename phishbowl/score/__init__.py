"""Risk scoring (PRD §6.3, §8).

Transparent over clever: the score is the sum of triggered, YAML-weighted rules
clamped to 0-100, each emitting a human-readable reason with its evidence and
tagged by source (offline | enrichment). The offline verdict is always computed
independent of enrichment.

A *rule* is ``{id, description, weight, source, detector}`` (:mod:`.rules`):
detectors and their identities live in code (:mod:`.detectors`), weights and
verdict bands in an editable YAML with a deep-merge override mechanism
(:mod:`.config`), and the scorer wires them together (:mod:`.engine`).

Typical use::

    from phishbowl.parse import parse
    from phishbowl.extract import extract_iocs
    from phishbowl.score import score_email

    parsed = parse("suspicious.eml")
    result = score_email(parsed, extract_iocs(parsed))
    print(result.score, result.verdict)
    for reason in result.reasons:
        print(" -", reason)
"""

from __future__ import annotations

from .config import Band, ScoringConfig, load_config
from .detectors import OFFLINE_DETECTORS, ScoringContext
from .engine import build_rules, score_email, verdict_for
from .rules import DetectorSpec, FiredRule, Rule, RuleSource, ScoreResult

__all__ = [
    # Scorer entry point
    "score_email",
    "ScoreResult",
    # Config
    "load_config",
    "ScoringConfig",
    "Band",
    # Rule engine internals (stable enough for tests / tuning)
    "build_rules",
    "verdict_for",
    "Rule",
    "DetectorSpec",
    "FiredRule",
    "RuleSource",
    "ScoringContext",
    "OFFLINE_DETECTORS",
]
