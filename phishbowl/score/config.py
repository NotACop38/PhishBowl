"""Scoring configuration — load, override, and normalize (PRD §8, §11).

Every tunable number and list the scorer needs lives in an editable YAML file
(``defaults.yaml`` next to this module): rule weights, verdict bands, and the
supporting lists (freemail providers, URL shorteners, credential/urgency/role
keywords, the bundled brand-impersonation list, and operator org domains).

The **override mechanism** is a deep merge: load the bundled defaults, then
layer a site file and/or a programmatic ``dict`` on top, so an operator only has
to specify the keys they want to change. Resolution order, lowest to highest
precedence:

1. bundled ``defaults.yaml``
2. the file at ``$PHISHBOWL_SCORING_CONFIG`` (if set)
3. an explicit ``path=`` argument to :func:`load_config`
4. an explicit ``overrides=`` dict argument to :func:`load_config`

Loading is offline and side-effect free — it reads local YAML only and never
touches the network (AGENTS.md). Validation is strict: an unknown rule id, a
non-numeric weight, or a scalar where a list belongs raises :class:`ValueError`
naming the key, because a silently ignored typo would quietly change verdicts.
"""

from __future__ import annotations

import difflib
import math
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from phishbowl.domains import normalize_domain_pattern

DEFAULT_CONFIG_PATH = Path(__file__).with_name("defaults.yaml")

# Env var pointing at a site override file (PRD §11 — config via a YAML file).
ENV_CONFIG = "PHISHBOWL_SCORING_CONFIG"


@dataclass(frozen=True)
class Band:
    """One verdict band: every score ``<= max`` (and above the prior band) maps
    to ``verdict``."""

    max: int
    verdict: str


@dataclass(frozen=True)
class ScoringConfig:
    """Resolved, normalized scoring configuration.

    Lists that are membership-tested are stored as case-folded ``frozenset``s;
    ordered keyword lists stay lists (their order is irrelevant but duplicates
    are harmless). ``brands`` maps a lower-cased brand keyword to its set of
    legitimate domains.
    """

    weights: dict[str, float]
    bands: tuple[Band, ...]
    freemail_domains: frozenset[str]
    url_shorteners: frozenset[str]
    credential_keywords: tuple[str, ...]
    urgency_keywords: tuple[str, ...]
    role_keywords: tuple[str, ...]
    brands: dict[str, frozenset[str]]
    org_domains: frozenset[str]

    def weight(self, rule_id: str) -> float:
        """Weight for ``rule_id``; ``0.0`` if the rule isn't in the config.

        A rule weighted 0 still fires and reports its evidence, at +0: that is
        how a rule is switched off without hiding what it observed.
        """
        return float(self.weights.get(rule_id, 0.0))


def _deep_merge(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    """Recursively merge ``override`` into a copy of ``base``.

    Nested mappings merge key-by-key; every other value (scalars AND lists) is
    replaced wholesale. Replacing lists rather than concatenating is deliberate:
    an operator who sets ``url_shorteners`` means *exactly these*, not "these
    plus the defaults" — wholesale replacement keeps overrides predictable.
    """
    out = dict(base)
    for key, value in override.items():
        existing = out.get(key)
        if isinstance(existing, dict) and value is None:
            # An empty "weights:" key would otherwise zero every rule silently.
            raise ValueError(f"'{key}' is empty; remove the key or give it entries")
        if isinstance(existing, dict) and not isinstance(value, Mapping):
            # "weights: []" (or 0, "") must not silently replace every weight.
            raise ValueError(f"'{key}' must be a mapping, got {type(value).__name__}")
        if isinstance(existing, dict):
            out[key] = _deep_merge(existing, value)
        else:
            out[key] = value
    return out


# Top-level keys a scoring config may set.
_LIST_KEYS = (
    "freemail_domains",
    "url_shorteners",
    "credential_keywords",
    "urgency_keywords",
    "role_keywords",
    "org_domains",
)

# A single rule can never need more than the whole score.
_MAX_WEIGHT = 100.0
_KNOWN_KEYS = frozenset({"weights", "bands", "brands", *_LIST_KEYS})

# Weights for enrichment signals are keyed by connector-defined ids, so any key
# under this prefix is accepted (third-party connectors define their own).
ENRICHMENT_PREFIX = "enrichment."


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        try:
            data = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise ValueError(f"{path} is not valid YAML: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"scoring config {path} must be a mapping, got {type(data).__name__}")
    return data


def _string_list(values: Any, key: str) -> list[str]:
    """The non-empty, case-folded strings of list ``key`` (a scalar is an error)."""
    if values is None:
        return []
    if not isinstance(values, list):
        raise ValueError(f"'{key}' must be a list, got {type(values).__name__}")
    return [str(v).strip().casefold() for v in values if str(v).strip()]


def _weights(raw: dict[str, Any]) -> dict[str, float]:
    from .detectors import OFFLINE_DETECTORS  # deferred: detectors import this module

    values = raw.get("weights")
    values = {} if values is None else values
    if not isinstance(values, Mapping):
        raise ValueError(f"'weights' must be a mapping, got {type(values).__name__}")
    known = {spec.id for spec in OFFLINE_DETECTORS}
    weights: dict[str, float] = {}
    for key, value in values.items():
        rule = str(key)
        if rule not in known and not rule.startswith(ENRICHMENT_PREFIX):
            hint = difflib.get_close_matches(rule, sorted(known), n=1)
            suggestion = f" (did you mean '{hint[0]}'?)" if hint else ""
            raise ValueError(f"unknown rule id '{rule}' in weights{suggestion}")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"weight for '{rule}' must be a number, got {value!r}")
        weight = float(value)
        if not math.isfinite(weight) or not 0 <= weight <= _MAX_WEIGHT:
            raise ValueError(f"weight for '{rule}' must be between 0 and {_MAX_WEIGHT:g}")
        weights[rule] = weight
    return weights


def _bands(raw: dict[str, Any]) -> tuple[Band, ...]:
    entries = raw.get("bands")
    entries = [] if entries is None else entries
    if not isinstance(entries, list):
        raise ValueError(f"'bands' must be a list, got {type(entries).__name__}")
    bands: list[Band] = []
    for entry in entries:
        limit = entry.get("max") if isinstance(entry, Mapping) else None
        verdict = entry.get("verdict") if isinstance(entry, Mapping) else None
        if isinstance(limit, bool) or not isinstance(limit, int) or not isinstance(verdict, str):
            message = f"each band needs an integer 'max' and a 'verdict': {entry!r}"
            raise ValueError(message)
        bands.append(Band(max=limit, verdict=verdict))
    bands.sort(key=lambda b: b.max)
    if (
        not bands
        or bands[-1].max != 100
        or any(b.max < 0 or b.max > 100 or not b.verdict.strip() for b in bands)
        or len({b.max for b in bands}) != len(bands)
    ):
        raise ValueError("bands need unique limits in 0..100 ending at 100 and nonempty verdicts")
    return tuple(bands)


def _brands(raw: dict[str, Any]) -> dict[str, frozenset[str]]:
    values = raw.get("brands")
    values = {} if values is None else values
    if not isinstance(values, Mapping):
        raise ValueError(f"'brands' must be a mapping, got {type(values).__name__}")
    brands: dict[str, frozenset[str]] = {}
    for name, domains in values.items():
        owned = frozenset(_string_list(domains, f"brands.{name}"))
        # An empty list (or null) removes a bundled brand: a brand that owns no
        # domain would otherwise flag every sender that mentions it.
        if owned:
            brands[str(name).casefold()] = owned
    return brands


def _build(raw: dict[str, Any]) -> ScoringConfig:
    unknown = sorted(set(raw) - _KNOWN_KEYS)
    if unknown:
        raise ValueError(f"unknown scoring config key(s): {', '.join(map(str, unknown))}")
    lists = {key: _string_list(raw.get(key), key) for key in _LIST_KEYS}
    return ScoringConfig(
        weights=_weights(raw),
        bands=_bands(raw),
        freemail_domains=frozenset(lists["freemail_domains"]),
        url_shorteners=frozenset(lists["url_shorteners"]),
        credential_keywords=tuple(lists["credential_keywords"]),
        urgency_keywords=tuple(lists["urgency_keywords"]),
        role_keywords=tuple(lists["role_keywords"]),
        brands=_brands(raw),
        org_domains=frozenset(normalize_domain_pattern(d) for d in lists["org_domains"]),
    )


def load_config(
    path: str | Path | None = None,
    overrides: Mapping[str, Any] | None = None,
) -> ScoringConfig:
    """Load scoring config: bundled defaults, then env file, ``path``, ``overrides``.

    Each later source deep-merges over the earlier ones (see module docstring),
    so a caller only supplies the keys they want to change. Returns a fully
    resolved, immutable :class:`ScoringConfig`.
    """
    raw = _load_yaml(DEFAULT_CONFIG_PATH)

    env_path = os.environ.get(ENV_CONFIG)
    if env_path:
        raw = _deep_merge(raw, _load_yaml(Path(env_path)))

    if path is not None:
        raw = _deep_merge(raw, _load_yaml(Path(path)))

    if overrides is not None:
        raw = _deep_merge(raw, overrides)

    return _build(raw)
