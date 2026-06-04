"""Scoring configuration — load, override, and normalize (PRD §8, §11).

Every tunable number and list the scorer needs lives in an editable YAML file
(``defaults.yaml`` next to this module): rule weights, verdict bands, and the
supporting lists (freemail providers, URL shorteners, credential/urgency
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
touches the network (CLAUDE.md).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

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
    brands: dict[str, frozenset[str]]
    org_domains: frozenset[str]

    def weight(self, rule_id: str) -> float:
        """Weight for ``rule_id``; ``0.0`` if the rule isn't in the config.

        A rule absent from ``weights`` is effectively disabled (it can fire but
        contributes nothing), which is the intended way to switch a rule off via
        config without code changes.
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
        if isinstance(existing, dict) and isinstance(value, Mapping):
            out[key] = _deep_merge(existing, value)
        else:
            out[key] = value
    return out


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"scoring config {path} must be a mapping, got {type(data).__name__}")
    return data


def _folded_set(values: Any) -> frozenset[str]:
    """Case-fold a sequence of strings into a frozenset (empty for ``None``)."""
    if not values:
        return frozenset()
    return frozenset(str(v).strip().casefold() for v in values if str(v).strip())


def _str_tuple(values: Any) -> tuple[str, ...]:
    if not values:
        return ()
    return tuple(str(v).strip().casefold() for v in values if str(v).strip())


def _build(raw: dict[str, Any]) -> ScoringConfig:
    weights = {str(k): float(v) for k, v in (raw.get("weights") or {}).items()}

    bands: list[Band] = []
    for entry in raw.get("bands") or []:
        bands.append(Band(max=int(entry["max"]), verdict=str(entry["verdict"])))
    bands.sort(key=lambda b: b.max)

    brands_raw = raw.get("brands") or {}
    brands = {str(name).casefold(): _folded_set(domains) for name, domains in brands_raw.items()}

    return ScoringConfig(
        weights=weights,
        bands=tuple(bands),
        freemail_domains=_folded_set(raw.get("freemail_domains")),
        url_shorteners=_folded_set(raw.get("url_shorteners")),
        credential_keywords=_str_tuple(raw.get("credential_keywords")),
        urgency_keywords=_str_tuple(raw.get("urgency_keywords")),
        brands=brands,
        org_domains=_folded_set(raw.get("org_domains")),
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
