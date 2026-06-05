"""SOAR export (PRD §6.6) — draft playbook artifacts for XSOAR and Sentinel.

Phase 6 layers on top of the already-complete offline product: it maps the triage
triple — :class:`~phishbowl.models.ParsedEmail` + verdict + IOCs, projected once
through a :class:`~phishbowl.report.view.ReportView` so defanging, PII redaction,
severity, and enrichment status stay consistent with the other outputs — into two
platform artifacts:

* :func:`render_xsoar` — a Cortex XSOAR 6.x **playbook** YAML;
* :func:`render_sentinel` — a Microsoft Sentinel **playbook** (Azure Logic App) ARM
  deployment template (JSON).

Each artifact ships with an *expected schema* under :mod:`phishbowl.export.schemas`,
and :func:`validate_export` checks an artifact against it (the Phase 6 validation
DoD) with a small, dependency-free validator — no third-party library, fully
offline, in keeping with ``make test`` staying self-contained.

**Draft / export only — Phishbowl never acts (CLAUDE.md, PRD §4).** Both artifacts
are inert by construction *and* by schema: every XSOAR task is a manual task
(``iscommand`` is ``const false``) and the Sentinel workflow ships disabled
(``state`` is ``const "Disabled"``) behind a manual trigger with no remediation
connector. Importing either one triggers nothing — Phishbowl proposes a
human-review playbook seeded with the verdict and indicators; an analyst reviews
and runs it. See ``docs/SOAR_EXPORT.md`` for the field mappings and import steps.
"""

from __future__ import annotations

from typing import Any

from .common import DRAFT_DISCLAIMER, NEVER_ACTS, load_schema
from .sentinel import build_sentinel_playbook, render_sentinel
from .validate import validate
from .xsoar import build_xsoar_playbook, render_xsoar

# The two bundled expected schemas, loaded lazily and cached by :func:`load_schema`.
XSOAR_SCHEMA_NAME = "xsoar_playbook"
SENTINEL_SCHEMA_NAME = "sentinel_playbook"


def xsoar_schema() -> dict[str, Any]:
    """The expected JSON Schema for the XSOAR playbook artifact."""
    return load_schema(XSOAR_SCHEMA_NAME)


def sentinel_schema() -> dict[str, Any]:
    """The expected JSON Schema for the Sentinel playbook artifact."""
    return load_schema(SENTINEL_SCHEMA_NAME)


def validate_export(artifact: dict[str, Any], schema_name: str) -> list[str]:
    """Validate an export artifact against a bundled schema; return error strings.

    ``schema_name`` is a schema stem (:data:`XSOAR_SCHEMA_NAME` /
    :data:`SENTINEL_SCHEMA_NAME`). An empty list means the artifact conforms.
    """
    return validate(artifact, load_schema(schema_name))


__all__ = [
    # XSOAR
    "build_xsoar_playbook",
    "render_xsoar",
    "xsoar_schema",
    "XSOAR_SCHEMA_NAME",
    # Sentinel
    "build_sentinel_playbook",
    "render_sentinel",
    "sentinel_schema",
    "SENTINEL_SCHEMA_NAME",
    # Validation
    "validate",
    "validate_export",
    "load_schema",
    # Safety framing
    "DRAFT_DISCLAIMER",
    "NEVER_ACTS",
]
