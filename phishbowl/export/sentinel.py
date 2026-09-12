"""Microsoft Sentinel playbook export (PRD §6.6).

A Microsoft Sentinel *playbook* is an Azure Logic App, deployed via an Azure
Resource Manager (ARM) template. This module maps the triage triple —
:class:`~phishbowl.models.ParsedEmail` + verdict + IOCs, projected through a
:class:`~phishbowl.report.view.ReportView` — into that ARM deployment template
(``azuredeploy.json``). See ``docs/SOAR_EXPORT.md`` for the field mapping and the
deploy/import steps.

**Draft / export only — never acts (CLAUDE.md, PRD §4).** The emitted workflow is
inert by construction and the invariant is enforced three ways — in this code, in
the prose stamped into the artifact, and structurally by the schema:

* ``properties.state`` is **"Disabled"** (schema: ``const "Disabled"``) — a draft
  playbook is never deployed in a running state; it cannot fire until an analyst
  reviews and explicitly enables it;
* the only trigger is a **manual** HTTP request trigger — deliberately *not* an
  automatic Microsoft Sentinel incident/alert trigger — so import never wires it to
  run on its own;
* the actions are **inert** ``Compose`` steps that merely hold the triage object
  (verdict, indicators, draft review steps). There is no Office 365 / Sentinel /
  block / quarantine connector action, so there is nothing to remediate.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any

from .common import DRAFT_DISCLAIMER, TriageCore, triage_core, triage_summary

if TYPE_CHECKING:
    from phishbowl.report import ReportView

_DEPLOYMENT_SCHEMA = (
    "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
)
_WORKFLOW_DEFINITION_SCHEMA = (
    "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/"
    "2016-06-01/workflowdefinition.json#"
)
_LOGIC_APPS_API_VERSION = "2017-07-01"
# Prefix for the default Logic App name; the per-analysis seed is appended so two
# drafts deployed into the same resource group don't overwrite one another.
_DEFAULT_PLAYBOOK_PREFIX = "Phishbowl-Triage-Draft"


def _trigger() -> dict[str, Any]:
    """A manual HTTP request trigger — never an automatic Sentinel alert trigger."""
    return {
        "manual": {
            "type": "Request",
            "kind": "Http",
            "inputs": {
                "schema": {
                    "type": "object",
                    "properties": {},
                    "description": (
                        "Manual trigger only. This draft playbook is not wired to a "
                        "Microsoft Sentinel alert/incident trigger and ships disabled."
                    ),
                }
            },
        }
    }


def _literal(value):
    """Keep hostile strings out of ARM and Workflow Definition Language syntax.

    Fixed base64ToString expressions decode data once at workflow execution;
    the result is a value, never another expression. Ordinary strings stay readable.
    See docs/SOAR_EXPORT.md for the platform references and qualification boundary.
    """
    if isinstance(value, str):
        if value.startswith(("[", "@")) or "@{" in value:
            encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
            return "@base64ToString('" + encoded + "')"
        return value
    if isinstance(value, dict):
        return {key: _literal(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_literal(item) for item in value]
    return value


def _arm_literal(value: str) -> str:
    return "[" + value if value.startswith("[") and value.endswith("]") else value


def _actions(core: TriageCore) -> dict[str, Any]:
    """Inert Compose actions holding the triage object and the draft review steps.

    Compose outputs a constant value and calls nothing — there is no connector
    action, so the workflow cannot block, quarantine, send, or fetch anything.
    """
    summary = triage_summary(core)
    return {
        # The whole triage object (raw + defanged indicators, verdict, reasons).
        "Compose_Phishbowl_Triage_DRAFT": {
            "type": "Compose",
            "runAfter": {},
            "inputs": _literal(summary),
            "description": DRAFT_DISCLAIMER,
        },
        # The never-acts banner, surfaced on its own so it is impossible to miss.
        "Compose_Draft_Notice": {
            "type": "Compose",
            "runAfter": {"Compose_Phishbowl_Triage_DRAFT": ["Succeeded"]},
            "inputs": DRAFT_DISCLAIMER,
        },
    }


def build_sentinel_playbook(
    view: ReportView, *, playbook_name: str | None = None
) -> dict[str, Any]:
    """Build the Sentinel playbook ARM template (a dict) from a prepared view.

    ``playbook_name`` defaults to ``Phishbowl-Triage-Draft-<analysis-seed>`` — a
    per-analysis name — so deploying drafts for several messages into the same
    resource group creates distinct Logic Apps instead of overwriting one another.
    Pass an explicit name to override.
    """
    core = triage_core(view)
    playbook_name = playbook_name or f"{_DEFAULT_PLAYBOOK_PREFIX}-{core.analysis_seed()}"

    workflow = {
        "type": "Microsoft.Logic/workflows",
        "apiVersion": _LOGIC_APPS_API_VERSION,
        "name": "[parameters('PlaybookName')]",
        "location": "[resourceGroup().location]",
        "tags": {
            "phishbowl": "draft",
            "phishbowl-never-acts": "true",
            "LogicAppsCategory": "security",
        },
        "properties": {
            # Draft: deployed disabled so it cannot run until a human enables it.
            "state": "Disabled",
            "definition": {
                "$schema": _WORKFLOW_DEFINITION_SCHEMA,
                "contentVersion": "1.0.0.0",
                "parameters": {},
                "triggers": _trigger(),
                "actions": _actions(core),
                "outputs": {
                    "PhishbowlVerdict": {
                        "type": "String",
                        "value": _literal(f"{core.verdict} ({core.score}/{core.max_score})"),
                    }
                },
            },
        },
    }

    return {
        "$schema": _DEPLOYMENT_SCHEMA,
        "contentVersion": "1.0.0.0",
        "metadata": {
            "_generator": {"name": core.tool, "draft": True},
            "description": DRAFT_DISCLAIMER,
        },
        "parameters": {
            "PlaybookName": {
                "type": "string",
                "defaultValue": _arm_literal(playbook_name),
                "metadata": {
                    "description": (
                        "Name for the draft Logic App. It deploys DISABLED — review and "
                        "enable it manually; Phishbowl never acts."
                    )
                },
            }
        },
        "variables": {},
        "resources": [workflow],
        "outputs": {
            "draftNotice": {"type": "string", "value": DRAFT_DISCLAIMER},
        },
    }


def render_sentinel(view: ReportView, *, playbook_name: str | None = None) -> str:
    """Render the Sentinel playbook as a JSON string (the ARM deployment template)."""
    template = build_sentinel_playbook(view, playbook_name=playbook_name)
    # Deterministic, human-diffable JSON; insertion order preserved.
    return json.dumps(template, indent=2, ensure_ascii=False) + "\n"


__all__ = ["build_sentinel_playbook", "render_sentinel"]
