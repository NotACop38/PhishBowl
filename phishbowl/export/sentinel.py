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
_DEFAULT_PLAYBOOK_NAME = "Phishbowl-Triage-Draft"


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
            "inputs": summary,
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
    view: ReportView, *, playbook_name: str = _DEFAULT_PLAYBOOK_NAME
) -> dict[str, Any]:
    """Build the Sentinel playbook ARM template (a dict) from a prepared view."""
    core = triage_core(view)

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
                        "value": f"{core.verdict} ({core.score}/{core.max_score})",
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
                "defaultValue": playbook_name,
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


def render_sentinel(view: ReportView, *, playbook_name: str = _DEFAULT_PLAYBOOK_NAME) -> str:
    """Render the Sentinel playbook as a JSON string (the ARM deployment template)."""
    template = build_sentinel_playbook(view, playbook_name=playbook_name)
    # Deterministic, human-diffable JSON; insertion order preserved.
    return json.dumps(template, indent=2, ensure_ascii=False) + "\n"


__all__ = ["build_sentinel_playbook", "render_sentinel"]
