"""Cortex XSOAR playbook export (PRD §6.6).

Maps the triage triple — :class:`~phishbowl.models.ParsedEmail` + verdict + IOCs,
projected through a :class:`~phishbowl.report.view.ReportView` — into a Cortex
XSOAR 6.x **playbook** YAML artifact, the format an analyst uploads under
*Playbooks → Upload*. See ``docs/SOAR_EXPORT.md`` for the field-by-field mapping
and import steps.

**Draft / export only — never acts (CLAUDE.md, PRD §4).** Every task in the
emitted playbook is a *manual* task (``task.iscommand: false``, ``task.brand: ""``).
A manual task in XSOAR is a checklist item an analyst completes by hand — it binds
no integration command — so importing and even *running* this playbook triggers no
automation: no block, no quarantine, no send. The extracted indicators ride along
as playbook **inputs** (raw, for the analyst to pivot/hunt on) and as defanged
listings inside the task notes (safe to read in an editor). The never-acts framing
is enforced three ways: in this code, in the prose stamped into the artifact, and
structurally by the schema (``iscommand`` is ``const false``), so a regression that
introduced an auto-running command task would fail validation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import yaml

from .common import (
    BUCKET_LABELS,
    BUCKETS,
    DRAFT_DISCLAIMER,
    TriageCore,
    stable_uuid,
    triage_core,
)

if TYPE_CHECKING:
    from phishbowl.report import ReportView

# Targets the XSOAR 6.x playbook format. Imports into later versions too; the
# editor fills any cosmetic defaults this draft omits.
_FROM_VERSION = "6.5.0"

# Layout hint XSOAR stores per task (a JSON string). Cosmetic only — the editor
# re-lays-out on import — but included so the uploaded playbook renders cleanly.
_VIEW_TEMPLATE = '{{"position":{{"x":450,"y":{y}}}}}'


def _task(
    *,
    seq: int,
    task_type: str,
    name: str,
    description: str,
    next_seq: int | None,
) -> dict[str, Any]:
    """One playbook task. Always manual: ``iscommand`` is false, ``brand`` empty."""
    uid = stable_uuid("xsoar-task", str(seq), name)
    task: dict[str, Any] = {
        "id": str(seq),
        "taskid": uid,
        "type": task_type,
        "task": {
            "id": uid,
            "version": -1,
            "name": name,
            "description": description,
            "type": task_type,
            # The load-bearing safety invariant: a draft export never binds an
            # automation command, so import/run cannot remediate (schema: const false).
            "iscommand": False,
            "brand": "",
        },
        "separatecontext": False,
        "continueonerrortype": "",
        "view": _VIEW_TEMPLATE.format(y=50 + seq * 200),
        "timertriggers": [],
        "ignoreworker": False,
        "skipunavailable": False,
        "quietmode": 0,
        "isautoswitchedtoquietmode": False,
    }
    if next_seq is not None:
        task["nexttasks"] = {"#none#": [str(next_seq)]}
    return task


def _inputs(core: TriageCore) -> list[dict[str, Any]]:
    """Playbook inputs: the verdict and the RAW indicators, for tooling/pivots.

    Raw values are what a SOAR acts on, and these inputs are inert until an analyst
    wires them into a (manual) step — nothing here auto-runs. Redacted indicators
    (bystander PII) are already dropped from the raw channel, so they never appear.
    """
    inputs: list[dict[str, Any]] = [
        _input("PhishbowlVerdict", core.verdict, "Phishbowl verdict band for the message."),
        _input(
            "PhishbowlScore",
            f"{core.score}/{core.max_score}",
            "Phishbowl risk score (0-100) and its maximum.",
        ),
    ]
    raw = core.raw_buckets()
    for bucket in BUCKETS:
        values = raw[bucket]
        if not values:
            continue
        key = "Phishbowl" + "".join(part.capitalize() for part in bucket.split("_"))
        inputs.append(
            _input(
                key,
                ",".join(values),
                f"Raw {BUCKET_LABELS[bucket].lower()} extracted from the email "
                f"(comma-separated; for analyst pivot/hunt — not auto-actioned).",
            )
        )
    return inputs


def _input(key: str, value: str, description: str) -> dict[str, Any]:
    return {
        "key": key,
        "value": {"simple": value},
        "required": False,
        "description": description,
        "playbookInputQuery": None,
    }


def _description(core: TriageCore) -> str:
    """The playbook description: disclaimer first, then the verdict at a glance."""
    return (
        f"{DRAFT_DISCLAIMER}\n\n"
        f"Phishbowl triage summary\n"
        f"Verdict: {core.verdict} (score {core.score}/{core.max_score}, "
        f"offline {core.offline_score}).\n"
        f"Source: {core.source_filename or 'message'} ({core.source_format}).\n"
        f"Authentication: {core.auth_summary() or 'n/a'}.\n"
        f"Indicators: {core.raw_indicator_count()} extracted "
        f"(listed defanged in the tasks below; raw values are in the playbook inputs).\n"
        f"Rules fired: {len(core.reasons)}.\n"
        + (
            "PII redaction was active: bystander recipients/internal topology are withheld.\n"
            if core.redaction_enabled
            else ""
        )
    )


def build_xsoar_playbook(view: ReportView) -> dict[str, Any]:
    """Build the XSOAR playbook artifact (a dict) from a prepared report view."""
    core = triage_core(view)

    # A linear chain of manual tasks: start → title → review steps. Each step is a
    # checklist item; none binds a command, so the playbook is inert on import.
    verdict_note = (
        f"{DRAFT_DISCLAIMER}\n\n"
        f"Verdict: {core.verdict}  (score {core.score}/{core.max_score}, "
        f"offline {core.offline_score}, severity {core.severity}).\n"
        f"Subject: {core.subject or '—'}\n\n"
        f"Why this score:\n{core.reason_block()}"
    )
    indicators_note = (
        "Indicators are shown DEFANGED — neutralised for safe reading. The raw values "
        "(for pivoting/hunting) are in the playbook inputs.\n\n"
        f"{core.defanged_indicator_block()}"
    )
    auth_note = (
        f"Sender authentication: {core.auth_summary() or 'n/a'}.\n"
        "Review SPF/DKIM/DMARC and the From / Reply-To / Return-Path alignment for spoofing."
    )
    containment_note = "DRAFT — Phishbowl proposes; it never acts.\n\n" + "\n".join(
        f"- {step}" for step in core.recommended_review()
    )

    steps = [
        ("Review Phishbowl verdict", verdict_note),
        ("Review extracted indicators (defanged)", indicators_note),
        ("Review sender authentication", auth_note),
        ("Decide containment & response (MANUAL — analyst-driven)", containment_note),
    ]

    tasks: dict[str, dict[str, Any]] = {}
    # Task 0 is the mandatory start node, flowing into the title.
    tasks["0"] = _task(seq=0, task_type="start", name="", description="", next_seq=1)
    tasks["1"] = _task(
        seq=1,
        task_type="title",
        name="Phishbowl Triage (DRAFT — review before acting)",
        description=DRAFT_DISCLAIMER,
        next_seq=2,
    )
    for offset, (name, note) in enumerate(steps):
        seq = 2 + offset
        next_seq = seq + 1 if offset < len(steps) - 1 else None
        tasks[str(seq)] = _task(
            seq=seq,
            task_type="regular",
            name=name,
            description=note,
            next_seq=next_seq,
        )

    return {
        "id": stable_uuid("xsoar-playbook", core.source_filename or "message", core.verdict),
        "version": -1,
        "name": f"Phishbowl Triage — {core.verdict} (DRAFT)",
        "description": _description(core),
        "starttaskid": "0",
        "tasks": tasks,
        "inputs": _inputs(core),
        "outputs": [],
        "tags": ["phishbowl", "phishing", "triage", "draft", "manual", "no-auto-remediation"],
        "fromversion": _FROM_VERSION,
        "system": False,
    }


def render_xsoar(view: ReportView) -> str:
    """Render the XSOAR playbook as a YAML string (the uploadable artifact)."""
    playbook = build_xsoar_playbook(view)
    # sort_keys=False preserves our deliberate field order; width is wide so long
    # indicator/disclaimer lines aren't hard-wrapped mid-token. Deterministic output.
    return yaml.safe_dump(
        playbook,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=4096,
    )


__all__ = ["build_xsoar_playbook", "render_xsoar"]
