"""Tests for the Phase 6 SOAR export layer (PRD §6.6).

Two things matter here. First, **conformance**: each export must validate against
its committed expected schema on every fixture — that is the Phase 6 DoD. Second,
and load-bearing, the **never-acts invariant** (CLAUDE.md / PRD §4): a draft export
must be inert by construction, and the schemas encode that (XSOAR ``iscommand`` is
``const false``; Sentinel ``state`` is ``const "Disabled"``), so the same
validation that proves conformance also proves the artifact can't auto-remediate.
We additionally prove the validator is not vacuous — it rejects a tampered artifact
that flips either invariant — so "it validates" actually means something.

The exports reuse the report layer's prepared :class:`ReportView`, so defanging and
PII redaction stay consistent with the HTML/JSON/CLI outputs: raw indicators feed
the machine channel (playbook inputs / workflow variables), defanged values feed
every human-readable note, and redaction withholds bystander PII from both.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from phishbowl.cli import app
from phishbowl.export import (
    DRAFT_DISCLAIMER,
    SENTINEL_SCHEMA_NAME,
    XSOAR_SCHEMA_NAME,
    build_sentinel_playbook,
    build_xsoar_playbook,
    render_sentinel,
    render_xsoar,
    sentinel_schema,
    validate,
    validate_export,
    xsoar_schema,
)
from phishbowl.extract import extract_iocs
from phishbowl.parse import parse
from phishbowl.report import RedactionPolicy, build_report
from phishbowl.score import load_config, score_email

FIXTURES = Path(__file__).parent / "fixtures"
MALICIOUS = FIXTURES / "crafted_malicious.eml"
BENIGN = FIXTURES / "benign_newsletter.eml"
HOSTILE = FIXTURES / "hostile_content.eml"

ALL_FIXTURES = sorted(
    p for p in FIXTURES.iterdir() if p.suffix.lower() in {".eml", ".msg"} and p.is_file()
)

runner = CliRunner()

# Sentinel actions Phishbowl emits are all inert "Compose" steps — they hold data
# and call nothing. A draft export must never contain a connector/HTTP action that
# could egress or remediate, so the allowed set is deliberately this small.
_INERT_ACTION_TYPES = {"Compose"}


def _view(path: Path, *, policy: RedactionPolicy | None = None, overrides=None):
    parsed = parse(path)
    config = load_config(overrides=overrides) if overrides else load_config()
    iocs = extract_iocs(parsed)
    result = score_email(parsed, iocs, config)
    return build_report(parsed, iocs, result, policy=policy, config=config)


# --------------------------------------------------------------------------- #
# The tiny JSON Schema validator itself — prove it is sound (not vacuous)      #
# --------------------------------------------------------------------------- #


def test_validator_accepts_a_conforming_instance() -> None:
    schema = {
        "type": "object",
        "required": ["a", "b"],
        "properties": {"a": {"type": "string"}, "b": {"type": "integer"}},
    }
    assert validate({"a": "x", "b": 1}, schema) == []


@pytest.mark.parametrize(
    "instance,schema",
    [
        (5, {"type": "string"}),  # wrong type
        ({}, {"type": "object", "required": ["a"]}),  # missing required
        ("nope", {"const": "yes"}),  # const mismatch
        ("c", {"enum": ["a", "b"]}),  # not in enum
        ("xy", {"type": "string", "minLength": 3}),  # too short
        ([], {"type": "array", "minItems": 1}),  # too few items
        ({}, {"type": "object", "minProperties": 1}),  # too few properties
        ("abc", {"type": "string", "pattern": "zzz"}),  # pattern miss
        (True, {"type": "integer"}),  # bool is not integer
        ({"x": 1}, {"type": "object", "additionalProperties": False}),  # extra prop
        ({"x": "no"}, {"additionalProperties": {"type": "integer"}}),  # extra prop wrong type
    ],
)
def test_validator_rejects_nonconforming_instances(instance, schema) -> None:
    assert validate(instance, schema) != []


def test_validator_resolves_local_refs() -> None:
    schema = {
        "type": "object",
        "properties": {"item": {"$ref": "#/$defs/leaf"}},
        "$defs": {"leaf": {"type": "string", "const": "ok"}},
    }
    assert validate({"item": "ok"}, schema) == []
    assert validate({"item": "bad"}, schema) != []


def test_bundled_schemas_load_and_are_self_describing() -> None:
    for schema in (xsoar_schema(), sentinel_schema()):
        assert schema["$schema"].startswith("https://json-schema.org/")
        assert "$defs" in schema
        # The never-acts framing is documented in the schema description itself.
        assert "never" in schema["description"].lower()


# --------------------------------------------------------------------------- #
# Cortex XSOAR playbook                                                        #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda p: p.name)
def test_xsoar_validates_against_schema_on_every_fixture(fixture: Path) -> None:
    playbook = build_xsoar_playbook(_view(fixture))
    assert validate_export(playbook, XSOAR_SCHEMA_NAME) == []
    # …and the serialized YAML round-trips back to a conforming structure.
    reloaded = yaml.safe_load(render_xsoar(_view(fixture)))
    assert validate_export(reloaded, XSOAR_SCHEMA_NAME) == []


def test_xsoar_carries_verdict_indicators_and_disclaimer() -> None:
    view = _view(MALICIOUS)
    playbook = build_xsoar_playbook(view)
    yaml_text = render_xsoar(view)

    assert "Malicious" in playbook["name"]
    assert DRAFT_DISCLAIMER in playbook["description"]
    # Raw indicators ride along as playbook inputs (machine channel, for pivoting).
    inputs_blob = json.dumps(playbook["inputs"])
    assert "examp1e.com" in inputs_blob  # raw, live value
    assert "198.51.100.99" in inputs_blob
    # Human-readable task notes show the SAME indicators defanged.
    assert "examp1e[.]com" in yaml_text
    assert "198[.]51[.]100[.]99" in yaml_text


def test_xsoar_every_task_is_manual_so_import_cannot_remediate() -> None:
    view = _view(MALICIOUS)
    playbook = build_xsoar_playbook(view)
    # Structurally: no task binds an automation command.
    for task in playbook["tasks"].values():
        assert task["task"]["iscommand"] is False
        assert task["task"]["brand"] == ""
    # And textually, the never-acts string is impossible to find in the artifact.
    assert "iscommand: true" not in render_xsoar(view).lower()


def test_xsoar_starts_at_the_start_task() -> None:
    playbook = build_xsoar_playbook(_view(BENIGN))
    start = playbook["tasks"][playbook["starttaskid"]]
    assert start["type"] == "start"


# --------------------------------------------------------------------------- #
# Microsoft Sentinel playbook (Logic App ARM template)                        #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda p: p.name)
def test_sentinel_validates_against_schema_on_every_fixture(fixture: Path) -> None:
    template = build_sentinel_playbook(_view(fixture))
    assert validate_export(template, SENTINEL_SCHEMA_NAME) == []
    reloaded = json.loads(render_sentinel(_view(fixture)))
    assert validate_export(reloaded, SENTINEL_SCHEMA_NAME) == []


def test_sentinel_ships_disabled_behind_a_manual_trigger() -> None:
    template = build_sentinel_playbook(_view(MALICIOUS))
    workflow = template["resources"][0]
    assert workflow["type"] == "Microsoft.Logic/workflows"
    props = workflow["properties"]
    # Draft: never imported in a running state.
    assert props["state"] == "Disabled"
    # Manual trigger only — not an automatic Sentinel incident/alert trigger.
    assert props["definition"]["triggers"]["manual"]["type"] == "Request"
    # 'Enabled' must never appear as a workflow state anywhere in the artifact.
    assert '"state": "Enabled"' not in render_sentinel(_view(MALICIOUS))


def test_sentinel_actions_are_all_inert_compose_steps() -> None:
    template = build_sentinel_playbook(_view(MALICIOUS))
    actions = template["resources"][0]["properties"]["definition"]["actions"]
    assert actions  # there is at least one action
    for action in actions.values():
        assert action["type"] in _INERT_ACTION_TYPES


def test_sentinel_carries_verdict_indicators_and_disclaimer() -> None:
    view = _view(MALICIOUS)
    template = build_sentinel_playbook(view)
    json_text = render_sentinel(view)

    summary = template["resources"][0]["properties"]["definition"]["actions"][
        "Compose_Phishbowl_Triage_DRAFT"
    ]["inputs"]
    assert summary["verdict"]["text"] == "Malicious — high confidence"
    assert summary["disclaimer"] == DRAFT_DISCLAIMER
    assert summary["never_acts"] is True
    # Raw indicators for hunting (machine channel) and defanged for humans both ride along.
    assert "198.51.100.99" in summary["indicators_raw"]["ips"]
    assert "198[.]51[.]100[.]99" in json_text


# --------------------------------------------------------------------------- #
# Validation actually catches a tampered (acting) artifact — not vacuous       #
# --------------------------------------------------------------------------- #


def test_validation_rejects_an_xsoar_playbook_that_would_run_a_command() -> None:
    playbook = build_xsoar_playbook(_view(MALICIOUS))
    # Flip a task into an automation command — exactly what a draft must never do.
    playbook["tasks"]["2"]["task"]["iscommand"] = True
    errors = validate_export(playbook, XSOAR_SCHEMA_NAME)
    assert errors and any("iscommand" in e for e in errors)


def test_validation_rejects_a_sentinel_playbook_that_ships_enabled() -> None:
    template = build_sentinel_playbook(_view(MALICIOUS))
    template["resources"][0]["properties"]["state"] = "Enabled"
    errors = validate_export(template, SENTINEL_SCHEMA_NAME)
    assert errors and any("state" in e or "Disabled" in e for e in errors)


# --------------------------------------------------------------------------- #
# PII redaction carries through to both exports                                #
# --------------------------------------------------------------------------- #


def test_redaction_withholds_recipients_from_both_exports() -> None:
    view = _view(MALICIOUS, policy=RedactionPolicy.standard())
    xsoar_text = render_xsoar(view)
    sentinel_text = render_sentinel(view)
    for text in (xsoar_text, sentinel_text):
        # The bystander recipient is gone from both the raw and defanged channels…
        assert "analyst@example.org" not in text
        assert "analyst[at]example[.]org" not in text
        # …while the attacker's indicators are fully retained (threat intel intact).
        assert "examp1e.com" in text  # raw, machine channel
        assert "examp1e[.]com" in text  # defanged, human channel


def test_no_redaction_by_default_keeps_recipient_fidelity() -> None:
    # Without --redact the export mirrors the report's full fidelity (defanged).
    xsoar_text = render_xsoar(_view(MALICIOUS))
    assert "analyst[at]example[.]org" in xsoar_text
    assert "[redacted" not in xsoar_text


# --------------------------------------------------------------------------- #
# Determinism — re-exporting the same analysis is byte-identical               #
# --------------------------------------------------------------------------- #


def test_exports_are_deterministic_for_a_given_analysis() -> None:
    view = _view(MALICIOUS)  # one view → fixed parse time and stable ids
    assert render_xsoar(view) == render_xsoar(view)
    assert render_sentinel(view) == render_sentinel(view)


# --------------------------------------------------------------------------- #
# Building an export opens no socket (defensive-only, PRD §4)                   #
# --------------------------------------------------------------------------- #


def test_building_exports_opens_no_outbound_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object):
        raise AssertionError("export attempted outbound network egress")

    monkeypatch.setattr(socket.socket, "connect", boom, raising=False)
    monkeypatch.setattr(socket, "create_connection", boom, raising=False)

    view = _view(HOSTILE)
    assert render_xsoar(view)
    assert render_sentinel(view)


# --------------------------------------------------------------------------- #
# CLI integration                                                              #
# --------------------------------------------------------------------------- #


def test_cli_emits_both_soar_drafts(tmp_path: Path) -> None:
    xsoar_path = tmp_path / "playbook.yml"
    sentinel_path = tmp_path / "azuredeploy.json"
    result = runner.invoke(
        app,
        [
            "analyze",
            str(MALICIOUS),
            "--xsoar",
            str(xsoar_path),
            "--sentinel",
            str(sentinel_path),
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert "DRAFT" in result.stdout and "never acts" in result.stdout

    # Both files exist and validate against their schemas after a round-trip on disk.
    playbook = yaml.safe_load(xsoar_path.read_text())
    template = json.loads(sentinel_path.read_text())
    assert validate_export(playbook, XSOAR_SCHEMA_NAME) == []
    assert validate_export(template, SENTINEL_SCHEMA_NAME) == []
    # The safety invariants survive the full CLI path.
    assert template["resources"][0]["properties"]["state"] == "Disabled"
    assert all(t["task"]["iscommand"] is False for t in playbook["tasks"].values())
