"""Tests for the ``analyze`` CLI command.

As of Phase 4, ``analyze`` runs the full offline pipeline and prints a rich
verdict summary (and optionally writes HTML/JSON). The detailed CLI behaviour —
output rendering, defanging, redaction, control-character stripping — is covered
in ``test_report.py``; this module keeps the basic command-wiring smoke tests:
the fixture parses end-to-end, and bad input degrades into a clean error rather
than a traceback.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from phishbowl.cli import app

FIXTURE = Path(__file__).parent / "fixtures" / "benign_newsletter.eml"

runner = CliRunner()


def test_analyze_command_runs_full_pipeline_on_fixture() -> None:
    result = runner.invoke(app, ["analyze", str(FIXTURE)])

    assert result.exit_code == 0
    # The benign newsletter surfaces a verdict banner and the source filename.
    assert "VERDICT" in result.stdout
    assert "benign_newsletter.eml" in result.stdout


def test_analyze_command_rejects_unsupported_suffix(tmp_path: Path) -> None:
    bogus = tmp_path / "notes.txt"
    bogus.write_text("not an email")

    result = runner.invoke(app, ["analyze", str(bogus)])

    assert result.exit_code != 0


def test_analyze_command_missing_file() -> None:
    result = runner.invoke(app, ["analyze", "/does/not/exist.eml"])

    assert result.exit_code != 0


def test_analyze_command_missing_msg_file() -> None:
    # A missing .msg must error like the .eml path, not report a phantom parse.
    result = runner.invoke(app, ["analyze", "/does/not/exist.msg"])

    assert result.exit_code != 0
