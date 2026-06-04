"""Tests for the ``analyze`` CLI command (Phase 1).

``analyze`` now runs the real ``.eml`` parser and prints a summary. We assert
the command parses the synthetic fixture and surfaces key facts, and that bad
input degrades into a clean CLI error rather than a traceback.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from phishbowl.cli import app

FIXTURE = Path(__file__).parent / "fixtures" / "benign_newsletter.eml"

runner = CliRunner()


def test_analyze_command_parses_fixture() -> None:
    result = runner.invoke(app, ["analyze", str(FIXTURE)])

    assert result.exit_code == 0
    assert "benign_newsletter.eml" in result.stdout
    assert "format=eml" in result.stdout
    # The summary reflects real parsing, not a stub.
    assert "Your weekly Example.com community digest" in result.stdout
    assert "newsletter@example.com" in result.stdout


def test_analyze_command_rejects_unsupported_suffix(tmp_path: Path) -> None:
    bogus = tmp_path / "notes.txt"
    bogus.write_text("not an email")

    result = runner.invoke(app, ["analyze", str(bogus)])

    assert result.exit_code != 0


def test_analyze_command_missing_file() -> None:
    result = runner.invoke(app, ["analyze", "/does/not/exist.eml"])

    assert result.exit_code != 0
