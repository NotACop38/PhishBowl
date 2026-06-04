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


def test_analyze_command_missing_msg_file() -> None:
    # A missing .msg must error like the .eml path, not report a phantom parse.
    result = runner.invoke(app, ["analyze", "/does/not/exist.msg"])

    assert result.exit_code != 0


def test_analyze_strips_control_chars_from_email_fields(tmp_path: Path) -> None:
    # A Subject carrying terminal escape/OSC sequences must not reach the
    # terminal raw (PRD §13: email text is hostile input).
    evil = tmp_path / "evil.eml"
    evil.write_bytes(b"From: a@example.com\r\nSubject: clear\x1b[2Jscreen\x07bell\r\n\r\nbody\r\n")

    result = runner.invoke(app, ["analyze", str(evil)])

    assert result.exit_code == 0
    assert "\x1b" not in result.stdout
    assert "\x07" not in result.stdout
    # The visible text survives with the control bytes removed.
    assert "clear[2Jscreenbell" in result.stdout
