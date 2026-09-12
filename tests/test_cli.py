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

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE = FIXTURES / "benign_newsletter.eml"
MSG_FIXTURE = FIXTURES / "synthetic_phish.msg"

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


def test_analyze_dash_reads_eml_from_stdin() -> None:
    result = runner.invoke(app, ["analyze", "-"], input=FIXTURE.read_bytes())

    assert result.exit_code == 0
    assert "VERDICT" in result.stdout
    # Stdin has no filename; the sniffed format shows in the source banner.
    assert "stdin.eml" in result.stdout


def test_analyze_dash_sniffs_msg_from_stdin() -> None:
    # No suffix to dispatch on — the OLE2 magic alone must route to the .msg parser.
    result = runner.invoke(app, ["analyze", "-"], input=MSG_FIXTURE.read_bytes())

    assert result.exit_code == 2  # Outlook fixture lacks authentication evidence
    assert "Incomplete" in result.stdout
    assert "VERDICT" in result.stdout
    assert "stdin.msg" in result.stdout


def test_analyze_dash_empty_stdin_is_clean_error() -> None:
    result = runner.invoke(app, ["analyze", "-"], input=b"")

    assert result.exit_code != 0
    assert "stdin" in result.output


def test_outputs_cannot_overwrite_source_or_aliases(tmp_path: Path) -> None:
    source = tmp_path / "evidence.eml"
    original = FIXTURE.read_bytes()
    source.write_bytes(original)
    symlink = tmp_path / "link.html"
    symlink.symlink_to(source)
    hardlink = tmp_path / "hardlink.json"
    hardlink.hardlink_to(source)
    for destination in (source, symlink, hardlink):
        result = runner.invoke(app, ["analyze", str(source), "--html", str(destination)])
        assert result.exit_code == 2
        assert "output" in result.output.lower()
        assert source.read_bytes() == original


def test_output_collisions_are_rejected_before_any_write(tmp_path: Path) -> None:
    destination = tmp_path / "report"
    result = runner.invoke(
        app,
        [
            "analyze",
            str(FIXTURE),
            "--html",
            str(destination),
            "--json",
            str(destination),
        ],
    )
    assert result.exit_code == 2
    assert not destination.exists()


def test_output_cannot_overwrite_scoring_config(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("weights: {}\n")
    result = runner.invoke(
        app,
        [
            "analyze",
            str(FIXTURE),
            "--scoring-config",
            str(config),
            "--html",
            str(config),
        ],
    )
    assert result.exit_code == 2
    assert config.read_text() == "weights: {}\n"
