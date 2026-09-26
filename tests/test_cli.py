"""Tests for the ``analyze`` CLI command.

As of Phase 4, ``analyze`` runs the full offline pipeline and prints a rich
verdict summary (and optionally writes HTML/JSON). The detailed CLI behaviour —
output rendering, defanging, redaction, control-character stripping — is covered
in ``test_report.py``; this module keeps the basic command-wiring smoke tests:
the fixture parses end-to-end, and bad input degrades into a clean error rather
than a traceback.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
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

    # Missing Outlook authentication results are a notice, not a coverage gap.
    assert result.exit_code == 0
    assert "Note: no SPF/DKIM/DMARC results" in result.stdout
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


# --- exit status contract: 0 complete · 1 threshold · 2 usage · 3 incomplete ---


def _incomplete_email(tmp_path: Path) -> Path:
    # A multipart whose close boundary is missing: the structure is ambiguous,
    # so a mail client could show content the parser did not separate.
    path = tmp_path / "ambiguous.eml"
    path.write_bytes(
        b"From: sender@example.com\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n"
        b"--x\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
    )
    return path


def test_incomplete_analysis_exits_3_after_writing_reports(tmp_path: Path) -> None:
    report = tmp_path / "report.html"
    result = runner.invoke(
        app, ["analyze", str(_incomplete_email(tmp_path)), "--html", str(report)]
    )

    assert result.exit_code == 3
    assert "analysis incomplete" in result.output
    assert "Not analyzed" in result.output
    assert report.exists()
    assert "(incomplete analysis)" in report.read_text(encoding="utf-8")


def test_fail_on_threshold_takes_precedence_over_incomplete(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["analyze", "-q", "--fail-on", "0", str(_incomplete_email(tmp_path))]
    )
    assert result.exit_code == 1


@pytest.mark.parametrize(
    ("fixture", "level", "expected"),
    [
        ("crafted_malicious.eml", "critical", 1),  # scores 100
        ("crafted_malicious.eml", "CRITICAL", 1),
        ("crafted_malicious.eml", "85", 1),
        ("benign_newsletter.eml", "low", 0),  # scores 0
        ("benign_newsletter.eml", "1", 0),
        ("benign_newsletter.eml", "0", 1),
    ],
)
def test_fail_on_accepts_severity_names_and_scores(fixture: str, level: str, expected: int) -> None:
    result = runner.invoke(app, ["analyze", "-q", "--fail-on", level, str(FIXTURES / fixture)])
    assert result.exit_code == expected


@pytest.mark.parametrize("level", ["malicious", "101", "-1", "high-ish"])
def test_fail_on_rejects_unknown_levels_as_usage_errors(level: str) -> None:
    result = runner.invoke(app, ["analyze", "--fail-on", level, str(FIXTURE)])
    assert result.exit_code == 2
    assert "--fail-on" in result.output


def test_inner_triages_an_outlook_item_attached_to_a_msg(tmp_path: Path) -> None:
    import sys

    sys.path.insert(0, str(FIXTURES))
    import build_synthetic_msg as msgbuild

    inner = msgbuild.embedded_message_storage(
        subject="Reported phish", body_text="claim at https://prize.example/claim"
    )
    outer = tmp_path / "forward.msg"
    outer.write_bytes(
        msgbuild.build_message(
            subject="FW: suspicious",
            body_text="see attached",
            sender=("Reporter", "reporter@example.org"),
            embedded=[("Reported phish.msg", inner)],
        )
    )

    result = runner.invoke(app, ["analyze", "--inner", "--json", "-", str(outer)])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["subject"] == "Reported phish"
    assert payload["source"]["filename"] == "Reported phish.msg"


def test_inner_index_alone_selects_an_attached_email() -> None:
    forwarded = FIXTURES / "forwarded_eml.eml"
    outer = json.loads(runner.invoke(app, ["analyze", "--json", "-", str(forwarded)]).stdout)
    result = runner.invoke(app, ["analyze", "--inner-index", "0", "--json", "-", str(forwarded)])
    assert result.exit_code in (0, 3), result.output
    inner = json.loads(result.stdout)
    assert inner["subject"] != outer["subject"]


def test_negative_inner_index_is_a_usage_error() -> None:
    result = runner.invoke(app, ["analyze", "--inner-index", "-1", str(FIXTURE)])
    assert result.exit_code == 2


def test_unknown_connector_names_are_rejected_with_a_suggestion() -> None:
    result = runner.invoke(app, ["analyze", "--connector", "virustotl", str(FIXTURE)])
    assert result.exit_code == 2
    assert "virustotal" in result.output


def test_output_into_a_missing_directory_fails_before_analysis(tmp_path: Path) -> None:
    target = tmp_path / "no-such-dir" / "report.html"
    result = runner.invoke(app, ["analyze", "--html", str(target), str(FIXTURE)])
    assert result.exit_code == 2
    assert "VERDICT" not in result.output  # nothing was analyzed
    assert not target.exists()


def test_a_failed_write_exits_2_with_a_clear_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def full_disk(self, *_args, **_kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Path, "write_text", full_disk)
    target = tmp_path / "report.html"
    result = runner.invoke(app, ["analyze", "-q", "--html", str(target), str(FIXTURE)])
    assert result.exit_code == 2
    assert "could not write the HTML report" in result.output
    assert "No space left on device" in result.output


def test_output_cannot_overwrite_a_file_redirected_to_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import phishbowl.cli as cli

    source = tmp_path / "mail.eml"
    source.write_bytes(FIXTURE.read_bytes())
    info = source.stat()
    monkeypatch.setattr(cli, "_stdin_file_id", lambda: (info.st_dev, info.st_ino))
    result = runner.invoke(app, ["analyze", "--html", str(source), "-"], input=FIXTURE.read_bytes())
    assert result.exit_code == 2
    assert source.read_bytes() == FIXTURE.read_bytes()


def test_serve_brackets_ipv6_hosts_and_warns_off_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    uvicorn = pytest.importorskip("uvicorn")
    monkeypatch.setattr(uvicorn, "run", lambda *_args, **_kwargs: None)

    local = runner.invoke(app, ["serve", "--host", "::1"])
    assert local.exit_code == 0
    assert "http://[::1]:8000" in local.output
    assert "warning" not in local.output

    exposed = runner.invoke(app, ["serve", "--host", "0.0.0.0", "--port", "9000"])
    assert "http://0.0.0.0:9000" in exposed.output
    assert "no authentication" in exposed.output
