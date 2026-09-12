"""Tests for analyst-workflow improvements: scoring fixes, --inner, CLI ergonomics."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from phishbowl.cli import app
from phishbowl.extract import extract_iocs
from phishbowl.models import Attachment, AttachmentFlag, IOCs
from phishbowl.parse import list_embedded_emails, parse, parse_eml
from phishbowl.pipeline import triage
from phishbowl.report import build_report
from phishbowl.score import score_email

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


def test_urgency_keywords_fire_on_html_only_body() -> None:
    raw = (
        b"From: a@example.com\r\n"
        b"To: b@example.com\r\n"
        b"Subject: account notice\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: text/html; charset="utf-8"\r\n'
        b"\r\n"
        b"<html><body><p>Your account has been locked - verify now.</p></body></html>\r\n"
    )
    parsed = parse_eml(raw, filename="html_only.eml")
    assert parsed.body.text is None
    assert parsed.body.has_html
    fired = {f.id for f in score_email(parsed, extract_iocs(parsed)).fired}
    assert "content.urgency_keywords" in fired


def test_archive_attachment_rule_fires() -> None:
    from phishbowl.models import Address, Addresses, EmailFormat, ParsedEmail, Source

    parsed = ParsedEmail(
        source=Source(format=EmailFormat.EML, parser_version="test"),
        addresses=Addresses(from_=Address(addr_spec="a@example.com", domain="example.com")),
        attachments=[
            Attachment(filename="invoice.zip", flags=[AttachmentFlag.ARCHIVE]),
        ],
    )
    fired = {f.id for f in score_email(parsed, IOCs()).fired}
    assert "attach.archive" in fired


def test_list_embedded_emails_finds_rfc822_attachment() -> None:
    data = (FIXTURES / "forwarded_eml.eml").read_bytes()
    found = list_embedded_emails(data)
    assert len(found) == 1
    assert found[0].filename == "reported.eml"
    assert b"You have won a prize" in found[0].data


def test_analyze_inner_triages_attached_email() -> None:
    result = runner.invoke(app, ["analyze", "--inner", str(FIXTURES / "forwarded_eml.eml")])
    assert result.exit_code == 0
    # Inner subject, not the outer "Fwd: reported message for triage".
    assert "You have won a prize" in result.stdout
    assert "Fwd: reported message" not in result.stdout


def test_analyze_without_inner_notes_attached_email() -> None:
    result = runner.invoke(app, ["analyze", str(FIXTURES / "forwarded_eml.eml")])
    assert result.exit_code == 0
    assert "attached email" in result.stdout.casefold()
    assert "--inner" in result.stdout


def test_analyze_inner_without_attachment_is_clean_error() -> None:
    result = runner.invoke(app, ["analyze", "--inner", str(FIXTURES / "benign_newsletter.eml")])
    assert result.exit_code != 0
    assert "attached email" in result.output.casefold() or "no attached" in result.output.casefold()


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "phishbowl" in result.stdout.casefold()


def test_json_stdout_and_quiet() -> None:
    result = runner.invoke(
        app,
        ["analyze", "-q", "--json", "-", str(FIXTURES / "benign_newsletter.eml")],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "verdict" in payload
    assert "score" in payload
    assert "VERDICT" not in result.stdout  # quiet / json-stdout suppresses Rich banner


def test_fail_on_exits_nonzero_for_malicious() -> None:
    result = runner.invoke(
        app,
        ["analyze", "-q", "--fail-on", "suspicious", str(FIXTURES / "crafted_malicious.eml")],
    )
    assert result.exit_code == 1


def test_fail_on_passes_for_benign() -> None:
    result = runner.invoke(
        app,
        ["analyze", "-q", "--fail-on", "suspicious", str(FIXTURES / "benign_newsletter.eml")],
    )
    assert result.exit_code == 0


def test_scoring_config_cli_flag(tmp_path: Path) -> None:
    cfg = tmp_path / "weights.yaml"
    cfg.write_text("weights:\n  content.urgency_keywords: 0\n", encoding="utf-8")
    # auth_fail_spoofed fires urgency; zeroing it must change the score path.
    baseline = runner.invoke(
        app, ["analyze", "-q", "--json", "-", str(FIXTURES / "auth_fail_spoofed.eml")]
    )
    overridden = runner.invoke(
        app,
        [
            "analyze",
            "-q",
            "--json",
            "-",
            "--scoring-config",
            str(cfg),
            str(FIXTURES / "auth_fail_spoofed.eml"),
        ],
    )
    assert baseline.exit_code == 0 and overridden.exit_code == 0
    base_score = json.loads(baseline.stdout)["score"]
    over_score = json.loads(overridden.stdout)["score"]
    assert over_score == base_score - 4


def test_report_includes_headers_and_sending_ip() -> None:
    parsed = parse(FIXTURES / "auth_fail_spoofed.eml")
    view, _ = triage(parsed)
    assert view.headers, "full header set should be projected into the report"
    assert any(h.name.casefold() == "received" for h in view.headers)
    html = __import__("phishbowl.report", fromlist=["render_html"]).render_html(view)
    assert "@media print" in html
    assert "Show ordered raw headers" in html

    # Documentation TEST-NET IPs are treated as non-public by ipaddress, so craft
    # a hop with a genuinely public IP to exercise the sending-IP highlight.
    raw = (
        b"Received: from mail.example.net (mail.example.net [8.8.8.8]) "
        b"by mx.example.org; Wed, 03 Jun 2026 02:05:09 +0000\r\n"
        b"From: a@example.com\r\nTo: b@example.com\r\nSubject: sip\r\n\r\nbody\r\n"
    )
    sip_view, _ = triage(parse_eml(raw, filename="sip.eml"))
    assert sip_view.sending_ip_raw == "8.8.8.8"
    assert sip_view.sending_ip_display == "8[.]8[.]8[.]8"
    assert "Received-header IP candidate" in __import__(
        "phishbowl.report", fromlist=["render_html"]
    ).render_html(sip_view)


def test_html_only_body_gets_visible_text_preview() -> None:
    raw = (
        b"From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n"
        b'MIME-Version: 1.0\r\nContent-Type: text/html; charset="utf-8"\r\n\r\n'
        b"<html><body><p>Visible preview text for analysts.</p></body></html>\r\n"
    )
    parsed = parse_eml(raw, filename="html.eml")
    view = build_report(parsed, extract_iocs(parsed), score_email(parsed, extract_iocs(parsed)))
    assert view.body_preview is not None
    assert "Visible preview text" in view.body_preview
    assert "never rendered" in (view.body_note or "").casefold()
