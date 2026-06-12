"""Tests for the Phase 4 reporting layer (PRD §10).

The load-bearing guarantees here are *security* guarantees: the HTML report must
neutralize hostile content (no executable markup, no remote loads, no raw
attacker body), the JSON must stay well-formed, redaction must actually withhold
PII while keeping attacker indicators, and the whole offline path must be fast
and key-free.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from phishbowl.cli import app
from phishbowl.extract import defang_text, extract_iocs
from phishbowl.parse import parse
from phishbowl.report import (
    RedactionPolicy,
    build_report,
    render_cli,
    render_html,
    render_json,
)
from phishbowl.score import load_config, score_email

FIXTURES = Path(__file__).parent / "fixtures"
HOSTILE = FIXTURES / "hostile_content.eml"
MALICIOUS = FIXTURES / "crafted_malicious.eml"
BENIGN = FIXTURES / "benign_newsletter.eml"

runner = CliRunner()


def _report(path: Path, *, policy: RedactionPolicy | None = None, overrides=None):
    parsed = parse(path)
    iocs = extract_iocs(parsed)
    config = load_config(overrides=overrides) if overrides else load_config()
    result = score_email(parsed, iocs, config)
    return build_report(parsed, iocs, result, policy=policy, config=config)


# --------------------------------------------------------------------------- #
# HTML report — hostile content is neutralized                                #
# --------------------------------------------------------------------------- #

# Opening tags that would execute or load remote resources. The report template
# itself contains none of these, so any occurrence could only come from injected
# email content — which must never happen.
_FORBIDDEN_TAGS = ("<script", "<iframe", "<img", "<svg", "<object", "<embed", "<link", "<base")


def test_html_contains_no_executable_or_remote_markup() -> None:
    html = render_html(_report(HOSTILE))
    low = html.lower()

    # No live tags survived from the (hostile) subject/body.
    for tag in _FORBIDDEN_TAGS:
        assert tag not in low, f"forbidden markup {tag!r} present in HTML"

    # No live scheme — every URL is defanged, and the template references nothing
    # remote, so the report performs zero network egress when opened.
    assert "http://" not in low
    assert "https://" not in low
    assert "javascript:" not in low
    assert "url(" not in low  # no CSS remote/background fetches


def test_html_escapes_hostile_subject_rather_than_injecting_it() -> None:
    html = render_html(_report(HOSTILE))
    # The attacker's <script> from the Subject is present only in escaped form.
    assert "&lt;script&gt;" in html
    assert "subject-xss" in html  # the text survives, inert, fully escaped
    assert "<script>alert('subject-xss')" not in html  # but never as live markup


def test_html_never_injects_the_raw_html_body() -> None:
    html = render_html(_report(HOSTILE))
    # Strings that live ONLY in the raw HTML body part — as event-handler
    # attribute values, which the IOC extractor never lifts out and the
    # plaintext preview never contains. Their absence proves html_raw was never
    # rendered (escaped or otherwise) into the report.
    assert "body-onload" not in html
    assert "document.cookie" not in html


def test_html_is_self_contained_document() -> None:
    html = render_html(_report(MALICIOUS))
    assert html.lstrip().startswith("<!DOCTYPE html>")
    assert "</html>" in html
    assert "<style>" in html  # inline CSS, not a remote stylesheet
    # The verdict text and a defanged indicator both make it into the document.
    assert "Malicious" in html
    assert "examp1e[.]com" in html


# --------------------------------------------------------------------------- #
# JSON report — well-formed, defanged + clearly-labelled raw                  #
# --------------------------------------------------------------------------- #


def test_json_is_well_formed_for_hostile_input() -> None:
    payload = render_json(_report(HOSTILE))
    data = json.loads(payload)  # raises if malformed
    assert data["verdict"]
    assert data["severity"] in {"benign", "low", "elevated", "high", "critical"}


def test_json_carries_both_defanged_and_clearly_labelled_raw() -> None:
    data = json.loads(render_json(_report(MALICIOUS)))
    urls = next(g for g in data["ioc_groups"] if g["type"] == "url")["items"]
    sample = urls[0]
    # Defanged display is neutered; raw is the live value, clearly separated.
    assert "value_display" in sample and "value_raw" in sample
    assert "hxxp" in sample["value_display"]
    assert sample["value_raw"].startswith("http")


def test_json_uses_natural_field_aliases() -> None:
    data = json.loads(render_json(_report(MALICIOUS)))
    assert "from" in data and "from_" not in data


# --------------------------------------------------------------------------- #
# PII redaction                                                               #
# --------------------------------------------------------------------------- #


def test_redaction_withholds_recipients_but_keeps_attacker_indicators() -> None:
    policy = RedactionPolicy.standard()
    payload = render_json(_report(MALICIOUS, policy=policy))

    # The recipient (a bystander) is gone from both the display and raw channels.
    assert "analyst@example.org" not in payload
    assert "analyst[at]example[.]org" not in payload
    assert "[redacted:recipient]" in payload

    # The attacker's domain is still fully present — redaction never blunts the
    # actual threat intel.
    assert "evil[.]example" in payload


def test_redaction_withholds_internal_hosts_via_org_domains() -> None:
    policy = RedactionPolicy.standard()
    payload = render_json(
        _report(MALICIOUS, policy=policy, overrides={"org_domains": ["example.org"]})
    )
    data = json.loads(payload)
    assert data["redaction"]["enabled"] is True
    assert "internal hosts" in data["redaction"]["categories"]
    # example.org is internal topology here → withheld; evil.example is not.
    assert "[redacted:internal-host]" in payload
    assert "evil[.]example" in payload


def test_no_redaction_by_default_keeps_full_fidelity() -> None:
    data = json.loads(render_json(_report(MALICIOUS)))
    assert data["redaction"]["enabled"] is False
    assert "[redacted" not in render_json(_report(MALICIOUS))


def test_hop_text_display_names_and_auth_detail_are_defanged() -> None:
    # Received-hop text, address display names, and auth details all quote
    # attacker-influenced header content; the view contract says every
    # free-text field is defanged, so a copy-paste from the report can never
    # hand an analyst a live URL/IP from any of them.
    from phishbowl.parse import parse_eml

    raw = (
        b"Received: from mail.evil-relay.example (mail.evil-relay.example "
        b"[203.0.113.9]) by mx.example.org with ESMTPS; "
        b"Mon, 02 Jun 2026 09:00:00 +0000\r\n"
        b'From: "http://lure.evil-relay.example/claim" <noreply@evil-relay.example>\r\n'
        b"To: analyst@example.org\r\n"
        b"Subject: synthetic defang coverage\r\n"
        b"Authentication-Results: mx.example.org; spf=fail "
        b"(sender ip is 203.0.113.9) smtp.mailfrom=evil-relay.example\r\n"
        b"\r\n"
        b"Synthetic body.\r\n"
    )
    parsed = parse_eml(raw, filename="synthetic.eml")
    iocs = extract_iocs(parsed)
    config = load_config()
    view = build_report(parsed, iocs, score_email(parsed, iocs, config), config=config)

    hop = view.routing[0]
    assert "203[.]0[.]113[.]9" in hop.raw
    assert "203.0.113.9" not in hop.raw
    # Bare hostnames in hop prose follow the same free-text policy as subjects:
    # left legible (they are not one-click linkable), only URL/email/IP tokens
    # are rewritten.
    assert hop.from_ == "mail.evil-relay.example"

    assert "hxxp://lure[.]evil-relay[.]example/claim" in (view.from_.display_name or "")
    assert "http://" not in (view.from_.display_name or "")

    spf = next(a for a in view.auth if a.mechanism == "SPF")
    assert "203[.]0[.]113[.]9" in (spf.detail or "")
    assert "203.0.113.9" not in (spf.detail or "")


# --------------------------------------------------------------------------- #
# defang_text helper                                                          #
# --------------------------------------------------------------------------- #


def test_defang_text_neuters_indicators_but_keeps_prose() -> None:
    out = defang_text("Go http://evil.example/login or mail a@evil.example from 203.0.113.5 now.")
    assert "http://" not in out
    assert "hxxp://evil[.]example/login" in out
    assert "a[at]evil[.]example" in out
    assert "203[.]0[.]113[.]5" in out
    assert "now" in out  # ordinary prose is untouched


def test_defang_text_passes_through_empty() -> None:
    assert defang_text(None) is None
    assert defang_text("") == ""


# --------------------------------------------------------------------------- #
# "Under 60s", zero keys                                                       #
# --------------------------------------------------------------------------- #


def test_full_offline_pipeline_is_fast_and_keyless(monkeypatch: pytest.MonkeyPatch) -> None:
    # Strip anything key-shaped from the environment to prove the offline path
    # needs no API keys whatsoever.
    for var in list(__import__("os").environ):
        if "KEY" in var or "TOKEN" in var or "SECRET" in var:
            monkeypatch.delenv(var, raising=False)

    start = time.monotonic()
    html = render_html(_report(MALICIOUS))
    elapsed = time.monotonic() - start

    assert elapsed < 60.0
    assert html and "</html>" in html


# --------------------------------------------------------------------------- #
# CLI integration                                                              #
# --------------------------------------------------------------------------- #


def test_cli_analyze_prints_verdict_and_defangs_addresses() -> None:
    result = runner.invoke(app, ["analyze", str(MALICIOUS)])
    assert result.exit_code == 0
    assert "Malicious" in result.stdout
    # Indicators are shown defanged, never as live addresses.
    assert "security[at]account-secure[.]example" in result.stdout
    assert "security@account-secure.example" not in result.stdout


def test_cli_analyze_writes_html_and_json(tmp_path: Path) -> None:
    html_path = tmp_path / "report.html"
    json_path = tmp_path / "report.json"
    result = runner.invoke(
        app, ["analyze", str(MALICIOUS), "--html", str(html_path), "--json", str(json_path)]
    )
    assert result.exit_code == 0
    assert html_path.exists() and "</html>" in html_path.read_text()
    json.loads(json_path.read_text())  # well-formed
    low = html_path.read_text().lower()
    assert "<script" not in low and "http://" not in low


def test_cli_redact_flag_withholds_recipients(tmp_path: Path) -> None:
    json_path = tmp_path / "r.json"
    result = runner.invoke(app, ["analyze", str(MALICIOUS), "--redact", "--json", str(json_path)])
    assert result.exit_code == 0
    payload = json_path.read_text()
    assert "analyst@example.org" not in payload
    assert "[redacted:recipient]" in payload


def test_cli_strips_terminal_control_chars_from_subject(tmp_path: Path) -> None:
    evil = tmp_path / "evil.eml"
    evil.write_bytes(b"From: a@example.com\r\nSubject: clear\x1b[2Jscreen\x07bell\r\n\r\nbody\r\n")
    result = runner.invoke(app, ["analyze", str(evil)])
    assert result.exit_code == 0
    assert "\x1b" not in result.stdout
    assert "\x07" not in result.stdout
    assert "clear[2Jscreenbell" in result.stdout


def test_cli_rejects_unsupported_suffix(tmp_path: Path) -> None:
    bogus = tmp_path / "notes.txt"
    bogus.write_text("not an email")
    assert runner.invoke(app, ["analyze", str(bogus)]).exit_code != 0


def test_cli_missing_file_errors_cleanly() -> None:
    assert runner.invoke(app, ["analyze", "/does/not/exist.eml"]).exit_code != 0


def test_render_cli_handles_benign_without_error() -> None:
    from io import StringIO

    from rich.console import Console

    buf = StringIO()
    render_cli(_report(BENIGN), Console(file=buf, width=100, highlight=False))
    out = buf.getvalue()
    assert "VERDICT" in out
