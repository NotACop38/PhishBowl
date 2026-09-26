"""Tests for the Phase 4 reporting layer (PRD §10).

The load-bearing guarantees here are *security* guarantees: the HTML report must
neutralize hostile content (no executable markup, no remote loads, no raw
attacker body), the JSON must stay well-formed, redaction must actually withhold
PII while keeping attacker indicators, and the whole offline path must be fast
and key-free.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote

import pytest
from rich.console import Console
from typer.testing import CliRunner

from phishbowl.cli import app
from phishbowl.export import render_sentinel, render_xsoar
from phishbowl.extract import defang_text, extract_iocs
from phishbowl.parse import parse, parse_eml
from phishbowl.pipeline import triage
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
    assert "Very high suspicion" in html
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


def _every_output(view) -> list[str]:
    """The report in every format an analyst can share."""
    terminal = io.StringIO()
    render_cli(view, Console(file=terminal, width=160))
    return [
        render_json(view),
        render_html(view),
        render_xsoar(view),
        render_sentinel(view),
        terminal.getvalue(),
    ]


def test_redaction_covers_delivery_headers_and_received_for_clauses() -> None:
    raw = (
        b"Received: from mx.evil.example by mx.victim-org.example with ESMTP\r\n"
        b" for <rcvd-7731@victim-org.example>; Wed, 03 Jun 2026 02:05:09 +0000\r\n"
        b"Delivered-To: dlvr-7731@victim-org.example\r\n"
        b"X-Original-To: orig-7731@victim-org.example\r\n"
        b"Bcc: Quinn Blindcopy <bcc-7731@victim-org.example>\r\n"
        b"From: attacker@evil.example\r\n"
        b"To: undisclosed-recipients:;\r\n"
        b"Subject: Invoice\r\n\r\n"
        b"For dlvr-7731@victim-org.example: https://evil.example/login\r\n"
    )
    view, _ = triage(parse_eml(raw), policy=RedactionPolicy.standard())
    for output in _every_output(view):
        for secret in ("7731", "Quinn Blindcopy", "victim-org"):
            assert secret not in output
        assert "evil[.]example" in output


def test_redaction_matches_whole_tokens_only() -> None:
    raw = (
        b"From: attacker@evil.example\r\n"
        b"To: IT <it@victim-org.example>, Sam Lee <sam@victim-org.example>\r\n"
        b"Subject: Submit your Sample\r\n\r\n"
        b"Dear Sam Lee, submit the IT sample: Samuel, Sample, submitted.\r\n"
    )
    view, _ = triage(parse_eml(raw), policy=RedactionPolicy.standard())
    assert view.subject == "Submit your Sample"
    assert "Sam Lee" not in (view.body_preview or "")
    # A two-letter display name is too generic to redact, and a name never
    # matches inside a longer word.
    assert "submit the IT sample: Samuel, Sample, submitted." in (view.body_preview or "")


def test_redaction_keeps_shared_freemail_domains_visible() -> None:
    raw = (
        b"From: Payroll <payroll.dept@gmail.com>\r\n"
        b"To: victim.person@gmail.com\r\n"
        b"Subject: Update\r\n\r\n"
        b"Reply to payroll.dept@gmail.com today.\r\n"
    )
    view, _ = triage(parse_eml(raw), policy=RedactionPolicy.standard())
    payload = render_json(view)
    assert "victim.person" not in payload and "victim[.]person" not in payload
    # gmail.com identifies no one, so the attacker's freemail address stays.
    assert view.from_ is not None and view.from_.addr_spec_raw == "payroll.dept@gmail.com"
    assert "payroll[.]dept[at]gmail[.]com" in payload


def test_unrelated_percent_encoding_does_not_withhold_the_body() -> None:
    raw = (
        b"From: attacker@evil.example\r\n"
        b"To: Victim Person <victim@victim-org.example>\r\n"
        b"Subject: Update\r\n\r\n"
        b"Hi Victim Person, open https://evil.example/a%20b now.\r\n"
    )
    view, _ = triage(parse_eml(raw), policy=RedactionPolicy.standard())
    preview = view.body_preview or ""
    assert "Victim Person" not in preview
    # Redacted in place: the rest of the body is still readable.
    assert preview.startswith("Hi [redacted:recipient], open")
    assert "evil[.]example" in preview


def test_percent_encoded_recipient_withholds_the_whole_value() -> None:
    target = "https://evil.example/login?u=" + quote("victim@victim-org.example", safe="")
    raw = (
        b"From: attacker@evil.example\r\n"
        b"To: victim@victim-org.example\r\n"
        b"Subject: Update\r\n\r\n" + quote(target, safe=":/").encode() + b"\r\n"
    )
    view, _ = triage(parse_eml(raw), policy=RedactionPolicy.standard())
    for output in _every_output(view):
        assert "victim" not in output


def test_ipv6_redaction_stays_linear_on_hostile_text() -> None:
    # A subprocess timeout turns a backtracking regression into a failure
    # instead of a hung test run.
    subprocess.run(
        [
            sys.executable,
            "-c",
            """
from phishbowl.parse import parse_eml
from phishbowl.report import RedactionPolicy
from phishbowl.report.redact import Redactor
from phishbowl.score import load_config

redactor = Redactor(
    RedactionPolicy.standard(),
    parse_eml(b"From: a@b.example\\r\\nTo: v@victim.example\\r\\n\\r\\nx"),
    load_config(overrides={"org_domains": ["corp.example"]}),
)
for text in ("1:" * 100_000, ":" * 200_000 + "g", "a." * 100_000, "a@" * 100_000):
    redactor.text(text)
""",
        ],
        check=True,
        timeout=10,
    )


def test_hidden_auth_and_received_headers_hide_what_is_parsed_from_them() -> None:
    raw = (
        b"Authentication-Results: mx.victim-org.example; spf=fail "
        b"smtp.mailfrom=relay-5521.example; dkim=none; dmarc=fail header.from=evil.example\r\n"
        b"Received: from relay-5521.example (relay-5521.example [203.0.113.9])\r\n"
        b" by mx.victim-org.example; Wed, 03 Jun 2026 02:05:09 +0000\r\n"
        b"From: attacker@evil.example\r\n"
        b"To: victim@victim-org.example\r\n"
        b"Subject: Update\r\n\r\nhello\r\n"
    )
    policy = RedactionPolicy.standard(("Authentication-Results", "Received"))
    view, result = triage(parse_eml(raw), policy=policy)
    assert any(rule.id.startswith("auth.") for rule in result.fired)
    assert all(line.result == "redacted" and line.detail is None for line in view.auth)
    for rule in view.fired_rules:
        if rule.id.startswith("auth."):
            assert rule.evidence == ["[redacted:field]"]
    assert [hop.raw for hop in view.routing] == ["[redacted:field]"]
    assert view.sending_ip_display is None and view.sending_ip_raw is None
    for output in _every_output(view):
        for secret in ("relay-5521", "203.0.113.9", "203[.]0[.]113[.]9"):
            assert secret not in output


def test_operator_field_redaction_uses_each_address_headers_own_name() -> None:
    raw = (
        b"From: attacker@evil.example\r\n"
        b"To: visible@first.example\r\n"
        b"Cc: Copied Person <copied@second.example>\r\n"
        b"Subject: Update\r\n\r\nhello\r\n"
    )
    policy = RedactionPolicy(enabled=True, recipients=False, internal=False, extra_fields=("Cc",))
    view, _ = triage(parse_eml(raw), policy=policy)
    assert view.to[0].addr_spec_raw == "visible@first.example"
    assert view.cc[0].redacted and view.cc[0].addr_spec_display == "[redacted:field]"
    payload = render_json(view)
    assert "Copied Person" not in payload and "second" not in payload


def test_attachment_types_are_control_stripped_in_every_renderer() -> None:
    raw = (
        b"From: attacker@evil.example\r\n"
        b"Content-Type: multipart/mixed; boundary=b\r\n\r\n"
        b"--b\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n"
        b"--b\r\nContent-Type: application/x-\x1b[31mevil\r\n"
        b"Content-Disposition: attachment; filename=report.bin\r\n\r\ndata\r\n--b--\r\n"
    )
    view, _ = triage(parse_eml(raw))
    assert view.attachments and "\x1b" not in (view.attachments[0].declared_type or "")
    for output in _every_output(view):
        assert "\x1b" not in output


def test_redacted_wrapped_link_keeps_wrapper_metadata_but_no_raw_value() -> None:
    target = "https://evil.example/login?u=victim.person@victim-org.example"
    wrapped = (
        "https://nam02.safelinks.protection.outlook.com/?url="
        + quote(target, safe="")
        + "&data=05%7C01"
    )
    raw = (
        b"From: attacker@evil.example\r\n"
        b"To: victim.person@victim-org.example\r\n"
        b"Subject: Update\r\n\r\n" + wrapped.encode() + b"\r\n"
    )
    view, _ = triage(parse_eml(raw), policy=RedactionPolicy.standard())
    wrapped_items = [i for g in view.ioc_groups for i in g.items if i.wrapper]
    assert wrapped_items
    for item in wrapped_items:
        assert item.wrapper == "safelinks"
        assert item.redacted and item.value_raw is None and item.wrapped_display is None
    for output in _every_output(view):
        assert "victim.person" not in output and "victim[.]person" not in output


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
    # The parsed from/by fields are host indicators and are defanged like the
    # IOC tables; bare hostnames in the raw hop prose follow the free-text
    # policy (left legible — not one-click linkable — while URL/email/IP tokens
    # are rewritten).
    assert hop.from_ == "mail[.]evil-relay[.]example"
    assert hop.by == "mx[.]example[.]org"
    assert "from mail.evil-relay.example" in hop.raw

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
    assert "Very high suspicion" in result.stdout
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


# --------------------------------------------------------------------------- #
# Quality-review regressions                                                  #
# --------------------------------------------------------------------------- #


def test_html_routing_shows_each_hops_from_by_and_with() -> None:
    # The hop view model aliases from_/with_; the template must read the
    # attribute names, or only "by" would ever render.
    html = render_html(_report(FIXTURES / "auth_fail_spoofed.eml"))
    line = html[html.index('<div class="ln">') : html.index('<div class="raw">')]
    assert "from <b>unknown</b>" in line
    assert "by <b>mx[.]example[.]org</b>" in line
    assert "with ESMTP" in line


def test_lowest_severity_is_minimal_not_benign() -> None:
    from phishbowl.report import severity_for

    view = _report(BENIGN)
    assert view.score == 0
    assert view.severity == "minimal"
    assert [severity_for(s) for s in (0, 19, 20, 39, 40, 64, 65, 84, 85, 100)] == [
        "minimal",
        "minimal",
        "low",
        "low",
        "elevated",
        "elevated",
        "high",
        "high",
        "critical",
        "critical",
    ]


def test_incomplete_analysis_is_flagged_in_every_renderer(tmp_path: Path) -> None:
    import io

    from rich.console import Console

    from phishbowl.parse import parse_eml
    from phishbowl.pipeline import triage

    parsed = parse_eml(
        b"From: sender@example.com\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n"
        b"--x\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
    )
    view, _ = triage(parsed)

    html = render_html(view)
    assert '<span class="tag">Incomplete</span>' in html
    assert "not analyzed" in html
    data = json.loads(render_json(view))
    assert data["analysis_complete"] is False
    assert data["verdict"].endswith("(incomplete analysis)")
    assert data["anomalies"][0]["coverage_gap"] is True
    console = io.StringIO()
    render_cli(view, Console(file=console, width=160))
    assert "Not analyzed: CloseBoundaryNotFoundDefect" in console.getvalue()


def test_report_tool_version_matches_the_package() -> None:
    from phishbowl import __version__

    assert _report(BENIGN).tool == f"phishbowl/{__version__}"
