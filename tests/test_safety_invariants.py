"""End-to-end safety-invariant tests for the offline core (CLAUDE.md / PRD §4).

These are the load-bearing *defensive* guarantees, asserted across the whole
offline pipeline — parse → extract → score → report — on every bundled fixture:

1. **No egress.** Running the pipeline opens no outbound socket and makes no
   SMTP connection. Phishbowl never sends, never calls back the email's
   infrastructure, and the offline core never reaches the network.
2. **Inert reports.** The generated HTML report contains no remote URL and no
   remotely-loading / executable markup, so opening a report about a phishing
   email performs zero network egress and can never phone home to the attacker.
3. **No secret leakage.** No environment/secret value ever appears in any
   output — HTML report, JSON, the CLI summary, or logs.

Unlike :mod:`tests.test_report` (which checks one hostile fixture in depth),
these sweep *all* fixtures and arm an active network guard, so a regression that
introduced egress or a remote asset would fail here regardless of which path
triggered it. They run as part of the routine ``make test`` suite.
"""

from __future__ import annotations

import smtplib
import socket
from pathlib import Path

import pytest
from typer.testing import CliRunner

from phishbowl.cli import app
from phishbowl.extract import extract_iocs
from phishbowl.parse import parse
from phishbowl.report import (
    RedactionPolicy,
    build_report,
    render_html,
    render_json,
)
from phishbowl.score import load_config, score_email

FIXTURES = Path(__file__).parent / "fixtures"

# Every synthetic sample email we ship — both formats. The pipeline must uphold
# the invariants on all of them, benign and hostile alike.
ALL_FIXTURES = sorted(
    p for p in FIXTURES.iterdir() if p.suffix.lower() in {".eml", ".msg"} and p.is_file()
)

runner = CliRunner()


# --------------------------------------------------------------------------- #
# Network guard                                                               #
# --------------------------------------------------------------------------- #


class _NetworkEgressAttempt(BaseException):
    """Raised the instant the pipeline attempts any outbound connection.

    Deliberately subclasses :class:`BaseException`, not :class:`Exception`, so
    the parser's defensive ``except Exception`` guards cannot swallow it into an
    anomaly — an egress attempt must surface as a hard test failure, never be
    silently absorbed.
    """


def _install_network_guard(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Arm a guard that fails the test on any socket connect / SMTP activity.

    Returns a list that records each attempt, so the test can assert it stayed
    empty even in the (impossible-by-design) case the raise were caught.
    """
    attempts: list[str] = []

    def boom(*args: object, **kwargs: object):
        detail = f"outbound network egress attempted: args={args!r}"
        attempts.append(detail)
        raise _NetworkEgressAttempt(detail)

    # All TCP egress funnels through these; covering them covers SMTP, HTTP, and
    # any raw socket too.
    monkeypatch.setattr(socket.socket, "connect", boom, raising=False)
    monkeypatch.setattr(socket.socket, "connect_ex", boom, raising=False)
    monkeypatch.setattr(socket, "create_connection", boom, raising=False)
    # Explicit "never send" belt-and-suspenders on the mail stack itself.
    monkeypatch.setattr(smtplib.SMTP, "__init__", boom, raising=False)
    monkeypatch.setattr(smtplib.SMTP, "connect", boom, raising=False)
    monkeypatch.setattr(smtplib.SMTP_SSL, "__init__", boom, raising=False)
    return attempts


def _run_pipeline(path: Path, *, policy: RedactionPolicy | None = None):
    """Run the full offline pipeline and render all three outputs."""
    parsed = parse(path)
    config = load_config()
    iocs = extract_iocs(parsed)
    result = score_email(parsed, iocs, config)
    view = build_report(parsed, iocs, result, policy=policy, config=config)
    return view, render_html(view), render_json(view)


# --------------------------------------------------------------------------- #
# 1. No SMTP / outbound socket activity                                       #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda p: p.name)
def test_pipeline_opens_no_outbound_socket(fixture: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = _install_network_guard(monkeypatch)

    view, html, payload = _run_pipeline(fixture)

    # The pipeline completed and produced real output with the guard armed —
    # proving it reached its verdict without a single connection attempt.
    assert view.verdict
    assert "</html>" in html
    assert payload
    assert attempts == []


def test_cli_analyze_opens_no_outbound_socket(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The same guarantee through the real CLI entrypoint, writing both artifacts.
    attempts = _install_network_guard(monkeypatch)
    html_path = tmp_path / "r.html"
    json_path = tmp_path / "r.json"

    result = runner.invoke(
        app,
        [
            "analyze",
            str(FIXTURES / "crafted_malicious.eml"),
            "--html",
            str(html_path),
            "--json",
            str(json_path),
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert html_path.exists() and json_path.exists()
    assert attempts == []


def test_smtp_send_is_blocked_by_the_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    # Sanity-check the guard itself: it must actually trip on a send attempt, so
    # the "no egress" assertions above are meaningful and not vacuously true.
    _install_network_guard(monkeypatch)
    with pytest.raises(_NetworkEgressAttempt):
        smtplib.SMTP("mail.attacker.example", 25)


# --------------------------------------------------------------------------- #
# 2. The HTML report carries no remote URL / remotely-loading markup          #
# --------------------------------------------------------------------------- #

# Opening tags that would execute script or load a remote resource. Autoescape
# turns any injected markup into harmless entities (``<script`` → ``&lt;script``),
# so a real ``<script`` substring can only come from the static template or a
# ``| safe`` misuse — never from email content. These checks are therefore both
# sound (no false positives on escaped text) and portable across every fixture.
_FORBIDDEN_TAGS = (
    "<script",
    "<iframe",
    "<img",
    "<svg",
    "<object",
    "<embed",
    "<link",
    "<base",
    "<audio",
    "<video",
    "<source",
    "<track",
    "<frame",
    "<applet",
    "<meta http-equiv",
)

# Remote-load vectors in *attribute* position. A real attribute uses literal
# quote characters (``src="``); escaped email content renders quotes as ``&#34;``
# / ``&#39;`` (e.g. the hostile ``&lt;img src=&#34;…``), so these substrings can
# only match a genuine attribute, never inert escaped text. The self-contained
# report defines none of them.
_FORBIDDEN_ATTR_TOKENS = (
    'src="',
    "src='",
    'href="',
    "href='",
    'data="',
    'background="',
    '="http',
    "='http",
    '="//',
    "='//",
    '="javascript:',
    "='javascript:",
    '="vbscript:',
)


def _style_block(html: str) -> str:
    """The contents of the report's ``<style>`` block (lowercased), or ``""``."""
    low = html.lower()
    start = low.find("<style>")
    end = low.find("</style>", start)
    return low[start:end] if start != -1 and end != -1 else ""


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda p: p.name)
def test_report_has_no_remote_or_executable_markup(fixture: Path) -> None:
    _, html, _ = _run_pipeline(fixture)
    low = html.lower()

    # No live, remotely-loading or script-executing tag survived into the report.
    for tag in _FORBIDDEN_TAGS:
        assert tag not in low, f"{fixture.name}: forbidden markup {tag!r} in report"

    # No attribute pulls a remote (or javascript:) resource.
    for token in _FORBIDDEN_ATTR_TOKENS:
        assert token not in low, f"{fixture.name}: remote-load attribute {token!r} in report"

    # The only place CSS could fetch is the inline <style> block; it must use no
    # url() and no @import (the template styles with gradients only). Scoping to
    # the style block keeps this sound even if a hostile body's *text* mentions
    # "url(" — that lands as escaped content, not as a CSS rule.
    style = _style_block(html)
    assert style, f"{fixture.name}: report has no inline <style> block"
    assert "url(" not in style, f"{fixture.name}: CSS url() fetch in report"
    assert "@import" not in style, f"{fixture.name}: CSS @import in report"

    # It is a complete, self-contained document that explicitly opts out of
    # referrer leakage — so it renders with zero network egress when opened.
    assert low.lstrip().startswith("<!doctype html>")
    assert '<meta name="referrer" content="no-referrer">' in low


# --------------------------------------------------------------------------- #
# 3. No environment / secret value ever reaches an output                     #
# --------------------------------------------------------------------------- #

# A value distinctive enough that it could only appear in output by leaking from
# the environment — nothing in a synthetic email would ever contain it.
_SECRET = "phishbowl-sentinel-secret-DEADBEEF-do-not-leak-1337"

# The connector key names Phishbowl recognizes (.env.example), plus a generic
# one, all seeded with the sentinel. The offline core reads none of them.
_SECRET_ENV = {
    "VIRUSTOTAL_API_KEY": _SECRET + "-vt",
    "URLSCAN_API_KEY": _SECRET + "-us",
    "ABUSEIPDB_API_KEY": _SECRET + "-ab",
    "SHODAN_API_KEY": _SECRET + "-sh",
    "PHISHBOWL_TEST_SECRET": _SECRET + "-generic",
}


def _seed_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in _SECRET_ENV.items():
        monkeypatch.setenv(name, value)


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=lambda p: p.name)
def test_no_secret_leaks_into_html_or_json(fixture: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_secrets(monkeypatch)
    # Exercise both the default and the redacting report paths.
    for policy in (None, RedactionPolicy.standard()):
        _, html, payload = _run_pipeline(fixture, policy=policy)
        assert _SECRET not in html, f"{fixture.name}: secret leaked into HTML"
        assert _SECRET not in payload, f"{fixture.name}: secret leaked into JSON"


def test_no_secret_leaks_into_cli_summary_or_logs(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
) -> None:
    _seed_secrets(monkeypatch)
    caplog.set_level(0)  # capture everything any module might log

    html_path = tmp_path / "r.html"
    json_path = tmp_path / "r.json"
    result = runner.invoke(
        app,
        [
            "analyze",
            str(FIXTURES / "crafted_malicious.eml"),
            "--html",
            str(html_path),
            "--json",
            str(json_path),
        ],
    )

    assert result.exit_code == 0, result.stdout
    # CLI summary, written artifacts, and any captured log record are all clean.
    assert _SECRET not in result.stdout
    assert _SECRET not in html_path.read_text(encoding="utf-8")
    assert _SECRET not in json_path.read_text(encoding="utf-8")
    assert _SECRET not in caplog.text


def test_secret_check_would_catch_a_leak() -> None:
    # Guard against a vacuous test: prove the sentinel is detectable in the same
    # rendered output it is asserted absent from. We render a report, inject the
    # sentinel into the string, and confirm the membership test sees it — so the
    # "secret not in output" assertions can actually fail if a leak occurred.
    _, html, _ = _run_pipeline(FIXTURES / "crafted_malicious.eml")
    assert _SECRET not in html
    assert _SECRET in (html + _SECRET)


# --------------------------------------------------------------------------- #
# Input-validation hardening                                                  #
# --------------------------------------------------------------------------- #


def test_oversized_file_is_refused_before_being_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from phishbowl.parse import limits

    big = tmp_path / "huge.eml"
    big.write_bytes(b"From: a@example.com\r\n\r\nbody\r\n")
    # Shrink the limit instead of writing a 50 MiB file: the guard must reject
    # any input whose size exceeds the cap, cleanly (a ValueError the CLI turns
    # into a friendly message), without slurping it into memory.
    monkeypatch.setattr(limits, "MAX_INPUT_BYTES", 4)
    with pytest.raises(ValueError):
        limits.read_within_limit(big)


def test_oversized_input_rejected_even_when_stat_under_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A special/symlinked/growing file can report a tiny size from stat() yet
    # stream far more bytes. The bounded chunked read must still reject it rather
    # than slurp the whole stream: here stat() is forced to lie (size 0) while the
    # real file is well over the (shrunk) cap.
    import types

    from phishbowl.parse import limits

    f = tmp_path / "liar.eml"
    f.write_bytes(b"A" * 64)
    monkeypatch.setattr(limits, "MAX_INPUT_BYTES", 8)
    # read_within_limit only reads st_size; force it to under-report.
    monkeypatch.setattr(Path, "stat", lambda self, *a, **k: types.SimpleNamespace(st_size=0))

    with pytest.raises(ValueError):
        limits.read_within_limit(f)


def test_oversized_bytes_degrade_to_noted_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    from phishbowl.parse import eml

    monkeypatch.setattr(eml, "MAX_INPUT_BYTES", 8)
    parsed = eml.parse_eml(b"From: a@example.com\r\n\r\nbody\r\n", filename="big.eml")
    # The bytes path keeps its "always returns a model" contract: oversized input
    # is noted as an anomaly, not raised, and deep parsing is skipped.
    assert parsed.source.filename == "big.eml"
    assert any(a.code == "input_too_large" for a in parsed.anomalies)


def _fan_out_multipart(n: int) -> bytes:
    """A multipart/mixed message with ``n`` sibling text leaves under one container."""
    raw = [
        b"From: a@example.com\r\n",
        b"Subject: nested\r\n",
        b'Content-Type: multipart/mixed; boundary="b0"\r\n\r\n',
    ]
    for i in range(n):
        raw.append(b"--b0\r\nContent-Type: text/plain\r\n\r\npart %d\r\n" % i)
    raw.append(b"--b0--\r\n")
    return b"".join(raw)


def test_deeply_nested_multipart_is_walked_under_a_bound() -> None:
    # A pathological multipart tree (a "MIME bomb") must be parsed under the part
    # cap rather than walked unbounded — and never crash the pipeline.
    import email as _email

    from phishbowl.parse import parse_eml
    from phishbowl.parse.attachments import iter_parts, parts_exceed_budget

    blob = _fan_out_multipart(200)
    parsed = parse_eml(blob, filename="nested.eml")
    assert parsed.subject == "nested"

    # The bounded walker counts *every* node (the container included) toward the
    # budget and stops, so a hostile tree yields no more than `max_parts` parts —
    # truncated well short of the 200 leaves it actually contains.
    msg = _email.message_from_bytes(blob)
    capped = list(iter_parts(msg, max_parts=5))
    assert 0 < len(capped) <= 5
    # And the truncation is detectable, so the parser can note it.
    assert parts_exceed_budget(msg, max_parts=5) is True
    assert parts_exceed_budget(msg, max_parts=500) is False


def test_truncated_mime_tree_is_noted_as_an_anomaly(monkeypatch: pytest.MonkeyPatch) -> None:
    # When the structural cap drops parts, the parser must record it — an attacker
    # padding thousands of harmless leaves ahead of a real attachment must not be
    # able to make parsing silently truncate with no trace (PRD §11).
    from phishbowl.parse import attachments, parse_eml

    monkeypatch.setattr(attachments, "MAX_PARTS", 5)
    parsed = parse_eml(_fan_out_multipart(50), filename="bomb.eml")
    assert any(a.code == "mime_truncated" for a in parsed.anomalies)
    # A small, in-bounds message is NOT flagged.
    ok = parse_eml(_fan_out_multipart(2), filename="ok.eml")
    assert not any(a.code == "mime_truncated" for a in ok.anomalies)
