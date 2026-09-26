"""Synthetic regressions for the critical project review. No live services."""

import asyncio
import base64
import io
import json
import tempfile
from urllib.parse import quote

import httpx
import pytest
from fastapi.testclient import TestClient
from rich.console import Console

from phishbowl.connectors.targets import build_targets
from phishbowl.domains import registrable_domain
from phishbowl.export import render_sentinel, render_xsoar
from phishbowl.extract import extract_iocs
from phishbowl.parse import parse_eml, parse_msg
from phishbowl.pipeline import triage
from phishbowl.report import RedactionPolicy, render_cli, render_html, render_json
from phishbowl.score import load_config


def email(body, *, subject="Review", html=True):
    return parse_eml(
        (
            f"From: sender@example.com\r\nTo: Alice Example <alice@example.org>\r\n"
            f"Subject: {subject}\r\nContent-Type: text/{'html' if html else 'plain'}\r\n\r\n" + body
        ).encode()
    )


def test_malformed_and_unquoted_links_keep_all_evidence():
    view, result = triage(
        email(
            '<a href="http://[">Review</a>'
            "<a href=https://credential.example/verify>https://example.com</a>"
        )
    )
    values = {i.value_raw for g in view.ioc_groups for i in g.items}
    assert "https://credential.example/verify" in values
    assert "http://[" in values
    assert any(r.id == "url.anchor_href_mismatch" for r in result.fired)


def test_mime_factory_refuses_before_allocating_all_parts(monkeypatch):
    from phishbowl.parse import limits, mime

    monkeypatch.setattr(limits, "MAX_PARTS", 8)
    made = 0
    original = mime.Message

    def counted(*args, **kwargs):
        nonlocal made
        made += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(mime, "Message", counted)
    raw = (
        b"From: sender@example.com\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n"
        + b"--x\r\nContent-Type: text/plain\r\n\r\nhello\r\n" * 30
        + b"--x--\r\n"
    )
    view, result = triage(parse_eml(raw))
    assert made <= 8
    assert not result.analysis_complete
    assert view.verdict.endswith("(incomplete analysis)")


def test_secondary_body_parts_are_analyzed():
    raw = (
        b"From: sender@example.com\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n"
        b"--x\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
        b"--x\r\nContent-Type: text/plain\r\n\r\nhttps://credential.example/login\r\n--x--\r\n"
    )
    assert any(i.value == "https://credential.example/login" for i in extract_iocs(parse_eml(raw)))


def test_failed_and_truncated_analysis_never_claims_safety():
    for parsed in (parse_msg(b"not OLE"), email("<" * 300_000)):
        view, result = triage(parsed)
        assert not result.analysis_complete
        assert view.verdict.endswith("(incomplete analysis)")
        assert any(a.coverage_gap for a in view.anomalies)
        output = io.StringIO()
        render_cli(view, Console(file=output))
        assert "Not analyzed" in output.getvalue()


def test_redaction_applies_to_every_renderer_and_derived_copy():
    parsed = email(
        "Alice Example alice@example.org 10.0.0.4 [::1] "
        "https://example.net/?user=alice%40example.org",
        html=False,
        subject="PRIVATE-SUBJECT alice@example.org",
    )
    parsed.source.filename = "alice@example.org.eml"
    view, _ = triage(parsed, policy=RedactionPolicy.standard(("Subject",)))
    output = io.StringIO()
    render_cli(view, Console(file=output, width=120))
    for text in (
        render_json(view),
        render_html(view),
        render_sentinel(view),
        render_xsoar(view),
        output.getvalue(),
    ):
        for secret in (
            "Alice Example",
            "alice",
            "PRIVATE-SUBJECT",
            "10.0.0.4",
            "10[.]0[.]0[.]4",
            "10[[.]]0[[.]]0[[.]]4",
            "::1",
        ):
            assert secret not in text


@pytest.mark.parametrize(
    "value",
    [
        "[resourceGroup().location]",
        "@triggerBody()",
        "prefix @{utcNow()}",
        "@@literal",
        "[[literal]",
    ],
)
def test_sentinel_hostile_strings_are_literal_data(value):
    view, _ = triage(email("hello", subject=value, html=False))
    template = json.loads(render_sentinel(view))
    actual = template["resources"][0]["properties"]["definition"]["actions"][
        "Compose_Phishbowl_Triage_DRAFT"
    ]["inputs"]["subject"]
    assert actual.startswith("@base64ToString('")
    assert base64.b64decode(actual[17:-2]).decode() == view.subject
    assert template["resources"][0]["properties"]["state"] == "Disabled"


def test_private_ips_and_private_url_hosts_never_become_vendor_targets():
    parsed = email(
        "10.0.0.4 127.0.0.1 fc00::1 https://127.0.0.1/login "
        "https://[::1]/login https://intranet.local/ "
        "https://example.net/login",
        html=False,
    )
    values = {i.value for i in build_targets(parsed, extract_iocs(parsed))}
    assert not values & {
        "10.0.0.4",
        "127.0.0.1",
        "fc00::1",
        "https://127.0.0.1/login",
        "https://[::1]/login",
        "https://intranet.local/",
        "example.org",
    }
    assert "https://example.net/login" in values


def test_upload_over_spool_threshold_stays_off_disk(monkeypatch):
    from phishbowl.web.app import create_app

    def forbidden(*args, **kwargs):
        pytest.fail("raw upload rolled to disk")

    monkeypatch.setattr(tempfile.SpooledTemporaryFile, "rollover", forbidden)
    response = TestClient(create_app()).post(
        "/analyze",
        files={"file": ("large.eml", b"From: sender@example.com\r\n\r\n" + b"x " * 600_000)},
    )
    assert response.status_code == 200
    assert "Incomplete" in response.text


def test_chunked_upload_stops_receiving_before_multipart_finishes(monkeypatch):
    # Import the module explicitly because phishbowl.web exposes an app instance.
    import importlib

    web = importlib.import_module("phishbowl.web.app")
    monkeypatch.setattr(web, "MAX_INPUT_BYTES", 100)
    consumed = 0

    async def body():
        nonlocal consumed
        yield b'--x\r\nContent-Disposition: form-data; name="file"; filename="large.eml"\r\n\r\n'
        for _ in range(200):
            consumed += 1
            yield b"x" * 1024
        yield b"\r\n--x--\r\n"

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=web.create_app()), base_url="http://testserver"
        ) as client:
            return await client.post(
                "/analyze",
                content=body(),
                headers={"content-type": "multipart/form-data; boundary=x"},
            )

    response = asyncio.run(run())
    assert response.status_code == 413
    assert consumed < 100


def test_public_suffixes_and_private_tenants_stay_distinct():
    assert registrable_domain("login.example.co.uk") == "example.co.uk"
    assert registrable_domain("one.github.io") != registrable_domain("two.github.io")


@pytest.mark.parametrize("weight", [-1, float("nan"), float("inf")])
def test_invalid_weights_are_rejected(weight):
    with pytest.raises(ValueError):
        load_config(overrides={"weights": {"auth.spf_fail": weight}})


def test_pathological_email_regex_times_out_with_explicit_limitation():
    view, result = triage(email("a." * 5000, html=False))
    assert not result.analysis_complete
    assert any(a.code == "extraction_timeout" for a in view.anomalies)


def test_enrichment_failure_keeps_offline_analysis(monkeypatch):
    import phishbowl.pipeline as pipeline
    from phishbowl.connectors import EnrichmentSettings

    def fail(*args):
        raise RuntimeError("vendor/cache/connector failure")

    monkeypatch.setattr(pipeline, "enrich_email", fail)
    parsed = email("Review this", html=False)
    expected, _ = triage(parsed)
    view, result = triage(parsed, enrichment_settings=EnrichmentSettings(enabled=True))
    assert result.score == expected.score
    assert view.enrichment.connectors[0].outcome == "failed"


def test_cache_malformed_shape_and_naive_timestamp_are_misses(tmp_path):
    from phishbowl.connectors.cache import EnrichmentCache

    cache = EnrichmentCache(tmp_path)
    path = cache._path("rdap", "domain", "example.com")
    path.parent.mkdir(parents=True)
    for payload in ([], {"stored_at": "2026-09-12T00:00:00", "result": {}}):
        path.write_text(json.dumps(payload))
        assert cache.get("rdap", "domain", "example.com", ttl=3600) is None


def test_malformed_html_declaration_is_incomplete_and_recoverable():
    view, result = triage(email("<![foo]><a href=https://credential.example/login>Review</a>"))
    assert "credential" in render_json(view)
    if any(a.code == "html_incomplete" for a in view.anomalies):
        assert not result.analysis_complete


def test_explicit_header_redaction_removes_normalized_derivatives():
    parsed = parse_eml(
        b"From: Secret Name <secret@confidential.example>\r\n"
        b"Reply-To: Other Name <private@response.example>\r\n"
        b"Date: Wed, 03 Jun 2026 02:05:09 +0000\r\n\r\nhello"
    )
    view, _ = triage(parsed, policy=RedactionPolicy.standard(("From", "Reply-To", "Date")))
    for output in (render_json(view), render_html(view), render_xsoar(view), render_sentinel(view)):
        for secret in (
            "confidential",
            "response.example",
            "response[.]example",
            "2026-06-03",
            "Secret Name",
            "Other Name",
        ):
            assert secret not in output


def test_defanged_internal_values_are_redacted_in_evidence():
    from phishbowl.report.redact import Redactor

    redactor = Redactor(
        RedactionPolicy.standard(),
        email("hello"),
        load_config(overrides={"org_domains": ["corp.example"]}),
    )
    for value in (
        "host.corp[.]example",
        "10[.]0[.]0[.]4",
        "10[[.]]0[[.]]0[[.]]4",
        "fc00[:][:]1",
        "hxxps://host.corp[.]example/",
    ):
        redacted = redactor.text(value)
        assert "[redacted:internal-" in redacted
        assert "corp" not in redacted and "10" not in redacted and "fc00" not in redacted


def test_multipart_container_defects_make_analysis_incomplete():
    raw = (
        b"From: sender@example.com\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n"
        b"--x\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
    )
    view, result = triage(parse_eml(raw))
    assert not result.analysis_complete
    assert any("CloseBoundaryNotFoundDefect" in a.message for a in view.anomalies)


def test_routing_protocol_field_obeys_redaction():
    parsed = email("hello", html=False)
    from phishbowl.models.routing import ReceivedHop

    parsed.routing.hops.append(ReceivedHop(raw="", with_="alice@example.org"))
    view, _ = triage(parsed, policy=RedactionPolicy.standard())
    assert "alice" not in render_json(view)


def test_public_ipv6_url_keeps_url_reputation_target():
    value = "https://[2606:4700:4700::1111]/login"
    parsed = email(value, html=False)
    assert value in {target.value for target in build_targets(parsed, extract_iocs(parsed))}


@pytest.mark.parametrize("content_type", ["text/calendar", "text/rtf"])
def test_other_inline_text_body_is_scanned_and_listed(content_type):
    parsed = parse_eml(
        (
            f"From: sender@example.com\r\nContent-Type: {content_type}\r\n\r\n"
            "DESCRIPTION:Verify at https://credential.example/login"
        ).encode()
    )
    view, result = triage(parsed)
    # The part is scanned as text, so its link is evidence and nothing is skipped.
    assert result.analysis_complete
    assert any(a.code == "other_body_type" and not a.coverage_gap for a in view.anomalies)
    assert "https://credential.example/login" in {
        i.value_raw for group in view.ioc_groups for i in group.items
    }
    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].sha256


def test_long_anchor_label_finishes_within_process_budget():
    import subprocess
    import sys

    # Subprocess timeout makes a future CPU regression fail instead of hanging pytest.
    subprocess.run(
        [
            sys.executable,
            "-c",
            """
from phishbowl.score.detectors import _first_host_in_text
assert _first_host_in_text('a' * 250_000) is None
assert _first_host_in_text('a.' * 120_000) is None
assert _first_host_in_text('visit https://example.org/login') == 'example.org'
""",
        ],
        check=True,
        timeout=5,
    )


@pytest.mark.parametrize("label", ["Visit paypal.com.", "paypal.com. ", "paypal.com"])
def test_anchor_host_followed_by_punctuation_still_detects_mismatch(label):
    _, result = triage(email(f'<a href="https://credential.example/login">{label}</a>'))
    assert any(rule.id == "url.anchor_href_mismatch" for rule in result.fired)


# --------------------------------------------------------------------------- #
# Second review: parse layer                                                  #
# --------------------------------------------------------------------------- #


def _renders(view) -> None:
    """Every renderer accepts the view (the crash class these tests guard)."""
    render_json(view)
    render_html(view).encode("utf-8")
    render_cli(view, Console(file=io.StringIO(), width=120))


def test_a_nul_in_a_charset_label_loses_nothing():
    raw = (
        b"From: a@sender.example\r\nSubject: =?utf-8\x00?q?Locked?=\r\n"
        b"Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=sender.example\r\n"
        b"Content-Type: multipart/mixed; boundary=b\r\n\r\n"
        b"--b\r\nContent-Type: text/plain; charset*=utf-8%00''x\r\n\r\n"
        b"Pay at https://evil.example/pay\r\n"
        b"--b\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename*=utf-8%00''invoice.pdf.exe\r\n\r\n"
        b"MZ\r\n--b--\r\n"
    )
    parsed = parse_eml(raw)
    assert parsed.subject == "Locked"
    assert parsed.auth.spf.result.value == "fail"
    assert "https://evil.example/pay" in {i.value for i in extract_iocs(parsed)}
    assert [a.filename for a in parsed.attachments] == ["invoice.pdf.exe"]


def test_adjacent_encoded_words_may_split_a_character():
    parsed = parse_eml(
        b"From: a@sender.example\r\n"
        b"Subject: =?utf-8?q?Rechnung_f=C3?= =?utf-8?q?=BCr_Kunde?=\r\n\r\nhi\r\n"
    )
    assert parsed.subject == "Rechnung für Kunde"


@pytest.mark.parametrize(
    "raw",
    [
        # The first header line of a part is a continuation, quoting raw bytes.
        b"From: a@b.example\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n"
        b"--b\r\n \xc3\x28 note\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b--\r\n",
        # A misplaced "From " envelope line among the headers.
        b"From: a@b.example\r\nFrom \xc3\x28 note\r\nSubject: s\r\n\r\nhi\r\n",
    ],
)
def test_mime_defects_quoting_raw_bytes_still_render(raw):
    view, _ = triage(parse_eml(raw))
    assert any(a.code == "mime_defect" for a in view.anomalies)
    _renders(view)


def test_models_never_hold_lone_surrogates():
    from phishbowl.models import Anomaly

    assert Anomaly(message="x\udcc3y").message == "x�y"


def test_mixed_rfc2231_parameters_keep_the_message():
    raw = (
        b"From: a@sender.example\r\nSubject: hello\r\n"
        b"Content-Type: multipart/mixed; boundary*0=b; boundary*=x\r\n\r\n"
        b"--b\r\nContent-Type: text/plain\r\n\r\nhttps://evil.example/x\r\n--b--\r\n"
    )
    parsed = parse_eml(raw)
    assert parsed.addresses.from_ is not None and parsed.subject == "hello"
    assert "https://evil.example/x" in {i.value for i in extract_iocs(parsed)}
    assert not triage(parsed)[1].analysis_complete  # the structure is ambiguous

    part_level = (
        b"From: a@sender.example\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n"
        b"--b\r\nContent-Type: text/plain\r\n"
        b"Content-Disposition: inline; filename*0=a; filename*=b\r\n\r\n"
        b"https://evil.example/x\r\n"
        b"--b\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename*0=c; filename*=d\r\n\r\nMZ\r\n--b--\r\n"
    )
    parsed = parse_eml(part_level)
    assert parsed.body.text and "evil.example" in parsed.body.text
    assert len(parsed.attachments) == 1


def test_nested_comments_in_one_header_cost_no_other_address():
    raw = (
        b"From: boss@corp.example\r\nReply-To: " + b"(" * 600 + b"\r\n"
        b"To: v@victim.example\r\nSubject: s\r\n\r\nhi\r\n"
    )
    parsed = parse_eml(raw)
    assert parsed.addresses.from_.addr_spec == "boss@corp.example"
    assert [a.addr_spec for a in parsed.addresses.to] == ["v@victim.example"]


def test_malformed_msg_strings_cost_no_other_evidence(monkeypatch):
    from pathlib import Path

    monkeypatch.syspath_prepend(str(Path(__file__).parent / "fixtures"))
    import build_synthetic_msg as msgbuild

    monkeypatch.setattr(msgbuild, "_unistr", lambda text: text.encode("utf-16-le", "surrogatepass"))
    raw = msgbuild.build_message(
        subject="s",
        body_text="plain \ud800 text",
        html=b"<a href='https://evil.example/login'>x</a>",
        attachments=[
            ("invoice.pdf", "application/pdf", b"%PDF-1.4"),
            ("pay\ud800load.pdf.exe", "application/octet-stream", b"MZ\x90\x00"),
        ],
    )
    parsed = parse_msg(raw)
    assert [a.filename for a in parsed.attachments] == ["invoice.pdf", "pay�load.pdf.exe"]
    assert parsed.body.text == "plain � text"
    assert "https://evil.example/login" in {i.value for i in extract_iocs(parsed)}


@pytest.mark.parametrize(
    "code",
    [
        # RFC 2047 encoded-word scan with "*" runs.
        "from phishbowl.parse.charset import decode_mime_words\n"
        "decode_mime_words('=?' + 'a*' * 100_000)",
        # Re-serializing an attached message whose header is three folded,
        # within-budget lines of many short words.
        "from phishbowl.parse import parse_eml\n"
        "pad = b'\\r\\n '.join([b' '.join([b'a'] * 20_000)] * 3)\n"
        "inner = b'From: x@y.example\\r\\nX-Pad: ' + pad + b'\\r\\n\\r\\nb'\n"
        "parse_eml(b'From: a@b.example\\r\\nContent-Type: multipart/mixed; boundary=b\\r\\n\\r\\n"
        "--b\\r\\nContent-Type: message/rfc822\\r\\n\\r\\n' + inner + b'\\r\\n--b--\\r\\n')",
        # IDNA-encoding a hostile, oversized Unicode domain.
        "from phishbowl.domains import ascii_host\n"
        "ascii_host(''.join(chr(0x4E00 + i) for i in range(30_000)) + '.example')",
    ],
)
def test_parse_helpers_stay_fast_on_hostile_input(code):
    import subprocess
    import sys

    subprocess.run([sys.executable, "-c", code], check=True, timeout=10)


# --------------------------------------------------------------------------- #
# Second review: authentication, HTML, extraction, defanging                  #
# --------------------------------------------------------------------------- #


def test_a_lower_authentication_results_copy_cannot_forge_dkim():
    parsed = parse_eml(
        b"Authentication-Results: mx.corp.example; dkim=fail (bad signature) "
        b"header.d=evil.example; spf=fail smtp.mailfrom=evil.example; "
        b"dmarc=fail header.from=bank.example\r\n"
        b"Authentication-Results: mx.corp.example; dkim=pass header.d=bank.example\r\n"
        b"From: alerts@bank.example\r\nSubject: s\r\n\r\nhi\r\n"
    )
    assert parsed.auth.dkim.result.value == "fail"
    assert any(a.code == "auth_repeated_results" for a in parsed.anomalies)


def test_an_exchange_style_header_without_an_id_is_trusted_alone():
    parsed = parse_eml(
        b"Authentication-Results: spf=fail (sender IP is 203.0.113.9) "
        b"smtp.mailfrom=evil.example; dkim=none (message not signed) header.d=none; "
        b"dmarc=fail action=none header.from=bank.example;\r\n"
        b"Authentication-Results: spf=fail; dkim=pass header.d=bank.example\r\n"
        b"From: alerts@bank.example\r\nSubject: s\r\n\r\nhi\r\n"
    )
    assert (parsed.auth.spf.result.value, parsed.auth.dkim.result.value) == ("fail", "none")
    assert parsed.auth.dmarc.result.value == "fail"


def test_dkim_alignment_reads_the_domain_of_header_i():
    parsed = parse_eml(
        b"Authentication-Results: mx.corp.example; dkim=pass header.i=news@esp.example; "
        b"dkim=fail header.i=alerts@bank.example\r\n"
        b"From: alerts@bank.example\r\n\r\nhi\r\n"
    )
    assert parsed.auth.dkim.result.value == "fail"


@pytest.mark.parametrize(
    "href",
    [
        "ht&#9;tps://evil.example/login",
        "https&#10;://evil.example/login",
        "\x01https://evil.example/login",
    ],
)
def test_links_are_read_as_browsers_read_them(href):
    view, _ = triage(email(f'<a href="{href}">x</a>'))
    values = {i.value_raw for g in view.ioc_groups for i in g.items}
    assert "https://evil.example/login" in values


@pytest.mark.parametrize(
    "markup",
    [
        '<a href="search-ms:query=x&amp;crumb=location:\\\\evil.example\\share">x</a>',
        '<a href="ms-word:ofe|u|https://evil.example/x.docx">x</a>',
        '<a href="smb://evil.example/share">x</a>',
        '<img src="\\\\evil.example\\share\\x.png">',
        '<meta http-equiv="refresh" content="0; https://evil.example/login">',
        '<meta http-equiv="refresh" content="0,https://evil.example/login">',
    ],
)
def test_links_to_other_protocols_and_bare_refreshes_are_evidence(markup):
    view, _ = triage(email(markup))
    domains = {i.value_raw for g in view.ioc_groups if g.type == "domain" for i in g.items}
    assert "evil.example" in domains


def test_a_url_after_many_matches_still_fits_the_time_budget():
    body = "See https://benign.example/newsletter/item\n" * 5000
    parsed = email(body + "https://evil.example/login\n", html=False)
    assert "https://evil.example/login" in {i.value for i in extract_iocs(parsed)}


@pytest.mark.parametrize(
    "url", ["HTTPS://evil.example/login", "Http://evil.example/login", "hXXps://evil.example"]
)
def test_defanging_is_case_insensitive_about_web_schemes(url):
    from phishbowl.extract import defang_url, refang

    shown = defang_url(url)
    assert shown.startswith("hxxp") or shown.startswith("hXXp")
    assert refang(shown).casefold().startswith("http")


@pytest.mark.parametrize(
    "code",
    [
        # Meta refresh content full of spaces.
        "from phishbowl.html_analysis import inspect_html\n"
        "inspect_html('<meta http-equiv=\"refresh\" content=\"' + ' ' * 200_000 + 'x\">')",
        # CSS url() followed by a long whitespace run.
        "from phishbowl.html_analysis import inspect_html\n"
        "inspect_html('<div style=\"background:url(' + ('\\n' + ' ' * 999) * 200 + ')\">')",
        # Received-SPF with an unbalanced run of parentheses.
        "from phishbowl.parse.auth import _parse_received_spf\n"
        "_parse_received_spf(['pass ' + '(' * 200_000])",
    ],
)
def test_html_and_auth_parsing_stay_fast_on_hostile_input(code):
    import subprocess
    import sys

    subprocess.run([sys.executable, "-c", code], check=True, timeout=10)


# --------------------------------------------------------------------------- #
# Second review: scoring                                                      #
# --------------------------------------------------------------------------- #


def _url_rules(raw: bytes, **overrides):
    config = load_config(overrides=overrides) if overrides else None
    _, result = triage(parse_eml(raw), config=config)
    return {rule.id for rule in result.fired if rule.id.startswith("url.")}


def test_a_punycode_label_that_decodes_to_a_surrogate_still_renders():
    view, result = triage(email("see https://xn--ab-zd9k.example/login", html=False))
    assert "url.punycode" in {rule.id for rule in result.fired}
    _renders(view)


@pytest.mark.parametrize(
    "raw",
    [
        # A recipient's own domain is not screened as the sender's claim.
        b"From: bob@partner.example\r\nTo: alice@the-office-group.co.uk\r\n\r\nhello\r\n",
        # Brand-owned auxiliary domains name the brand without a lure word.
        b"From: ship@amazon.com\r\nContent-Type: text/html\r\n\r\n"
        b"<img src='https://m.media-amazon.com/i.png'>"
        b"<a href='https://paypal-community.com/t'>forum</a>\r\n",
        # Link text naming a file is not a host.
        b"From: a@b.example\r\nContent-Type: text/html\r\n\r\n"
        b"<a href='https://github.com/o/r/files'>README.md</a>"
        b"<a href='https://github.com/o/r/blob/main/setup.py'>setup.py</a>\r\n",
    ],
)
def test_benign_mail_does_not_fire_lookalike_or_anchor_rules(raw):
    assert _url_rules(raw) & {"url.lookalike", "url.anchor_href_mismatch"} == set()


def test_combosquats_with_a_lure_word_still_fire():
    raw = b"From: a@b.example\r\n\r\nhttps://paypal-secure.net/x https://secure-paypal.com/y\r\n"
    assert "url.lookalike" in _url_rules(raw)


def test_an_org_domain_without_a_public_suffix_compares_its_name():
    benign = b"From: a@shop-local.co.uk\r\n\r\nhello\r\n"
    assert "url.lookalike" not in _url_rules(benign, org_domains=["acmecorp.local"])
    squat = b"From: a@acmecorp-login.co.uk\r\n\r\nhello\r\n"
    assert "url.lookalike" in _url_rules(squat, org_domains=["acmecorp.local"])


@pytest.mark.parametrize(
    "override",
    [{"weights": []}, {"weights": 0}, {"weights": False}, {"brands": []}, {"brands": ""}],
)
def test_a_non_mapping_where_a_mapping_belongs_is_an_error(override):
    with pytest.raises(ValueError, match="must be a mapping"):
        load_config(overrides=override)


# --------------------------------------------------------------------------- #
# Second review: redaction                                                    #
# --------------------------------------------------------------------------- #


def _outputs(view) -> list[str]:
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


def _leaks(view, *secrets: str) -> set[str]:
    return {secret for secret in secrets for output in _outputs(view) if secret in output}


def test_sender_written_recipients_cannot_hide_the_senders_indicators():
    raw = (
        b"From: jane.ceo@acme-c0rp.com\r\nTo: finance@acme-corp.com\r\n"
        b"Cc: bob.cfo@acme-c0rp.com, a@com, b@net\r\nSubject: Wire\r\n\r\n"
        b"Pay via https://acme-c0rp.com/wire or https://pay.net/x today.\r\n"
    )
    view, _ = triage(parse_eml(raw), policy=RedactionPolicy.standard())
    assert view.from_.addr_spec_raw == "jane.ceo@acme-c0rp.com"
    raw_values = {i.value_raw for g in view.ioc_groups for i in g.items}
    assert {"https://acme-c0rp.com/wire", "acme-c0rp.com", "https://pay.net/x"} <= raw_values
    assert "https://acme-c0rp.com/wire" in render_xsoar(view)
    # The recipients themselves, and a domain named only by them, are withheld.
    assert not _leaks(view, "bob.cfo", "bob[.]cfo", "finance[at]", "a[at]com", "acme-corp")


def test_a_wrapper_that_encodes_the_recipient_keeps_the_link_it_wraps():
    wrapped = (
        "https://nam02.safelinks.protection.outlook.com/?url="
        + quote("https://evil.example/login", safe="")
        + "&data=05%7C02%7Cvictim%40victim-org.example%7Cabc&reserved=0"
    )
    raw = (
        b"From: attacker@evil.example\r\nTo: victim@victim-org.example\r\n"
        b"Content-Type: text/html\r\n\r\n<a href='" + wrapped.encode() + b"'>Sign in</a>\r\n"
    )
    view, _ = triage(parse_eml(raw), policy=RedactionPolicy.standard())
    [link] = [i for g in view.ioc_groups for i in g.items if i.type == "url"]
    assert link.value_raw == "https://evil.example/login" and not link.redacted
    assert link.wrapper == "safelinks" and link.wrapped_display is None
    assert "https://evil.example/login" in render_xsoar(view)
    assert not _leaks(view, "victim%40", "victim@", "victim[at]")


def test_redaction_time_does_not_grow_with_the_recipient_count():
    import subprocess
    import sys

    code = """
from phishbowl.models import Address
from phishbowl.parse import parse_eml
from phishbowl.report import RedactionPolicy
from phishbowl.report.redact import Redactor
from phishbowl.score import load_config

parsed = parse_eml(b"From: a@sender.example\\r\\n\\r\\nx")
parsed.addresses.to = [
    Address(display_name=f"Person {i}", addr_spec=f"u{i}@r{i}.example", domain=f"r{i}.example")
    for i in range(20_000)
]
redactor = Redactor(RedactionPolicy.standard(), parsed, load_config())
text = "Dear Person 7, write to u9@r9.example about https://evil.example/login. " * 3_000
redacted = redactor.text(text)
assert "Person 7" not in redacted and "u9@" not in redacted and "evil.example" in redacted
"""
    subprocess.run([sys.executable, "-c", code], check=True, timeout=10)


def test_defanging_in_attacker_text_is_not_a_redaction():
    raw = (
        b'From: <"pay(.)ments"@evil.example>\r\nTo: victim@victim-org.example\r\n'
        b"Content-Type: text/html\r\n\r\n"
        b"<a href='https://evil.example/u[at]x'>a</a><a href='https://evil.example/a[.]b/c'>b</a>"
        b"<a href='https://evil.example/q?(.)'>c</a>"
        b"<a href='https://evil.example/?next=hxxp://x'>d</a>\r\n"
    )
    view, _ = triage(parse_eml(raw), policy=RedactionPolicy.standard())
    links = [i for g in view.ioc_groups for i in g.items if i.type == "url"]
    assert len(links) == 4
    assert all(i.value_raw and not i.redacted for i in links)
    assert "hxxps://evil[.]example/u[at]x" in {i.value_display for i in links}
    assert view.from_.addr_spec_raw == '"pay(.)ments"@evil.example' and not view.from_.redacted


def test_text_with_nothing_to_protect_is_returned_as_given():
    from phishbowl.report.redact import Redactor

    redactor = Redactor(RedactionPolicy.standard(), email("hi"), load_config())
    value = "see hxxps://evil[.]example/u[at]x?(.) and user[AT]evil[.]example"
    assert redactor.text(value) is value
    assert redactor.text("mail alice[AT]example[.]org") == "mail [redacted:recipient]"


def test_delivery_headers_name_recipients():
    raw = (
        b"X-Apparently-To: victim.person@yahoo.com; Tue, 03 Jun 2026 02:05:09 +0000\r\n"
        b"X-Forwarded-For: fwd.person@gmail.com relay.person@victim-org.example\r\n"
        b"X-Delivered-To: dlv.person@victim-org.example\r\n"
        b"From: attacker@evil.example\r\nTo: undisclosed-recipients:;\r\nSubject: Hi\r\n\r\n"
        b"Dear victim.person@yahoo.com, fwd.person@gmail.com: https://evil.example/login\r\n"
    )
    view, _ = triage(parse_eml(raw), policy=RedactionPolicy.standard())
    assert not _leaks(view, "victim.person", "victim[.]person", "fwd", "dlv", "victim-org")
    hidden = {h.name for h in view.headers if h.value == "[redacted:recipient]"}
    assert {"X-Apparently-To", "X-Forwarded-For", "X-Delivered-To"} <= hidden
    assert "evil[.]example" in render_json(view)


def test_internal_addresses_are_redacted_in_every_notation():
    raw = (
        b"Received: from [IPv6:fd12:3456:789a::25] (unknown [IPv6:fd12:3456:789a::25])\r\n"
        b" by mx.victim.example; Tue, 03 Jun 2026 02:05:09 +0000\r\n"
        b"From: attacker@evil.example\r\nTo: v@victim.example\r\nContent-Type: text/html\r\n\r\n"
        b"<a href='http://167772165/'>a</a><a href='http://10.5/'>b</a>"
        b"<a href='http://0xa000005/'>c</a>\r\n"
    )
    parsed = parse_eml(raw)
    # A browser reads each of these hosts as 10.0.0.5, so the indicator does too.
    iocs = {(i.type.value, i.value) for i in extract_iocs(parsed)}
    assert ("ipv4", "10.0.0.5") in iocs and ("domain", "0xa000005") not in iocs
    view, _ = triage(parsed, policy=RedactionPolicy.standard())
    assert not _leaks(view, "fd12", "167772165", "10[.]5/", "0xa000005", "10[.]0[.]0[.]5")


def test_msg_attachment_types_are_defanged_and_redacted(monkeypatch):
    from pathlib import Path

    monkeypatch.syspath_prepend(str(Path(__file__).parent / "fixtures"))
    import build_synthetic_msg as msgbuild

    raw = msgbuild.build_message(
        subject="Invoice",
        body_text="See attached.",
        recipients=[(msgbuild.RECIP_TO, "Victim Person", "victim.person@gmail.com")],
        attachments=[
            ("invoice.pdf", "https://evil.example/pay?u=victim.person@gmail.com", b"%PDF-1.4\n")
        ],
    )
    plain, _ = triage(parse_msg(raw))
    assert plain.attachments[0].declared_type.startswith("hxxps://evil[.]example/pay")
    assert not _leaks(plain, "https://evil.example")
    redacted, _ = triage(parse_msg(raw), policy=RedactionPolicy.standard())
    assert not _leaks(redacted, "victim.person", "victim[.]person")


def test_a_hidden_received_header_hides_its_addresses_in_enrichment_evidence():
    from phishbowl.connectors import EnrichmentSettings, run_enrichment
    from phishbowl.connectors.targets import sending_ips

    raw = (
        b"Received: from relay.sender.example (relay.sender.example [8.8.8.8])\r\n"
        b" by mx.victim.example; Tue, 03 Jun 2026 02:05:09 +0000\r\n"
        b"From: attacker@evil.example\r\nTo: v@victim.example\r\n\r\nhello\r\n"
    )
    parsed = parse_eml(raw)

    async def nosleep(_seconds):
        return None

    settings = EnrichmentSettings(
        enabled=True,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"data": {"abuseConfidenceScore": 80, "totalReports": 3}}
            )
        ),
        sleep=nosleep,
        cache_enabled=False,
        api_keys={"abuseipdb": "test-key"},
        select=frozenset({"abuseipdb"}),
    )
    report = run_enrichment(sending_ips(parsed), settings)
    view, result = triage(parsed, policy=RedactionPolicy.standard(("Received",)), enrichment=report)
    assert any(rule.id == "enrichment.abuseipdb.confidence" for rule in result.fired)
    assert not _leaks(view, "8[.]8[.]8[.]8", "8.8.8.8", "relay.sender", "relay[.]sender")


def test_idn_recipient_domains_are_redacted_in_either_spelling():
    raw = (
        "Delivered-To: kim@bücher.example\r\nFrom: attacker@evil.example\r\n"
        "To: kim@bücher.example\r\nSubject: Hi\r\n\r\n"
        "Ask boss@bücher.example, or mail.bücher.example, or mx1.xn--bcher-kva.example.\r\n"
    ).encode()
    view, _ = triage(parse_eml(raw), policy=RedactionPolicy.standard())
    assert not _leaks(view, "bücher", "xn--bcher", "boss")


def test_recipients_are_found_in_any_spacing_case_or_defanging():
    raw = (
        b"From: attacker@evil.example\r\nTo: Jonathan Whitaker <victim.person@gmail.com>\r\n"
        b"Subject: Hi\r\n\r\n"
        b"Hi Jonathan\r\nWhitaker, JONATHAN   WHITAKER: write victim.person[AT]gmail.com,\r\n"
        b"victim.person (at) gmail (dot) com, or victim.person [at] gmail [dot] com.\r\n"
    )
    view, _ = triage(parse_eml(raw), policy=RedactionPolicy.standard())
    preview = view.body_preview or ""
    assert "jonathan" not in preview.casefold() and "whitaker" not in preview.casefold()
    assert "victim" not in preview and preview.startswith("Hi [redacted:recipient],")


def test_generic_names_and_short_values_leave_indicators_alone():
    raw = (
        b"From: attacker@evil.example\r\nTo: Sales <sales@victim.example>\r\n"
        b"X-MS-Exchange-Organization-SCL: 1\r\nContent-Type: text/html\r\n\r\n"
        b"<a href='https://evil.example/sales/invoice.php'>a</a>"
        b"<a href='https://sales.evil.example/'>b</a><a href='http://evil.example/1/login'>c</a>\r\n"
    )
    policy = RedactionPolicy.standard(("X-MS-Exchange-Organization-SCL",))
    view, _ = triage(parse_eml(raw), policy=policy)
    links = {i.value_raw for g in view.ioc_groups for i in g.items if i.type == "url"}
    assert links == {
        "https://evil.example/sales/invoice.php",
        "https://sales.evil.example/",
        "http://evil.example/1/login",
    }
    assert "[redacted:field]" in {h.value for h in view.headers}
