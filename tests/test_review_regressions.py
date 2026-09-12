"""Synthetic regressions for the critical project review. No live services."""

import asyncio
import base64
import io
import json
import tempfile

import httpx
import pytest
from fastapi.testclient import TestClient
from rich.console import Console

from phishbowl.connectors.targets import build_targets
from phishbowl.export import render_sentinel, render_xsoar
from phishbowl.extract import extract_iocs
from phishbowl.parse import parse_eml, parse_msg
from phishbowl.pipeline import triage
from phishbowl.report import RedactionPolicy, render_cli, render_html, render_json
from phishbowl.score import load_config
from phishbowl.score.detectors import registrable_domain


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
    assert "Incomplete" in view.verdict


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
        assert view.verdict.startswith("Incomplete")
        assert view.anomalies
        output = io.StringIO()
        render_cli(view, Console(file=output))
        assert "Analysis limitation" in output.getvalue()


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
        assert redactor.text(value).startswith("[redacted:")


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
def test_unsupported_inline_text_body_is_visible_and_incomplete(content_type):
    parsed = parse_eml(
        (
            f"From: sender@example.com\r\nContent-Type: {content_type}\r\n\r\n"
            "DESCRIPTION:Verify at https://credential.example/login"
        ).encode()
    )
    view, result = triage(parsed)
    assert not result.analysis_complete
    assert any(a.code == "unsupported_body_type" for a in view.anomalies)
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
