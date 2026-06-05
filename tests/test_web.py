"""Tests for the optional FastAPI upload UI (PRD §15 stretch; CHECKLIST Phase 7).

The upload UI is purely *additive*: it must run the **same** offline pipeline as
the CLI and render the **same** self-contained, zero-egress report, with no logic
fork (PRD §15). These tests pin that contract plus the upload hardening:

* **Happy path** — a real ``.eml`` fixture uploads, returns ``200`` HTML, and the
  rendered report is byte-for-byte the CLI pipeline's output (timestamps aside),
  proving the report layer is reused unchanged.
* **Oversized input** is refused ``413`` before being fully read.
* **Wrong-type input** is refused ``415`` before being parsed at all.
* The served report (and the upload form) carry the no-egress guarantees: no
  remote/executable markup, and strict ``Content-Security-Policy`` headers.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from phishbowl.extract import extract_iocs
from phishbowl.parse import parse_bytes
from phishbowl.report import build_report, render_html
from phishbowl.score import load_config, score_email
from phishbowl.web import app

# The submodule that holds MAX_INPUT_BYTES (the package's ``app`` name is the
# FastAPI instance above, so reach the module object explicitly to monkeypatch it).
web_app_module = importlib.import_module("phishbowl.web.app")

FIXTURES = Path(__file__).parent / "fixtures"
BENIGN = FIXTURES / "benign_newsletter.eml"
MALICIOUS = FIXTURES / "crafted_malicious.eml"

client = TestClient(app)

# ISO-8601 timestamps are the only per-run-varying content in the report (the
# parse time). Normalizing them lets us assert the web report equals the CLI
# pipeline's output exactly everywhere else — i.e. the report layer is reused
# unchanged, no fork.
_ISO_TS = re.compile(r"\d{4}-\d{2}-\d{2}T[0-9:.+\-]+")


def _normalize(html: str) -> str:
    return _ISO_TS.sub("<TS>", html)


def _cli_pipeline_html(path: Path) -> str:
    """Render the report exactly as the CLI ``analyze`` path would, for comparison."""
    data = path.read_bytes()
    parsed = parse_bytes(data, filename=path.name)
    config = load_config()
    iocs = extract_iocs(parsed)
    result = score_email(parsed, iocs, config)
    view = build_report(parsed, iocs, result, config=config)
    return render_html(view)


def _upload(path: Path, *, filename: str | None = None, content_type: str = "message/rfc822"):
    with path.open("rb") as fh:
        return client.post(
            "/analyze",
            files={"file": (filename or path.name, fh, content_type)},
        )


# --------------------------------------------------------------------------- #
# Happy path                                                                  #
# --------------------------------------------------------------------------- #


def test_upload_returns_the_same_report_the_cli_produces() -> None:
    response = _upload(BENIGN)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    body = response.text
    assert body.lstrip().lower().startswith("<!doctype html>")
    # The served report is identical to the CLI pipeline's (timestamps aside):
    # same ParsedEmail, same scorer, same report layer — no logic fork (PRD §15).
    assert _normalize(body) == _normalize(_cli_pipeline_html(BENIGN))


def test_upload_renders_the_verdict_for_a_malicious_sample() -> None:
    response = _upload(MALICIOUS)

    assert response.status_code == 200
    # The crafted-malicious fixture surfaces a real verdict through the UI, just
    # as it does on the CLI — the scorer is shared, not reimplemented.
    assert _normalize(response.text) == _normalize(_cli_pipeline_html(MALICIOUS))


def test_index_serves_a_self_contained_upload_form() -> None:
    response = client.get("/")

    assert response.status_code == 200
    body = response.text.lower()
    assert "<form" in body and 'type="file"' in body
    # The form page is self-contained: no script, no remote assets, no remote URLs.
    assert "<script" not in body
    assert "http://" not in body and "https://" not in body


# --------------------------------------------------------------------------- #
# Upload hardening                                                            #
# --------------------------------------------------------------------------- #


def test_oversized_upload_is_refused_413(monkeypatch: pytest.MonkeyPatch) -> None:
    # Shrink the cap instead of uploading 50 MiB: any body over the limit must be
    # rejected before it is fully buffered, never parsed into a report.
    monkeypatch.setattr(web_app_module, "MAX_INPUT_BYTES", 16)

    oversized = b"From: a@example.com\r\n\r\n" + b"A" * 4096
    response = client.post(
        "/analyze",
        files={"file": ("big.eml", oversized, "message/rfc822")},
    )

    assert response.status_code == 413


def test_wrong_type_upload_is_refused_415() -> None:
    # A non-email type is rejected up front, before any parsing happens.
    response = client.post(
        "/analyze",
        files={"file": ("notes.txt", b"just some text, not an email", "text/plain")},
    )

    assert response.status_code == 415


def test_extensionless_upload_is_refused_415() -> None:
    response = client.post(
        "/analyze",
        files={"file": ("no_extension", b"From: a@example.com\r\n\r\nhi", "message/rfc822")},
    )

    assert response.status_code == 415


def test_wrong_type_is_rejected_even_when_oversized(monkeypatch: pytest.MonkeyPatch) -> None:
    # Type is checked before size, so a wrong-type upload reports 415 (not 413)
    # and is never read into memory at all.
    monkeypatch.setattr(web_app_module, "MAX_INPUT_BYTES", 16)
    response = client.post(
        "/analyze",
        files={"file": ("big.txt", b"B" * 4096, "text/plain")},
    )

    assert response.status_code == 415


# --------------------------------------------------------------------------- #
# No-egress guarantees                                                        #
# --------------------------------------------------------------------------- #


def test_served_report_has_no_remote_or_executable_markup() -> None:
    body = _upload(MALICIOUS).text.lower()
    for tag in ("<script", "<iframe", "<img", "<link", "<object", "<embed", "<base"):
        assert tag not in body, f"forbidden markup {tag!r} served by the upload UI"
    for token in ('src="http', "src='http", '="http', "='http", '="//', "='//"):
        assert token not in body, f"remote-load attribute {token!r} served by the upload UI"


def test_responses_carry_strict_no_egress_headers() -> None:
    for response in (client.get("/"), _upload(BENIGN)):
        csp = response.headers["content-security-policy"]
        assert "default-src 'none'" in csp
        assert "script-src 'none'" in csp
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["x-content-type-options"] == "nosniff"
