"""The FastAPI application: upload a suspicious email, get the report back.

Two routes, both serving self-contained, zero-egress HTML:

* ``GET /`` — a tiny upload form (static markup, no remote assets);
* ``POST /analyze`` — accept one ``.eml``/``.msg`` upload, run the offline
  pipeline, and return the **same** report :func:`phishbowl.report.render_html`
  produces for the CLI.

Upload hardening (PRD §13, CHECKLIST Phase 7), in order:

1. **Type check** — the filename suffix must be ``.eml`` or ``.msg`` (the same
   :data:`~phishbowl.parse.SUPPORTED_SUFFIXES` the CLI accepts); anything else is
   rejected ``415`` before a single byte is parsed.
2. **Size limit** — the body is read in bounded chunks up to exactly one byte
   past :data:`~phishbowl.parse.limits.MAX_INPUT_BYTES` and rejected ``413`` if
   that much arrives, so an oversized (or chunked / lying-``Content-Length``)
   upload can never be slurped whole into memory.

The pipeline itself reaches no network and the report loads nothing remote;
strict ``Content-Security-Policy`` / ``Referrer-Policy`` / nosniff headers are
attached as belt-and-suspenders so a browser opening the report still makes zero
outbound requests even if the static template ever regressed.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, Response

from phishbowl.extract import extract_iocs
from phishbowl.parse import SUPPORTED_SUFFIXES, parse_bytes
from phishbowl.parse.limits import MAX_INPUT_BYTES
from phishbowl.report import build_report, render_html
from phishbowl.score import load_config, score_email

# Read the upload body in 1 MiB chunks, capping at one byte past the limit so we
# can detect an over-cap upload without ever buffering more than that.
_READ_CHUNK = 1024 * 1024

# Defense-in-depth for the rendered report: forbid every remote-load vector while
# allowing the report's inline ``<style>`` (and ``style=`` attributes), and let
# the upload form post back to its own origin. This reinforces the report's own
# zero-egress guarantee (PRD §10) at the transport layer — a browser honours it
# even before parsing the document.
_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
    "font-src 'none'; script-src 'none'; base-uri 'none'; form-action 'self'"
)

# The upload form. Deliberately a static, self-contained document: no email-derived
# content, no remote assets, no JavaScript — so it carries the same zero-egress
# property as the report and needs no autoescaping.
_UPLOAD_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Phishbowl — triage an email</title>
<style>
  :root { color-scheme: light dark; }
  body {
    font-family: ui-sans-serif, system-ui, sans-serif; line-height: 1.5;
    max-width: 42rem; margin: 4rem auto; padding: 0 1.25rem;
  }
  h1 { font-family: Georgia, "Times New Roman", serif; font-weight: 600; }
  .card {
    border: 1px solid color-mix(in srgb, currentColor 25%, transparent);
    border-radius: 0.75rem; padding: 1.5rem; margin-top: 1.5rem;
  }
  input[type=file] { display: block; margin: 1rem 0; width: 100%; }
  button {
    font: inherit; padding: 0.6rem 1.25rem; border-radius: 0.5rem;
    border: 1px solid currentColor; cursor: pointer; background: transparent;
  }
  .note { font-size: 0.85rem; opacity: 0.75; }
  code { font-family: ui-monospace, SFMono-Regular, monospace; }
</style>
</head>
<body>
  <h1>Phishbowl</h1>
  <p>Drop in a suspicious <code>.eml</code> or <code>.msg</code> to triage it.
     Phishbowl never sends, opens, or fetches anything from the email — it only
     parses it locally and renders a self-contained report.</p>
  <form class="card" action="analyze" method="post" enctype="multipart/form-data">
    <label for="file"><strong>Suspicious email</strong></label>
    <input id="file" type="file" name="file" accept=".eml,.msg" required>
    <button type="submit">Analyze</button>
    <p class="note">Max __MAX_MIB__ MiB. The file is analyzed in memory and never
       written to disk, executed, or contacted.</p>
  </form>
</body>
</html>
""".replace("__MAX_MIB__", str(MAX_INPUT_BYTES // (1024 * 1024)))


def create_app() -> FastAPI:
    """Build the Phishbowl upload application."""
    app = FastAPI(
        title="Phishbowl",
        description="Defensive-only phishing triage — upload an email, get a report.",
        docs_url=None,  # no Swagger UI: it loads remote assets, breaking zero-egress
        redoc_url=None,
    )

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        """Stamp every response with strict no-egress / no-sniff headers."""
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = _CSP
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        return HTMLResponse(_UPLOAD_PAGE)

    @app.post("/analyze", response_class=HTMLResponse)
    async def analyze(file: UploadFile) -> Response:
        # A bare ``UploadFile`` parameter is FastAPI's idiom for a required
        # multipart file upload (no ``File(...)`` default needed).
        return await _analyze_upload(file)

    return app


async def _analyze_upload(file: UploadFile) -> HTMLResponse:
    """Type-check, size-check, then run the unchanged pipeline and render HTML."""
    filename = file.filename or ""
    if Path(filename).suffix.casefold() not in SUPPORTED_SUFFIXES:
        # Reject the wrong type up front, before reading or parsing the body.
        raise HTTPException(
            status_code=415,
            detail="unsupported file type; upload a .eml or .msg email",
        )

    data = await _read_within_limit(file)

    # From here on it is the identical offline pipeline the CLI runs — same
    # ParsedEmail, same scorer, same report layer — with no fork (PRD §15).
    parsed = parse_bytes(data, filename=filename)
    config = load_config()
    iocs = extract_iocs(parsed)
    result = score_email(parsed, iocs, config)
    view = build_report(parsed, iocs, result, config=config)
    return HTMLResponse(render_html(view))


async def _read_within_limit(file: UploadFile) -> bytes:
    """Read the upload, refusing anything over :data:`MAX_INPUT_BYTES`.

    Reads in bounded chunks up to one byte past the cap so an oversized body —
    or one whose ``Content-Length`` lies or is absent (chunked) — is rejected
    ``413`` without ever being fully buffered, mirroring the parse layer's
    :func:`phishbowl.parse.limits.read_within_limit` file guard.
    """
    remaining = MAX_INPUT_BYTES + 1
    chunks: list[bytes] = []
    while remaining > 0:
        chunk = await file.read(min(_READ_CHUNK, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > MAX_INPUT_BYTES:
        raise HTTPException(
            status_code=413,
            detail=(
                f"upload exceeds the {MAX_INPUT_BYTES // (1024 * 1024)} MiB limit; "
                "refused before parsing"
            ),
        )
    return data
