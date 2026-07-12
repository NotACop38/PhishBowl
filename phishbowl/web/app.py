"""The FastAPI application: upload a suspicious email, get the report back.

Two routes, both serving self-contained, zero-egress HTML:

* ``GET /`` — a tiny upload form (static markup, no remote assets);
* ``POST /analyze`` — accept one ``.eml``/``.msg`` upload, run the offline
  pipeline, and return the **same** report :func:`phishbowl.report.render_html`
  produces for the CLI.

Upload hardening (PRD §13, CHECKLIST Phase 7), in order:

1. **Type check** — the filename suffix must be ``.eml`` or ``.msg``;
2. **Size limit** — bounded chunked read capped at ``MAX_INPUT_BYTES``.

The pipeline itself reaches no network and the report loads nothing remote;
strict ``Content-Security-Policy`` / ``Referrer-Policy`` / nosniff headers are
attached as belt-and-suspenders. Form options (redact / analyze attached email)
map to the same ``RedactionPolicy`` / ``--inner`` paths the CLI uses — no fork.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response

from phishbowl.parse import SUPPORTED_SUFFIXES, list_embedded_emails, parse_bytes
from phishbowl.parse.limits import MAX_INPUT_BYTES
from phishbowl.pipeline import triage
from phishbowl.report import RedactionPolicy, render_html
from phishbowl.score import load_config

_READ_CHUNK = 1024 * 1024

_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
    "font-src 'none'; script-src 'none'; base-uri 'none'; form-action 'self'"
)

_MAX_MIB = MAX_INPUT_BYTES // (1024 * 1024)

_UPLOAD_PAGE = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Phishbowl — triage an email</title>
<style>
  :root {{
    color-scheme: light dark;
    --ink: #142028;
    --muted: #4a5a66;
    --faint: #7a8a96;
    --paper: #e8eef2;
    --card: #f4f7f9;
    --line: #b8c4ce;
    --accent: #0d6e6e;
    --accent-ink: #e6f7f5;
    --font-display: "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, serif;
    --font-body: "Segoe UI", "Helvetica Neue", sans-serif;
    --font-mono: ui-monospace, "Cascadia Code", "SF Mono", Menlo, monospace;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --ink: #e4ebee;
      --muted: #9aabb6;
      --faint: #6a7a86;
      --paper: #0e1418;
      --card: #151c22;
      --line: #2a3640;
      --accent: #2aa8a0;
      --accent-ink: #061414;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; min-height: 100vh; color: var(--ink);
    font-family: var(--font-body); line-height: 1.55;
    background:
      radial-gradient(1100px 560px at 8% -8%,
        color-mix(in srgb, var(--accent) 16%, transparent), transparent 58%),
      radial-gradient(800px 480px at 100% 0%,
        color-mix(in srgb, #2a5a8a 14%, transparent), transparent 50%),
      linear-gradient(165deg, var(--paper), color-mix(in srgb, var(--paper) 88%, var(--accent)));
  }}
  .wrap {{ max-width: 40rem; margin: 0 auto; padding: 4.5rem 1.25rem 3rem; }}
  .brand {{
    font-family: var(--font-display); font-size: clamp(2.6rem, 7vw, 3.4rem);
    font-weight: 600; letter-spacing: -0.02em; line-height: 1.05; margin: 0;
  }}
  .brand b {{ color: var(--accent); font-weight: 600; }}
  .lede {{ color: var(--muted); font-size: 1.05rem; margin: 0.85rem 0 0; max-width: 34rem; }}
  form.panel {{
    margin-top: 2rem; padding: 1.5rem; background: var(--card);
    border: 1px solid var(--line); border-radius: 2px;
  }}
  .drop {{
    display: block; border: 1.5px dashed var(--line); border-radius: 2px;
    padding: 1.35rem 1rem; text-align: center; color: var(--muted);
    background: color-mix(in srgb, var(--paper) 70%, transparent);
    transition: border-color 160ms ease, background 160ms ease;
  }}
  .drop:focus-within {{
    border-color: var(--accent);
    background: color-mix(in srgb, var(--accent) 8%, var(--card));
  }}
  .drop strong {{ display: block; color: var(--ink); font-size: 1rem; margin-bottom: 0.35rem; }}
  .drop span {{ font-size: 0.85rem; }}
  input[type=file] {{
    display: block; width: 100%; margin-top: 0.85rem; font: inherit; color: var(--ink);
  }}
  .opts {{ margin: 1.15rem 0 0; display: grid; gap: 0.65rem; }}
  .opts label {{
    display: flex; gap: 0.65rem; align-items: flex-start;
    font-size: 0.92rem; color: var(--ink); cursor: pointer;
  }}
  .opts input {{ margin-top: 0.2rem; accent-color: var(--accent); }}
  .opts small {{ display: block; color: var(--faint); font-size: 0.8rem; margin-top: 0.15rem; }}
  button {{
    margin-top: 1.25rem; font: inherit; font-weight: 600; letter-spacing: 0.01em;
    padding: 0.7rem 1.35rem; border-radius: 2px; cursor: pointer;
    border: none; background: var(--accent); color: var(--accent-ink);
  }}
  button:hover {{ filter: brightness(1.05); }}
  button:active {{ transform: translateY(1px); }}
  .note {{
    margin: 1.1rem 0 0; font-size: 0.8rem; color: var(--faint);
    font-family: var(--font-mono);
  }}
  .inv {{
    margin-top: 2.5rem; padding-top: 1.25rem; border-top: 1px solid var(--line);
    font-size: 0.8rem; color: var(--faint); line-height: 1.7;
  }}
  code {{ font-family: var(--font-mono); font-size: 0.88em; }}
</style>
</head>
<body>
  <main class="wrap">
    <h1 class="brand">Phish<b>Bowl</b></h1>
    <p class="lede">Drop in a suspicious <code>.eml</code> or <code>.msg</code>.
      Phishbowl never sends, opens, or fetches anything from the email — it only
      parses it locally and renders a self-contained report.</p>
    <form class="panel" action="analyze" method="post" enctype="multipart/form-data">
      <label class="drop" for="file">
        <strong>Suspicious email</strong>
        <span>Choose a <code>.eml</code> or <code>.msg</code> file to triage</span>
        <input id="file" type="file" name="file" accept=".eml,.msg" required>
      </label>
      <div class="opts">
        <label>
          <input type="checkbox" name="inner" value="1">
          <span>Analyze attached email if present
            <small>For forward wrappers — triage the enclosed message/rfc822
              instead of the outer mail.</small>
          </span>
        </label>
        <label>
          <input type="checkbox" name="redact" value="1">
          <span>Redact bystander PII
            <small>Withhold recipients and internal hosts/IPs so the report
              is safer to share.</small>
          </span>
        </label>
      </div>
      <button type="submit">Analyze</button>
      <p class="note">Max {_MAX_MIB} MiB · analyzed in memory · never written
        to disk, executed, or contacted</p>
    </form>
    <p class="inv">Defensive-only · offline-first · zero-egress report ·
      never sends, detonates, fetches, or remediates.</p>
  </main>
</body>
</html>
"""


def _error_page(title: str, message: str, status: int) -> HTMLResponse:
    """Self-contained HTML error page (browsers should never see raw JSON here)."""
    # title/message are tool-authored, never email-derived — still escape for safety.
    from html import escape

    body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Phishbowl — {escape(title)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{
    font-family: Georgia, "Times New Roman", serif; line-height: 1.5;
    max-width: 36rem; margin: 4rem auto; padding: 0 1.25rem;
  }}
  h1 {{ font-size: 1.6rem; margin-bottom: 0.4rem; }}
  p {{ opacity: 0.85; }}
  a {{ color: inherit; }}
  code {{ font-family: ui-monospace, monospace; }}
</style>
</head>
<body>
  <h1>{escape(title)}</h1>
  <p>{escape(message)}</p>
  <p><a href="/">← Back to upload</a></p>
</body>
</html>
"""
    return HTMLResponse(body, status_code=status)


def create_app() -> FastAPI:
    """Build the Phishbowl upload application."""
    app = FastAPI(
        title="Phishbowl",
        description="Defensive-only phishing triage — upload an email, get a report.",
        docs_url=None,
        redoc_url=None,
    )

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = _CSP
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.exception_handler(HTTPException)
    async def _html_http_error(request: Request, exc: HTTPException) -> Response:
        accept = (request.headers.get("accept") or "").casefold()
        if "application/json" in accept and "text/html" not in accept:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        title = {
            413: "Upload too large",
            415: "Unsupported file type",
            400: "Could not analyze",
        }.get(exc.status_code, f"Error {exc.status_code}")
        detail = exc.detail if isinstance(exc.detail, str) else "Request failed."
        return _error_page(title, detail, exc.status_code)

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        return HTMLResponse(_UPLOAD_PAGE)

    @app.post("/analyze", response_class=HTMLResponse)
    async def analyze(
        file: UploadFile,
        inner: Annotated[str, Form()] = "",
        redact: Annotated[str, Form()] = "",
    ) -> Response:
        return await _analyze_upload(file, inner=bool(inner), redact=bool(redact))

    return app


async def _analyze_upload(
    file: UploadFile,
    *,
    inner: bool = False,
    redact: bool = False,
) -> HTMLResponse:
    """Type-check, size-check, then run the shared pipeline and render HTML."""
    filename = file.filename or ""
    if Path(filename).suffix.casefold() not in SUPPORTED_SUFFIXES:
        raise HTTPException(
            status_code=415,
            detail="Unsupported file type — upload a .eml or .msg email.",
        )

    data = await _read_within_limit(file)

    try:
        if inner:
            embedded = list_embedded_emails(data, filename=filename)
            if not embedded:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "No attached email found. Uncheck “Analyze attached email” "
                        "to triage this message as-is, or upload a forward that "
                        "includes a message/rfc822 / .eml attachment."
                    ),
                )
            target = embedded[0]
            parsed = parse_bytes(target.data, filename=target.filename)
        else:
            parsed = parse_bytes(data, filename=filename)
    except HTTPException:
        raise
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    policy = RedactionPolicy.standard() if redact else RedactionPolicy.disabled()
    view, _result = triage(parsed, config=load_config(), policy=policy)
    return HTMLResponse(render_html(view))


async def _read_within_limit(file: UploadFile) -> bytes:
    """Read the upload, refusing anything over :data:`MAX_INPUT_BYTES`."""
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
            detail=(f"Upload exceeds the {_MAX_MIB} MiB limit and was refused before parsing."),
        )
    return data
