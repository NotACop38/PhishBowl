"""Phishbowl command-line interface.

Wires up the Typer surface and the ``analyze`` command. As of Phase 4 (the
offline MVP milestone), ``analyze`` runs the full offline pipeline —
parse → extract → defang → score → report — and prints a rich terminal summary,
optionally writing a self-contained HTML report and/or a complete JSON result.

Phase 5 adds an opt-in ``--enrich`` flag: with API keys configured (env only),
it augments the offline verdict with allowlisted OSINT connectors and re-scores,
tagging every added point ``[enrichment]``. Without ``--enrich`` (and without
keys) the pipeline is entirely offline and unchanged.

Phase 6 adds optional SOAR export: ``--xsoar`` and ``--sentinel`` write a Cortex
XSOAR playbook and a Microsoft Sentinel playbook (Logic App ARM template)
respectively. These are **drafts** — every XSOAR task is manual and the Sentinel
workflow ships disabled — so importing one triggers no automation.

Phase 7 (stretch) adds ``serve``: an optional FastAPI upload UI that runs the
**same** offline pipeline and renders the **same** zero-egress report — no logic
fork. It lives behind the ``web`` extra and is imported lazily, so the offline
CLI never hard-requires FastAPI.

Phishbowl is defensive-only: it never sends, detonates, fetches the email's
URLs, or auto-remediates (CLAUDE.md invariants). Even with ``--enrich``, the only
network egress is to allowlisted vendor APIs — never the analyzed email's URLs.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from phishbowl.connectors import EnrichmentReport, EnrichmentSettings, enrich_email
from phishbowl.export import render_sentinel, render_xsoar
from phishbowl.extract import extract_iocs
from phishbowl.models import ParsedEmail
from phishbowl.parse import parse, parse_bytes, sniff_suffix
from phishbowl.parse.limits import read_stream_within_limit
from phishbowl.report import (
    RedactionPolicy,
    build_report,
    render_cli,
    render_html,
    render_json,
)
from phishbowl.score import load_config, score_email

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """Phishbowl — a self-hostable, defensive-only phishing triage tool.

    Offline-first phishing triage: parse a suspicious .eml/.msg, extract and
    defang IOCs, risk-score it, and produce an analyst-ready report.

    This callback intentionally does nothing; it exists so that ``analyze``
    (and future commands) stay subcommands — i.e. ``phishbowl analyze <file>``
    — instead of Typer collapsing a lone command into the root program.
    """


def _parse_stdin() -> ParsedEmail:
    """Read an email from stdin (``analyze -``) and parse it (PRD §6.1).

    Stdin has no filename to dispatch on, so the format is sniffed from the
    bytes (OLE2 magic → ``.msg``, else ``.eml``) and handed to the very same
    :func:`parse_bytes` path the upload UI uses. The read is bounded by the
    parse layer's size cap, so a runaway pipe can never be slurped whole, and
    an empty stream is a clean usage error rather than a meaningless report.
    """
    data = read_stream_within_limit(sys.stdin.buffer)
    if not data:
        raise ValueError(
            "no input on stdin; pipe a .eml/.msg, e.g. `phishbowl analyze - < mail.eml`"
        )
    return parse_bytes(data, filename=f"stdin{sniff_suffix(data)}")


@app.command()
def analyze(
    path: Annotated[
        str,
        typer.Argument(help="Path to a suspicious .eml or .msg file, or '-' to read from stdin."),
    ],
    html: Annotated[
        Path | None,
        typer.Option("--html", "-H", help="Write the self-contained HTML report to this path."),
    ] = None,
    json_out: Annotated[
        Path | None,
        typer.Option("--json", "-j", help="Write the complete JSON result to this path."),
    ] = None,
    xsoar: Annotated[
        Path | None,
        typer.Option(
            "--xsoar",
            help="Write a Cortex XSOAR playbook DRAFT (YAML) to this path. Manual tasks only.",
        ),
    ] = None,
    sentinel: Annotated[
        Path | None,
        typer.Option(
            "--sentinel",
            help="Write a Microsoft Sentinel playbook DRAFT (ARM JSON). Ships disabled.",
        ),
    ] = None,
    redact: Annotated[
        bool,
        typer.Option("--redact", help="Redact bystander PII (recipients, internal hosts/IPs)."),
    ] = False,
    redact_field: Annotated[
        list[str] | None,
        typer.Option("--redact-field", help="Header to redact (repeatable). Implies --redact."),
    ] = None,
    enrich: Annotated[
        bool,
        typer.Option(
            "--enrich",
            help="Augment the verdict with allowlisted OSINT connectors (needs API keys in env).",
        ),
    ] = False,
    urlscan_submit: Annotated[
        bool,
        typer.Option(
            "--urlscan-submit",
            help="Allow urlscan to actively submit URLs (private by default). Implies --enrich.",
        ),
    ] = False,
) -> None:
    """Triage a suspicious email and produce a report (HTML / JSON / CLI).

    Runs the offline pipeline end-to-end with zero API keys and prints a rich
    summary; pass ``--html``/``--json`` to also write those outputs, and
    ``--xsoar``/``--sentinel`` to emit SOAR playbook drafts. Add ``--enrich`` to
    layer in OSINT enrichment (key-gated, reading secrets from the environment
    only). Phishbowl is defensive-only: it never sends, detonates, fetches the
    email's URLs, or auto-remediates — SOAR exports are inert drafts for an analyst
    to review, never executed automation.
    """
    try:
        parsed = _parse_stdin() if path == "-" else parse(path)
    except (OSError, ValueError) as exc:
        # Missing, unreadable (permissions/I/O), or unsupported input degrades
        # into a clean CLI error rather than an internal traceback (PRD §11).
        raise typer.BadParameter(str(exc)) from exc

    config = load_config()
    iocs = extract_iocs(parsed)

    enrichment: EnrichmentReport | None = None
    if enrich or urlscan_submit:
        settings = EnrichmentSettings(
            enabled=True,
            urlscan_submit=urlscan_submit,
        )
        enrichment = enrich_email(parsed, iocs, settings)

    result = score_email(parsed, iocs, config, enrichment=enrichment)

    extra_fields = tuple(redact_field or ())
    policy = (
        RedactionPolicy.standard(extra_fields=extra_fields)
        if redact or extra_fields
        else RedactionPolicy.disabled()
    )
    view = build_report(parsed, iocs, result, policy=policy, config=config, enrichment=enrichment)

    render_cli(view, Console())

    if html is not None:
        html.write_text(render_html(view), encoding="utf-8")
        typer.echo(f"phishbowl: wrote HTML report to {html}")
    if json_out is not None:
        json_out.write_text(render_json(view), encoding="utf-8")
        typer.echo(f"phishbowl: wrote JSON result to {json_out}")
    if xsoar is not None:
        xsoar.write_text(render_xsoar(view), encoding="utf-8")
        typer.echo(
            f"phishbowl: wrote XSOAR playbook DRAFT to {xsoar} "
            "(manual tasks only — review before running; Phishbowl never acts)"
        )
    if sentinel is not None:
        sentinel.write_text(render_sentinel(view), encoding="utf-8")
        typer.echo(
            f"phishbowl: wrote Microsoft Sentinel playbook DRAFT to {sentinel} "
            "(ships disabled — review and enable manually; Phishbowl never acts)"
        )


@app.command()
def serve(
    host: Annotated[
        str,
        typer.Option("--host", help="Interface to bind. Defaults to localhost only."),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", "-p", help="Port to listen on."),
    ] = 8000,
) -> None:
    """Run the optional FastAPI upload UI (PRD §15 stretch).

    Serves a minimal browser front door that runs the **same** offline pipeline
    as ``analyze`` and renders the identical self-contained, zero-egress report —
    no logic fork. Uploads are hardened (size + type limits, analyzed in memory,
    never written to disk/executed/fetched). Binds to localhost by default; this
    is a self-hosted analyst tool, not a public service. Requires the ``web``
    extra: ``pip install 'phishbowl[web]'``.
    """
    try:
        import uvicorn

        # Import lazily so the offline CLI never hard-requires FastAPI just to
        # run ``analyze``. Keep it in the same optional-extra guard as uvicorn:
        # an environment can have one web dependency but not the other.
        from phishbowl.web import app as web_app
    except ImportError as exc:  # pragma: no cover - exercised via the install path
        raise typer.BadParameter(
            "the upload UI needs the optional 'web' extra — "
            "install it with: pip install 'phishbowl[web]'"
        ) from exc

    typer.echo(f"phishbowl: serving the upload UI on http://{host}:{port} (Ctrl-C to stop)")
    uvicorn.run(web_app, host=host, port=port)


if __name__ == "__main__":  # pragma: no cover
    app()
