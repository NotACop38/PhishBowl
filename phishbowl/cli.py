"""Phishbowl command-line interface.

Wires up the Typer surface and the ``analyze`` / ``serve`` commands. ``analyze``
runs the full offline pipeline — parse → extract → defang → score → report —
and prints a rich terminal summary, optionally writing HTML / JSON / SOAR drafts.
``--enrich`` layers allowlisted OSINT on top; ``--inner`` re-triages an attached
email inside a forward wrapper (the common SOC hand-off).

Phishbowl is defensive-only: it never sends, detonates, fetches the email's
URLs, or auto-remediates (CLAUDE.md invariants). Even with ``--enrich``, the only
network egress is to allowlisted vendor APIs — never the analyzed email's URLs.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from phishbowl import __version__
from phishbowl.connectors import EnrichmentSettings
from phishbowl.export import render_sentinel, render_xsoar
from phishbowl.parse import list_embedded_emails, parse, parse_bytes, sniff_suffix
from phishbowl.parse.limits import read_stream_within_limit, read_within_limit
from phishbowl.pipeline import triage
from phishbowl.report import RedactionPolicy, render_cli, render_html, render_json, severity_for
from phishbowl.score import load_config

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
)

# ``--fail-on`` thresholds keyed by severity slug (same bands as the report).
_FAIL_ON_THRESHOLDS = {
    "low": 20,
    "suspicious": 40,
    "elevated": 40,
    "likely": 65,
    "high": 65,
    "malicious": 85,
    "critical": 85,
}


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"phishbowl {__version__}")
        raise typer.Exit(0)


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Print the Phishbowl version and exit.",
            is_eager=True,
            callback=_version_callback,
        ),
    ] = False,
) -> None:
    """Phishbowl — a self-hostable, defensive-only phishing triage tool.

    Offline-first phishing triage: parse a suspicious .eml/.msg, extract and
    defang IOCs, risk-score it, and produce an analyst-ready report.
    """
    _ = version


def _load_input_bytes(path: str) -> tuple[bytes, str]:
    """Return ``(bytes, filename)`` for a path or stdin (``-``)."""
    if path == "-":
        data = read_stream_within_limit(sys.stdin.buffer)
        if not data:
            raise ValueError(
                "no input on stdin; pipe a .eml/.msg, e.g. `phishbowl analyze - < mail.eml`"
            )
        return data, f"stdin{sniff_suffix(data)}"
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"no such file: {path}")
    return read_within_limit(p), p.name


def _resolve_parsed(
    path: str,
    *,
    inner: bool,
    inner_index: int,
):
    """Parse ``path``, optionally swapping in an attached inner email."""
    data, filename = _load_input_bytes(path)
    if not inner:
        return parse_bytes(data, filename=filename)

    embedded = list_embedded_emails(data, filename=filename)
    if not embedded:
        raise ValueError(
            "no attached email found to analyze with --inner "
            "(expected a message/rfc822 or .eml attachment)"
        )
    if inner_index < 0 or inner_index >= len(embedded):
        raise ValueError(
            f"--inner-index {inner_index} out of range; "
            f"found {len(embedded)} attached email(s) (0..{len(embedded) - 1})"
        )
    target = embedded[inner_index]
    return parse_bytes(target.data, filename=target.filename)


def _validate_output_paths(source: str, outputs: list[Path], config: Path | None) -> None:
    """Reject aliases before analysis or enrichment can have side effects."""
    from phishbowl.score.config import DEFAULT_CONFIG_PATH, ENV_CONFIG

    protected = [DEFAULT_CONFIG_PATH]
    if source != "-":
        protected.append(Path(source))
    if config is not None:
        protected.append(config)
    if os.environ.get(ENV_CONFIG):
        protected.append(Path(os.environ[ENV_CONFIG]))

    def aliases(left: Path, right: Path) -> bool:
        return left.resolve() == right.resolve() or (
            left.exists() and right.exists() and left.samefile(right)
        )

    try:
        for index, output in enumerate(outputs):
            if any(aliases(output, other) for other in protected + outputs[:index]):
                raise typer.BadParameter(
                    "output paths must be distinct from the source email, scoring config, "
                    "and other outputs (including filesystem aliases)"
                )
    except (OSError, RuntimeError) as exc:
        raise typer.BadParameter(f"could not validate output paths: {exc}") from exc


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
        str | None,
        typer.Option(
            "--json",
            "-j",
            help="Write the complete JSON result to this path, or '-' for stdout.",
        ),
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
    connector: Annotated[
        list[str] | None,
        typer.Option(
            "--connector",
            help="Only run this enrichment connector (repeatable). Implies --enrich.",
        ),
    ] = None,
    disable_connector: Annotated[
        list[str] | None,
        typer.Option(
            "--disable-connector",
            help="Skip this enrichment connector (repeatable). Implies --enrich.",
        ),
    ] = None,
    scoring_config: Annotated[
        Path | None,
        typer.Option(
            "--scoring-config",
            help="YAML scoring override layered over the bundled defaults.",
        ),
    ] = None,
    inner: Annotated[
        bool,
        typer.Option(
            "--inner",
            help="Triage an attached email (message/rfc822 / .eml) instead of the outer wrapper.",
        ),
    ] = False,
    inner_index: Annotated[
        int,
        typer.Option(
            "--inner-index",
            help=(
                "Which attached email to triage when several are present "
                "(0-based). Implies --inner."
            ),
        ),
    ] = 0,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            "-q",
            help="Suppress the rich CLI summary (still writes --html/--json/etc.).",
        ),
    ] = False,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help=(
                "Exit 1 when the severity is at least this level "
                "(low|suspicious|likely|malicious). Useful for SOAR/CI glue."
            ),
        ),
    ] = None,
) -> None:
    """Triage a suspicious email and produce a report (HTML / JSON / CLI).

    Runs the offline pipeline end-to-end with zero API keys and prints a rich
    summary; pass ``--html``/``--json`` to also write those outputs, and
    ``--xsoar``/``--sentinel`` to emit SOAR playbook drafts. Add ``--enrich`` to
    layer in OSINT enrichment (key-gated, reading secrets from the environment
    only). Use ``--inner`` when the input is a forward wrapper with the phish
    attached. Phishbowl is defensive-only: it never sends, detonates, fetches the
    email's URLs, or auto-remediates.
    """
    if fail_on is not None:
        key = fail_on.strip().casefold()
        if key not in _FAIL_ON_THRESHOLDS:
            raise typer.BadParameter(
                f"unknown --fail-on level '{fail_on}'; "
                f"expected one of: {', '.join(sorted(set(_FAIL_ON_THRESHOLDS)))}"
            )

    outputs = [p for p in (html, xsoar, sentinel) if p is not None]
    if json_out is not None and json_out != "-":
        outputs.append(Path(json_out))
    _validate_output_paths(path, outputs, scoring_config)

    use_inner = inner or (inner_index != 0)
    try:
        # Prefer the path-based parser when not doing --inner so existing error
        # messages for unsupported suffixes stay identical; --inner needs bytes.
        if use_inner or path == "-":
            parsed = _resolve_parsed(path, inner=use_inner, inner_index=inner_index)
        else:
            parsed = parse(path)
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    try:
        config = load_config(path=scoring_config) if scoring_config else load_config()
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(f"scoring config: {exc}") from exc

    want_enrich = bool(enrich or urlscan_submit or connector or disable_connector)
    enrichment_settings: EnrichmentSettings | None = None
    if want_enrich:
        enrichment_settings = EnrichmentSettings(
            enabled=True,
            urlscan_submit=urlscan_submit,
            select=frozenset(c.strip().casefold() for c in connector) if connector else None,
            disable=frozenset(c.strip().casefold() for c in (disable_connector or ())),
        )

    extra_fields = tuple(redact_field or ())
    policy = (
        RedactionPolicy.standard(extra_fields=extra_fields)
        if redact or extra_fields
        else RedactionPolicy.disabled()
    )

    view, result = triage(
        parsed,
        config=config,
        policy=policy,
        enrichment_settings=enrichment_settings,
    )

    # JSON to stdout suppresses the Rich summary unless the operator also asked
    # for HTML/SOAR (those still need a place to acknowledge writes).
    json_to_stdout = json_out == "-"
    show_cli = not quiet and not json_to_stdout
    if show_cli:
        render_cli(view, Console())

    if html is not None:
        html.write_text(render_html(view), encoding="utf-8")
        if not json_to_stdout:
            typer.echo(f"phishbowl: wrote HTML report to {html}")
    if json_out is not None:
        payload = render_json(view)
        if json_to_stdout:
            sys.stdout.write(payload)
            if not payload.endswith("\n"):
                sys.stdout.write("\n")
        else:
            Path(json_out).write_text(payload, encoding="utf-8")
            typer.echo(f"phishbowl: wrote JSON result to {json_out}")
    if xsoar is not None:
        xsoar.write_text(render_xsoar(view), encoding="utf-8")
        if not json_to_stdout:
            typer.echo(
                f"phishbowl: wrote XSOAR playbook DRAFT to {xsoar} "
                "(manual tasks only — review before running; Phishbowl never acts)"
            )
    if sentinel is not None:
        sentinel.write_text(render_sentinel(view), encoding="utf-8")
        if not json_to_stdout:
            typer.echo(
                f"phishbowl: wrote Microsoft Sentinel playbook DRAFT to {sentinel} "
                "(ships disabled — review and enable manually; Phishbowl never acts)"
            )

    if not result.analysis_complete:
        raise typer.Exit(2)

    if fail_on is not None:
        if result.score >= _FAIL_ON_THRESHOLDS[key]:
            if show_cli:
                typer.echo(
                    f"phishbowl: failing (score {result.score}, "
                    f"severity={severity_for(result.score)}) — threshold '{key}'",
                    err=True,
                )
            raise typer.Exit(1)


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
