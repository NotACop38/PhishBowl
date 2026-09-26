"""PhishBowl command-line interface.

Wires up the Typer surface and the ``analyze`` / ``serve`` commands. ``analyze``
runs the full offline pipeline — parse → extract → defang → score → report —
and prints a rich terminal summary, optionally writing HTML / JSON / SOAR drafts.
``--enrich`` layers allowlisted OSINT on top; ``--inner`` re-triages an attached
email inside a forward wrapper (the common SOC hand-off).

Exit status of ``analyze``: ``0`` analysis complete (and below any ``--fail-on``
threshold); ``1`` the score reached the ``--fail-on`` threshold; ``2`` invalid
usage, unreadable input, or an output that could not be written; ``3`` some of
the message's evidence could not be analyzed. Requested outputs are written
before a ``1`` or ``3`` exit.

PhishBowl is defensive-only: it never sends, detonates, fetches the email's
URLs, or auto-remediates (AGENTS.md invariants). Even with ``--enrich``, the only
network egress is to allowlisted vendor APIs — never the analyzed email's URLs.
"""

from __future__ import annotations

import difflib
import os
import stat
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from phishbowl import __version__
from phishbowl.connectors import EnrichmentSettings, discover
from phishbowl.export import render_sentinel, render_xsoar
from phishbowl.parse import list_embedded_emails, parse, parse_bytes, sniff_suffix
from phishbowl.parse.limits import read_stream_within_limit, read_within_limit
from phishbowl.pipeline import triage
from phishbowl.report import (
    SEVERITY_FLOORS,
    RedactionPolicy,
    render_cli,
    render_html,
    render_json,
    severity_for,
)
from phishbowl.score import load_config

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
)

# Exit statuses of ``analyze`` (documented in the module docstring and README).
EXIT_THRESHOLD = 1
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3

# ``--fail-on`` accepts a severity name (the report's ``severity`` field) or a
# number; severity names map to the lowest score of that severity.
_FAIL_ON_SEVERITIES = {slug: floor for floor, slug in SEVERITY_FLOORS if floor > 0}


def _fail_on_threshold(value: str) -> int:
    """Parse ``--fail-on`` into a 0-100 score threshold."""
    key = value.strip().casefold()
    if key in _FAIL_ON_SEVERITIES:
        return _FAIL_ON_SEVERITIES[key]
    try:
        threshold = int(key)
    except ValueError:
        threshold = -1
    if not 0 <= threshold <= 100:
        raise typer.BadParameter(
            f"expected a score from 0 to 100 or one of: {', '.join(_FAIL_ON_SEVERITIES)}",
            param_hint="'--fail-on'",
        )
    return threshold


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
            help="Print the PhishBowl version and exit.",
            is_eager=True,
            callback=_version_callback,
        ),
    ] = False,
) -> None:
    """PhishBowl — self-hostable, defensive-only phishing triage.

    Parse a suspicious .eml/.msg offline, extract and defang its indicators,
    score it with transparent rules, and write an analyst-ready report.
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


def _resolve_parsed(path: str, *, inner_index: int | None):
    """Parse ``path``, or the attached email at ``inner_index`` when one is given."""
    data, filename = _load_input_bytes(path)
    if inner_index is None:
        return parse_bytes(data, filename=filename)

    embedded = list_embedded_emails(data)
    if not embedded:
        raise ValueError(
            "no attached email found to analyze with --inner "
            "(expected a message/rfc822, .eml, or Outlook item attachment)"
        )
    if inner_index >= len(embedded):
        raise ValueError(
            f"--inner-index {inner_index} out of range; "
            f"found {len(embedded)} attached email(s) (0..{len(embedded) - 1})"
        )
    target = embedded[inner_index]
    return parse_bytes(target.data, filename=target.filename)


def _stdin_file_id() -> tuple[int, int] | None:
    """``(device, inode)`` of stdin when it is redirected from a regular file."""
    try:
        info = os.fstat(sys.stdin.fileno())
    except (AttributeError, OSError, ValueError):
        return None  # no real file descriptor (e.g. an in-memory test stream)
    return (info.st_dev, info.st_ino) if stat.S_ISREG(info.st_mode) else None


def _validate_output_paths(source: str, outputs: list[Path], config: Path | None) -> None:
    """Reject unusable or aliased outputs before analysis or enrichment has side effects.

    An output may not overwrite the source email (also when it arrives on stdin
    from a file), the scoring config, or another output, and must go to a
    directory that exists, so a typo fails fast instead of after a slow
    enrichment run.
    """
    from phishbowl.score.config import DEFAULT_CONFIG_PATH, ENV_CONFIG

    protected = [DEFAULT_CONFIG_PATH]
    if source != "-":
        protected.append(Path(source))
    if config is not None:
        protected.append(config)
    if os.environ.get(ENV_CONFIG):
        protected.append(Path(os.environ[ENV_CONFIG]))
    stdin_id = _stdin_file_id() if source == "-" else None

    def aliases(left: Path, right: Path) -> bool:
        return left.resolve() == right.resolve() or (
            left.exists() and right.exists() and left.samefile(right)
        )

    def is_stdin(output: Path) -> bool:
        if stdin_id is None or not output.exists():
            return False
        info = output.stat()
        return (info.st_dev, info.st_ino) == stdin_id

    try:
        for index, output in enumerate(outputs):
            if is_stdin(output) or any(
                aliases(output, other) for other in protected + outputs[:index]
            ):
                raise typer.BadParameter(
                    "output paths must be distinct from the source email, scoring config, "
                    "and other outputs (including filesystem aliases)"
                )
            if output.is_dir():
                raise typer.BadParameter(f"output path is a directory: {output}")
            if not output.resolve().parent.is_dir():
                raise typer.BadParameter(f"output directory does not exist: {output.parent}")
    except (OSError, RuntimeError) as exc:
        raise typer.BadParameter(f"could not validate output paths: {exc}") from exc


def _connector_names(values: list[str] | None, option: str) -> frozenset[str]:
    """Normalize ``--connector`` names, rejecting any no installed connector has."""
    names = frozenset(v.strip().casefold() for v in values or () if v.strip())
    known = sorted(discover())
    for name in sorted(names - set(known)):
        close = difflib.get_close_matches(name, known, n=1)
        hint = f"did you mean {close[0]!r}? " if close else ""
        raise typer.BadParameter(
            f"unknown connector {name!r}; {hint}available: {', '.join(known)}",
            param_hint=f"'{option}'",
        )
    return names


def _write_output(path: Path, text: str, what: str) -> bool:
    """Write one requested output; report a failure instead of a traceback."""
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        typer.echo(f"phishbowl: could not write {what} to {path}: {exc.strerror or exc}", err=True)
        return False
    return True


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
        int | None,
        typer.Option(
            "--inner-index",
            min=0,
            help=(
                "Which attached email to triage when several are present "
                "(0-based; default 0). Implies --inner."
            ),
        ),
    ] = None,
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
            metavar="LEVEL",
            help=(
                "Exit 1 when the score reaches this level: a severity "
                "(low|elevated|high|critical) or a score from 0 to 100."
            ),
        ),
    ] = None,
) -> None:
    """Triage a suspicious email and produce a report (HTML / JSON / CLI).

    Runs the offline pipeline end-to-end with zero API keys and prints a rich
    summary; pass --html/--json to also write those outputs, and
    --xsoar/--sentinel to emit SOAR playbook drafts. Add --enrich to layer in
    OSINT enrichment (key-gated, reading secrets from the environment only). Use
    --inner when the input is a forward wrapper with the phish attached.

    Exit status: 0 complete analysis, 1 --fail-on threshold reached, 2 usage,
    input, or output error, 3 incomplete analysis (some evidence was not analyzed).
    """
    threshold = _fail_on_threshold(fail_on) if fail_on is not None else None
    selected = _connector_names(connector, "--connector")
    disabled = _connector_names(disable_connector, "--disable-connector")

    outputs = [p for p in (html, xsoar, sentinel) if p is not None]
    if json_out is not None and json_out != "-":
        outputs.append(Path(json_out))
    _validate_output_paths(path, outputs, scoring_config)

    if inner and inner_index is None:
        inner_index = 0
    try:
        # Prefer the path-based parser when not doing --inner so existing error
        # messages for unsupported suffixes stay identical; --inner needs bytes.
        if inner_index is not None or path == "-":
            parsed = _resolve_parsed(path, inner_index=inner_index)
        else:
            parsed = parse(path)
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    try:
        config = load_config(path=scoring_config) if scoring_config else load_config()
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(f"scoring config: {exc}") from exc

    want_enrich = bool(enrich or urlscan_submit or selected or disabled)
    enrichment_settings: EnrichmentSettings | None = None
    if want_enrich:
        enrichment_settings = EnrichmentSettings(
            enabled=True,
            urlscan_submit=urlscan_submit,
            select=selected or None,
            disable=disabled,
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
        render_cli(view, Console(highlight=False))

    written = True
    if html is not None:
        if _write_output(html, render_html(view), "the HTML report"):
            if not json_to_stdout:
                typer.echo(f"phishbowl: wrote HTML report to {html}")
        else:
            written = False
    if json_out is not None:
        payload = render_json(view)
        if json_to_stdout:
            sys.stdout.write(payload)
            if not payload.endswith("\n"):
                sys.stdout.write("\n")
        elif _write_output(Path(json_out), payload, "the JSON result"):
            typer.echo(f"phishbowl: wrote JSON result to {json_out}")
        else:
            written = False
    if xsoar is not None:
        if _write_output(xsoar, render_xsoar(view), "the XSOAR playbook draft"):
            if not json_to_stdout:
                typer.echo(
                    f"phishbowl: wrote XSOAR playbook DRAFT to {xsoar} "
                    "(manual tasks only — review before running; PhishBowl never acts)"
                )
        else:
            written = False
    if sentinel is not None:
        if _write_output(sentinel, render_sentinel(view), "the Sentinel playbook draft"):
            if not json_to_stdout:
                typer.echo(
                    f"phishbowl: wrote Microsoft Sentinel playbook DRAFT to {sentinel} "
                    "(ships disabled — review and enable manually; PhishBowl never acts)"
                )
        else:
            written = False
    if not written:
        # A missing requested output outranks the verdict: whatever consumes
        # it (a ticket, a pipeline) would otherwise act on stale or no data.
        raise typer.Exit(EXIT_USAGE)

    # A score at or above the threshold is conclusive even when the analysis is
    # incomplete (the score can only be a lower bound); below it, an incomplete
    # analysis cannot vouch for the message.
    if threshold is not None and result.score >= threshold:
        if not quiet:
            typer.echo(
                f"phishbowl: score {result.score} (severity {severity_for(result.score)}) "
                f"reached the --fail-on threshold {threshold}",
                err=True,
            )
        raise typer.Exit(EXIT_THRESHOLD)
    if not result.analysis_complete:
        if not quiet:
            typer.echo(
                "phishbowl: analysis incomplete — some evidence was not analyzed; "
                "see the listed limitations",
                err=True,
            )
        raise typer.Exit(EXIT_INCOMPLETE)


@app.command()
def serve(
    host: Annotated[
        str,
        typer.Option("--host", help="Interface to bind. Defaults to localhost only."),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", "-p", min=0, max=65535, help="Port to listen on."),
    ] = 8000,
) -> None:
    """Run the optional local upload UI (requires the 'web' extra).

    Serves a browser front door that runs the same offline pipeline as
    'analyze' and returns the identical self-contained report. Uploads are
    size- and type-checked and analyzed in memory. Binds to localhost by
    default: a single-user analyst tool, not a public service. Install with:
    pip install 'phishbowl[web]'.
    """
    try:
        import uvicorn

        from phishbowl.web import app as web_app
    except ImportError as exc:  # pragma: no cover - exercised via the install path
        raise typer.BadParameter(
            "the upload UI needs the optional 'web' extra — "
            "install it with: pip install 'phishbowl[web]'"
        ) from exc

    shown = f"[{host}]" if ":" in host else host  # an IPv6 literal needs brackets in a URL
    typer.echo(f"phishbowl: serving the upload UI on http://{shown}:{port} (Ctrl-C to stop)")
    if not _is_loopback(host):
        typer.echo(
            "phishbowl: warning — the upload UI has no authentication; binding to a "
            "non-loopback interface lets anyone who can reach it submit files",
            err=True,
        )
    uvicorn.run(web_app, host=host, port=port)


def _is_loopback(host: str) -> bool:
    """True when ``host`` names only this machine (``localhost`` or a loopback IP)."""
    import ipaddress

    if host.strip().casefold().rstrip(".") == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip().strip("[]")).is_loopback
    except ValueError:
        return False


if __name__ == "__main__":  # pragma: no cover
    app()
