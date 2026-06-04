"""Phishbowl command-line interface.

Scaffold: this wires up the Typer surface and a *stub* ``analyze`` that loads
input and returns a :class:`~phishbowl.models.ParsedEmail`. No real parsing
happens yet — the message body is not interpreted, only the ``Source`` is
populated. Real parsing lands in Phase 1 per ``docs/CHECKLIST.md``; do not jump
ahead.
"""

from __future__ import annotations

from pathlib import Path

import typer

from phishbowl import __version__
from phishbowl.models import EmailFormat, ParsedEmail, Source

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
)

_FORMATS_BY_SUFFIX = {
    ".eml": EmailFormat.EML,
    ".msg": EmailFormat.MSG,
}


def load_stub(path: str | Path) -> ParsedEmail:
    """Load ``path`` and return a stub :class:`ParsedEmail` (no real parsing).

    Confirms the file exists and is a supported format, then returns a
    ``ParsedEmail`` whose ``Source`` is populated and whose remaining fields
    are left at their (empty) defaults. Phase 1 replaces this with a real
    parser; the contract it returns stays the same.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"no such file: {p}")

    fmt = _FORMATS_BY_SUFFIX.get(p.suffix.casefold())
    if fmt is None:
        supported = ", ".join(sorted(_FORMATS_BY_SUFFIX))
        raise ValueError(f"unsupported input '{p.suffix}'; expected one of: {supported}")

    # Read the bytes to confirm the input loads. The pipeline is not built yet,
    # so we deliberately do not interpret them (no parse, no fetch, no detonate).
    p.read_bytes()

    return ParsedEmail(
        source=Source(filename=p.name, format=fmt, parser_version=__version__),
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


@app.command()
def analyze(
    path: str = typer.Argument(..., help="Path to a suspicious .eml or .msg file."),
) -> None:
    """Triage a suspicious email and produce a report.

    Stub: loads the file into a ``ParsedEmail`` and reports what it loaded. The
    parse/extract/score/report pipeline is not implemented yet. Phishbowl is
    defensive-only: it will never send, detonate, fetch the email's URLs, or
    auto-remediate.
    """
    try:
        parsed = load_stub(path)
    except (FileNotFoundError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc

    typer.echo(
        f"phishbowl: loaded {parsed.source.filename} "
        f"(format={parsed.source.format.value}); "
        "the analysis pipeline is not implemented yet (scaffold)."
    )


if __name__ == "__main__":  # pragma: no cover
    app()
