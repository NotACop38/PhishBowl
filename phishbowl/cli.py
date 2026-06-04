"""Phishbowl command-line interface.

Wires up the Typer surface and the ``analyze`` command. As of Phase 1,
``analyze`` runs the real ``.eml`` parser (``.msg`` lands later in the phase)
and prints a short summary of what was parsed. Extraction, scoring, and the
report layer are later phases per ``docs/CHECKLIST.md``; do not jump ahead.

Phishbowl is defensive-only: it never sends, detonates, fetches the email's
URLs, or auto-remediates (CLAUDE.md invariants).
"""

from __future__ import annotations

import re

import typer

from phishbowl.models import ParsedEmail
from phishbowl.parse import parse

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
)

# C0/C1 control characters (incl. ESC, CR/LF, DEL). Email-derived text is
# hostile input (PRD §13): a Subject carrying terminal escape/OSC sequences
# could rewrite the analyst's terminal or forge hyperlinks, so we strip these
# before echoing any email-controlled field.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _safe(text: str | None) -> str:
    """Strip terminal control characters from an email-derived string."""
    if not text:
        return "(none)"
    return _CONTROL_CHARS.sub("", text)


@app.callback()
def main() -> None:
    """Phishbowl — a self-hostable, defensive-only phishing triage tool.

    Offline-first phishing triage: parse a suspicious .eml/.msg, extract and
    defang IOCs, risk-score it, and produce an analyst-ready report.

    This callback intentionally does nothing; it exists so that ``analyze``
    (and future commands) stay subcommands — i.e. ``phishbowl analyze <file>``
    — instead of Typer collapsing a lone command into the root program.
    """


def _summarize(parsed: ParsedEmail) -> str:
    """One-line-per-fact summary of a parsed message (no report layer yet)."""
    src = parsed.source
    from_ = parsed.addresses.from_
    lines = [
        f"phishbowl: parsed {src.filename} (format={src.format.value})",
        f"  subject:     {_safe(parsed.subject)}",
        f"  from:        {_safe(from_.addr_spec if from_ else None)}",
        f"  spf/dkim/dmarc: "
        f"{parsed.auth.spf.result}/{parsed.auth.dkim.result}/{parsed.auth.dmarc.result}",
        f"  headers:     {len(parsed.headers)}",
        f"  hops:        {len(parsed.routing)}",
        f"  attachments: {len(parsed.attachments)}",
        f"  anomalies:   {len(parsed.anomalies)}",
    ]
    return "\n".join(lines)


@app.command()
def analyze(
    path: str = typer.Argument(..., help="Path to a suspicious .eml or .msg file."),
) -> None:
    """Triage a suspicious email and produce a report.

    Phase 1: parses the file into a ``ParsedEmail`` and prints a summary. The
    extract/score/report stages are not implemented yet. Phishbowl is
    defensive-only: it will never send, detonate, fetch the email's URLs, or
    auto-remediate.
    """
    try:
        parsed = parse(path)
    except (OSError, ValueError) as exc:
        # Missing, unreadable (permissions/I/O), or unsupported input degrades
        # into a clean CLI error rather than an internal traceback (PRD §11).
        raise typer.BadParameter(str(exc)) from exc

    typer.echo(_summarize(parsed))


if __name__ == "__main__":  # pragma: no cover
    app()
