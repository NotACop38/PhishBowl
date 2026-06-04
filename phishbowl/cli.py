"""Phishbowl command-line interface.

Scaffold only: this wires up the Typer surface but implements no analysis
logic. Commands are stubs that establish the CLI shape. Real behaviour lands
phase by phase per ``docs/CHECKLIST.md`` — do not jump ahead.
"""

import typer

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


@app.command()
def analyze(
    path: str = typer.Argument(..., help="Path to a suspicious .eml or .msg file."),
) -> None:
    """Triage a suspicious email and produce a report.

    Not implemented yet — this is a scaffold. Phishbowl is defensive-only: it
    will never send, detonate, fetch the email's URLs, or auto-remediate.
    """
    typer.echo(
        f"phishbowl: the analysis pipeline is not implemented yet (scaffold). Would analyze: {path}"
    )


if __name__ == "__main__":  # pragma: no cover
    app()
