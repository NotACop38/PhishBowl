"""FastAPI upload UI (PRD §15 stretch; CHECKLIST Phase 7).

A minimal, self-hostable browser front door for the **exact same** offline
pipeline the CLI runs: upload a suspicious ``.eml``/``.msg`` → parse → extract →
defang → score → render the identical self-contained, zero-egress HTML report
(:func:`phishbowl.report.render_html`). It is purely *additive* — it reuses
:class:`~phishbowl.models.ParsedEmail` and the report layer unchanged, with no
logic fork (the contract was designed for this, PRD §15 / §7).

Every defensive invariant the CLI upholds holds here too (CLAUDE.md / PRD §4):
the server never sends, never detonates, never fetches the analyzed email's
URLs, and never auto-remediates. The upload path is additionally hardened
against hostile *input*: size and type are enforced before any deep parsing,
the bytes are never written to disk or executed, and the rendered report keeps
all of its no-egress guarantees (reinforced with strict response headers).
"""

from .app import create_app

# A module-level application for ``uvicorn phishbowl.web:app`` and the test
# client. ``create_app`` stays available for callers that want a fresh instance.
app = create_app()

__all__ = ["app", "create_app"]
