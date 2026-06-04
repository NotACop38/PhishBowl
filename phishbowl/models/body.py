"""Message body parts (PRD §7 — *Body*).

The raw HTML is **stored but NEVER rendered** (CLAUDE.md / PRD §10): downstream
works on ``text`` (or a sanitized representation), and the report shows escaped
plaintext only. ``html_raw`` is retained purely for analysis (link/anchor
extraction in Phase 2) and must never be injected into any output.
"""

from __future__ import annotations

from ._base import PhishbowlModel


class Body(PhishbowlModel):
    """Decoded body parts and a flag for whether an HTML part was present."""

    text: str | None = None
    # Stored for analysis only — NEVER rendered or injected into output.
    html_raw: str | None = None
    has_html: bool = False
