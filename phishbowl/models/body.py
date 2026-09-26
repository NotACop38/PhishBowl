"""Message body parts (PRD §7 — *Body*).

The raw HTML is **stored but NEVER rendered** (AGENTS.md / PRD §10): downstream
works on ``text`` (or a sanitized representation), and the report shows escaped
plaintext only. ``html_raw`` is retained purely for analysis (link/anchor
extraction) and must never be injected into any output.
"""

from __future__ import annotations

from pydantic import Field

from ._base import PhishbowlModel


class TextPart(PhishbowlModel):
    """An inline body part in a text format other than plain text or HTML.

    Calendar invitations (``text/calendar``) and similar parts carry links and
    addresses too. Their decoded text is scanned for indicators exactly like
    the plaintext body, and is never rendered.
    """

    content_type: str
    text: str


class Body(PhishbowlModel):
    """Decoded body parts and a flag for whether an HTML part was present."""

    text: str | None = None
    # Stored for analysis only — NEVER rendered or injected into output.
    html_raw: str | None = None
    has_html: bool = False
    # Other inline text formats (text/calendar, text/rtf, ...), scanned for
    # indicators as plain text.
    other_text: list[TextPart] = Field(default_factory=list)
