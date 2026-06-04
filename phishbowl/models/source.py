"""Provenance of the analyzed message (PRD §7 — *Source*)."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import Field

from ._base import PhishbowlModel
from .enums import EmailFormat


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Source(PhishbowlModel):
    """Where this ``ParsedEmail`` came from and how it was produced.

    ``parser_version`` is recorded so a report (or a re-run on the same file)
    is traceable to the code that generated it.
    """

    filename: str | None = None
    format: EmailFormat
    parsed_at: datetime = Field(default_factory=_utcnow)
    parser_version: str
