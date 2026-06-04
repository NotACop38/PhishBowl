"""Attachment metadata (PRD §7 — *Attachments*).

Attachments are described by metadata and hashes only. Phishbowl never
executes an attachment and never auto-extracts an archive (CLAUDE.md defensive
invariants); ``detected_type`` comes from magic-byte inspection (PRD §6.1).
"""

from __future__ import annotations

from pydantic import Field

from ._base import PhishbowlModel
from .enums import AttachmentFlag


class Attachment(PhishbowlModel):
    """One attachment: identity, declared vs. detected type, size, hashes, flags."""

    filename: str | None = None
    declared_type: str | None = None
    detected_type: str | None = None
    size: int | None = None
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    flags: list[AttachmentFlag] = Field(default_factory=list)
