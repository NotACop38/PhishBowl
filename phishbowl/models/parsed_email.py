"""The ``ParsedEmail`` contract (PRD §7).

The single internal model everything downstream of parsing consumes. Both the
``.eml`` and ``.msg`` paths normalize into it, so nothing after parsing needs
to know the source format (PRD §5). Sub-models live in sibling modules; this
ties them together and adds the top-level fields (subject, date) and anomaly
notes.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from ._base import PhishbowlModel
from .addresses import Addresses
from .attachments import Attachment
from .auth import Auth
from .body import Body
from .headers import Headers
from .iocs import IOCs
from .routing import Routing
from .source import Source


class Anomaly(PhishbowlModel):
    """A structural oddity noted during parsing (PRD §6.1).

    Captured rather than raised: a malformed email degrades gracefully into a
    noted partial result, it never crashes the run (PRD §11).
    """

    code: str | None = None
    message: str


class ParsedEmail(PhishbowlModel):
    """Normalized, format-agnostic view of one analyzed message."""

    source: Source
    headers: Headers = Field(default_factory=Headers)
    auth: Auth = Field(default_factory=Auth)
    routing: Routing = Field(default_factory=Routing)
    addresses: Addresses = Field(default_factory=Addresses)
    subject: str | None = None
    date: datetime | None = None
    body: Body = Field(default_factory=Body)
    attachments: list[Attachment] = Field(default_factory=list)
    iocs: IOCs = Field(default_factory=IOCs)
    anomalies: list[Anomaly] = Field(default_factory=list)
