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
from .routing import Routing
from .source import Source


class Anomaly(PhishbowlModel):
    """A structural oddity or analysis limit noted while processing a message.

    Captured rather than raised: a malformed email degrades gracefully into a
    noted partial result, it never crashes the run (PRD §11).

    ``coverage_gap`` separates the two kinds of anomaly. A coverage gap means
    some of the message's evidence was not analyzed — a budget was exhausted, a
    section failed to parse, or the MIME structure is ambiguous enough that a
    mail client could display content the parser did not see — so the
    assessment is incomplete. Anything else is an informational notice (a
    recoverable encoding defect, evidence the input format cannot carry). The
    default is ``True`` so an unclassified anomaly fails closed.
    """

    code: str | None = None
    message: str
    coverage_gap: bool = True

    @classmethod
    def notice(cls, code: str, message: str) -> Anomaly:
        """An informational anomaly that does not make the analysis incomplete."""
        return cls(code=code, message=message, coverage_gap=False)


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
    anomalies: list[Anomaly] = Field(default_factory=list)

    @property
    def analysis_complete(self) -> bool:
        """True unless an anomaly records evidence that was not analyzed."""
        return not any(a.coverage_gap for a in self.anomalies)
