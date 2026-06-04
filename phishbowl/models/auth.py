"""Authentication results (PRD §7 — *Auth*).

SPF/DKIM/DMARC extracted from ``Authentication-Results`` and ``Received-SPF``
(PRD §6.1). Each is a ``{result, detail}`` pair; ``detail`` keeps the human
text (e.g. the failing selector or the SPF explanation) for the report.
"""

from __future__ import annotations

from pydantic import Field

from ._base import PhishbowlModel
from .enums import AuthResultState


class AuthResult(PhishbowlModel):
    """One authentication mechanism's outcome."""

    result: AuthResultState = AuthResultState.NONE
    detail: str | None = None


class Auth(PhishbowlModel):
    """SPF, DKIM, and DMARC results.

    Defaults to ``NONE`` for each so an email whose ``Authentication-Results``
    is missing entirely is representable (itself a scoring signal, PRD §8).
    """

    spf: AuthResult = Field(default_factory=AuthResult)
    dkim: AuthResult = Field(default_factory=AuthResult)
    dmarc: AuthResult = Field(default_factory=AuthResult)
