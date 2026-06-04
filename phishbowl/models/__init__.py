"""Internal data models — the ``ParsedEmail`` contract (PRD §7).

Pydantic v2. This single model is what every stage downstream of parsing
consumes, so both the ``.eml`` and ``.msg`` paths normalize into it. Sub-models
are split one-per-§7-concept across sibling modules and re-exported here, so
callers can simply ``from phishbowl.models import ParsedEmail, Address, ...``.

Design notes from the PRD that are load-bearing here:
- Headers preserve order and duplicates (PRD §6.1).
- From / Return-Path / Reply-To are trivially comparable — domain mismatch is
  a core offline scoring signal (PRD §8); see :mod:`phishbowl.models.addresses`.
- ``Body.html_raw`` is stored but NEVER rendered (CLAUDE.md / PRD §10).
"""

from .addresses import Address, Addresses
from .attachments import Attachment
from .auth import Auth, AuthResult
from .body import Body
from .enums import AttachmentFlag, AuthResultState, EmailFormat, IOCType
from .headers import Header, Headers
from .iocs import IOC, IOCs
from .parsed_email import Anomaly, ParsedEmail
from .routing import ReceivedHop, Routing
from .source import Source

__all__ = [
    # Top-level contract
    "ParsedEmail",
    # Sub-models
    "Source",
    "Header",
    "Headers",
    "Auth",
    "AuthResult",
    "Routing",
    "ReceivedHop",
    "Address",
    "Addresses",
    "Body",
    "Attachment",
    "IOC",
    "IOCs",
    "Anomaly",
    # Enums
    "EmailFormat",
    "AuthResultState",
    "IOCType",
    "AttachmentFlag",
]
