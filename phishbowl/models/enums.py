"""Closed vocabularies used across the ``ParsedEmail`` contract (PRD §7).

Kept in one place so the parser, scorer, and reporter all agree on the exact
spelling of every state. All are string enums so they serialize to plain JSON
strings (and read cleanly in a report) with no custom encoder.
"""

from __future__ import annotations

from enum import StrEnum


class EmailFormat(StrEnum):
    """Source container the message was ingested from (PRD §6.1)."""

    EML = "eml"
    MSG = "msg"


class AuthResultState(StrEnum):
    """SPF/DKIM/DMARC outcome states (PRD §7).

    Mirrors the result keywords used in ``Authentication-Results`` /
    ``Received-SPF``. ``NONE`` doubles as "no result was present", which the
    scorer treats differently from an explicit ``FAIL``.
    """

    PASS = "pass"  # nosec B105 - SPF/DKIM/DMARC result value, not a credential
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"


class IOCType(StrEnum):
    """Indicator categories extracted in Phase 2 (PRD §6.2)."""

    EMAIL = "email"
    URL = "url"
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    HASH = "hash"


class AttachmentFlag(StrEnum):
    """Structural red flags on an attachment (PRD §6.1 / §8).

    Set by metadata/magic-byte inspection only — Phishbowl never executes an
    attachment or extracts an archive (CLAUDE.md defensive invariants).
    """

    ARCHIVE = "archive"
    MACRO_CAPABLE = "macro_capable"
    EXECUTABLE = "executable"
    TYPE_MISMATCH = "type_mismatch"
    DOUBLE_EXTENSION = "double_extension"
    PASSWORD_PROTECTED = "password_protected"  # nosec B105 - attachment flag name, not a credential
