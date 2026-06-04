"""Connector error types (PRD §9).

A small, explicit hierarchy so the orchestrator can tell *why* a connector did
not produce a result and turn it into the right report note — without ever
crashing the run (PRD §9 graceful degrade). The orchestrator catches every one
of these (and any unexpected exception) and records a soft-fail note instead of
propagating it.
"""

from __future__ import annotations


class ConnectorError(Exception):
    """Base class for a connector failing to enrich an indicator.

    A connector raises this (or a subclass) to signal "I couldn't answer for
    this indicator" — the orchestrator soft-fails it with a note and moves on.
    """


class SSRFGuardError(ConnectorError):
    """A request was blocked because its host is not on the connector's allowlist.

    The load-bearing connector guarantee: a connector may only reach its
    vendor's documented API and must **never** be coerced into fetching a URL
    taken from the analyzed email (PRD §9, §13). Any attempt to do so raises
    this before a single byte leaves the process.
    """


class RateLimitedError(ConnectorError):
    """The vendor kept returning a rate-limit status after exhausting backoff.

    Raised by the HTTP client when a ``429``/``503`` persists past the retry
    budget, so the orchestrator can note the connector as rate-limited rather
    than silently dropping it.
    """
