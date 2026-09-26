"""Env-only API-key access for connectors (PRD §9, §11).

Connector secrets come from environment variables *only* — never a committed
file, never the CLI, never the analyzed email. Each connector names its
variable (:attr:`~phishbowl.connectors.base.Connector.api_key_env`); the key is
read here, handed to the connector through its
:class:`~phishbowl.connectors.base.EnrichContext`, and otherwise never touched:
never logged, never written into a report or JSON output, and defensively
scrubbed from any retained raw response (see :func:`scrub_secrets`).
``.env.example`` documents the bundled connectors' variable names.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from typing import Any


def api_key_from_env(env_var: str) -> str | None:
    """Read an API key from ``env_var``; ``None`` if the name is empty or the value blank."""
    if not env_var:
        return None
    value = os.environ.get(env_var, "").strip()
    return value or None


def key_values(env_vars: Iterable[str]) -> frozenset[str]:
    """Every non-blank value currently set in ``env_vars``.

    Used purely defensively: the orchestrator scrubs these out of retained
    responses, notes and HTTP logs so a key can never ride along into an output,
    even if a vendor were to echo it back (PRD §11).
    """
    return frozenset(value for var in env_vars if (value := api_key_from_env(var)))


def scrub_secrets(value: Any, secrets: frozenset[str]) -> Any:
    """Recursively replace any known secret string with ``[redacted]``.

    Walks dicts/lists/tuples/strings (the shapes a normalized raw response takes)
    and blanks out exact key matches and any string that *contains* a key. A
    no-op when there are no secrets to scrub. Belt-and-suspenders behind the rule
    that connectors simply never put keys in their output to begin with.
    """
    if not secrets:
        return value
    if isinstance(value, str):
        out = value
        # Longest first: a key that contains another key must go whole, not
        # leave its remainder behind around a shorter key's placeholder.
        for secret in sorted(secrets, key=len, reverse=True):
            if secret and secret in out:
                out = out.replace(secret, "[redacted]")
        return out
    if isinstance(value, dict):
        return {scrub_secrets(k, secrets): scrub_secrets(v, secrets) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(scrub_secrets(v, secrets) for v in value)
    return value
