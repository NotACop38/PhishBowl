"""Env-only API-key access for connectors (PRD §9, §11).

Connector secrets come from environment variables *only* — never a committed
file, never the CLI, never the analyzed email. They are read here, handed to a
connector through its :class:`~phishbowl.connectors.base.EnrichContext`, and
otherwise never touched: never logged, never written into a report or JSON
output, and defensively scrubbed from any retained raw response (see
:func:`scrub_secrets`). ``.env.example`` documents the variable names.
"""

from __future__ import annotations

import os
from typing import Any

# Connector name → the environment variable holding its key. Keyless connectors
# (WHOIS/RDAP) are intentionally absent.
ENV_KEYS: dict[str, str] = {
    "virustotal": "VIRUSTOTAL_API_KEY",
    "urlscan": "URLSCAN_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "shodan": "SHODAN_API_KEY",
}


def env_var_for(connector_name: str) -> str | None:
    """The env-var name a connector's key is read from, or ``None`` if keyless."""
    return ENV_KEYS.get(connector_name)


def api_key_from_env(connector_name: str) -> str | None:
    """Read a connector's API key from its env var; ``None`` if unset/blank."""
    var = ENV_KEYS.get(connector_name)
    if not var:
        return None
    value = os.environ.get(var, "").strip()
    return value or None


def active_key_values() -> frozenset[str]:
    """Every API-key value currently set in the environment.

    Used purely defensively: the orchestrator scrubs these out of any retained
    raw response so a key can never ride along into an output, even if a vendor
    were to echo it back (PRD §11).
    """
    values: set[str] = set()
    for var in ENV_KEYS.values():
        value = os.environ.get(var, "").strip()
        if value:
            values.add(value)
    return frozenset(values)


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
        for secret in secrets:
            if secret and secret in out:
                out = out.replace(secret, "[redacted]")
        return out
    if isinstance(value, dict):
        return {k: scrub_secrets(v, secrets) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(scrub_secrets(v, secrets) for v in value)
    return value
