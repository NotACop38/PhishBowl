"""On-disk enrichment cache (PRD §9).

Keyed by ``(connector, ioc_type, value)`` with a **per-connector TTL**, so repeat
runs and the bundled demo are fast and don't burn a vendor's free-tier quota. The
cache stores only the normalized :class:`~phishbowl.connectors.base.EnrichmentResult`
(which is secret-free by construction), as JSON, one file per key.

The store is best-effort and never load-bearing: any read/write/parse error is
swallowed into a cache miss, because a broken cache must never crash a run
(PRD §11) — at worst it costs one live lookup.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .base import EnrichmentResult, EnrichmentSignal, EnrichmentVerdict

# Operator override for the cache location; otherwise an XDG-style user cache dir.
ENV_CACHE_DIR = "PHISHBOWL_CACHE_DIR"


def default_cache_dir() -> Path:
    """Resolve the cache directory: ``$PHISHBOWL_CACHE_DIR`` or ``~/.cache/phishbowl``."""
    override = os.environ.get(ENV_CACHE_DIR)
    if override:
        return Path(override)
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "phishbowl" / "enrichment"


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _serialize(result: EnrichmentResult) -> dict[str, Any]:
    return {
        "connector": result.connector,
        "ioc_type": result.ioc_type,
        "indicator": result.indicator,
        "verdict": result.verdict.value,
        "signals": [
            {
                "id": s.id,
                "description": s.description,
                "magnitude": s.magnitude,
                "evidence": s.evidence,
            }
            for s in result.signals
        ],
        "references": list(result.references),
        "raw": result.raw,
    }


def _deserialize(data: dict[str, Any]) -> EnrichmentResult:
    return EnrichmentResult(
        connector=str(data["connector"]),
        ioc_type=str(data["ioc_type"]),
        indicator=str(data["indicator"]),
        verdict=EnrichmentVerdict(data.get("verdict", "unknown")),
        signals=tuple(
            EnrichmentSignal(
                id=str(s["id"]),
                description=str(s["description"]),
                magnitude=float(s["magnitude"]),
                evidence=str(s["evidence"]),
            )
            for s in data.get("signals", [])
        ),
        references=tuple(data.get("references", [])),
        raw=data.get("raw"),
    )


class EnrichmentCache:
    """A simple JSON file cache keyed by ``(connector, ioc_type, value)`` (PRD §9).

    ``ttl`` is supplied per lookup (each connector declares its own), so the same
    store serves a long-lived RDAP domain-age result and a short-lived reputation
    lookup side by side. Pass ``enabled=False`` to bypass it entirely.
    """

    def __init__(
        self,
        directory: Any = None,
        *,
        enabled: bool = True,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._dir = Path(directory) if directory else default_cache_dir()
        self._enabled = enabled
        self._now = now or _utcnow

    def _path(self, connector: str, ioc_type: str, value: str) -> Path:
        digest = hashlib.sha256(f"{connector}\x00{ioc_type}\x00{value}".encode()).hexdigest()
        return self._dir / connector / f"{digest}.json"

    def get(
        self, connector: str, ioc_type: str, value: str, *, ttl: int
    ) -> EnrichmentResult | None:
        """Return a fresh cached result, or ``None`` on miss/stale/error."""
        if not self._enabled:
            return None
        path = self._path(connector, ioc_type, value)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            stored_at = datetime.fromisoformat(payload["stored_at"])
            if stored_at.tzinfo is None:
                return None
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if ttl >= 0:
            age = (self._now() - stored_at).total_seconds()
            if age < 0 or age > ttl:
                return None
        try:
            return _deserialize(payload["result"])
        except (KeyError, ValueError, TypeError):
            return None

    def put(self, result: EnrichmentResult) -> None:
        """Store ``result`` keyed by its connector/type/indicator (best-effort)."""
        if not self._enabled:
            return
        path = self._path(result.connector, result.ioc_type, result.indicator)
        payload = {"stored_at": self._now().isoformat(), "result": _serialize(result)}
        tmp = None
        try:
            # The cache holds the analyzed email's indicators (URLs, domains,
            # sending IPs) — keep it private to the operator on shared hosts:
            # 0700 on the cache tree we own, 0600 on each entry.
            path.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(self._dir, 0o700)
            os.chmod(path.parent, 0o700)
            fd, tmp_name = tempfile.mkstemp(prefix=".cache-", dir=path.parent)
            tmp = Path(tmp_name)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(payload))
            tmp.replace(path)  # atomic swap — a concurrent reader sees old or new, never half
        except (OSError, TypeError, ValueError):
            return  # cache failures do not prevent offline analysis
        finally:
            if tmp is not None:
                tmp.unlink(missing_ok=True)
