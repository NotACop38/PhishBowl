"""Proactive rate limiting (PRD §9).

The HTTP client handles the *reactive* case — backing off when a vendor returns
``429`` (:mod:`.http`). This module handles the *proactive* case: spacing
requests so a connector stays within its documented free-tier budget (e.g.
VirusTotal public ≈ 4 req/min) in the first place, rather than hammering the API
and getting throttled. The orchestrator additionally caps *global* concurrency
with an :class:`asyncio.Semaphore` so all connectors together never exceed a
small number of in-flight requests.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable


async def _async_sleep(delay: float) -> None:
    await asyncio.sleep(delay)


class RateLimiter:
    """A minimal async spacing limiter: ``>= interval`` seconds between acquires.

    Token-bucket-free and dependency-free: it simply remembers when the next
    request is allowed and waits if a caller arrives early. ``clock``/``sleep``
    are injectable so tests can assert spacing deterministically without real
    waits. A non-positive rate disables limiting (used when a vendor publishes no
    meaningful limit, or in tests).
    """

    def __init__(
        self,
        per_minute: float,
        *,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._interval = 60.0 / per_minute if per_minute and per_minute > 0 else 0.0
        self._sleep = sleep or _async_sleep
        self._clock = clock
        self._next_allowed = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Block until the next request is allowed under the configured spacing."""
        if self._interval <= 0:
            return
        async with self._lock:
            now = self._clock()
            wait = self._next_allowed - now
            if wait > 0:
                await self._sleep(wait)
                now = self._clock()
            self._next_allowed = max(now, self._next_allowed) + self._interval
