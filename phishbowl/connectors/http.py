"""SSRF-guarded async HTTP client for connectors (PRD §9, §13).

The single chokepoint through which every connector reaches the network. Before
any request leaves the process the client checks the target host against the
connector's allowlist and refuses anything else — so a connector physically
cannot be coerced into fetching a URL taken from the analyzed email, no matter
how its code is written or what an indicator contains. This is the load-bearing
SSRF guarantee (PRD §9): *connectors reach only their vendor's documented API*.

The client also owns reactive rate-limit handling: a ``429``/``503`` is retried
with exponential backoff (honoring ``Retry-After`` when present), and a persistent
one past the retry budget raises :class:`RateLimitedError` so the orchestrator can
note it rather than hang. Proactive spacing lives in :mod:`.ratelimit`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

from .errors import RateLimitedError, SSRFGuardError

# Statuses that mean "slow down / try again", not "here's your answer".
_RETRY_STATUSES = frozenset({429, 503})
# Schemes a connector may use. Vendor APIs are HTTPS; anything exotic
# (file://, gopher://, ftp://, …) is refused outright as an SSRF vector.
_ALLOWED_SCHEMES = frozenset({"http", "https"})
# Cap a single backoff wait so a hostile ``Retry-After`` can't park a run forever.
_MAX_BACKOFF_SECONDS = 30.0


async def _async_sleep(delay: float) -> None:
    await asyncio.sleep(delay)


def host_is_allowed(host: str, allowed: frozenset[str]) -> bool:
    """True iff ``host`` exactly matches, or is a subdomain of, an allowed host."""
    host = host.strip().casefold().rstrip(".")
    if not host:
        return False
    return any(host == a or host.endswith("." + a) for a in allowed)


class AllowlistedClient:
    """An :class:`httpx.AsyncClient` that can only reach allowlisted hosts.

    Construct it bound to a connector's ``allowed_hosts``; every ``get``/``post``
    is guarded first and only then dispatched. A blocked host raises
    :class:`SSRFGuardError` *before* any connection attempt. The ``transport`` and
    ``sleep`` seams keep the client fully testable offline (a mocked transport,
    a no-wait sleep) while exercising the exact guard + backoff code paths.
    """

    def __init__(
        self,
        *,
        allowed_hosts: frozenset[str],
        timeout: float = 10.0,
        max_retries: int = 3,
        transport: Any = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        follow_redirects: bool = False,
    ) -> None:
        self._allowed = frozenset(h.strip().casefold().rstrip(".") for h in allowed_hosts if h)
        self._max_retries = max(0, max_retries)
        self._sleep = sleep or _async_sleep
        self._client = httpx.AsyncClient(
            timeout=timeout,
            transport=transport,
            follow_redirects=follow_redirects,
        )
        #: Backoff waits performed, in order — observable so tests can assert it.
        self.sleeps: list[float] = []

    def _guard(self, url: str) -> None:
        try:
            parts = urlsplit(url)
            host = parts.hostname or ""
        except ValueError as exc:
            # Fail closed: a URL we can't even parse is never allowed out.
            raise SSRFGuardError("refused unparseable request URL") from exc
        if parts.scheme.casefold() not in _ALLOWED_SCHEMES:
            raise SSRFGuardError(f"refused non-web scheme {parts.scheme!r}")
        if not host_is_allowed(host, self._allowed):
            # The message names the host but never the indicator/path that may
            # have carried per-victim data — and never a secret.
            raise SSRFGuardError(
                f"refused egress to non-allowlisted host {host!r} "
                f"(connector may reach only {sorted(self._allowed)})"
            )

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Guard, then dispatch, retrying transient rate-limit statuses with backoff."""
        self._guard(url)
        attempt = 0
        while True:
            response = await self._client.request(method, url, **kwargs)
            if response.status_code not in _RETRY_STATUSES:
                return response
            if attempt >= self._max_retries:
                raise RateLimitedError(
                    f"{url.split('?', 1)[0]} still rate-limited after "
                    f"{self._max_retries} retr{'y' if self._max_retries == 1 else 'ies'}"
                )
            delay = self._retry_delay(response, attempt)
            self.sleeps.append(delay)
            await self._sleep(delay)
            attempt += 1

    @staticmethod
    def _retry_delay(response: httpx.Response, attempt: int) -> float:
        """Honor ``Retry-After`` if sane, else exponential backoff (1, 2, 4, …s)."""
        header = response.headers.get("Retry-After")
        if header:
            try:
                return min(max(float(header), 0.0), _MAX_BACKOFF_SECONDS)
            except ValueError:
                pass  # HTTP-date form — fall through to exponential backoff
        return min(2.0**attempt, _MAX_BACKOFF_SECONDS)

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> AllowlistedClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
