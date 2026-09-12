"""SSRF-guarded async HTTP client for connectors (PRD §9, §13).

Bundled connectors use this client to check vendor hosts before requests and
redirects. It never directly fetches an analyzed email URL. RDAP has an explicit
HTTPS bootstrap redirect exception. Third-party plugins are trusted Python code;
this helper is not a network or process sandbox.

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

from .errors import ConnectorError, RateLimitedError, SSRFGuardError

# Statuses that mean "slow down / try again", not "here's your answer".
_RETRY_STATUSES = frozenset({429, 503})
# Schemes a connector may use. Vendor APIs are HTTPS; anything exotic
# (file://, gopher://, ftp://, …) is refused outright as an SSRF vector.
_ALLOWED_SCHEMES = frozenset({"http", "https"})
# Cap a single backoff wait so a hostile ``Retry-After`` can't park a run forever.
_MAX_BACKOFF_SECONDS = 30.0
# Most redirect hops a vendor chain may take (RDAP bootstrap → registry →
# registrar is two or three); a longer chain is abuse, not an API.
_MAX_REDIRECTS = 5


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
        bootstrap_redirect: bool = False,
    ) -> None:
        self._allowed = frozenset(h.strip().casefold().rstrip(".") for h in allowed_hosts if h)
        self._max_retries = max(0, max_retries)
        self._sleep = sleep or _async_sleep
        self._follow_redirects = follow_redirects or bootstrap_redirect
        self._bootstrap_redirect = bootstrap_redirect
        # Redirect-following is NEVER delegated to httpx: it would chase a 3xx
        # internally without re-checking the allowlist, so a vendor (or anyone
        # who can influence a vendor's redirect chain) could bounce the request
        # to an arbitrary host unchecked. Redirects are handled hop-by-hop in
        # request(), each hop re-guarded before any connection attempt.
        self._client = httpx.AsyncClient(
            timeout=timeout,
            transport=transport,
            follow_redirects=False,
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
        """Guard every hop, then dispatch, retrying rate-limit statuses with backoff.

        When the client was built with ``follow_redirects=True``, a 3xx is
        followed manually: the resolved ``Location`` target goes through the
        same :meth:`_guard` as the original URL *before* any connection attempt,
        so the allowlist holds across the whole redirect chain — the SSRF
        guarantee httpx's internal following would silently bypass.

        With ``bootstrap_redirect=True`` (RDAP), exactly one hop issued by an
        allowlisted host may leave the allowlist — https only — because the
        vendor's documented job is to designate the authoritative host. The
        designated host gets exactly one request: a further redirect from it
        soft-fails, so a registrant-chosen second hop can never be followed.
        """
        self._guard(url)
        request = self._client.build_request(method, url, **kwargs)
        redirects = 0
        off_allowlist = False
        while True:
            response = await self._send_with_backoff(request)
            next_request = response.next_request
            if not (self._follow_redirects and response.is_redirect and next_request is not None):
                return response
            if off_allowlist:
                # The bootstrap-designated host got its one request; it may not
                # forward us anywhere else (e.g. a registry bouncing to the
                # registrant-chosen registrar RDAP) — soft-fail instead.
                raise SSRFGuardError("refused redirect issued by a bootstrap-designated host")
            if redirects >= _MAX_REDIRECTS:
                # Soft-fail (never names the path/query, which can carry
                # per-victim data): the orchestrator notes it and moves on.
                raise ConnectorError(f"gave up after {_MAX_REDIRECTS} redirects")
            await response.aclose()
            # The load-bearing re-check: the redirect target is allowlist-guarded
            # exactly like the original URL before a single byte leaves. The one
            # exception: a bootstrap redirector's designated host (https only).
            try:
                self._guard(str(next_request.url))
            except SSRFGuardError:
                if not self._bootstrap_redirect:
                    raise
                if next_request.url.scheme != "https":
                    raise SSRFGuardError("refused non-https bootstrap redirect target") from None
                off_allowlist = True
            request = next_request
            redirects += 1

    async def _send_with_backoff(self, request: httpx.Request) -> httpx.Response:
        """Send one (already-guarded) request, backing off on 429/503."""
        attempt = 0
        while True:
            response = await self._client.send(request)
            if response.status_code not in _RETRY_STATUSES:
                return response
            if attempt >= self._max_retries:
                # Strip the query — it can carry an API key (e.g. Shodan's).
                raise RateLimitedError(
                    f"{request.url.copy_with(query=None)} still rate-limited after "
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
