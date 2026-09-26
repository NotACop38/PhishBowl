"""SSRF-guarded async HTTP client for connectors (PRD §9, §13).

Bundled connectors use this client to check vendor hosts before requests and
redirects. It never directly fetches an analyzed email URL. RDAP has an explicit
HTTPS bootstrap redirect exception. Third-party plugins are trusted Python code;
this helper is not a network or process sandbox.

The client also owns reactive rate-limit handling: a ``429``/``503`` is retried
with exponential backoff (honoring a finite ``Retry-After`` when present), and a
persistent one past the retry budget raises :class:`RateLimitedError` so the
orchestrator can note it rather than hang. Proactive spacing lives in
:mod:`.ratelimit`. :func:`json_object` reads a vendor's JSON body, turning a
malformed one into a :class:`ConnectorError` the orchestrator soft-fails.
"""

from __future__ import annotations

import asyncio
import math
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

from phishbowl.domains import public_host

from .errors import ConnectorError, RateLimitedError, SSRFGuardError

# Statuses that mean "slow down / try again", not "here's your answer".
_RETRY_STATUSES = frozenset({429, 503})
# Vendor APIs are HTTPS. Plain http would expose API keys and results on the
# wire, and anything exotic (file://, gopher://, ...) is an SSRF vector.
_ALLOWED_SCHEMES = frozenset({"https"})
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


def json_object(response: httpx.Response, vendor: str) -> dict[str, Any]:
    """The response body as a JSON object, or a :class:`ConnectorError`.

    Vendor responses are untrusted input: an HTML error page, a truncated body,
    or a JSON array where an object belongs is a soft failure for that one
    indicator, never a crash.
    """
    try:
        body = response.json()
    except ValueError:  # JSONDecodeError and UnicodeDecodeError are ValueErrors
        raise ConnectorError(f"{vendor} returned a non-JSON response") from None
    if not isinstance(body, dict):
        raise ConnectorError(f"{vendor} returned an unexpected JSON document")
    return body


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
            raise SSRFGuardError(f"refused non-https scheme {parts.scheme!r}")
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
        allowlisted host may leave the allowlist, because the vendor's
        documented job is to designate the authoritative host. That hop must be
        https to a public DNS name (never an IP literal or a local name), and
        the designated host gets exactly one request, without rate-limit
        retries: a further redirect from it soft-fails, so a registrant-chosen
        second hop can never be followed.
        """
        self._guard(url)
        request = self._client.build_request(method, url, **kwargs)
        redirects = 0
        off_allowlist = False
        while True:
            retries = 0 if off_allowlist else self._max_retries
            response = await self._send_with_backoff(request, retries)
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
                designated = public_host(next_request.url.host)
                if designated is None or designated[0] != "name":
                    raise SSRFGuardError(
                        "refused bootstrap redirect to an IP literal or local host"
                    ) from None
                off_allowlist = True
            request = next_request
            redirects += 1

    async def _send_with_backoff(self, request: httpx.Request, retries: int) -> httpx.Response:
        """Send one (already-guarded) request, backing off on 429/503."""
        attempt = 0
        while True:
            response = await self._client.send(request)
            if response.status_code not in _RETRY_STATUSES:
                return response
            if attempt >= retries:
                await response.aclose()
                # Name the host only: a path or query can carry the indicator
                # (per-victim data) or an API key (Shodan's).
                raise RateLimitedError(
                    f"{request.url.host} still rate-limited after "
                    f"{retries} retr{'y' if retries == 1 else 'ies'}"
                )
            await response.aclose()
            delay = self._retry_delay(response, attempt)
            self.sleeps.append(delay)
            await self._sleep(delay)
            attempt += 1

    @staticmethod
    def _retry_delay(response: httpx.Response, attempt: int) -> float:
        """Honor a finite ``Retry-After`` in seconds, else back off exponentially (1, 2, 4, …s)."""
        header = response.headers.get("Retry-After")
        if header:
            try:
                seconds = float(header)
            except ValueError:
                seconds = math.nan  # HTTP-date form: fall back to exponential backoff
            if math.isfinite(seconds):
                return min(max(seconds, 0.0), _MAX_BACKOFF_SECONDS)
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
