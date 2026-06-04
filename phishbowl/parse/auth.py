"""Authentication-results extraction (PRD §6.1 / §7 — *Auth*).

SPF / DKIM / DMARC are pulled from every ``Authentication-Results`` header
(they can repeat) plus ``Received-SPF`` as a fallback for SPF. Each result is
mapped onto the closed :class:`AuthResultState` vocabulary; the human text
(selector, explanation, ``smtp.mailfrom=``) is kept verbatim in ``detail`` for
the report.

Best-effort and total: an unparseable header is skipped, never fatal.
"""

from __future__ import annotations

import re

from phishbowl.models import Auth, AuthResult, AuthResultState
from phishbowl.models.headers import Headers

# Methods we care about within an Authentication-Results header.
_METHODS = ("dkim", "spf", "dmarc")

# A leading ``method=result`` at the start of an A-R clause, e.g. ``spf=pass``.
_METHOD_RESULT = re.compile(
    r"^\s*(?P<method>[A-Za-z0-9-]+)\s*=\s*(?P<result>[A-Za-z]+)\s*(?P<detail>.*)$",
    re.DOTALL,
)

# Map A-R result keywords onto our states. Unknown keywords stay ``None`` so an
# odd token never silently masquerades as a real result.
_RESULT_MAP = {
    "pass": AuthResultState.PASS,
    "fail": AuthResultState.FAIL,
    "hardfail": AuthResultState.FAIL,
    "softfail": AuthResultState.SOFTFAIL,
    "neutral": AuthResultState.NEUTRAL,
    "none": AuthResultState.NONE,
    "temperror": AuthResultState.TEMPERROR,
    "permerror": AuthResultState.PERMERROR,
}


def _state(keyword: str) -> AuthResultState | None:
    return _RESULT_MAP.get(keyword.casefold())


def _iter_method_results(header_value: str):
    """Yield ``(method, state, detail)`` for each method clause in an A-R header.

    The header is ``authserv-id; method=result detail; method=result detail``.
    Splitting on ``;`` separates the clauses; the first (authserv-id) simply
    won't match the ``method=result`` shape and is skipped.
    """
    for clause in header_value.split(";"):
        match = _METHOD_RESULT.match(clause)
        if not match:
            continue
        method = match.group("method").casefold()
        if method not in _METHODS:
            continue
        state = _state(match.group("result"))
        if state is None:
            continue
        detail = match.group("detail").strip() or None
        yield method, state, detail


def parse_auth(headers: Headers) -> Auth:
    """Build :class:`Auth` from ``Authentication-Results`` + ``Received-SPF``."""
    auth = Auth()
    seen: set[str] = set()

    # Authentication-Results is authoritative. First occurrence of a method wins
    # (closest to the receiving MTA), matching how analysts read these top-down.
    for raw in headers.get_all("Authentication-Results"):
        for method, state, detail in _iter_method_results(raw):
            if method in seen:
                continue
            seen.add(method)
            setattr(auth, method, AuthResult(result=state, detail=detail))

    # Received-SPF supplements SPF only when A-R didn't already carry it.
    if "spf" not in seen:
        spf = _parse_received_spf(headers.get_all("Received-SPF"))
        if spf is not None:
            auth.spf = spf

    return auth


def _parse_received_spf(values: list[str]) -> AuthResult | None:
    """Parse the leading result keyword (and parenthetical detail) of Received-SPF."""
    for value in values:
        stripped = value.strip()
        if not stripped:
            continue
        keyword = re.split(r"[\s(]", stripped, maxsplit=1)[0]
        state = _state(keyword)
        if state is None:
            continue
        # Keep the explanatory parenthetical, if present, as detail.
        paren = re.search(r"\(([^)]*)\)", stripped)
        detail = paren.group(1).strip() if paren else None
        return AuthResult(result=state, detail=detail)
    return None
