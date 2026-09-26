"""Authentication-results extraction (PRD §6.1 / §7 — *Auth*).

SPF / DKIM / DMARC come from ``Authentication-Results`` (RFC 8601), with
``Received-SPF`` (RFC 7208) as a fallback for SPF. Each result is mapped onto
the closed :class:`AuthResultState` vocabulary; the result's properties
(``smtp.mailfrom=``, ``header.d=``, …) are kept verbatim in ``detail``.

Two rules keep a hostile sender from writing their own verdict:

* **Syntax.** A header is split into ``authserv-id; resinfo; resinfo`` only at
  semicolons outside quoted strings and comments, so ``"x;dmarc=pass"`` inside
  a property value or ``(…; dmarc=pass)`` inside a comment is never a result.
* **Trust.** Receiving servers *prepend* their header, so the topmost
  ``Authentication-Results`` is the one the analyst's own infrastructure wrote;
  headers further down arrived with the message and may be forged. Only headers
  carrying the topmost header's ``authserv-id`` are used, and headers from other
  ids are reported as an anomaly for the analyst to review. Each method's
  result comes from the topmost of those headers that reports it, so a lower
  copy claiming the same id (easy to forge) can never override it; a header
  with no ``authserv-id`` at all (Exchange Online writes these) is trusted on
  its own. Only the topmost ``Received-SPF`` is read.

These are still header *claims*: PhishBowl does not re-verify signatures or
SPF records. Best-effort and total: an unparseable header is skipped, never fatal.
"""

from __future__ import annotations

import re

from phishbowl.models import Anomaly, Auth, AuthResult, AuthResultState
from phishbowl.models.headers import Headers

# Methods we report. Others (arc, bimi, iprev, auth, ...) are ignored.
_METHODS = ("spf", "dkim", "dmarc")

# ``method[/version]=result`` at the start of a resinfo clause.
_METHOD_RESULT = re.compile(
    r"^\s*(?P<method>[A-Za-z0-9-]+)(?:\s*/\s*\d+)?\s*=\s*(?P<result>[A-Za-z]+)\s*(?P<detail>.*)$",
    re.DOTALL,
)

# Map result keywords onto our states. Unknown keywords stay ``None`` so an
# odd token never silently masquerades as a real result. "hardfail", "unknown"
# and "error" are legacy spellings (RFC 4408) of fail / permerror / temperror.
_RESULT_MAP = {
    "pass": AuthResultState.PASS,
    "fail": AuthResultState.FAIL,
    "hardfail": AuthResultState.FAIL,
    "softfail": AuthResultState.SOFTFAIL,
    "neutral": AuthResultState.NEUTRAL,
    "none": AuthResultState.NONE,
    "temperror": AuthResultState.TEMPERROR,
    "error": AuthResultState.TEMPERROR,
    "permerror": AuthResultState.PERMERROR,
    "unknown": AuthResultState.PERMERROR,
}

_WHITESPACE = re.compile(r"\s+")


def _state(keyword: str) -> AuthResultState | None:
    return _RESULT_MAP.get(keyword.casefold())


def split_clauses(value: str) -> list[str]:
    """Split an A-R value at semicolons outside quoted strings and comments.

    Comments nest (RFC 5322 §3.2.2); a backslash escapes the next character in
    both. The returned clauses keep their comments; an unterminated quote or
    comment simply runs to the end of the value.
    """
    clauses: list[str] = []
    current: list[str] = []
    depth = 0
    quoted = False
    escaped = False
    for char in value:
        if escaped:
            escaped = False
        elif char == "\\" and (quoted or depth):
            escaped = True
        elif quoted:
            quoted = char != '"'
        elif char == '"' and not depth:
            quoted = True
        elif char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
        elif char == ";" and not depth:
            clauses.append("".join(current))
            current = []
            continue
        current.append(char)
    clauses.append("".join(current))
    return clauses


def strip_comments(text: str) -> str:
    """Remove (possibly nested) parenthesized comments outside quoted strings."""
    out: list[str] = []
    depth = 0
    quoted = False
    escaped = False
    for char in text:
        if escaped:
            escaped = False
            if not depth:
                out.append(char)
            continue
        if char == "\\" and (quoted or depth):
            escaped = True
            if not depth:
                out.append(char)
            continue
        if quoted:
            quoted = char != '"'
            out.append(char)
        elif char == '"' and not depth:
            quoted = True
            out.append(char)
        elif char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
        elif not depth:
            out.append(char)
    return "".join(out)


def authserv_id(value: str) -> str:
    """The ``authserv-id`` (first token of the first clause), lower-cased.

    Empty when the header has none: an id is a token, and a first clause that
    contains ``=`` is already a result (``spf=fail ...``), as Exchange Online
    writes them.
    """
    first = strip_comments(split_clauses(value)[0]).strip()
    if not first or "=" in first:
        return ""
    return first.split(None, 1)[0].casefold()


def _results(value: str):
    """Yield ``(method, state, detail)`` for each result clause in an A-R value."""
    clauses = split_clauses(value)
    for clause in clauses if not authserv_id(value) else clauses[1:]:
        match = _METHOD_RESULT.match(strip_comments(clause))
        if not match:
            continue
        method = match.group("method").casefold()
        state = _state(match.group("result"))
        if method not in _METHODS or state is None:
            continue
        # The detail keeps the receiver's comments ("(p=reject)", "(sender IP
        # is …)"): they explain the result to the analyst. They were only
        # ignored when deciding what the result *is*.
        original = _METHOD_RESULT.match(clause)
        detail = original.group("detail") if original else match.group("detail")
        yield method, state, _WHITESPACE.sub(" ", detail).strip() or None


def _dkim_choice(results: list[tuple[AuthResultState, str | None]], from_domain: str | None):
    """Pick the DKIM result that speaks for the From domain, when one does.

    A message can carry several signatures (the sender's and an ESP's); the one
    whose ``header.d`` (or ``header.i``) is the From domain is what DMARC
    alignment — and the analyst — care about. Otherwise the first result wins.
    """
    if from_domain:
        target = from_domain.casefold().rstrip(".")
        for state, detail in results:
            for match in re.finditer(r"header\.[di]=(?:[^\s;@]*@)?([^\s;@]+)", detail or "", re.I):
                domain = match.group(1).casefold().rstrip(".")
                if domain == target or target.endswith("." + domain):
                    return state, detail
    return results[0]


def parse_auth(headers: Headers, *, from_domain: str | None = None) -> tuple[Auth, list[Anomaly]]:
    """Build :class:`Auth` from the trusted ``Authentication-Results`` headers.

    Returns the results plus any anomalies worth showing the analyst (results
    from other authserv-ids that were not trusted).
    """
    auth = Auth()
    anomalies: list[Anomaly] = []
    values = headers.get_all("Authentication-Results")
    collected: dict[str, list[tuple[AuthResultState, str | None]]] = {}
    if values:
        trusted = authserv_id(values[0])
        # A header without an id cannot be matched to anything: trust it alone.
        candidates = values if trusted else values[:1]
        ignored: set[str] = set()
        repeated: set[str] = set()
        for value in candidates:
            server = authserv_id(value)
            if server != trusted:
                ignored.add(server or "(none)")
                continue
            found: dict[str, list[tuple[AuthResultState, str | None]]] = {}
            for method, state, detail in _results(value):
                found.setdefault(method, []).append((state, detail))
            for method, results in found.items():
                # The topmost header that reports a method decides it.
                if method in collected:
                    repeated.add(method)
                else:
                    collected[method] = results
        ignored.update("(none)" for value in values[len(candidates) :])
        if ignored:
            anomalies.append(
                Anomaly.notice(
                    "auth_untrusted_results",
                    "Authentication-Results from other servers were not used "
                    f"(only the topmost, {trusted or 'without an id'}): "
                    f"{', '.join(sorted(ignored))}",
                )
            )
        if repeated:
            anomalies.append(
                Anomaly.notice(
                    "auth_repeated_results",
                    f"a lower Authentication-Results header from {trusted} repeated "
                    f"{', '.join(sorted(repeated))}; the topmost result was used",
                )
            )

    for method, results in collected.items():
        if method == "dkim":
            state, detail = _dkim_choice(results, from_domain)
        else:
            state, detail = results[0]
        setattr(auth, method, AuthResult(result=state, detail=detail))

    # Received-SPF supplements SPF only when the trusted A-R didn't carry it,
    # and only the topmost one (added by the receiving server) is read.
    if "spf" not in collected:
        spf = _parse_received_spf(headers.get_all("Received-SPF")[:1])
        if spf is not None:
            auth.spf = spf

    return auth, anomalies


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
        # "[^()]" (not "[^)]"): an unbalanced run of "(" cannot trigger a
        # rescan from each one, which is quadratic.
        paren = re.search(r"\(([^()]*)\)", stripped)
        detail = paren.group(1).strip() if paren else None
        return AuthResult(result=state, detail=detail)
    return None
