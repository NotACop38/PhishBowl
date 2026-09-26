"""Protective-link unwrapping — pure string transform, **never a fetch** (PRD §6.2).

Mail gateways rewrite links through "URL protection" wrappers. To triage the
real destination an analyst needs the wrapped link decoded — but PhishBowl must
**never open the link** to do it (AGENTS.md: never fetch the email's URLs).
Every unwrapper here is therefore a deterministic string/codec transform over
the rewritten URL; nothing in this module touches the network. All decoders are
linear-time string operations, and a wrapper longer than 16 KiB is reported as
unresolved rather than decoded.

Reversible offline:

- **Microsoft Safelinks** (``*.safelinks.protection.outlook.com``) — the target
  is percent-encoded in the ``url`` query parameter.
- **Proofpoint URL Defense v1/v2/v3** — three documented encodings (percent /
  ``-_`` substitution / base64 run-length tokens).
- **Barracuda Link Protection** (``linkprotect.cudasvc.com/url?a=…``) — the
  target is percent-encoded in the ``a`` parameter.
- **Cisco Secure Email** (``secure-web.cisco.com/<token>/<target>``) — the
  target is the percent-encoded last path segment.

Detect-but-cannot-reverse offline (kept wrapped, flagged "wrapped, unresolved"):

- **Mimecast** (``protect*.mimecast.com/s/…``) — the target lives on Mimecast's
  servers; the ``domain`` parameter, when present, still names the target host.

Both forms are always retained by the caller (PRD §6.2): the unwrapped target in
``value`` and the original wrapper string in ``wrapped``.
"""

from __future__ import annotations

import html
import re
from base64 import urlsafe_b64decode
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit

# Reversible wrappers
SAFELINKS = "safelinks"
PROOFPOINT = "proofpoint"
BARRACUDA = "barracuda"
CISCO = "cisco"
# Non-reversible-offline wrappers (kept wrapped, flagged unresolved)
MIMECAST = "mimecast"

NON_REVERSIBLE = frozenset({MIMECAST})

# Don't chase wrappers forever — a rewritten link may nest, but a handful of
# layers is plenty and bounds adversarial input (PRD §13).
_MAX_DEPTH = 5

# Longest wrapped URL we decode. Real rewritten links are far shorter.
_MAX_WRAPPED_LENGTH = 16 * 1024


@dataclass(frozen=True)
class UnwrapResult:
    """Outcome of unwrapping one URL.

    ``value`` is the best-known target (the unwrapped URL when reversible, else
    the wrapped URL unchanged); ``wrapped`` is always the original on-wire
    wrapper string; ``wrapper`` names it; ``unresolved`` marks a wrapper we could
    detect but not reverse offline. ``target_domain`` is the destination host a
    non-reversible wrapper still discloses (Mimecast's ``domain`` parameter).
    """

    value: str
    wrapped: str
    wrapper: str
    unresolved: bool
    target_domain: str | None = None


def _host(url: str) -> str:
    try:
        netloc = urlsplit(url).netloc
    except ValueError:
        return ""
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    return netloc.split(":", 1)[0].casefold().rstrip(".")


def _under(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def detect_wrapper(url: str) -> str | None:
    """Return the protective-wrapper name for ``url``, or ``None`` if it's plain."""
    # Browsers treat backslashes as slashes in web URLs, unlike urlsplit.
    # Keep ambiguous URLs intact instead of trusting a different authority.
    if "\\" in url:
        return None
    host = _host(url)
    try:
        path = urlsplit(url).path
    except ValueError:
        return None
    if _under(host, "safelinks.protection.outlook.com"):
        return SAFELINKS
    if _under(host, "urldefense.proofpoint.com") or _under(host, "urldefense.com"):
        return PROOFPOINT
    if _under(host, "mimecast.com") and path.startswith("/s/"):
        return MIMECAST
    if _under(host, "cudasvc.com"):
        return BARRACUDA
    if _under(host, "secure-web.cisco.com"):
        return CISCO
    return None


def _query_value(url: str, name: str) -> str | None:
    """The raw (still-encoded) value of query parameter ``name``, or ``None``."""
    try:
        query = urlsplit(url).query
    except ValueError:
        return None
    prefix = name + "="
    for field in query.split("&"):
        if field.startswith(prefix):
            return field[len(prefix) :]
    return None


def _web_url(value: str | None) -> str | None:
    """``value`` if it is an http(s) URL, else ``None``."""
    if value and value.casefold().startswith(("http://", "https://")):
        return value
    return None


# --- Microsoft Safelinks ---------------------------------------------------


def unwrap_safelinks(url: str) -> str | None:
    """Decode the ``url`` query parameter of a Safelinks-wrapped link."""
    params = parse_qs(urlsplit(url).query)
    target = params.get("url")
    if not target:
        return None
    decoded = target[0]  # parse_qs already decoded this wrapper layer.
    return decoded or None


# --- Proofpoint URL Defense ------------------------------------------------

_PP_V3_TOKEN = re.compile(r"\*(\*.)?")
_PP_V3_SINGLE_SLASH = re.compile(r"^([a-z0-9+.-]+:/)([^/].*)", re.IGNORECASE | re.DOTALL)

# Run-length map: a "**x" token expands to (b64-index(x) + 2) replaced chars; a
# bare "*" is a single replaced char. Alphabet is URL-safe base64.
_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_PP_RUN = {ch: i + 2 for i, ch in enumerate(_B64_ALPHABET)}


def _pp_version(url: str) -> str | None:
    try:
        path = urlsplit(url).path
    except ValueError:
        return None
    m = re.match(r"/(v[123])/", path)
    return m.group(1) if m else None


def _decode_pp_v1(url: str) -> str | None:
    value = _query_value(url, "u")
    return html.unescape(unquote(value)) if value else None


def _decode_pp_v2(url: str) -> str | None:
    value = _query_value(url, "u")
    if not value:
        return None
    return html.unescape(unquote(value.replace("-", "%").replace("_", "/")))


def _decode_pp_v3(url: str) -> str | None:
    start = url.find("/v3/__")
    if start < 0:
        return None
    start += len("/v3/__")
    end = url.find("__;", start)
    if end < 0:
        return None
    bang = url.find("!", end + 3)
    if bang < 0:
        return None
    target = url[start:end]
    trailer = url[end + 3 : bang]
    # Proofpoint collapses "https://" to "https:/" in some rewrites.
    single = _PP_V3_SINGLE_SLASH.match(target)
    if single:
        target = single.group(1) + "/" + single.group(2)
    encoded_url = unquote(target)
    try:
        padded = trailer + "=" * (-len(trailer) % 4)
        dec_bytes = urlsafe_b64decode(padded).decode("utf-8") if trailer else ""
    except (ValueError, UnicodeDecodeError):
        return None

    marker = 0
    out: list[str] = []
    pos = 0
    for tok in _PP_V3_TOKEN.finditer(encoded_url):
        out.append(encoded_url[pos : tok.start()])
        token = tok.group(0)
        run = 1 if token == "*" else _PP_RUN.get(token[-1], 0)  # nosec B105 - run-token
        if marker + run > len(dec_bytes):
            return None  # the tokens ask for more characters than the trailer holds
        out.append(dec_bytes[marker : marker + run])
        marker += run
        pos = tok.end()
    out.append(encoded_url[pos:])
    return "".join(out)


def unwrap_proofpoint(url: str) -> str | None:
    """Decode a Proofpoint URL Defense v1/v2/v3 link to its target."""
    version = _pp_version(url)
    if version == "v1":
        return _decode_pp_v1(url)
    if version == "v2":
        return _decode_pp_v2(url)
    if version == "v3":
        return _decode_pp_v3(url)
    return None


# --- Barracuda and Cisco ---------------------------------------------------


def unwrap_barracuda(url: str) -> str | None:
    """Decode the ``a`` parameter of a Barracuda Link Protection link."""
    value = _query_value(url, "a")
    return _web_url(unquote(value)) if value else None


def unwrap_cisco(url: str) -> str | None:
    """Decode the percent-encoded target that ends a Cisco Secure Email link."""
    try:
        path = urlsplit(url).path
    except ValueError:
        return None
    segments = [segment for segment in path.split("/") if segment]
    if len(segments) < 2:
        return None
    return _web_url(unquote(segments[-1]))


def _mimecast_domain(url: str) -> str | None:
    value = _query_value(url, "domain")
    domain = unquote(value).strip().casefold().rstrip(".") if value else ""
    return domain if domain and "." in domain and "/" not in domain else None


_DECODERS = {
    SAFELINKS: unwrap_safelinks,
    PROOFPOINT: unwrap_proofpoint,
    BARRACUDA: unwrap_barracuda,
    CISCO: unwrap_cisco,
}


def unwrap_url(url: str) -> UnwrapResult | None:
    """Unwrap a protective-link wrapper, or return ``None`` if ``url`` is plain.

    Reversible wrappers are decoded (chasing nested layers up to ``_MAX_DEPTH``);
    non-reversible ones are returned unchanged and flagged ``unresolved``. This is
    a pure string transform — it never fetches ``url`` (AGENTS.md).
    """
    original = url
    outer: str | None = None
    current = url
    seen: set[str] = set()

    for _ in range(_MAX_DEPTH):
        if current in seen:
            break
        seen.add(current)
        wrapper = detect_wrapper(current)
        if wrapper is None:
            break
        if wrapper in NON_REVERSIBLE or len(current) > _MAX_WRAPPED_LENGTH:
            # Detected but not reversible offline: keep the wrapped form, flag it.
            return UnwrapResult(
                value=current,
                wrapped=original,
                wrapper=outer or wrapper,
                unresolved=True,
                target_domain=_mimecast_domain(current) if wrapper == MIMECAST else None,
            )
        decoded = _DECODERS[wrapper](current)
        if not decoded or decoded == current:
            # Recognized the wrapper but couldn't decode it — treat as unresolved
            # rather than silently dropping the layer.
            return UnwrapResult(
                value=current, wrapped=original, wrapper=outer or wrapper, unresolved=True
            )
        if outer is None:
            outer = wrapper
        current = decoded

    if outer is None:
        return None
    # Still wrapped after the depth budget: the final target was never reached.
    unresolved = detect_wrapper(current) is not None
    return UnwrapResult(value=current, wrapped=original, wrapper=outer, unresolved=unresolved)
