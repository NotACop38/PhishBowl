"""Protective-link unwrapping — pure string transform, **never a fetch** (PRD §6.2).

Mail gateways rewrite links through "URL protection" wrappers. To triage the
real destination an analyst needs the wrapped link decoded — but Phishbowl must
**never open the link** to do it (CLAUDE.md: never fetch the email's URLs).
Every unwrapper here is therefore a deterministic string/codec transform over
the rewritten URL; nothing in this module touches the network.

Reversible offline:

- **Microsoft Safelinks** (``*.safelinks.protection.outlook.com``) — the target
  is percent-encoded in the ``url`` query parameter.
- **Proofpoint URL Defense v1/v2/v3** — three documented encodings (percent /
  ``-_`` substitution / base64 run-length tokens).

Detect-but-cannot-reverse offline (kept wrapped, flagged "wrapped, unresolved"):

- **Mimecast** (``protect*.mimecast.com/s/…``), **Barracuda**
  (``linkprotect.cudasvc.com``), **Cisco** (``secure-web.cisco.com``).

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
# Non-reversible-offline wrappers (kept wrapped, flagged unresolved)
MIMECAST = "mimecast"
BARRACUDA = "barracuda"
CISCO = "cisco"

NON_REVERSIBLE = frozenset({MIMECAST, BARRACUDA, CISCO})

# Don't chase wrappers forever — a rewritten link may nest, but a handful of
# layers is plenty and bounds adversarial input (PRD §13).
_MAX_DEPTH = 5


@dataclass(frozen=True)
class UnwrapResult:
    """Outcome of unwrapping one URL.

    ``value`` is the best-known target (the unwrapped URL when reversible, else
    the wrapped URL unchanged); ``wrapped`` is always the original on-wire
    wrapper string; ``wrapper`` names it; ``unresolved`` marks a wrapper we could
    detect but not reverse offline.
    """

    value: str
    wrapped: str
    wrapper: str
    unresolved: bool


def _host(url: str) -> str:
    try:
        netloc = urlsplit(url).netloc
    except ValueError:
        return ""
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    return netloc.split(":", 1)[0].casefold()


def detect_wrapper(url: str) -> str | None:
    """Return the protective-wrapper name for ``url``, or ``None`` if it's plain."""
    host = _host(url)
    try:
        path = urlsplit(url).path
    except ValueError:
        return None
    if host == "safelinks.protection.outlook.com" or host.endswith(
        ".safelinks.protection.outlook.com"
    ):
        return SAFELINKS
    if any(
        host == domain or host.endswith("." + domain)
        for domain in ("urldefense.proofpoint.com", "urldefense.com")
    ):
        return PROOFPOINT
    if host.endswith(".mimecast.com") or host == "mimecast.com":
        if path.startswith("/s/"):
            return MIMECAST
    if host == "linkprotect.cudasvc.com" or host.endswith(".cudasvc.com"):
        return BARRACUDA
    if host == "secure-web.cisco.com" or host.endswith(".secure-web.cisco.com"):
        return CISCO
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

_PP_V1 = re.compile(r"u=(.+?)&k=")
_PP_V2 = re.compile(r"u=(.+?)&[dc]=")
_PP_V3 = re.compile(r"v3/__(.+?)__;(.*?)!")
_PP_V3_TOKEN = re.compile(r"\*(\*.)?")

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
    m = _PP_V1.search(url)
    if not m:
        return None
    return html.unescape(unquote(m.group(1)))


def _decode_pp_v2(url: str) -> str | None:
    m = _PP_V2.search(url)
    if not m:
        return None
    no_run = m.group(1).replace("-", "%").replace("_", "/")
    return html.unescape(unquote(no_run))


def _decode_pp_v3(url: str) -> str | None:
    m = _PP_V3.search(url)
    if not m:
        return None
    encoded_url = unquote(m.group(1))
    trailer = m.group(2)
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
        if token == "*":  # nosec B105 - Proofpoint v3 run-token, not a credential
            out.append(dec_bytes[marker : marker + 1])
            marker += 1
        else:  # "**x" run token: x gives the run length
            run = _PP_RUN.get(token[-1], 0)
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


_DECODERS = {
    SAFELINKS: unwrap_safelinks,
    PROOFPOINT: unwrap_proofpoint,
}


def unwrap_url(url: str) -> UnwrapResult | None:
    """Unwrap a protective-link wrapper, or return ``None`` if ``url`` is plain.

    Reversible wrappers are decoded (chasing nested layers up to ``_MAX_DEPTH``);
    non-reversible ones are returned unchanged and flagged ``unresolved``. This is
    a pure string transform — it never fetches ``url`` (CLAUDE.md).
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
        if wrapper in NON_REVERSIBLE:
            # Detected but not reversible offline: keep the wrapped form, flag it.
            return UnwrapResult(
                value=current, wrapped=original, wrapper=outer or wrapper, unresolved=True
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
    return UnwrapResult(value=current, wrapped=original, wrapper=outer, unresolved=False)
