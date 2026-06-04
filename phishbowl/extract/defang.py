"""Defanging — render indicators inert for human-facing output (PRD §6.2).

Every URL, IP, email, and domain shown to an analyst is *defanged* by default so
a report or terminal can never auto-link or one-click an attacker's indicator
(``hxxps://evil[.]com``, ``1[.]2[.]3[.]4``, ``user[at]evil[.]com``). This is a
pure string transform — like everything in :mod:`phishbowl.extract`, it never
touches the network.

The JSON output keeps the raw ``value`` alongside the ``defanged`` form for tool
interchange (PRD §6.2); :func:`refang` reverses the transform so a round-trip is
lossless for the indicators we produce.
"""

from __future__ import annotations

import re

from phishbowl.models import IOCType

# http -> hxxp, https -> hxxps, only when it's a real scheme (followed by "://").
_SCHEME_RE = re.compile(r"^(https?)(?=://)", re.IGNORECASE)

# Dangerous code-execution / data URI schemes. A link extracted from a hostile
# message can carry these (e.g. an anchor href), and they must never appear live
# in any output, so we neuter the colon: ``javascript:`` -> ``javascript[:]``.
_DANGEROUS_SCHEME_RE = re.compile(r"^(javascript|data|vbscript)(?=:)", re.IGNORECASE)

# Indicator-shaped tokens inside free text (subject, body preview, evidence). We
# only ever defang things that are actually clickable/copyable indicators — full
# URLs, www-hosts, email addresses, and IPv4 literals — and leave ordinary prose
# (and bare words that merely contain a dot) untouched, so a defanged preview
# stays readable. Applied in order: a scheme URL is bracketed whole first, so the
# later passes never re-touch a host already inside a neutered URL.
_TEXT_URL_RE = re.compile(r"\b(?:https?|hxxps?)://[^\s<>\"'`]+", re.IGNORECASE)
_TEXT_WWW_RE = re.compile(r"\bwww\.[^\s<>\"'`]+", re.IGNORECASE)
_TEXT_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_TEXT_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def defang_url(value: str) -> str:
    """Defang a URL: neuter the scheme and bracket every dot.

    HTTP(S) schemes become ``hxxp(s)``; dangerous code/data URI schemes
    (``javascript:``/``data:``/``vbscript:``) have their colon bracketed so the
    string can never be a live, one-click URI in any viewer.
    """
    out = _SCHEME_RE.sub(lambda m: "hxxp" + m.group(1)[4:], value)
    out = _DANGEROUS_SCHEME_RE.sub(lambda m: m.group(1) + "[:]", out)
    return out.replace(".", "[.]")


def defang_ipv4(value: str) -> str:
    """Defang an IPv4 literal: ``1.2.3.4`` -> ``1[.]2[.]3[.]4``."""
    return value.replace(".", "[.]")


def defang_ipv6(value: str) -> str:
    """Defang an IPv6 literal by bracketing its separators."""
    return value.replace(":", "[:]")


def defang_email(value: str) -> str:
    """Defang an address: ``user@evil.com`` -> ``user[at]evil[.]com``."""
    return value.replace("@", "[at]").replace(".", "[.]")


def defang_domain(value: str) -> str:
    """Defang a bare domain: ``evil.com`` -> ``evil[.]com``."""
    return value.replace(".", "[.]")


def defang(value: str, ioc_type: IOCType) -> str:
    """Defang ``value`` according to its IOC type (PRD §6.2)."""
    if ioc_type is IOCType.URL:
        return defang_url(value)
    if ioc_type is IOCType.IPV4:
        return defang_ipv4(value)
    if ioc_type is IOCType.IPV6:
        return defang_ipv6(value)
    if ioc_type is IOCType.EMAIL:
        return defang_email(value)
    if ioc_type is IOCType.DOMAIN:
        return defang_domain(value)
    # Hashes carry no auto-linkable punctuation; nothing to defang.
    return value


def defang_text(text: str | None) -> str | None:
    """Defang the indicator-shaped tokens inside a free-text string (PRD §6.2).

    Used for human-facing prose — the subject, a body preview, rule evidence —
    where an attacker's live URL, address, or IP would otherwise be copy-pasteable
    (and, in some viewers, auto-linkable). Only URL/www/email/IPv4 tokens are
    rewritten; surrounding prose (and incidental dotted words) is left intact so
    the text stays legible. ``None`` and empty strings pass through unchanged.
    """
    if not text:
        return text
    text = _TEXT_URL_RE.sub(lambda m: defang_url(m.group(0)), text)
    text = _TEXT_WWW_RE.sub(lambda m: m.group(0).replace(".", "[.]"), text)
    text = _TEXT_EMAIL_RE.sub(lambda m: defang_email(m.group(0)), text)
    text = _TEXT_IPV4_RE.sub(lambda m: defang_ipv4(m.group(0)), text)
    return text


def refang(value: str) -> str:
    """Reverse :func:`defang` — restore a live indicator from its defanged form.

    Covers the brackets and scheme swaps Phishbowl emits, plus the common
    ``[at]`` / ``(.)`` variants seen in the wild, so a defang round-trip is
    lossless for the indicators we produce.
    """
    out = (
        value.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
        .replace("[:]", ":")
        .replace("[at]", "@")
        .replace("[@]", "@")
    )
    # Note: ``[:]`` round-trips IPv6 separators and the neutered dangerous-scheme
    # colon alike — both restore to a plain ``:``.
    return out.replace("hxxps://", "https://").replace("hxxp://", "http://")
