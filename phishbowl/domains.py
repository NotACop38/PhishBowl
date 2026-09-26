"""Host and registrable-domain helpers backed by the packaged Public Suffix List.

Shared by scoring (lookalike and sender comparisons), enrichment (RDAP queries
the registered domain, not a subdomain; only public hosts are ever sent to a
vendor), and reporting. The PSL snapshot ships with ``tldextract``; downloads
and on-disk caching are disabled, so these helpers never touch the network or
the filesystem. Private suffixes (``github.io``, ``s3.amazonaws.com``, ...) are
honoured, so two tenants of a hosting platform never compare as the same
organization.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Literal

from tldextract import TLDExtract

_PUBLIC_SUFFIX = TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)

# Names that only resolve inside a network (RFC 6761, RFC 8375, common practice).
_LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")
_DNS_NAME = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)+")


def _normalize(host: str) -> str:
    return host.strip().strip(".").casefold()


def registrable_domain(host: str) -> str:
    """The domain an organization registers (``www.example.co.uk`` → ``example.co.uk``).

    Falls back to the normalized host when it has no public suffix (an IP
    literal, ``localhost``, or an unknown TLD).
    """
    host = _normalize(host)
    return _PUBLIC_SUFFIX(host).top_domain_under_public_suffix or host


def registrable_label(host: str) -> str:
    """The label left of the public suffix (``www.paypal.co.uk`` → ``paypal``)."""
    return _PUBLIC_SUFFIX(_normalize(host)).domain


def ascii_host(host: str) -> str:
    """``host`` in ASCII (IDNA/punycode) form, lower-cased, without a trailing dot.

    ``bücher.example`` and ``xn--bcher-kva.example`` compare equal after this.
    A label the IDNA codec rejects leaves the host as-is (still lower-cased).
    """
    host = _normalize(host)
    if host.isascii():
        return host
    # A DNS name is at most 253 characters in labels of at most 63. Longer
    # input is not a host, and Python's punycode encoder is quadratic in label
    # length, so it is never handed attacker-sized strings.
    if len(host) > 253 or any(len(label) > 63 for label in host.split(".")):
        return host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def normalize_domain_pattern(value: str) -> str:
    """Normalize a configured domain: ``*.Example.COM.`` → ``example.com`` (ASCII)."""
    value = _normalize(value)
    return ascii_host(value.removeprefix("*."))


def in_domain(host: str, domains: frozenset[str]) -> bool:
    """True if ``host`` is one of ``domains`` or a subdomain of one (ASCII-normalized)."""
    host = ascii_host(host)
    return any(host == d or host.endswith("." + d) for d in domains)


def web_ipv4(host: str) -> str | None:
    """The dotted IPv4 a browser reads ``host`` as, or ``None`` if it is not IPv4.

    WHATWG URL parsing treats a host whose last label is numeric (decimal, or
    hex with ``0x``) as an IPv4 address in any of the legacy notations
    ``inet_aton`` accepts: ``127.1``, ``0x7f.0.0.1``, ``2130706433``, a trailing
    dot. Returns ``None`` for names; raises :class:`ValueError` for a host that
    ends in a number but is not a valid IPv4 address (browsers reject it).
    """
    host = _normalize(host)
    last = host.rsplit(".", 1)[-1]
    numeric = last.isdigit() or (
        last[:2] == "0x" and all(c in "0123456789abcdef" for c in last[2:])
    )
    if not last or not numeric:
        return None
    try:
        return socket.inet_ntoa(socket.inet_aton(host))
    except OSError:
        raise ValueError(f"invalid IPv4 host {host!r}") from None


def is_public_ip(value: str) -> bool:
    """True for a globally routable unicast IP literal (IPv4 or IPv6)."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


def public_host(host: str) -> tuple[Literal["ip", "name"], str] | None:
    """Classify a host a request could reach, or ``None`` if it is not public.

    Returns ``("ip", canonical)`` for a public IP literal — in any notation a
    browser accepts, bracketed IPv6 included — or ``("name", ascii)`` for a
    syntactically valid DNS name outside the local-only namespaces. Private,
    loopback and link-local addresses, single-label and local names, and
    malformed hosts all return ``None``.
    """
    host = host.strip().casefold()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    host = host.rstrip(".")
    if not host or any(c.isspace() for c in host):
        return None
    try:
        ip: str | None = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            ip = web_ipv4(host)
        except ValueError:
            return None  # ends in a number but is no valid IPv4: unusable host
    if ip is not None:
        return ("ip", ip) if is_public_ip(ip) else None
    name = ascii_host(host)
    if not _DNS_NAME.fullmatch(name) or name.endswith(_LOCAL_SUFFIXES):
        return None
    return ("name", name)
