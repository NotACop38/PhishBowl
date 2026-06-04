"""IOC extraction over a parsed message (PRD §6.2).

Pulls every indicator — addresses, URLs, domains, IPv4/IPv6, file hashes — out
of a :class:`~phishbowl.models.ParsedEmail` using ``iocextract`` plus custom
passes, then:

- **unwraps** protective link wrappers as a pure string transform (Safelinks,
  Proofpoint), retaining both forms (:mod:`phishbowl.extract.unwrap`);
- **defangs** every indicator for human-facing output
  (:mod:`phishbowl.extract.defang`);
- **deduplicates** and **normalizes** indicators while **preserving provenance**
  — which header or body part each was seen in.

Like the rest of :mod:`phishbowl.extract`, this never touches the network: the
analyzed email's URLs are pattern-matched and string-decoded, never fetched
(CLAUDE.md defensive invariants).
"""

from __future__ import annotations

import html
import re
from urllib.parse import urlsplit

import iocextract

from phishbowl.models import IOC, Address, IOCs, IOCType, ParsedEmail

from .defang import defang
from .unwrap import unwrap_url

# Ordered list of (provenance-label, address) for the header-derived addresses.
_ADDRESS_FIELDS = (
    ("From", "from_"),
    ("Reply-To", "reply_to"),
    ("Return-Path", "return_path"),
    ("Sender", "sender"),
)

# Link-bearing HTML attributes. We pull URLs from these by name rather than
# regexing the whole blob, so a quote-terminated href can't bleed into the
# following markup. The body HTML is only ever string-scanned, never rendered
# (PRD §10).
_HTML_LINK_ATTR = re.compile(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_HTML_TAG = re.compile(r"<[^>]+>")


class _Collector:
    """Accumulates IOCs keyed by ``(type, value)`` so duplicates merge.

    Insertion order is preserved (dicts are ordered), and re-seeing an indicator
    in another source just appends its provenance rather than creating a second
    entry. Wrapper metadata, once recorded, sticks.
    """

    def __init__(self) -> None:
        self._items: dict[tuple[IOCType, str], IOC] = {}

    def add(
        self,
        ioc_type: IOCType,
        value: str,
        provenance: str,
        *,
        wrapped: str | None = None,
        wrapper: str | None = None,
        unresolved: bool = False,
    ) -> None:
        if not value:
            return
        key = (ioc_type, value)
        existing = self._items.get(key)
        if existing is None:
            self._items[key] = IOC(
                type=ioc_type,
                value=value,
                defanged=defang(value, ioc_type),
                provenance=[provenance],
                wrapped=wrapped,
                wrapper=wrapper,
                unresolved=unresolved,
            )
            return
        if provenance not in existing.provenance:
            existing.provenance.append(provenance)
        # Fill wrapper metadata from whichever occurrence carried it.
        if wrapper and existing.wrapper is None:
            existing.wrapped = wrapped
            existing.wrapper = wrapper
            existing.unresolved = unresolved

    def result(self) -> IOCs:
        return IOCs(items=list(self._items.values()))


def extract_iocs(parsed: ParsedEmail) -> IOCs:
    """Extract, unwrap, defang, dedupe, and provenance-tag every IOC (PRD §6.2)."""
    collector = _Collector()

    # Addresses come from the structured parse (cleaner than regexing raw
    # headers), each tagged with the header it sat in.
    for label, attr in _ADDRESS_FIELDS:
        _add_address(collector, getattr(parsed.addresses, attr), f"header:{label}")
    for addr in parsed.addresses.to:
        _add_address(collector, addr, "header:To")
    for addr in parsed.addresses.cc:
        _add_address(collector, addr, "header:Cc")

    # Free-text sources: the subject and both body parts. ``html_raw`` is only
    # ever string-scanned here, never rendered (PRD §10).
    if parsed.subject:
        _scan_text(collector, parsed.subject, "header:Subject")
    if parsed.body.text:
        _scan_text(collector, parsed.body.text, "body:text")
    if parsed.body.html_raw:
        _scan_html(collector, parsed.body.html_raw, "body:html")

    return collector.result()


def _add_address(collector: _Collector, addr: Address | None, provenance: str) -> None:
    if addr is None or not addr.addr_spec:
        return
    email = addr.addr_spec.strip().casefold()
    collector.add(IOCType.EMAIL, email, provenance)
    domain = addr.domain or _domain_of_email(email)
    if domain:
        collector.add(IOCType.DOMAIN, domain.strip().casefold().rstrip("."), provenance)


def _scan_html(collector: _Collector, html_raw: str, provenance: str) -> None:
    """Extract IOCs from an HTML body part.

    Link URLs come from ``href`` / ``src`` attributes (HTML-unescaped), and the
    rest of the indicators from the de-tagged, unescaped visible text. The markup
    is only ever string-scanned here — never rendered (PRD §10).
    """
    for match in _HTML_LINK_ATTR.finditer(html_raw):
        _add_url(collector, html.unescape(match.group(1)), provenance)
    visible = html.unescape(_HTML_TAG.sub(" ", html_raw))
    _scan_text(collector, visible, provenance)


def _scan_text(collector: _Collector, text: str, provenance: str) -> None:
    """Run iocextract + custom passes over one text blob."""
    # ``extract_unencoded_urls`` (vs. ``extract_urls``) avoids re-decoding the
    # percent-encoded inner URL of a wrapper into a truncated junk indicator;
    # refang=True still recovers any defanged URLs present in the source.
    for raw_url in iocextract.extract_unencoded_urls(text, refang=True):
        _add_url(collector, raw_url, provenance)

    for ip in iocextract.extract_ipv4s(text, refang=True):
        collector.add(IOCType.IPV4, ip.strip(), provenance)
    for ip in iocextract.extract_ipv6s(text):
        collector.add(IOCType.IPV6, ip.strip(), provenance)

    for email in iocextract.extract_emails(text, refang=True):
        email = email.strip().casefold()
        collector.add(IOCType.EMAIL, email, provenance)
        domain = _domain_of_email(email)
        if domain:
            collector.add(IOCType.DOMAIN, domain, provenance)

    for digest in iocextract.extract_hashes(text):
        collector.add(IOCType.HASH, digest.strip().casefold(), provenance)


def _add_url(collector: _Collector, raw_url: str, provenance: str) -> None:
    """Add a URL, unwrapping a protective wrapper if present (string transform only)."""
    url = raw_url.strip().strip("<>\"'")
    if not url:
        return

    unwrapped = unwrap_url(url)
    if unwrapped is None:
        collector.add(IOCType.URL, url, provenance)
        effective = url
    else:
        collector.add(
            IOCType.URL,
            unwrapped.value,
            provenance,
            wrapped=unwrapped.wrapped,
            wrapper=unwrapped.wrapper,
            unresolved=unwrapped.unresolved,
        )
        effective = unwrapped.value

    # The destination host is itself an indicator. For a reversibly-unwrapped
    # link this surfaces the *real* target domain, not the gateway's.
    host = _host_of_url(effective)
    if host:
        collector.add(IOCType.DOMAIN, host, provenance)


def _domain_of_email(email: str) -> str | None:
    _, _, domain = email.partition("@")
    domain = domain.strip().rstrip(".")
    return domain or None


def _host_of_url(url: str) -> str | None:
    """Bare hostname of a URL, or ``None`` for IP-literal / unparseable hosts."""
    try:
        netloc = urlsplit(url).netloc
    except ValueError:
        return None
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    if netloc.startswith("["):  # IPv6 literal host — not a domain
        return None
    host = netloc.split(":", 1)[0].strip().casefold().rstrip(".")
    if not host or host.replace(".", "").isdigit():  # IPv4 literal host
        return None
    return host
