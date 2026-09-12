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

from urllib.parse import urlsplit

import iocextract

from phishbowl.html_analysis import MAX_TEXT_CHARS, inspect_html
from phishbowl.models import IOC, Address, Anomaly, IOCs, IOCType, ParsedEmail

from .defang import defang
from .unwrap import unwrap_url

# Ordered list of (provenance-label, address) for the header-derived addresses.
_ADDRESS_FIELDS = (
    ("From", "from_"),
    ("Reply-To", "reply_to"),
    ("Return-Path", "return_path"),
    ("Sender", "sender"),
)


class _Collector:
    """Accumulates IOCs keyed by ``(type, value)`` so duplicates merge.

    Insertion order is preserved (dicts are ordered), and re-seeing an indicator
    in another source just appends its provenance rather than creating a second
    entry. Wrapper metadata, once recorded, sticks.
    """

    def __init__(self, parsed: ParsedEmail) -> None:
        self.parsed = parsed
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
            if len(self._items) >= 1000:
                self.note("ioc_limit", "Indicator count exceeded 1,000; later indicators withheld")
                return
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

    def note(self, code: str, message: str) -> None:
        if not any(a.code == code and a.message == message for a in self.parsed.anomalies):
            self.parsed.anomalies.append(Anomaly(code=code, message=message))

    def result(self) -> IOCs:
        return IOCs(items=list(self._items.values()))


def extract_iocs(parsed: ParsedEmail) -> IOCs:
    """Extract, unwrap, defang, dedupe, and provenance-tag every IOC (PRD §6.2)."""
    collector = _Collector(parsed)

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

    for attachment in parsed.attachments:
        if attachment.sha256:
            collector.add(IOCType.HASH, attachment.sha256, "attachment:sha256")

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
    inspected = inspect_html(html_raw)
    if not inspected.complete:
        collector.note(
            "html_incomplete", "HTML parsing was incomplete; markup may contain unrecognized links"
        )
    for link in inspected.links:
        _add_url(collector, link, provenance)
    visible = inspected.text
    _scan_text(collector, visible, provenance)


def _scan_text(collector: _Collector, text: str, provenance: str) -> None:
    """Run iocextract + custom passes over one text blob."""
    if len(text) > MAX_TEXT_CHARS:
        collector.note("analysis_truncated", f"{provenance}: text analysis limit exceeded")
    text = text[:MAX_TEXT_CHARS]
    # iocextract uses the timeout-capable regex package. Its high-level generators
    # omit that budget (and its IPv4 iterator rescans the whole input per match).
    # Use the same patterns/refangers with a per-pass deadline instead.
    passes = (
        [
            (pattern, 1, IOCType.URL, iocextract.refang_data)
            for pattern in (
                iocextract.url_re(False),
                iocextract.BRACKET_URL_RE,
                iocextract.BACKSLASH_URL_RE,
            )
        ]
        + [
            (iocextract.ipv4_len(), 0, IOCType.IPV4, iocextract.refang_ipv4),
            (iocextract.IPV6_RE, 0, IOCType.IPV6, str),
            (iocextract.EMAIL_RE, 1, IOCType.EMAIL, iocextract.refang_email),
        ]
        + [
            (pattern, 1, IOCType.HASH, str)
            for pattern in (
                iocextract.MD5_RE,
                iocextract.SHA1_RE,
                iocextract.SHA256_RE,
                iocextract.SHA512_RE,
            )
        ]
    )
    for pattern, group, kind, normalize in passes:
        try:
            for match in pattern.finditer(text, timeout=0.15):
                value = normalize(match.group(group)).strip()
                if kind == IOCType.URL:
                    _add_url(collector, value, provenance)
                else:
                    value = value.casefold()
                    collector.add(kind, value, provenance)
                    if kind == IOCType.EMAIL:
                        domain = _domain_of_email(value)
                        if domain:
                            collector.add(IOCType.DOMAIN, domain, provenance)
        except TimeoutError:
            collector.note(
                "extraction_timeout",
                (
                    f"{provenance}: {kind.value} scan exceeded its time budget; "
                    "evidence may be missing"
                ),
            )


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
