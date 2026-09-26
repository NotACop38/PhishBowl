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
(AGENTS.md defensive invariants).
"""

from __future__ import annotations

import ipaddress
import re
import warnings
from urllib.parse import parse_qs, unquote, urlsplit

import regex

with warnings.catch_warnings():
    # iocextract 1.16 has invalid escape sequences in plain strings, which
    # Python 3.12+ reports as SyntaxWarning when it first compiles the module.
    # They are harmless (the strings mean what they say) and not ours to fix.
    warnings.simplefilter("ignore", SyntaxWarning)
    import iocextract

from phishbowl.domains import web_ipv4
from phishbowl.html_analysis import MAX_TEXT_CHARS, inspect_html
from phishbowl.models import IOC, Address, Anomaly, IOCs, IOCType, ParsedEmail

from .defang import defang
from .unwrap import unwrap_url

# At most this many distinct indicators are kept per message; later ones are
# withheld with a coverage-gap anomaly (a hostile message can list thousands).
MAX_IOCS = 1000

# Link schemes recorded as URL indicators. Script and inline-document URIs are
# recorded only as navigation targets (an ``href`` of ``javascript:``/``data:``
# is a hostile construct worth surfacing; an inline ``data:`` image is not).
_WEB_SCHEMES = frozenset({"http", "https", "ftp", "ftps", "file"})
_SCRIPT_SCHEMES = frozenset({"javascript", "vbscript", "data"})
# Schemes that name no network indicator: inline parts, phone numbers, the page itself.
_INERT_SCHEMES = frozenset({"cid", "mid", "tel", "sms", "callto", "about", "blob"})
_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*")

# Browsers delete tabs and newlines anywhere in a URL and ignore leading and
# trailing C0 controls and spaces: to them "ht\ttps://" is "https://".
_URL_DELETED = re.compile(r"[\t\n\r]")
_URL_TRIMMED = "".join(map(chr, range(0x21)))

# A UNC path (\\host\share): Windows reaches the host over SMB, sending the
# user's credentials, when such a link or image is opened.
_UNC_RE = re.compile(r"\\\\([^\\/\s?#]+)")

# Email addresses. iocextract's pattern tolerates spaces around the "@" so it
# can read defanged prose, which glues the preceding word onto real addresses
# ("Hello jane@corp.example" → "hellojane@corp.example"). Plain addresses are
# matched strictly instead (``\w`` is Unicode-aware, so IDN addresses count),
# and defanged ones only in their explicit bracketed forms
# (``user[at]evil[.]example``, ``user (at) evil (dot) example``). Both use the
# timeout-capable ``regex`` engine like the other passes.
_EMAIL_RE = regex.compile(
    r"(?<![\w.%+\-])[\w.%+\-]{1,64}@(?:[\w\-]{1,63}\.){1,127}[\w\-]{2,63}(?![\w\-])"
)
_DEFANGED_EMAIL_RE = regex.compile(
    r"(?<![\w.%+\-])[\w.%+\-]{1,64}\s?[\[\(\{]\s?(?:at|@)\s?[\]\)\}]\s?"
    r"(?:[\w\-]{1,63}\s?(?:[\[\(\{]\s?(?:dot|\.)\s?[\]\)\}]|\.)\s?){1,127}[\w\-]{2,63}(?![\w\-])",
    regex.IGNORECASE,
)

# Ordered list of (provenance-label, address) for the header-derived addresses.
_ADDRESS_FIELDS = (
    ("From", "from_"),
    ("Reply-To", "reply_to"),
    ("Return-Path", "return_path"),
    ("Sender", "sender"),
)


class _Collector:
    """Accumulates IOCs keyed by ``(type, value)`` so duplicates merge.

    Values are kept as found (after refanging and unwrapping, not otherwise
    canonicalized). Insertion order is preserved (dicts are ordered), and
    re-seeing an indicator in another source just appends its provenance rather
    than creating a second entry. Wrapper metadata, once recorded, sticks.
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
            if len(self._items) >= MAX_IOCS:
                self.note(
                    "ioc_limit", f"Indicator count exceeded {MAX_IOCS:,}; later indicators withheld"
                )
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
    """Extract, unwrap, defang, dedupe, and provenance-tag every IOC (PRD §6.2).

    Structured evidence is collected before free text — header addresses,
    attachment hashes, then HTML link targets — so the indicator cap can only
    ever withhold free-text matches, never a file hash or a link a reader
    would click.
    """
    collector = _Collector(parsed)

    # Addresses come from the structured parse (cleaner than regexing raw
    # headers), each tagged with the header it sat in.
    for label, attr in _ADDRESS_FIELDS:
        _add_address(collector, getattr(parsed.addresses, attr), f"header:{label}")
    for addr in parsed.addresses.to:
        _add_address(collector, addr, "header:To")
    for addr in parsed.addresses.cc:
        _add_address(collector, addr, "header:Cc")

    for attachment in parsed.attachments:
        if attachment.sha256:
            collector.add(IOCType.HASH, attachment.sha256, "attachment:sha256")

    # ``html_raw`` is only ever string-scanned here, never rendered (PRD §10).
    inspected = inspect_html(parsed.body.html_raw) if parsed.body.html_raw else None
    if inspected is not None:
        if not inspected.complete:
            collector.note(
                "html_incomplete",
                "HTML parsing was incomplete; markup may contain unrecognized links",
            )
        for link in inspected.links:
            _add_link(collector, link, "body:html", navigation=True)
        for resource in inspected.resources:
            _add_link(collector, resource, "body:html", navigation=False)

    # Free text: the subject and every body part, visible text before text a
    # renderer hides (script/style contents).
    if parsed.subject:
        _scan_text(collector, parsed.subject, "header:Subject")
    if parsed.body.text:
        _scan_text(collector, parsed.body.text, "body:text")
    if inspected is not None:
        _scan_text(collector, inspected.text, "body:html")
        if inspected.hidden_text.strip():
            _scan_text(collector, inspected.hidden_text, "body:html-hidden")
    for part in parsed.body.other_text:
        _scan_text(collector, part.text, f"body:{part.content_type}")

    return collector.result()


def _add_address(collector: _Collector, addr: Address | None, provenance: str) -> None:
    if addr is None or not addr.addr_spec:
        return
    email = addr.addr_spec.strip().casefold()
    collector.add(IOCType.EMAIL, email, provenance)
    domain = addr.domain or _domain_of_email(email)
    if domain:
        collector.add(IOCType.DOMAIN, domain.strip().casefold().rstrip("."), provenance)


def _add_link(collector: _Collector, link: str, provenance: str, *, navigation: bool) -> None:
    """Record an HTML attribute URL by what it can reach.

    The value is read the way a browser reads it (tabs and newlines deleted,
    surrounding controls and spaces ignored). Web URLs and protocol-relative
    ``//host`` links are URL indicators; ``mailto:`` links contribute their
    addresses; ``javascript:``/``data:`` navigation targets are kept as the
    hostile constructs they are. UNC paths (``\\\\host\\share``) and other
    application or file-sharing schemes (``search-ms:``, ``ms-word:``,
    ``smb:``) are kept too, with any host or web link inside them. Fragments,
    relative paths, ``cid:`` inline-image references and ``tel:`` links name
    no network indicator and are skipped.
    """
    value = _URL_DELETED.sub("", link).strip(_URL_TRIMMED)
    if value.startswith("//"):
        _add_url(collector, value, provenance)
        return
    if value.startswith("\\\\"):
        collector.add(IOCType.URL, value, provenance)
        _add_unc_hosts(collector, value, provenance)
        return
    scheme, separator, rest = value.partition(":")
    if not separator or not _SCHEME_RE.fullmatch(scheme):
        return
    scheme = scheme.casefold()
    if scheme in _WEB_SCHEMES or (navigation and scheme in _SCRIPT_SCHEMES):
        _add_url(collector, value, provenance)
    elif scheme == "mailto":
        # Recipients sit in the path and in to/cc/bcc; subject/body may carry links.
        path, _, query = rest.partition("?")
        fields = [unquote(path)] + [v for values in parse_qs(query).values() for v in values]
        _scan_text(collector, " ".join(fields), provenance)
    elif scheme not in _INERT_SCHEMES and scheme not in _SCRIPT_SCHEMES:
        # A protocol handler hands the value to another program; keep it as
        # evidence, with the host it names and the web links it usually wraps.
        collector.add(IOCType.URL, value, provenance)
        _add_host_iocs(collector, value, provenance)
        inner = unquote(rest)
        _add_unc_hosts(collector, inner, provenance)
        _scan_text(collector, inner, provenance)


def _add_unc_hosts(collector: _Collector, text: str, provenance: str) -> None:
    """Add the host of every UNC path (``\\\\host\\share``) in ``text``."""
    for host in _UNC_RE.findall(text):
        _add_host_iocs(collector, f"//{host}/", provenance)


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
            (_EMAIL_RE, 0, IOCType.EMAIL, str),
            (_DEFANGED_EMAIL_RE, 0, IOCType.EMAIL, _refang_email),
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
        # The time budget covers the regex alone: matches are collected (and
        # de-duplicated) first, so per-match work cannot use up the deadline.
        found_values: dict[str, None] = {}
        try:
            for match in pattern.finditer(text, timeout=0.15):
                found_values[match.group(group)] = None
        except TimeoutError:
            collector.note(
                "extraction_timeout",
                (
                    f"{provenance}: {kind.value} scan exceeded its time budget; "
                    "evidence may be missing"
                ),
            )
        for found in found_values:
            try:
                value = normalize(found).strip()
            except ValueError:
                # Refanging parses the URL; keep evidence it cannot parse as written.
                value = found.strip()
            if kind == IOCType.URL:
                _add_url(collector, value, provenance)
                continue
            value = value.casefold()
            if kind == IOCType.IPV6 and not _is_ipv6(value):
                continue  # times ("10:30:00") and MAC addresses look alike
            collector.add(kind, value, provenance)
            if kind == IOCType.EMAIL:
                domain = _domain_of_email(value)
                if domain:
                    collector.add(IOCType.DOMAIN, domain, provenance)


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
        if unwrapped.target_domain:
            # A non-reversible wrapper that still names its destination host.
            collector.add(IOCType.DOMAIN, unwrapped.target_domain, provenance)

    # The destination host is itself an indicator. For a reversibly-unwrapped
    # link this surfaces the *real* target domain, not the gateway's.
    _add_host_iocs(collector, effective, provenance)


def _add_host_iocs(collector: _Collector, url: str, provenance: str) -> None:
    """Add a URL's host as a domain indicator, or as an IP one for an IP literal."""
    ip = _ip_of_url(url)
    if ip is not None:
        collector.add(IOCType.IPV6 if ":" in ip else IOCType.IPV4, ip, provenance)
        return
    host = _host_of_url(url)
    if host:
        collector.add(IOCType.DOMAIN, host, provenance)


def _refang_email(value: str) -> str:
    """``user [at] evil (dot) example`` → ``user@evil.example``."""
    value = regex.sub(r"\s?[\[\(\{]\s?(?:at|@)\s?[\]\)\}]\s?", "@", value, flags=regex.I)
    value = regex.sub(r"\s?[\[\(\{]\s?(?:dot|\.)\s?[\]\)\}]\s?", ".", value, flags=regex.I)
    return value.replace(" ", "")


def _is_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return True


def _ip_of_url(url: str) -> str | None:
    """The canonical IP address hosting ``url``, or ``None`` for a named host.

    The host is read as a browser reads it, so the legacy IPv4 notations
    (``http://167772165/``, ``http://0x7f.1/``) name an address too.
    """
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        return web_ipv4(host)
    except ValueError:
        return None


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
    if not host:
        return None
    try:
        # A host ending in a number is an IPv4 address to a browser, or invalid.
        return None if web_ipv4(host) else host
    except ValueError:
        return None
