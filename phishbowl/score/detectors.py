"""Offline detectors — the §8 signal catalog (PRD §8).

Each detector is a pure function over a :class:`ScoringContext` (the parsed
message, its extracted IOCs, and the resolved config) that returns a list of
**evidence strings**: non-empty means the rule fired, empty means it stayed
silent. Detectors never mutate state and — like everything in the offline core —
never touch the network: the email's URLs are string-inspected, never fetched
(CLAUDE.md). All domain/URL evidence is defanged for human-facing output
(PRD §6.2).

Anti-double-counting is built in (PRD §8 "no signal is double-counted"):

* a rule contributes its weight at most once no matter how many indicators
  trigger it (the engine adds each fired rule's weight a single time);
* ``auth.results_missing`` only fires when the whole ``Authentication-Results``
  header is absent, while ``auth.dkim_none`` only fires when the header IS
  present — the two can never both claim the same gap;
* ``url.lookalike`` skips non-ASCII and punycode domains, leaving those to
  ``url.idn_homograph`` / ``url.punycode`` so a single confusable domain isn't
  counted twice.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import cached_property
from urllib.parse import urlsplit

from phishbowl.extract.defang import defang_domain
from phishbowl.models import IOC, AuthResultState, IOCType, ParsedEmail

from .config import ScoringConfig
from .rules import DetectorSpec, RuleSource

# --- small text/domain helpers ---------------------------------------------

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_TEXT_HOST_RE = re.compile(
    r"(?:https?://)?((?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,})", re.IGNORECASE
)
_ANCHOR_RE = re.compile(
    r"<a\b[^>]*?href\s*=\s*([\"'])(?P<href>.*?)\1[^>]*>(?P<text>.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain: the last two labels of ``host``.

    A deliberate approximation — Phishbowl ships no Public Suffix List in the
    offline core — so multi-label TLDs (``co.uk``) over-collapse. That's
    acceptable here: registrable comparison only ever feeds heuristics (lookalike
    distance, anchor/sender divergence), never a hard verdict, and the
    fixtures/brands use single-label TLDs.
    """
    host = host.strip().strip(".").casefold()
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    return ".".join(labels[-2:])


def url_host(url: str) -> str | None:
    """Lower-cased hostname of a URL (port and IPv6 brackets stripped)."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.casefold() if host else None


def is_ip_literal(host: str) -> bool:
    """True if ``host`` is an IPv4/IPv6 literal rather than a domain name."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance (insert/delete/substitute), iterative DP."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _script_of(ch: str) -> str | None:
    """Coarse Unicode script bucket for an alphabetic char (``None`` otherwise).

    Only enough scripts to catch the classic homograph attack — Latin mixed with
    a confusable from another alphabet (Cyrillic/Greek/...). Digits, hyphens, and
    dots return ``None`` so they never count as "another script".
    """
    if not ch.isalpha():
        return None
    o = ord(ch)
    if (0x41 <= o <= 0x5A) or (0x61 <= o <= 0x7A) or (0xC0 <= o <= 0x24F):
        return "Latin"
    if (0x0370 <= o <= 0x03FF) or (0x1F00 <= o <= 0x1FFF):
        return "Greek"
    if (0x0400 <= o <= 0x04FF) or (0x0500 <= o <= 0x052F):
        return "Cyrillic"
    if 0x0530 <= o <= 0x058F:
        return "Armenian"
    if 0x0590 <= o <= 0x05FF:
        return "Hebrew"
    if 0x0600 <= o <= 0x06FF:
        return "Arabic"
    return "Other"


def is_mixed_script(label: str) -> bool:
    """True if a single domain label mixes alphabets (a confusable homograph).

    The textbook IDN attack swaps one ASCII letter for an identical-looking glyph
    from another script (``pаypal`` — Cyrillic ``а`` among Latin), which shows up
    as more than one script within one label.
    """
    scripts = {s for s in (_script_of(c) for c in label) if s is not None}
    return len(scripts) > 1


def _word_in(word: str, text: str) -> bool:
    """Whole-word, case-insensitive match of ``word`` in ``text``."""
    return re.search(rf"\b{re.escape(word)}\b", text, re.IGNORECASE) is not None


def _first_host_in_text(text: str) -> str | None:
    m = _TEXT_HOST_RE.search(text)
    return m.group(1).casefold() if m else None


def _strip_tags(html: str) -> str:
    import html as _html

    return _WS_RE.sub(" ", _html.unescape(_TAG_RE.sub(" ", html))).strip()


def _dedup(items: list[str]) -> list[str]:
    """Order-preserving de-duplication of evidence strings."""
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


# --- scoring context --------------------------------------------------------


@dataclass(frozen=True)
class ScoringContext:
    """Everything a detector needs, with derived views computed once.

    Built from the offline pipeline's outputs (parsed message + extracted IOCs)
    plus the resolved config. Derived collections (candidate domains, URL IOCs,
    HTML anchors) are cached so the rule sweep stays cheap.
    """

    parsed: ParsedEmail
    iocs: object  # phishbowl.models.IOCs (typed loosely to avoid import cycle churn)
    config: ScoringConfig

    @cached_property
    def from_domain(self) -> str | None:
        frm = self.parsed.addresses.from_
        return frm.domain.casefold() if frm and frm.domain else None

    @cached_property
    def from_registrable(self) -> str | None:
        return registrable_domain(self.from_domain) if self.from_domain else None

    @cached_property
    def auth_present(self) -> bool:
        """Whether an ``Authentication-Results`` header was present at all."""
        return "Authentication-Results" in self.parsed.headers

    @cached_property
    def auth_lossy(self) -> bool:
        """Whether auth is unavailable due to format lossiness (e.g. .msg)."""
        return any(a.code == "msg_auth_unavailable" for a in self.parsed.anomalies)

    @cached_property
    def url_iocs(self) -> list[IOC]:
        return [i for i in self.iocs if i.type is IOCType.URL]

    @cached_property
    def candidate_domains(self) -> set[str]:
        """Every domain worth screening: domain IOCs, URL hosts, sender-side
        address domains — deduped and case-folded."""
        domains: set[str] = set()
        for ioc in self.iocs:
            if ioc.type is IOCType.DOMAIN:
                domains.add(ioc.value.casefold())
            elif ioc.type is IOCType.URL:
                host = url_host(ioc.value)
                if host and not is_ip_literal(host):
                    domains.add(host)
        addrs = self.parsed.addresses
        for addr in (addrs.from_, addrs.reply_to, addrs.return_path, addrs.sender):
            if addr and addr.domain:
                domains.add(addr.domain.casefold())
        return domains

    @cached_property
    def lookalike_targets(self) -> set[str]:
        """Domains worth typosquat-comparing against: bundled brands + org domains."""
        targets: set[str] = set(self.config.org_domains)
        for legit in self.config.brands.values():
            targets |= set(legit)
        return targets

    @cached_property
    def anchors(self) -> list[tuple[str, str]]:
        """``(href, visible_text)`` pairs from the HTML body, never rendered."""
        html = self.parsed.body.html_raw
        if not html:
            return []
        out: list[tuple[str, str]] = []
        for m in _ANCHOR_RE.finditer(html):
            out.append((m.group("href").strip(), _strip_tags(m.group("text"))))
        return out


# --- authentication detectors (PRD §8) -------------------------------------


def _auth_detail(detail: str | None) -> str:
    return f" — {detail}" if detail else ""


def spf_fail(ctx: ScoringContext) -> list[str]:
    r = ctx.parsed.auth.spf
    if r.result is AuthResultState.FAIL:
        return [f"spf=fail{_auth_detail(r.detail)}"]
    return []


def spf_softfail(ctx: ScoringContext) -> list[str]:
    r = ctx.parsed.auth.spf
    if r.result is AuthResultState.SOFTFAIL:
        return [f"spf=softfail{_auth_detail(r.detail)}"]
    return []


def dkim_fail(ctx: ScoringContext) -> list[str]:
    r = ctx.parsed.auth.dkim
    if r.result is AuthResultState.FAIL:
        return [f"dkim=fail{_auth_detail(r.detail)}"]
    return []


def dkim_none(ctx: ScoringContext) -> list[str]:
    # Only meaningful when other results ARE present; if the whole header is
    # missing, auth.results_missing owns that gap (no double-count).
    if ctx.auth_present and ctx.parsed.auth.dkim.result is AuthResultState.NONE:
        return ["dkim=none (message carries no valid DKIM signature)"]
    return []


def dmarc_fail(ctx: ScoringContext) -> list[str]:
    r = ctx.parsed.auth.dmarc
    if r.result is AuthResultState.FAIL:
        return [f"dmarc=fail{_auth_detail(r.detail)}"]
    return []


def auth_results_missing(ctx: ScoringContext) -> list[str]:
    # Absent header on a normal message is itself a signal — but NOT when the
    # format simply can't carry it (e.g. .msg), which is noted separately.
    if not ctx.auth_present and not ctx.auth_lossy:
        return ["no Authentication-Results header present"]
    return []


# --- identity / spoofing detectors (PRD §8) --------------------------------


def return_path_mismatch(ctx: ScoringContext) -> list[str]:
    addrs = ctx.parsed.addresses
    if addrs.return_path_mismatch:
        return [
            f"Return-Path {defang_domain(addrs.return_path.domain)} "
            f"≠ From {defang_domain(addrs.from_.domain)}"
        ]
    return []


def reply_to_mismatch(ctx: ScoringContext) -> list[str]:
    addrs = ctx.parsed.addresses
    if addrs.reply_to_mismatch:
        return [
            f"Reply-To {defang_domain(addrs.reply_to.domain)} "
            f"≠ From {defang_domain(addrs.from_.domain)}"
        ]
    return []


def sender_mismatch(ctx: ScoringContext) -> list[str]:
    addrs = ctx.parsed.addresses
    if addrs.sender_mismatch:
        return [
            f"Sender {defang_domain(addrs.sender.domain)} "
            f"≠ From {defang_domain(addrs.from_.domain)}"
        ]
    return []


def _domain_in_brand(domain: str, legit: frozenset[str]) -> bool:
    """True if ``domain`` is, or is a subdomain of, one of the brand's domains."""
    return any(domain == d or domain.endswith("." + d) for d in legit)


def display_name_brand_mismatch(ctx: ScoringContext) -> list[str]:
    frm = ctx.parsed.addresses.from_
    if not frm or not frm.display_name or not frm.domain:
        return []
    dn = frm.display_name
    dom = frm.domain.casefold()
    # Check EVERY brand the display name claims, not just the first match: a
    # legitimately-owned brand must not mask a second, unowned brand in the same
    # display name ("PayPal Apple Support" from paypal.com still impersonates Apple).
    hits: list[str] = []
    for brand, legit in ctx.config.brands.items():
        if not _word_in(brand, dn):
            continue
        if _domain_in_brand(dom, legit):
            continue  # the From domain legitimately owns this claimed brand
        hits.append(f'display name claims "{brand}" but From domain is {defang_domain(frm.domain)}')
    return hits


def freemail_brand(ctx: ScoringContext) -> list[str]:
    frm = ctx.parsed.addresses.from_
    if not frm or not frm.domain:
        return []
    dom = frm.domain.casefold()
    if dom not in ctx.config.freemail_domains:
        return []
    dn = frm.display_name or ""
    for brand, legit in ctx.config.brands.items():
        if dom in legit:
            continue  # this freemail IS the brand's domain (e.g. gmail/google)
        if _word_in(brand, dn):
            spec = frm.addr_spec or dom
            return [f'freemail sender {spec.replace("@", "[at]")} claims to be "{brand}"']
    return []


def display_name_is_email(ctx: ScoringContext) -> list[str]:
    frm = ctx.parsed.addresses.from_
    if frm and frm.display_name and _EMAIL_RE.search(frm.display_name):
        return [f'From display name is itself an email address: "{frm.display_name}"']
    return []


# --- domain / URL detectors (PRD §8) ---------------------------------------


def punycode(ctx: ScoringContext) -> list[str]:
    return _dedup(
        [
            f"punycode/xn-- domain present: {defang_domain(d)}"
            for d in sorted(ctx.candidate_domains)
            if "xn--" in d
        ]
    )


def idn_homograph(ctx: ScoringContext) -> list[str]:
    hits: list[str] = []
    for d in sorted(ctx.candidate_domains):
        if any(is_mixed_script(label) for label in d.split(".")):
            hits.append(f"mixed-script / confusable domain: {defang_domain(d)}")
    return _dedup(hits)


def lookalike(ctx: ScoringContext) -> list[str]:
    hits: list[str] = []
    targets = ctx.lookalike_targets
    for d in sorted(ctx.candidate_domains):
        # IDN homograph / punycode own non-ASCII & xn-- domains (no double-count).
        if not d.isascii() or "xn--" in d:
            continue
        reg = registrable_domain(d)
        for target in targets:
            if len(target) < 5:
                continue
            if reg == target or reg.endswith("." + target):
                break  # legitimately this brand/org domain — never a lookalike
            if 1 <= levenshtein(reg, target) <= 2:
                hits.append(
                    f"{defang_domain(reg)} is a lookalike of {defang_domain(target)} "
                    f"(edit distance {levenshtein(reg, target)})"
                )
                break
    return _dedup(hits)


def anchor_href_mismatch(ctx: ScoringContext) -> list[str]:
    hits: list[str] = []
    for href, text in ctx.anchors:
        href_host = url_host(href)
        # An unparseable or raw-IP href is already owned by url.raw_ip_host; only
        # compare named hosts here so one link can't fire both rules (no double-count).
        if not href_host or is_ip_literal(href_host):
            continue
        text_host = _first_host_in_text(text)
        if not text_host:
            continue
        if registrable_domain(text_host) != registrable_domain(href_host):
            hits.append(
                f"link text shows {defang_domain(text_host)} but href points to "
                f"{defang_domain(href_host)}"
            )
    return _dedup(hits)


def raw_ip_host(ctx: ScoringContext) -> list[str]:
    hits: list[str] = []
    for ioc in ctx.url_iocs:
        host = url_host(ioc.value)
        if host and is_ip_literal(host):
            hits.append(f"URL uses a raw IP host: {ioc.defanged}")
    return _dedup(hits)


def shortener(ctx: ScoringContext) -> list[str]:
    hits: list[str] = []
    for ioc in ctx.url_iocs:
        host = url_host(ioc.value)
        if host and registrable_domain(host) in ctx.config.url_shorteners:
            hits.append(f"URL shortener hides destination: {ioc.defanged}")
    return _dedup(hits)


def credential_keywords(ctx: ScoringContext) -> list[str]:
    hits: list[str] = []
    for ioc in ctx.url_iocs:
        try:
            parts = urlsplit(ioc.value)
        except ValueError:
            # A malformed URL (e.g. an invalid bracketed host) must degrade
            # gracefully, never crash the run (PRD §11). Other detectors route
            # through the guarded url_host(); this one parses path/query directly.
            continue
        haystack = f"{parts.path}?{parts.query}".casefold()
        found = sorted({kw for kw in ctx.config.credential_keywords if kw in haystack})
        if found:
            hits.append(
                f"credential-harvest keywords in URL path ({', '.join(found)}): {ioc.defanged}"
            )
    return _dedup(hits)


def wrapped_divergence(ctx: ScoringContext) -> list[str]:
    from_reg = ctx.from_registrable
    if not from_reg:
        return []
    hits: list[str] = []
    for ioc in ctx.url_iocs:
        # Only reversibly-unwrapped wrappers carry a known target to compare.
        if not ioc.wrapper or ioc.unresolved:
            continue
        host = url_host(ioc.value)
        if not host or is_ip_literal(host):
            continue
        reg = registrable_domain(host)
        if reg != from_reg:
            hits.append(
                f"{ioc.wrapper} link unwraps to {defang_domain(reg)} "
                f"(unrelated to sender {defang_domain(from_reg)})"
            )
    return _dedup(hits)


# --- attachment detectors (PRD §8) -----------------------------------------


def _attachments_with(ctx: ScoringContext, flag) -> list[str]:
    names = [a.filename or "(unnamed)" for a in ctx.parsed.attachments if flag in a.flags]
    return names


def macro_capable(ctx: ScoringContext) -> list[str]:
    from phishbowl.models import AttachmentFlag

    names = _attachments_with(ctx, AttachmentFlag.MACRO_CAPABLE)
    return [f"macro-capable office document: {n}" for n in names]


def double_extension(ctx: ScoringContext) -> list[str]:
    from phishbowl.models import AttachmentFlag

    names = _attachments_with(ctx, AttachmentFlag.DOUBLE_EXTENSION)
    return [f"double extension (e.g. invoice.pdf.exe): {n}" for n in names]


def type_mismatch(ctx: ScoringContext) -> list[str]:
    from phishbowl.models import AttachmentFlag

    names = _attachments_with(ctx, AttachmentFlag.TYPE_MISMATCH)
    return [f"declared content-type ≠ detected magic bytes: {n}" for n in names]


def executable(ctx: ScoringContext) -> list[str]:
    from phishbowl.models import AttachmentFlag

    names = _attachments_with(ctx, AttachmentFlag.EXECUTABLE)
    return [f"executable / script / LNK / disk-image attachment: {n}" for n in names]


def password_protected_archive(ctx: ScoringContext) -> list[str]:
    from phishbowl.models import AttachmentFlag

    names = _attachments_with(ctx, AttachmentFlag.PASSWORD_PROTECTED)
    return [f"password-protected archive (evades scanning): {n}" for n in names]


# --- weak content detector (PRD §8 — deliberately low weight) --------------


def urgency_keywords(ctx: ScoringContext) -> list[str]:
    haystack = f"{ctx.parsed.subject or ''} {ctx.parsed.body.text or ''}".casefold()
    found = sorted({kw for kw in ctx.config.urgency_keywords if kw in haystack})
    if found:
        return [f"urgency / financial-pressure phrasing: {', '.join(found)}"]
    return []


# --- the offline catalog ----------------------------------------------------

OFFLINE_DETECTORS: tuple[DetectorSpec, ...] = (
    # Authentication
    DetectorSpec("auth.spf_fail", "SPF authentication failed", RuleSource.OFFLINE, spf_fail),
    DetectorSpec(
        "auth.spf_softfail", "SPF authentication soft-failed", RuleSource.OFFLINE, spf_softfail
    ),
    DetectorSpec("auth.dkim_fail", "DKIM authentication failed", RuleSource.OFFLINE, dkim_fail),
    DetectorSpec(
        "auth.dkim_none", "Message carries no DKIM signature", RuleSource.OFFLINE, dkim_none
    ),
    DetectorSpec("auth.dmarc_fail", "DMARC authentication failed", RuleSource.OFFLINE, dmarc_fail),
    DetectorSpec(
        "auth.results_missing",
        "No Authentication-Results header at all",
        RuleSource.OFFLINE,
        auth_results_missing,
    ),
    # Identity / spoofing
    DetectorSpec(
        "identity.display_name_brand_mismatch",
        "From display name impersonates a brand it doesn't own",
        RuleSource.OFFLINE,
        display_name_brand_mismatch,
    ),
    DetectorSpec(
        "identity.return_path_mismatch",
        "Return-Path domain differs from From domain",
        RuleSource.OFFLINE,
        return_path_mismatch,
    ),
    DetectorSpec(
        "identity.reply_to_mismatch",
        "Reply-To domain differs from From domain",
        RuleSource.OFFLINE,
        reply_to_mismatch,
    ),
    DetectorSpec(
        "identity.sender_mismatch",
        "Envelope Sender domain differs from From domain",
        RuleSource.OFFLINE,
        sender_mismatch,
    ),
    DetectorSpec(
        "identity.freemail_brand",
        "Freemail sender claims to be a company/brand",
        RuleSource.OFFLINE,
        freemail_brand,
    ),
    DetectorSpec(
        "identity.display_name_is_email",
        "From display name is itself an email address",
        RuleSource.OFFLINE,
        display_name_is_email,
    ),
    # Domain / URL
    DetectorSpec("url.punycode", "Punycode / xn-- domain present", RuleSource.OFFLINE, punycode),
    DetectorSpec(
        "url.idn_homograph",
        "IDN homograph / mixed-script confusable domain",
        RuleSource.OFFLINE,
        idn_homograph,
    ),
    DetectorSpec(
        "url.lookalike",
        "Lookalike domain (edit distance) to a known brand/org",
        RuleSource.OFFLINE,
        lookalike,
    ),
    DetectorSpec(
        "url.anchor_href_mismatch",
        "Link text domain differs from the actual href domain",
        RuleSource.OFFLINE,
        anchor_href_mismatch,
    ),
    DetectorSpec(
        "url.raw_ip_host", "URL uses a raw IP as its host", RuleSource.OFFLINE, raw_ip_host
    ),
    DetectorSpec("url.shortener", "URL shortener present", RuleSource.OFFLINE, shortener),
    DetectorSpec(
        "url.credential_keywords",
        "Credential-harvest keywords in URL path",
        RuleSource.OFFLINE,
        credential_keywords,
    ),
    DetectorSpec(
        "url.wrapped_divergence",
        "Wrapped link unwraps to a domain unrelated to the sender",
        RuleSource.OFFLINE,
        wrapped_divergence,
    ),
    # Attachments
    DetectorSpec(
        "attach.macro_capable", "Macro-capable office document", RuleSource.OFFLINE, macro_capable
    ),
    DetectorSpec(
        "attach.double_extension",
        "Double-extension attachment (e.g. invoice.pdf.exe)",
        RuleSource.OFFLINE,
        double_extension,
    ),
    DetectorSpec(
        "attach.type_mismatch",
        "Declared content-type contradicts detected magic bytes",
        RuleSource.OFFLINE,
        type_mismatch,
    ),
    DetectorSpec(
        "attach.executable",
        "Executable / script / LNK / ISO / disk-image attachment",
        RuleSource.OFFLINE,
        executable,
    ),
    DetectorSpec(
        "attach.password_protected_archive",
        "Password-protected archive (evades scanning)",
        RuleSource.OFFLINE,
        password_protected_archive,
    ),
    # Weak content
    DetectorSpec(
        "content.urgency_keywords",
        "Urgency / financial-pressure language",
        RuleSource.OFFLINE,
        urgency_keywords,
    ),
)
