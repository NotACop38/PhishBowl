"""Offline detectors — the §8 signal catalog (PRD §8).

Each detector is a pure function over a :class:`ScoringContext` (the parsed
message, its extracted IOCs, and the resolved config) that returns a list of
**evidence strings**: non-empty means the rule fired, empty means it stayed
silent. Detectors never mutate state and — like everything in the offline core —
never touch the network: the email's URLs are string-inspected, never fetched
(AGENTS.md). All domain/URL evidence is defanged for human-facing output
(PRD §6.2).

Anti-double-counting is built in (PRD §8 "no signal is double-counted"):

* a rule contributes its weight at most once no matter how many indicators
  trigger it (the engine adds each fired rule's weight a single time);
* ``auth.results_missing`` only fires when the whole ``Authentication-Results``
  header is absent, while ``auth.dkim_none`` only fires when the header IS
  present — the two can never both claim the same gap;
* ``url.lookalike`` skips non-ASCII and punycode domains, leaving those to
  ``url.idn_homograph`` / ``url.punycode``, and ``url.punycode`` skips a domain
  ``url.idn_homograph`` already flagged, so one confusable domain counts once;
* ``identity.freemail_role`` stays silent when the display name claims a brand
  (``identity.display_name_brand_mismatch`` owns that fact), and
  ``attach.archive`` skips archives ``attach.password_protected_archive`` scores.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import cached_property
from urllib.parse import urlsplit

from phishbowl.domains import _PUBLIC_SUFFIX, registrable_domain, registrable_label, web_ipv4
from phishbowl.extract.defang import defang_domain, defang_email
from phishbowl.html_analysis import inspect_html
from phishbowl.models import IOC, AttachmentFlag, AuthResultState, IOCs, IOCType, ParsedEmail

from .config import ScoringConfig
from .confusables import (
    confusable_skeleton,
    decode_label,
    is_suspicious_mix,
    latin_skeleton,
)
from .rules import DetectorSpec, RuleSource

# --- small text/domain helpers ---------------------------------------------

_EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_TEXT_HOST_RE = re.compile(
    # A token boundary prevents retrying every suffix of long hostile text;
    # DNS label bounds also cap backtracking within each candidate.
    r"(?<![a-z0-9.\-])(?:https?://)?"
    r"((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){1,127}[a-z]{2,63})"
    r"(?![a-z0-9\-]|\.[a-z0-9\-])",
    re.IGNORECASE,
)
_WS_RE = re.compile(r"\s+")


def url_host(url: str) -> str | None:
    """Lower-cased hostname of a URL (port and IPv6 brackets stripped)."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.casefold() if host else None


def is_ip_literal(host: str) -> bool:
    """True if ``host`` is an IP address rather than a domain name.

    Includes the legacy IPv4 notations browsers still accept (``3405803785``,
    ``0xcb007109``, ``127.1``): they are raw-IP links in disguise.
    """
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            return web_ipv4(host) is not None
        except ValueError:
            return False
    return True


def edit_distance(a: str, b: str) -> int:
    """Optimal-string-alignment distance: insert, delete, substitute, transpose.

    A swapped pair of adjacent letters (``paypla``) costs 1, as it reads.
    """
    if a == b:
        return 0
    if not a or not b:
        return len(a) or len(b)
    before: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            if before is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cost = min(cost, before[j - 2] + 1)
            cur.append(cost)
        before, prev = prev, cur
    return prev[-1]


def _word_in(word: str, text: str) -> bool:
    """Whole-word, case-insensitive match of ``word`` in ``text``."""
    return re.search(rf"\b{re.escape(word)}\b", text, re.IGNORECASE) is not None


# Public suffixes that are also common file extensions: "invoice.zip" in link
# text names a file far more often than a host.
_FILE_EXTENSION_SUFFIXES = frozenset({"zip", "mov"})


def _first_host_in_text(text: str) -> str | None:
    """The first host name a reader would take from link text, if any.

    A candidate needs a real public suffix, so file names ("statement.pdf",
    "setup.exe") are not hosts; ".zip"/".mov" names count only when written
    with a scheme or "www.".
    """
    for match in _TEXT_HOST_RE.finditer(text):
        host = match.group(1).casefold()
        suffix = _PUBLIC_SUFFIX(host).suffix
        if not suffix:
            continue
        explicit = match.group(0).casefold().startswith(("http", "www."))
        if suffix in _FILE_EXTENSION_SUFFIXES and not explicit:
            continue
        return host
    return None


def _strip_tags(html: str) -> str:
    return _WS_RE.sub(" ", inspect_html(html).text).strip()


# --- scoring context --------------------------------------------------------


@dataclass(frozen=True)
class ScoringContext:
    """Everything a detector needs, with derived views computed once.

    Built from the offline pipeline's outputs (parsed message + extracted IOCs)
    plus the resolved config. Derived collections (candidate domains, URL IOCs,
    HTML anchors) are cached so the rule sweep stays cheap.
    """

    parsed: ParsedEmail
    iocs: IOCs
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
    def homographs(self) -> dict[str, str]:
        """Candidate domains that are IDN homographs, mapped to their evidence.

        Punycode labels are decoded first. A label is a homograph when it mixes
        scripts outside TR39's highly-restrictive profile, or when it is
        non-ASCII and folds (look-alike letters, accents) to a brand or org label.
        """
        target_labels = {
            confusable_skeleton(label): label
            for label in (registrable_label(t) for t in self.lookalike_targets)
            if len(label) >= _LOOKALIKE_MIN_LABEL
        }
        found: dict[str, str] = {}
        for domain in sorted(self.candidate_domains):
            labels = [decode_label(label) for label in domain.split(".")]
            display = ".".join(labels)
            shown = defang_domain(display) + (
                f" ({defang_domain(domain)})" if display != domain else ""
            )
            for label in labels:
                if label.isascii():
                    continue
                imitated = target_labels.get(latin_skeleton(label))
                if imitated:
                    found[domain] = f"{shown} imitates {imitated!r} with look-alike characters"
                    break
                if is_suspicious_mix(label):
                    found[domain] = f"mixed-script / confusable domain: {shown}"
                    break
        return found

    @cached_property
    def anchors(self) -> list[tuple[str, str]]:
        """``(href, visible_text)`` pairs from the HTML body, never rendered."""
        html = self.parsed.body.html_raw
        if not html:
            return []
        return list(inspect_html(html).anchors)


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


def freemail_role(ctx: ScoringContext) -> list[str]:
    """A free-webmail sender presenting as an organizational role or department.

    "IT Support <it.helpdesk.team@gmail.example>" is the business-email-compromise
    pattern: a personal mailbox claiming an organization's authority. Brand
    claims are left to ``identity.display_name_brand_mismatch`` so the same
    display name never scores twice.
    """
    frm = ctx.parsed.addresses.from_
    if not frm or not frm.domain or not frm.display_name:
        return []
    dom = frm.domain.casefold()
    if dom not in ctx.config.freemail_domains or display_name_brand_mismatch(ctx):
        return []
    roles = [role for role in ctx.config.role_keywords if _word_in(role, frm.display_name)]
    if not roles:
        return []
    spec = defang_email(frm.addr_spec or dom)
    return [f'freemail sender {spec} presents as "{frm.display_name}" ({", ".join(roles)})']


def multiple_from(ctx: ScoringContext) -> list[str]:
    """More than one ``From`` header: RFC 5322 allows exactly one.

    Mail clients disagree on which copy to display, and authentication checks
    may evaluate a different one, so a duplicate is a sender-spoofing technique
    rather than a formatting accident. The evidence lists every copy.
    """
    values = ctx.parsed.headers.get_all("From")
    if len(values) < 2:
        return []
    return [f"{len(values)} From headers: " + " | ".join(value.strip() for value in values)]


def display_name_is_email(ctx: ScoringContext) -> list[str]:
    frm = ctx.parsed.addresses.from_
    if not frm or not frm.display_name:
        return []
    shown = _EMAIL_RE.findall(frm.display_name)
    # A display name that simply repeats the real address is common and harmless.
    if not shown or {e.casefold() for e in shown} == {(frm.addr_spec or "").casefold()}:
        return []
    return [f'From display name is itself an email address: "{frm.display_name}"']


# --- domain / URL detectors (PRD §8) ---------------------------------------


def punycode(ctx: ScoringContext) -> list[str]:
    hits: list[str] = []
    for d in sorted(ctx.candidate_domains):
        if "xn--" not in d or d in ctx.homographs:
            continue  # a homograph is scored once, by url.idn_homograph
        decoded = ".".join(decode_label(label) for label in d.split("."))
        hits.append(f"punycode/xn-- domain present: {defang_domain(d)} ({decoded})")
    return list(dict.fromkeys(hits))


def idn_homograph(ctx: ScoringContext) -> list[str]:
    return list(dict.fromkeys(list(ctx.homographs.values())))


# Brand/org labels shorter than this are too short to compare meaningfully
# (``me``, ``fb``, ``live`` sit one edit away from countless unrelated names).
_LOOKALIKE_MIN_LABEL = 5


def _lookalike_reason(label: str, target_label: str) -> str | None:
    """Why ``label`` imitates ``target_label``, or ``None`` if it does not.

    Three patterns, checked in order: the same letters after folding ASCII
    confusables (``paypa1``); the brand as a hyphenated word of a longer name
    (``paypal-secure``, combosquatting); or a small typo that keeps the first
    letter — one edit for labels up to 8 characters, two for longer ones.
    Identical labels are not lookalikes: ``amazon.ca`` beside ``amazon.com`` is a
    suffix variant, not a typo, and brands legitimately own many of them.
    """
    if len(target_label) < _LOOKALIKE_MIN_LABEL or label == target_label:
        return None
    skeleton = confusable_skeleton(target_label)
    if confusable_skeleton(label) == skeleton:
        return "confusable characters"
    if "-" in label and skeleton in (confusable_skeleton(t) for t in label.split("-")):
        return f'embeds the name "{target_label}"'
    allowed = 1 if len(target_label) <= 8 else 2
    if (
        len(target_label) <= 5
        or label[0] != target_label[0]
        or abs(len(label) - len(target_label)) > allowed
    ):
        return None
    distance = edit_distance(label, target_label)
    return f"edit distance {distance}" if distance <= allowed else None


def lookalike(ctx: ScoringContext) -> list[str]:
    hits: list[str] = []
    targets = sorted(ctx.lookalike_targets)
    known = ctx.config.freemail_domains | ctx.config.url_shorteners
    for d in sorted(ctx.candidate_domains):
        # IDN homograph / punycode own non-ASCII & xn-- domains (no double-count).
        if not d.isascii() or "xn--" in d:
            continue
        # A brand/org domain (or a subdomain of one) is never its own lookalike.
        if any(d == t or d.endswith("." + t) for t in targets):
            continue
        reg = registrable_domain(d)
        label = registrable_label(d)
        if not label or reg in known:
            continue
        for target in targets:
            reason = _lookalike_reason(label, registrable_label(target))
            if reason:
                hits.append(
                    f"{defang_domain(reg)} is a lookalike of {defang_domain(target)} ({reason})"
                )
                break
    return list(dict.fromkeys(hits))


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
    return list(dict.fromkeys(hits))


def raw_ip_host(ctx: ScoringContext) -> list[str]:
    hits: list[str] = []
    for ioc in ctx.url_iocs:
        host = url_host(ioc.value)
        if host and is_ip_literal(host):
            hits.append(f"URL uses a raw IP host: {ioc.defanged}")
    return list(dict.fromkeys(hits))


def shortener(ctx: ScoringContext) -> list[str]:
    hits: list[str] = []
    for ioc in ctx.url_iocs:
        host = url_host(ioc.value)
        if host and registrable_domain(host) in ctx.config.url_shorteners:
            hits.append(f"URL shortener hides destination: {ioc.defanged}")
    return list(dict.fromkeys(hits))


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
    return list(dict.fromkeys(hits))


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
    return list(dict.fromkeys(hits))


# --- attachment detectors (PRD §8) -----------------------------------------


def _attachments_with(ctx: ScoringContext, flag: AttachmentFlag) -> list[str]:
    return [a.filename or "(unnamed)" for a in ctx.parsed.attachments if flag in a.flags]


def macro_capable(ctx: ScoringContext) -> list[str]:
    names = _attachments_with(ctx, AttachmentFlag.MACRO_CAPABLE)
    return [f"macro-capable office document: {n}" for n in names]


def double_extension(ctx: ScoringContext) -> list[str]:
    names = _attachments_with(ctx, AttachmentFlag.DOUBLE_EXTENSION)
    return [f"double extension (e.g. invoice.pdf.exe): {n}" for n in names]


def type_mismatch(ctx: ScoringContext) -> list[str]:
    names = _attachments_with(ctx, AttachmentFlag.TYPE_MISMATCH)
    return [f"declared content-type ≠ detected magic bytes: {n}" for n in names]


def executable(ctx: ScoringContext) -> list[str]:
    names = _attachments_with(ctx, AttachmentFlag.EXECUTABLE)
    return [f"executable / script / LNK / disk-image attachment: {n}" for n in names]


def password_protected_archive(ctx: ScoringContext) -> list[str]:
    names = _attachments_with(ctx, AttachmentFlag.PASSWORD_PROTECTED)
    return [f"password-protected archive (evades scanning): {n}" for n in names]


def html_attachment(ctx: ScoringContext) -> list[str]:
    """HTML/SVG attachments: a browser renders them outside the mail client.

    Attached web pages are a common credential-phishing and HTML-smuggling
    vector: a local form that posts credentials, or script that assembles a
    payload on open. The file is only flagged here, never opened.
    """
    names = _attachments_with(ctx, AttachmentFlag.HTML)
    return [f"HTML/SVG document attachment (opens in a browser): {n}" for n in names]


def archive(ctx: ScoringContext) -> list[str]:
    """Plain archive attachments (zip/rar/7z/…) — a common phish delivery vector.

    Password-protected archives are scored by the heavier
    ``attach.password_protected_archive`` instead, so an encrypted zip is not
    counted twice; this rule covers the unencrypted case.
    """
    names = [
        a.filename or "(unnamed)"
        for a in ctx.parsed.attachments
        if AttachmentFlag.ARCHIVE in a.flags and AttachmentFlag.PASSWORD_PROTECTED not in a.flags
    ]
    return [f"archive attachment (common delivery vector): {n}" for n in names]


# --- weak content detector (PRD §8 — deliberately low weight) --------------


def urgency_keywords(ctx: ScoringContext) -> list[str]:
    """Scan subject + plaintext + visible HTML text for pressure phrasing.

    HTML-only phishing is common; extraction already de-tags ``html_raw``, and
    scoring must do the same — otherwise urgency language that only lives in the
    HTML part is invisible to this (deliberately weak) signal.
    """
    parts = [ctx.parsed.subject or "", ctx.parsed.body.text or ""]
    if ctx.parsed.body.html_raw:
        parts.append(_strip_tags(ctx.parsed.body.html_raw))
    haystack = " ".join(parts).casefold()
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
        "identity.freemail_role",
        "Freemail sender presents as an organizational role",
        RuleSource.OFFLINE,
        freemail_role,
    ),
    DetectorSpec(
        "identity.multiple_from",
        "Message carries more than one From header",
        RuleSource.OFFLINE,
        multiple_from,
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
    DetectorSpec(
        "attach.html",
        "HTML or SVG document attachment",
        RuleSource.OFFLINE,
        html_attachment,
    ),
    DetectorSpec(
        "attach.archive",
        "Archive attachment (zip/rar/7z/… — common delivery vector)",
        RuleSource.OFFLINE,
        archive,
    ),
    # Weak content
    DetectorSpec(
        "content.urgency_keywords",
        "Urgency / financial-pressure language",
        RuleSource.OFFLINE,
        urgency_keywords,
    ),
)
