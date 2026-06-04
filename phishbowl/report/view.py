"""The report view-model (PRD §6.4, §10).

One function — :func:`build_report` — turns the raw analysis triple
(:class:`ParsedEmail`, :class:`IOCs`, :class:`ScoreResult`) into a single,
fully-prepared :class:`ReportView`. Doing the preparation **once**, here, is what
keeps the three renderers (HTML, JSON, CLI) honest and identical: defanging,
control-character stripping, PII redaction, and severity bucketing all happen in
this layer, so a renderer can never accidentally show a live indicator or raw
attacker markup.

Guarantees baked into the view:

* every human-facing indicator carries a **defanged** ``display`` *and* a
  clearly-labelled raw ``value`` (for the JSON consumer), never just one;
* every free-text field (subject, body preview, rule evidence, hop text) is
  control-stripped and indicator-defanged;
* the raw HTML body is **never** carried into the view — only an escaped,
  defanged plaintext preview or a neutered-and-withheld note;
* redaction, when active, is applied to both the ``display`` and the raw
  ``value`` so PII cannot leak through the "raw" channel either.
"""

from __future__ import annotations

import re

from pydantic import Field

from phishbowl.extract import defang, defang_text
from phishbowl.models import IOCs, IOCType, ParsedEmail, PhishbowlModel
from phishbowl.score import ScoreResult, ScoringConfig, load_config

from .redact import RedactionPolicy, Redactor

__version__ = "phishbowl/0.1.0"

# C0/C1 controls (incl. ESC, BEL, the terminal-hijack range) and DEL. Email text
# is hostile input (PRD §13); we strip these from every field before it reaches a
# terminal, an HTML escape pass, or a JSON string.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

# How the 0-100 score maps to a severity slug used for colour/iconography. Kept
# independent of the configurable verdict *text* so the visual language is stable
# even when an operator renames or re-bands their verdicts.
_SEVERITY_BANDS = (
    (20, "benign"),
    (40, "low"),
    (65, "elevated"),
    (85, "high"),
    (101, "critical"),
)


def _clean(text: str | None) -> str | None:
    """Strip control characters; collapse nothing else (preserve the text)."""
    if text is None:
        return None
    return _CONTROL_CHARS.sub("", text)


def _safe_text(text: str | None) -> str | None:
    """Control-strip *and* defang indicators in a free-text field."""
    return defang_text(_clean(text))


def severity_for(score: int) -> str:
    for ceiling, slug in _SEVERITY_BANDS:
        if score < ceiling:
            return slug
    return "critical"


class AddressView(PhishbowlModel):
    """One mailbox, defanged for display with the raw addr-spec kept labelled."""

    display_name: str | None = None
    addr_spec_display: str | None = None  # defanged (or redaction placeholder)
    addr_spec_raw: str | None = None  # raw value for tooling; None when redacted
    domain: str | None = None
    redacted: bool = False


class AuthLineView(PhishbowlModel):
    mechanism: str
    result: str
    detail: str | None = None


class FiredRuleView(PhishbowlModel):
    id: str
    description: str
    weight: float
    source: str
    evidence: list[str] = Field(default_factory=list)


class IOCView(PhishbowlModel):
    type: str
    value_display: str  # defanged (or redaction placeholder)
    value_raw: str | None = None  # raw indicator for tooling; None when redacted
    provenance: list[str] = Field(default_factory=list)
    wrapper: str | None = None
    wrapped_display: str | None = None  # defanged original wrapper string
    unresolved: bool = False
    redacted: bool = False


class IOCGroupView(PhishbowlModel):
    type: str
    label: str
    items: list[IOCView] = Field(default_factory=list)


class HopView(PhishbowlModel):
    index: int
    from_: str | None = Field(default=None, alias="from")
    by: str | None = None
    with_: str | None = Field(default=None, alias="with")
    timestamp: str | None = None
    raw: str


class AttachmentView(PhishbowlModel):
    filename: str | None = None
    declared_type: str | None = None
    detected_type: str | None = None
    type_mismatch: bool = False
    size: int | None = None
    size_human: str | None = None
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    flags: list[str] = Field(default_factory=list)


class AnomalyView(PhishbowlModel):
    code: str | None = None
    message: str


class SourceView(PhishbowlModel):
    filename: str | None = None
    format: str
    parsed_at: str
    parser_version: str


class RedactionView(PhishbowlModel):
    enabled: bool
    categories: list[str] = Field(default_factory=list)


class ReportView(PhishbowlModel):
    """Everything a renderer needs, already defanged, redacted, and labelled."""

    tool: str = __version__
    source: SourceView

    score: int
    offline_score: int
    max_score: int = 100
    verdict: str
    severity: str

    subject: str | None = None
    date: str | None = None

    from_: AddressView | None = Field(default=None, alias="from")
    reply_to: AddressView | None = None
    return_path: AddressView | None = None
    sender: AddressView | None = None
    to: list[AddressView] = Field(default_factory=list)
    cc: list[AddressView] = Field(default_factory=list)

    return_path_mismatch: bool = False
    reply_to_mismatch: bool = False
    sender_mismatch: bool = False

    auth: list[AuthLineView] = Field(default_factory=list)
    fired_rules: list[FiredRuleView] = Field(default_factory=list)
    ioc_groups: list[IOCGroupView] = Field(default_factory=list)
    ioc_total: int = 0
    routing: list[HopView] = Field(default_factory=list)
    attachments: list[AttachmentView] = Field(default_factory=list)

    body_preview: str | None = None
    body_note: str | None = None

    anomalies: list[AnomalyView] = Field(default_factory=list)
    redaction: RedactionView


# IOC type → display order and human label.
_IOC_GROUPS: tuple[tuple[str, str], ...] = (
    ("url", "URLs"),
    ("domain", "Domains"),
    ("email", "Email addresses"),
    ("ipv4", "IPv4 addresses"),
    ("ipv6", "IPv6 addresses"),
    ("hash", "File hashes"),
)

# Body previews are capped: a report is a summary, not a dump, and an unbounded
# attacker-controlled blob has no place ballooning the file.
_BODY_PREVIEW_LIMIT = 4000


def _human_size(size: int | None) -> str | None:
    if size is None:
        return None
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def _address_view(addr, redactor: Redactor, *, recipient: bool) -> AddressView | None:
    if addr is None:
        return None
    if recipient:
        redacted = redactor.recipient_address(addr)
        if redacted is not addr:
            return AddressView(
                display_name=None,
                addr_spec_display=redacted.addr_spec,
                addr_spec_raw=None,
                domain=None,
                redacted=True,
            )
    raw = addr.addr_spec
    return AddressView(
        display_name=_clean(addr.display_name),
        addr_spec_display=defang(raw, IOCType.EMAIL) if raw else None,
        addr_spec_raw=raw,
        domain=addr.domain,
        redacted=False,
    )


def _ioc_view(ioc, redactor: Redactor) -> IOCView:
    placeholder = redactor.classify_ioc(ioc.type.value, ioc.value)
    if placeholder is not None:
        return IOCView(
            type=ioc.type.value,
            value_display=placeholder,
            value_raw=None,
            provenance=list(ioc.provenance),
            wrapper=ioc.wrapper,
            wrapped_display=None,
            unresolved=ioc.unresolved,
            redacted=True,
        )
    wrapped_display = defang(ioc.wrapped, ioc.type) if ioc.wrapped else None
    return IOCView(
        type=ioc.type.value,
        value_display=ioc.defanged,
        value_raw=ioc.value,
        provenance=list(ioc.provenance),
        wrapper=ioc.wrapper,
        wrapped_display=wrapped_display,
        unresolved=ioc.unresolved,
        redacted=False,
    )


def _body(parsed: ParsedEmail) -> tuple[str | None, str | None]:
    """Return ``(preview, note)`` — escaped/defanged plaintext, never raw HTML."""
    if parsed.body.text:
        text = _safe_text(parsed.body.text) or ""
        if len(text) > _BODY_PREVIEW_LIMIT:
            text = text[:_BODY_PREVIEW_LIMIT]
            note = (
                f"Plaintext body shown defanged and truncated to the first "
                f"{_BODY_PREVIEW_LIMIT} characters."
            )
        else:
            note = "Plaintext body shown defanged. Indicators are neutralized for safe copy-paste."
        if parsed.body.has_html:
            note += " An HTML part was also present; its raw markup is never rendered."
        return text, note
    if parsed.body.has_html:
        return None, (
            "This message had an HTML body only. Phishbowl never renders attacker "
            "markup, and no plaintext alternative was available to preview."
        )
    return None, "No body content was parsed from this message."


def build_report(
    parsed: ParsedEmail,
    iocs: IOCs,
    result: ScoreResult,
    *,
    policy: RedactionPolicy | None = None,
    config: ScoringConfig | None = None,
) -> ReportView:
    """Assemble the single, fully-prepared :class:`ReportView` (PRD §10).

    All defanging, control-stripping, and redaction happen here so the three
    renderers downstream are pure presentation. ``config`` (the scoring config)
    supplies the org-domain set redaction needs; it is loaded if not provided.
    """
    policy = policy or RedactionPolicy.disabled()
    config = config or load_config()
    redactor = Redactor(policy, parsed, config)

    auth = [
        AuthLineView(mechanism=name, result=line.result.value, detail=_clean(line.detail))
        for name, line in (
            ("SPF", parsed.auth.spf),
            ("DKIM", parsed.auth.dkim),
            ("DMARC", parsed.auth.dmarc),
        )
    ]

    fired = [
        FiredRuleView(
            id=f.id,
            description=f.description,
            weight=f.weight,
            source=f.source.value,
            evidence=[_safe_text(e) or "" for e in f.evidence],
        )
        for f in sorted(result.fired, key=lambda f: (-f.weight, f.id))
    ]

    groups: list[IOCGroupView] = []
    total = 0
    for ioc_type, label in _IOC_GROUPS:
        items = [_ioc_view(i, redactor) for i in iocs.by_type(IOCType(ioc_type))]
        total += len(items)
        if items:
            groups.append(IOCGroupView(type=ioc_type, label=label, items=items))

    routing = [
        HopView(
            index=idx,
            **{"from": redactor.hop_text(_clean(hop.from_))},
            by=redactor.hop_text(_clean(hop.by)),
            **{"with": _clean(hop.with_)},
            timestamp=hop.timestamp.isoformat() if hop.timestamp else None,
            raw=redactor.hop_text(_clean(hop.raw)) or "",
        )
        for idx, hop in enumerate(parsed.routing.hops)
    ]

    attachments = [
        AttachmentView(
            filename=_clean(att.filename),
            declared_type=att.declared_type,
            detected_type=att.detected_type,
            type_mismatch="type_mismatch" in [f.value for f in att.flags],
            size=att.size,
            size_human=_human_size(att.size),
            md5=att.md5,
            sha1=att.sha1,
            sha256=att.sha256,
            flags=[f.value for f in att.flags],
        )
        for att in parsed.attachments
    ]

    body_preview, body_note = _body(parsed)

    return ReportView(
        source=SourceView(
            filename=_clean(parsed.source.filename),
            format=parsed.source.format.value,
            parsed_at=parsed.source.parsed_at.isoformat(),
            parser_version=parsed.source.parser_version,
        ),
        score=result.score,
        offline_score=result.offline_score,
        verdict=result.verdict,
        severity=severity_for(result.score),
        subject=_safe_text(parsed.subject),
        date=parsed.date.isoformat() if parsed.date else None,
        **{"from": _address_view(parsed.addresses.from_, redactor, recipient=False)},
        reply_to=_address_view(parsed.addresses.reply_to, redactor, recipient=False),
        return_path=_address_view(parsed.addresses.return_path, redactor, recipient=False),
        sender=_address_view(parsed.addresses.sender, redactor, recipient=False),
        to=[v for a in parsed.addresses.to if (v := _address_view(a, redactor, recipient=True))],
        cc=[v for a in parsed.addresses.cc if (v := _address_view(a, redactor, recipient=True))],
        return_path_mismatch=parsed.addresses.return_path_mismatch,
        reply_to_mismatch=parsed.addresses.reply_to_mismatch,
        sender_mismatch=parsed.addresses.sender_mismatch,
        auth=auth,
        fired_rules=fired,
        ioc_groups=groups,
        ioc_total=total,
        routing=routing,
        attachments=attachments,
        body_preview=body_preview,
        body_note=body_note,
        anomalies=[
            AnomalyView(code=a.code, message=_clean(a.message) or "") for a in parsed.anomalies
        ],
        redaction=RedactionView(
            enabled=redactor.active,
            categories=sorted(redactor.triggered),
        ),
    )
