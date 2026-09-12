"""Shared building blocks for the SOAR exports (PRD §6.6).

Both the Cortex XSOAR and Microsoft Sentinel builders map the *same* triage triple
— :class:`~phishbowl.models.ParsedEmail` + verdict + IOCs — into their platform's
artifact. To keep the two exports consistent (and to reuse the defanging, PII
redaction, severity bucketing, and enrichment status the report layer already
computed once), both build from a single, fully-prepared
:class:`~phishbowl.report.view.ReportView`. This module flattens that view into the
neutral pieces the builders share.

Two channels, by design — the same dual-channel contract the JSON report uses:

* **raw** indicator values (``IndicatorRow.raw``) feed the machine-addressable
  fields a SOAR actually pivots and hunts on (playbook inputs, workflow variables);
* **defanged** values (``IndicatorRow.defanged``) feed every human-readable note,
  so anyone *reading* the exported YAML/JSON in an editor is never handed a live
  link. Redaction is honoured throughout — a withheld indicator carries ``raw=None``
  and is dropped from the machine channel, so bystander PII never leaks either way.

**Draft / export only.** Nothing here (or in the artifacts it feeds) executes,
sends, fetches, or remediates. :data:`DRAFT_DISCLAIMER` is stamped into every
export; Phishbowl proposes a human-review playbook and never acts (CLAUDE.md).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from phishbowl.report import ReportView

_SCHEMA_DIR = Path(__file__).with_name("schemas")

# Stamped verbatim into every exported artifact. The load-bearing safety framing
# (PRD §4, CLAUDE.md): an export is a *draft* a human reviews and runs — Phishbowl
# itself never quarantines, blocks, sends, detonates, fetches, or acts.
DRAFT_DISCLAIMER = (
    "DRAFT EXPORT — Phishbowl produced this triage verdict and a response-playbook "
    "draft only. It never quarantines, blocks, sends, replies, detonates, fetches the "
    "email's URLs, or auto-remediates. Every step in this artifact is inert and must be "
    "reviewed, and explicitly executed, by a human analyst in your SOAR platform."
)

# A short machine-flag echoing the same invariant, embedded alongside the prose so
# downstream tooling can assert it too.
NEVER_ACTS = True

# Fixed namespace so XSOAR task UUIDs are derived deterministically from stable
# seeds — re-exporting the same analysis yields byte-identical artifacts (clean
# diffs, reproducible fixtures) rather than fresh random ids each run.
_UUID_NAMESPACE = uuid.UUID("9f2c7a40-7b5e-5d2e-8a3b-1c0d2e4f6a80")

# Defanged indicator lists embedded in human-readable notes are a summary, not a
# dump; cap each bucket so a hostile email padded with thousands of indicators
# can't balloon the artifact (mirrors the report's body cap, PRD §10).
_MAX_LINES_PER_BUCKET = 50


def stable_uuid(*parts: str) -> str:
    """A deterministic UUID5 from ``parts`` — same input, same id, every run."""
    return str(uuid.uuid5(_UUID_NAMESPACE, "::".join(parts)))


@cache
def load_schema(name: str) -> dict[str, Any]:
    """Load a bundled export JSON Schema by stem (e.g. ``"xsoar_playbook"``)."""
    path = _SCHEMA_DIR / f"{name}.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class IndicatorRow:
    """One indicator in both channels: ``raw`` (machine) and ``defanged`` (human).

    ``raw`` is ``None`` when the indicator was redacted (bystander PII): such rows
    are kept for the defanged/human view (which shows the redaction placeholder)
    but are dropped from every machine-addressable field.
    """

    bucket: str  # neutral grouping: urls | domains | ips | emails | file_hashes
    type: str  # the underlying IOCType value (url, domain, ipv4, ...)
    raw: str | None
    defanged: str
    provenance: tuple[str, ...] = ()


# IOCType value -> neutral SOAR bucket. IPv4/IPv6 collapse to one "ips" bucket;
# every email-type indicator (sender-side and any embedded address) lands in "emails".
_BUCKET_FOR_TYPE = {
    "url": "urls",
    "domain": "domains",
    "ipv4": "ips",
    "ipv6": "ips",
    "email": "emails",
    "hash": "file_hashes",
}

# Stable bucket order for every export.
BUCKETS: tuple[str, ...] = ("urls", "domains", "ips", "emails", "file_hashes")

# Bucket -> human label used in notes and platform field descriptions.
BUCKET_LABELS = {
    "urls": "URLs",
    "domains": "Domains",
    "ips": "IP addresses",
    "emails": "Email addresses",
    "file_hashes": "File hashes",
}


@dataclass(frozen=True)
class TriageCore:
    """The platform-neutral projection of a :class:`ReportView` the builders share."""

    tool: str
    generated_at: str  # the email's parse time (stable per analysis), never wall-clock
    source_filename: str | None
    source_format: str

    verdict: str
    score: int
    offline_score: int
    max_score: int
    severity: str
    analysis_complete: bool
    assessment_note: str

    subject: str | None  # already defanged/control-stripped by the report layer
    sender_display: str | None
    sender_addr_defanged: str | None
    sender_addr_raw: str | None
    sender_domain: str | None

    auth: tuple[dict[str, str | None], ...]
    reasons: tuple[dict[str, Any], ...]
    indicators: tuple[IndicatorRow, ...]
    redaction_enabled: bool
    redaction_categories: tuple[str, ...]
    enrichment_enabled: bool
    enrichment_connectors: tuple[dict[str, str], ...]

    # --- machine channel (raw, redaction-respecting) ----------------------- #
    def raw_buckets(self) -> dict[str, list[str]]:
        """Raw indicator values grouped by bucket, deduplicated, redacted dropped."""
        out: dict[str, list[str]] = {bucket: [] for bucket in BUCKETS}
        for row in self.indicators:
            if row.raw is None:
                continue
            if row.raw not in out[row.bucket]:
                out[row.bucket].append(row.raw)
        return out

    def raw_indicator_count(self) -> int:
        return sum(len(values) for values in self.raw_buckets().values())

    def analysis_seed(self) -> str:
        """A stable, analysis-specific digest used to make exported IDs unique.

        Derived from the salient triage content (parse time, verdict/score, subject,
        source, indicators, and the rules that fired). It is deterministic for a
        given analysis — re-exporting the same result yields the same seed (so
        artifacts stay reproducible) — yet two different messages produce different
        seeds even when they share a filename and verdict. XSOAR playbook/task IDs
        and the default Sentinel playbook name fold it in so importing two drafts
        never collides or overwrites a prior one.
        """
        payload = json.dumps(
            {
                "generated_at": self.generated_at,
                "source": self.source_filename,
                "verdict": self.verdict,
                "score": self.score,
                "offline_score": self.offline_score,
                "subject": self.subject,
                "indicators": self.raw_buckets(),
                "indicators_defanged": self.defanged_buckets(),
                "reasons": [r["id"] for r in self.reasons],
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    # --- human channel (defanged) ------------------------------------------ #
    def defanged_buckets(self) -> dict[str, list[str]]:
        """Defanged indicator strings grouped by bucket (includes redaction marks)."""
        out: dict[str, list[str]] = {bucket: [] for bucket in BUCKETS}
        for row in self.indicators:
            if row.defanged not in out[row.bucket]:
                out[row.bucket].append(row.defanged)
        return out

    def defanged_indicator_block(self) -> str:
        """A capped, human-readable, fully-defanged listing for note bodies."""
        lines: list[str] = []
        buckets = self.defanged_buckets()
        for bucket in BUCKETS:
            values = buckets[bucket]
            if not values:
                continue
            lines.append(f"{BUCKET_LABELS[bucket]} ({len(values)}):")
            for value in values[:_MAX_LINES_PER_BUCKET]:
                lines.append(f"  - {value}")
            hidden = len(values) - min(len(values), _MAX_LINES_PER_BUCKET)
            if hidden > 0:
                lines.append(f"  … and {hidden} more (see the full Phishbowl report)")
        return "\n".join(lines) if lines else "No indicators were extracted."

    def reason_block(self) -> str:
        """The fired-rule reasons as a defanged, human-readable list for notes."""
        if not self.reasons:
            return "No scoring rules fired."
        lines = []
        for reason in self.reasons:
            evidence = "; ".join(reason["evidence"]) if reason["evidence"] else ""
            detail = f" — {evidence}" if evidence else ""
            lines.append(
                f"  - {reason['description']}{detail} [+{reason['weight']:g}, {reason['source']}]"
            )
        return "\n".join(lines)

    def auth_summary(self) -> str:
        """One-line SPF/DKIM/DMARC summary."""
        return "  ".join(f"{a['mechanism']}={a['result']}" for a in self.auth)

    def recommended_review(self) -> list[str]:
        """The draft, analyst-driven review steps (proposals — never executed)."""
        return [
            "Confirm the Phishbowl verdict and score against your environment's context.",
            "Review every extracted indicator (shown defanged) before acting on it.",
            "Check sender authentication (SPF/DKIM/DMARC) and the From/Reply-To/Return-Path"
            " alignment for spoofing.",
            "If warranted, an analyst may MANUALLY block the sender, domains, URLs, or file"
            " hashes; search the mailbox for other recipients; and raise an incident."
            " Phishbowl performs none of these — it only proposes them.",
            "Treat this playbook as a starting draft: tailor the steps to your runbooks"
            " before enabling or running anything.",
        ]


def _auth_rows(view: ReportView) -> tuple[dict[str, str | None], ...]:
    return tuple(
        {"mechanism": a.mechanism, "result": a.result, "detail": a.detail} for a in view.auth
    )


def _reason_rows(view: ReportView) -> tuple[dict[str, Any], ...]:
    return tuple(
        {
            "id": r.id,
            "description": r.description,
            "weight": r.weight,
            "source": r.source,
            "evidence": list(r.evidence),
        }
        for r in view.fired_rules
    )


def _indicator_rows(view: ReportView) -> tuple[IndicatorRow, ...]:
    rows: list[IndicatorRow] = []
    for group in view.ioc_groups:
        bucket = _BUCKET_FOR_TYPE.get(group.type)
        if bucket is None:
            continue
        for item in group.items:
            rows.append(
                IndicatorRow(
                    bucket=bucket,
                    type=item.type,
                    raw=item.value_raw,
                    defanged=item.value_display,
                    provenance=tuple(item.provenance),
                )
            )
    # File hashes from attachments are first-class SOAR indicators too; add any not
    # already represented (raw value), with the filename as provenance.
    seen_hashes = {row.raw for row in rows if row.bucket == "file_hashes" and row.raw}
    for att in view.attachments:
        provenance = (f"attachment:{att.filename}",) if att.filename else ("attachment",)
        for value in (att.sha256, att.sha1, att.md5):
            if value and value not in seen_hashes:
                seen_hashes.add(value)
                rows.append(
                    IndicatorRow(
                        bucket="file_hashes",
                        type="hash",
                        raw=value,
                        defanged=value,  # a hash is inert; nothing to defang
                        provenance=provenance,
                    )
                )
    return tuple(rows)


def triage_core(view: ReportView) -> TriageCore:
    """Project a prepared :class:`ReportView` into the neutral :class:`TriageCore`."""
    sender = view.from_
    return TriageCore(
        tool=view.tool,
        generated_at=view.source.parsed_at,
        source_filename=view.source.filename,
        source_format=view.source.format,
        verdict=view.verdict,
        score=view.score,
        offline_score=view.offline_score,
        max_score=view.max_score,
        severity=view.severity,
        analysis_complete=view.analysis_complete,
        assessment_note=view.assessment_note,
        subject=view.subject,
        sender_display=sender.display_name if sender else None,
        sender_addr_defanged=sender.addr_spec_display if sender else None,
        sender_addr_raw=sender.addr_spec_raw if sender else None,
        sender_domain=sender.domain if sender else None,
        auth=_auth_rows(view),
        reasons=_reason_rows(view),
        indicators=_indicator_rows(view),
        redaction_enabled=view.redaction.enabled,
        redaction_categories=tuple(view.redaction.categories),
        enrichment_enabled=view.enrichment.enabled,
        enrichment_connectors=tuple(
            {"connector": c.connector, "outcome": c.outcome, "note": c.note}
            for c in view.enrichment.connectors
        ),
    )


def triage_summary(core: TriageCore) -> dict[str, Any]:
    """A neutral, JSON-serializable triage object embedded inside each artifact.

    Carries both indicator channels (raw for tooling, defanged for humans), the
    verdict, the per-rule reasons, authentication, the draft review steps, and the
    never-acts disclaimer. Used verbatim as the Sentinel Compose payload and as the
    structured backbone the XSOAR description/tasks summarise.
    """
    raw = core.raw_buckets()
    defanged = core.defanged_buckets()
    return {
        "tool": core.tool,
        "generated_at": core.generated_at,
        "draft": True,
        "never_acts": NEVER_ACTS,
        "disclaimer": DRAFT_DISCLAIMER,
        "source": {"filename": core.source_filename, "format": core.source_format},
        "verdict": {
            "text": core.verdict,
            "score": core.score,
            "offline_score": core.offline_score,
            "max_score": core.max_score,
            "severity": core.severity,
        },
        "analysis_complete": core.analysis_complete,
        "assessment_note": core.assessment_note,
        "subject": core.subject,
        "sender": {
            "display_name": core.sender_display,
            "address_defanged": core.sender_addr_defanged,
            "address_raw": core.sender_addr_raw,
            "domain": core.sender_domain,
        },
        "authentication": [dict(a) for a in core.auth],
        "reasons": [dict(r) for r in core.reasons],
        "indicators_raw": raw,
        "indicators_defanged": defanged,
        "redaction": {
            "enabled": core.redaction_enabled,
            "categories": list(core.redaction_categories),
        },
        "enrichment": {
            "enabled": core.enrichment_enabled,
            "connectors": [dict(c) for c in core.enrichment_connectors],
        },
        "recommended_review_draft": core.recommended_review(),
    }


__all__ = [
    "DRAFT_DISCLAIMER",
    "NEVER_ACTS",
    "BUCKETS",
    "BUCKET_LABELS",
    "IndicatorRow",
    "TriageCore",
    "triage_core",
    "triage_summary",
    "load_schema",
    "stable_uuid",
]
