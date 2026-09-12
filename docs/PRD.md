# Phishbowl — Product Requirements Document

**Status:** v1 (living document; all phases incl. the Phase 7 stretch are built) · **Owner:** project lead · **Last updated:** 2026-06-12

A self-hostable, vendor-neutral phishing triage tool. Drop in a suspicious email → parse it → extract and defang IOCs → enrich via OSINT → risk-score → produce an analyst-ready report, with optional SOAR playbook export.

---

## 1. Problem & opportunity

Phishing triage is the highest-volume, most repetitive task in a SOC. Tier 1 analysts burn hours pulling headers apart, checking auth results, copying indicators into a dozen lookup tabs, and re-typing the same summary into a ticket. Commercial SOAR platforms automate this but are expensive, heavyweight, and lock teams into a vendor.

There's a clear gap for a clean, open, vendor-neutral tool that does the grunt work and outputs something *presentable* — good enough to paste straight into a ticket. Phishbowl targets that gap. The bet for community traction is simple: `pip install` → run on a bundled sample → see a gorgeous, shareable HTML report in under a minute, with zero API keys required.

## 2. Goals & non-goals

**Goals**
- Turn a raw `.eml`/`.msg` into a complete, defensible triage verdict with human-readable reasoning.
- Work fully offline out of the box; enrichment is an enhancement layer, never a dependency.
- Produce outputs an analyst is *proud* to attach to a ticket (HTML), can pipe to other tools (JSON), and can read in a terminal (rich CLI).
- Expose a clean, documented connector plugin API so the community can contribute integrations.
- Be transparent and tunable: every point of the risk score traces to a named, editable rule.

**Non-goals**
- Not an email gateway, filter, or MTA.
- Not a sandbox or detonation environment.
- Never sends, replies, opens, fetches, or detonates anything from the analyzed email.
- Not a threat-intel platform or case-management system (it *exports* to those).

## 3. Users & jobs-to-be-done

- **Tier 1/2 SOC analysts** — "A user reported this email. Is it malicious, and what do I tell them / put in the ticket?"
- **Incident responders** — "Give me every IOC, defanged and structured, plus a verdict I can defend."
- **Small teams without SOAR** — "We don't have Phantom/XSOAR budget; give us 80% of the triage value as a CLI."

Broad appeal is the point. Defaults must be sane for someone running it for the first time with no config and no keys.

## 4. Defensive scope & safety guarantees (load-bearing)

Phishbowl analyzes emails the user **received or was forwarded**, for triage. This boundary is not negotiable and every feature decision references it.

**Hard guarantees, enforced in code and tested:**
- **No sending.** No SMTP, no replies, no read receipts, no callbacks of any kind to the email's infrastructure.
- **No detonation.** Attachments are hashed and inspected by metadata/magic bytes only. Contents are never executed; archives are not auto-extracted in the MVP.
- **No fetching of the email's URLs by Phishbowl itself.** We never open the suspicious links. Indicators are only ever submitted to *allowlisted third-party APIs* (see §9), and even there the operator chooses what is shared.
- **No auto-remediation.** Phishbowl produces a verdict and (optionally) a playbook *draft*. It never quarantines, blocks, or acts.
- **No report beaconing.** The HTML report performs zero network egress when opened — no remote images, fonts, scripts, or trackers. A report about a phishing email must never phone home to the attacker (see §10).
- **Safe samples only.** All bundled fixtures are synthetic, authored by us, using `example.com`-class indicators and obviously-fake malicious markers. Real phishing samples (which may carry live links, real PII, or actual malware) are never committed.

## 5. Product pipeline (offline-first architecture)

```
ingest → parse → extract → defang → score(offline) → [optional: enrich → re-score] → report
```

The **offline core** (parse → extract → defang → score → report) is built first and is always sufficient to produce a report of recovered evidence and analysis limitations. Enrichment is a distinct layer that *augments* signals and can shift the score, but the offline verdict is always computed and always shown. This is what makes the demo instant and the "graceful offline degrade" honest by construction rather than bolted on afterward.

Everything downstream consumes one internal contract: the `ParsedEmail` model (§7). Both the `.eml` and `.msg` paths normalize into it, so nothing after parsing needs to know the source format.

## 6. Functional requirements by stage

### 6.1 Ingest & parse
- Accept `.eml` (RFC 822/MIME) and `.msg` (Outlook OLE) input by path or stdin.
- Parse full headers, **preserving order and duplicates** (Received hops and others repeat — this matters for analysis).
- Decode RFC 2047 encoded-words in subject and display names (a common obfuscation vector).
- Extract authentication results — SPF, DKIM, DMARC — from `Authentication-Results` and `Received-SPF`, with result state and detail.
- Reconstruct the routing path from ordered `Received` hops (from / by / with / timestamp where parseable).
- Separate display name from addr-spec for `From`, `Reply-To`, `Return-Path`, `Sender`, `To`, `Cc`.
- Extract body parts (text + HTML), flagging which were present. Store raw HTML but **never render it**; extraction works on a parsed/sanitized representation.
- Enumerate attachments: filename, declared content-type, detected type (magic bytes), size, MD5/SHA1/SHA256, and structural flags (archive, macro-capable, extension/content-type mismatch, double extension).
- Record structural anomalies surfaced during parsing as notes.

### 6.2 IOC extraction & defang
- Extract: sender/reply-to/return-path addresses, URLs, domains, IPv4/IPv6, file hashes.
- **Unwrap protective wrappers** as a pure string transformation (never by fetching):
  - Microsoft Safelinks (`*.safelinks.protection.outlook.com`) — decode the `url` param.
  - Proofpoint URL Defense v1/v2/v3.
  - Note others (Mimecast, Barracuda, Cisco); where not reversible offline, keep wrapped form and mark "wrapped, unresolved."
  - Always retain both the wrapped and unwrapped forms.
- **Defang by default** in all human-facing output (`hxxps://evil[.]com`, `1[.]2[.]3[.]4`, `user[at]evil[.]com`). JSON output offers both defanged and (clearly labeled) raw for tool interchange.
- Deduplicate and normalize indicators; preserve provenance (which header/part each came from).

### 6.3 Risk scoring
See §8. Transparent, additive, YAML-defined weighted rules → numeric score → verdict band → list of human-readable reasons with evidence.

### 6.4 Reporting
- **HTML** — the primary deliverable and the community hook. Self-contained single file (see §10).
- **Rich CLI** — colorized terminal summary via `rich`: verdict banner, top reasons, IOC tables (defanged), auth results.
- **JSON** — complete structured output for piping to other tools.
- **PII redaction** — an opt-in mode that redacts recipient addresses, internal hostnames/IPs from Received hops, and other configured PII so reports can be shared externally.

### 6.5 Enrichment (layer, not dependency)
See §9. Pluggable, key-gated connectors: VirusTotal, urlscan, AbuseIPDB, Shodan, WHOIS/RDAP. Caching, rate-limit handling, graceful offline degrade.

### 6.6 SOAR export
- Export triage results as **Cortex XSOAR** and **Microsoft Sentinel** playbook artifacts. This is a draft/export — Phishbowl never executes remediation itself.

## 7. The `ParsedEmail` contract (sketch)

The single internal model everything downstream consumes. Pydantic v2 (validation + clean JSON serialization, and it pays forward into the FastAPI stretch). Final field list is locked in Phase 0; this is the intended shape:

- **Source** — `filename`, `format` (`eml`|`msg`), `parsed_at`, `parser_version`.
- **Headers** — ordered list of `(name, value)` preserving duplicates, plus convenience accessors.
- **Auth** — `spf`, `dkim`, `dmarc`, each `{result, detail}` over `pass|fail|softfail|neutral|none|temperror|permerror`.
- **Routing** — ordered list of parsed `Received` hops.
- **Addresses** — `from_`, `reply_to`, `return_path`, `sender`, `to`, `cc`, each split into `{display_name, addr_spec, domain}`.
- **Subject**, **Date**.
- **Body** — `text`, `html_raw` (stored, never rendered), `has_html`.
- **Attachments** — list of `{filename, declared_type, detected_type, size, md5, sha1, sha256, flags[]}`.
- **IOCs** — extracted + defanged collection with provenance.
- **Anomalies** — structural notes from parsing.

Design notes: From/Return-Path/Reply-To must be trivially comparable (mismatch is a core scoring signal). Encoding/charset handling is centralized here so downstream never re-decodes.

## 8. Risk scoring model

**Philosophy.** Transparent over clever. No ML black box. Score is the sum of weights of triggered rules, normalized to 0–100. Every triggered rule emits a human-readable reason with the evidence that fired it. Weights live in editable YAML so analysts can tune to their environment. Offline and online signals are tagged by source, so a verdict reached with zero API keys is still meaningful — and a reader can always see which points came from local heuristics vs enrichment.

**Combination rule.** Offline rules produce a base score that is always computed. Enrichment rules add on top, each tagged `[enrichment]`. No single missing connector can zero out a verdict; no signal is double-counted across detectors.

**Signal catalog** *(weights below are starting points — calibrated against synthetic samples in Phase 3, not fixed now)*:

| Signal | Source | Starting weight |
|---|---|---|
| SPF fail / softfail | offline | 15 / 8 |
| DKIM fail / none | offline | 12 / 5 |
| DMARC fail | offline | 18 |
| `Authentication-Results` missing entirely | offline | 8 |
| From display-name claims a brand, addr-spec domain doesn't match | offline | 20 |
| Return-Path domain ≠ From domain | offline | 10 |
| Reply-To domain ≠ From domain | offline | 12 |
| Envelope sender ≠ From | offline | 8 |
| Freemail From while body/display claims a company | offline | 12 |
| Display-name is itself an email address | offline | 8 |
| Punycode / `xn--` domain present | offline | 12 |
| IDN homograph / mixed-script confusable | offline | 18 |
| Lookalike (edit distance) to impersonation list / configured org domains | offline | 18 |
| URL anchor text domain ≠ actual href domain | offline | 16 |
| Raw IP as URL host | offline | 12 |
| URL shortener present | offline | 6 |
| Credential-harvest keywords in URL path (login/verify/secure/account) | offline | 8 |
| Wrapped link unwrapped to a different-looking domain | offline | 10 |
| Macro-capable office doc (.docm/.xlsm/…) | offline | 14 |
| Double extension (invoice.pdf.exe) | offline | 22 |
| Declared content-type ≠ detected magic bytes | offline | 16 |
| Executable / script / LNK / ISO / disk image attachment | offline | 22 |
| Password-protected archive | offline | 14 |
| Urgency / financial-pressure keywords | offline | 4 *(weak signal — deliberately low; high false-positive rate)* |
| VirusTotal: N engines flag URL/domain/hash | enrichment | scaled by detection ratio |
| urlscan: malicious / known-phishing verdict | enrichment | 20 |
| AbuseIPDB: confidence over threshold for sending IP | enrichment | scaled by confidence |
| RDAP/WHOIS: domain age < 30 days | enrichment | 18 *(strong phishing signal)* |
| Shodan: suspicious exposed services on related IP | enrichment | 6 *(contextual)* |

**Verdict bands** *(provisional, tuned in Phase 3):*

| Score | Verdict |
|---|---|
| 0–19 | Few signals — safety undetermined |
| 20–39 | Low suspicion |
| 40–64 | Suspicious — analyst review |
| 65–84 | High suspicion |
| 85–100 | Very high suspicion |

## 9. Connector plugin architecture

This is the community contribution surface, so the *interface* is designed before connector #1 and kept stable.

**Discovery.** Support both an in-repo registry (decorator-based) and Python entry-points (`phishbowl.connectors` group), so a third party can ship a pip package that auto-registers without forking.

**Connector interface (intended shape):**
- `name`, `version`, `supported_ioc_types` (which of ip/domain/url/hash/email it enriches).
- `requires_api_key: bool`, plus a config schema.
- `async def enrich(indicator, ctx) -> EnrichmentResult`.
- Each connector owns its own rate limiting, cache key, and normalization. It returns a **normalized** `EnrichmentResult` (verdict, signal contributions, retained raw response, reference links) so the scorer needs no per-vendor logic.

**Cross-cutting connector requirements:**
- **Caching** — on-disk, keyed by `(connector, ioc_type, value)`, TTL per connector, so repeat runs and the demo are fast and don't burn quota.
- **Rate limits** — respect documented free-tier limits (e.g., VT public ≈ 4 req/min), with backoff and a global concurrency cap.
- **Graceful degrade** — missing key → connector skipped with a clear report note ("VirusTotal: skipped, no API key"); network/API error → soft-fail with note, never crash the run.
- **Allowlisted egress** — connectors may only reach their vendor's documented API base URL. They must never be coerced into fetching an arbitrary URL taken from the email (SSRF guard).

**urlscan operational-security note.** urlscan is the one connector that causes a URL to be *visited* (on urlscan's infrastructure, not ours) — so it is never part of the offline default pipeline and is strictly **operator opt-in**. Submissions must default to **private** scans, but private is not a safety guarantee: it only hides the *result page*. The request to the (possibly attacker-controlled) host still happens — which can tip off an attacker that the email was detected — and phishing URLs often carry a per-victim token, so submitting the raw URL can leak victim-specific data to a third party. Prefer passive lookups/searches where they answer the question; treat active submission as a deliberate, per-run choice. A public scan compounds both risks; if we ever expose a public option it must be explicit and carry a warning.

## 10. Outputs & report security

The HTML report renders adversarial content — subject, sender, body, and URLs that all originate from a hostile email. The report itself must not become an attack vector when an analyst opens it.

**Requirements:**
- **Single self-contained file** — inline CSS, no external assets, so it renders anywhere and pastes into any ticket.
- **Zero network egress on open** — no remote images, fonts, scripts, or trackers. No beaconing.
- **Rigorous autoescaping** — Jinja2 autoescape on; never `| safe` on any email-derived content.
- **Never inject the raw HTML body.** If the body is shown, show escaped plaintext (or a clearly-labeled neutered rendering), not the attacker's markup.
- **Everything defanged** in display by default.
- Light/dark friendly, clean layout: verdict banner, score breakdown with per-rule reasons, auth results, IOC tables, routing path, attachment table.
- Minimal-to-no JavaScript; if any is used it loads nothing remote and is CSP-friendly.

## 11. Cross-cutting concerns

- **Secrets** — API keys via env vars / a gitignored config file. Never logged, never written into the report or JSON, redacted from any debug output. Ship `.env.example`.
- **Config** — YAML for scoring weights, verdict bands, connector toggles, org domains (for lookalike detection), and redaction rules. Sensible zero-config defaults.
- **PII redaction** — opt-in; clearly defines and redacts recipients, internal hostnames/IPs, and configured fields.
- **Logging** — quiet by default and secret-safe: API-key values are scrubbed
  even from the HTTP libraries' debug logs and connector crash tracebacks.
  Parse-layer issues surface as report *anomalies* (visible to the analyst)
  rather than log noise; a structured `--verbose` mode remains future work.
- **Errors** — a malformed email or failing connector degrades gracefully with a noted partial result; it never crashes the run.

## 12. Key technical decisions

| Decision | Options | Call | Status |
|---|---|---|---|
| Internal model | Pydantic v2 / dataclasses | **Pydantic v2** — validation, JSON, FastAPI payoff | Locked |
| `.eml` parsing | stdlib `email` / `mailparser` | **stdlib `email`** with our normalization layer | Locked |
| `.msg` parsing | `extract-msg` / `msg-parser` / raw OLE | **`extract-msg`**, normalized into `ParsedEmail` | Locked (note: `.msg` auth extraction is lossier) |
| IOC extraction | `iocextract` + custom defang/unwrap | **`iocextract` + custom** unwrapper & defanger | Locked |
| Scoring config | YAML weighted rules / hardcoded / ML | **YAML weighted rules**, additive, source-tagged | Locked (weights/bands tuned in Phase 3) |
| Connector discovery | registry / entry-points | **Both** — stable ABC, registry + entry-points | Locked |
| HTTP client | `httpx` (async) | **`httpx`** | Locked |
| Templating | `Jinja2` (autoescape on) | **`Jinja2`** | Locked |
| CLI | `Typer` | **`Typer`** | Locked |
| Report format | self-contained HTML, no egress | as specified §10 | Locked |
| urlscan default visibility | private / public | **private** | Locked |
| Org-domain config for lookalike detection | day one / later | **day one** (optional config) | Locked |

## 13. Security considerations (consolidated)

- The analyzed email is **hostile input** end to end. Treat every field as untrusted.
- The report is a potential XSS / beaconing vector → autoescape, no raw HTML, no remote loads (§10).
- Connectors are a potential SSRF vector → allowlisted vendor egress only; never fetch email URLs (§9).
- API keys are secrets → never logged, never in outputs (§11).
- Fixtures are a supply-chain/PII risk → synthetic only; document in CONTRIBUTING that real samples are never committed (§4).
- urlscan submission causes a third-party fetch of the email's URL → operator opt-in, private by default; even a private scan still reaches the host and can leak per-victim URL tokens, so prefer passive lookups (§9).

## 14. Success metrics

- **Time-to-first-report** from `pip install` on the bundled sample: **< 60s**, zero keys.
- Evidence integrity: preserve actual destinations, surface unsupported content, and prevent report destinations from overwriting source evidence.
- Bounded analysis: hostile synthetic regression cases finish within test budgets; exhausted or unsupported analysis is explicitly incomplete.
- Analyst usability: trace each scoring contribution to evidence in a readable, inert report. Visual polish supports this goal; it is not detection validation.
- Connector plugin API clear enough that an external contributor can ship one against the docs without reading core internals.
- External adoption and connector contributions are secondary indicators; stars and forks are not measures of detection quality.

## 15. Out of scope / future

- ~~FastAPI upload UI~~ — **built** (Phase 7 stretch): `phishbowl serve` runs the
  same offline pipeline behind an optional `web` extra, additive as designed.
- Additional connectors (community-driven via the plugin API).
- Archive content inspection / deeper attachment analysis (still no detonation).
- Multi-email / mailbox batch triage.
- Case-management features (we export to those systems, we don't become one).

## Critical review revision (2026-09-12)

This maintenance revision supersedes any stronger wording above about complete
verdicts, confidence or sharing safety. The product is an offline evidence and
heuristic triage aid. Report/JSON/SOAR consumers receive `analysis_complete` and
an assessment note; any recorded parse/analysis anomaly makes the assessment
incomplete. Authentication header claims are not independently verified. Scores
are not calibrated against real mail and are not probabilities.

Resource budgets, redaction limits and deployment assumptions are documented in
SECURITY.md. MIME construction is bounded before node allocation; all ordinary
body parts are analyzed within an explicit text budget. Compressed Outlook RTF
is excluded. Domain comparisons use the packaged Public Suffix List, including
private suffixes, with downloads and filesystem caching disabled. Updates to that
snapshot follow dependency updates, not a network fetch during analysis.
