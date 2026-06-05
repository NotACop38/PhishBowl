# Phishbowl — Engineering Checklist

**Status:** Draft v1 (living document) · Mirrors the build order in `PRD.md` §5.

Build the **offline core first** (Phases 0–4). The offline MVP — a complete verdict and a gorgeous self-contained HTML report with zero API keys — lands at the end of Phase 4. Enrichment (Phase 5) and SOAR export (Phase 6) layer on top of an already-complete product. We build one phase at a time; the lead approves moving to the next.

Each phase lists its **objective**, any **decision gates** (things to confirm before coding), **tasks**, and a **definition of done (DoD)**.

CI is intentionally lightweight: the routine gate is a fast `pytest` run (`make test`). Heavier checks (security scanners, release build) are run once, in their dedicated phases. No GitHub Actions are used — Claude is the runner.

---

## Phase 0 — Skeleton & contract

**Objective:** A runnable package with the data contract everything hangs off, plus a fast test harness and one safe fixture.

**Decision gates:**
- [x] Internal model = Pydantic v2 (locked in PRD).
- [ ] Final `ParsedEmail` field list approved by lead.

**Tasks:**
- [ ] `pyproject.toml` packaging (PEP 621), Python 3.11+, pinned core deps (`typer`, `pydantic`, `httpx`, `jinja2`, `rich`, `iocextract`, `extract-msg`, `pytest`).
- [ ] Package layout (`phishbowl/`: `models/`, `parse/`, `extract/`, `score/`, `report/`, `connectors/`, `cli.py`).
- [ ] Define the `ParsedEmail` Pydantic model and sub-models (§7 of PRD).
- [ ] `Typer` entrypoint with a no-op `analyze` command wired to the (stub) pipeline.
- [ ] One **synthetic** safe fixture email (`tests/fixtures/`), obviously benign.
- [ ] `pytest` harness + first test: fixture loads into `ParsedEmail`.
- [ ] Lightweight Makefile (`format`, `lint`, `test`); `make test` is the routine gate. No GitHub Actions, no coverage gate, no type-checker.
- [ ] `.gitignore`, `.env.example`, MIT license, README stub, `CONTRIBUTING.md` stub stating **no real samples** rule.

**DoD:** `pip install -e .` then `phishbowl --help` works; the stub command runs end-to-end on the fixture and returns a `ParsedEmail`; `make test` is green.

---

## Phase 1 — Ingest & parse

**Objective:** Turn `.eml` and `.msg` into a fully populated `ParsedEmail`, format-agnostic downstream.

**Decision gates:**
- [x] `.eml` via stdlib `email`; `.msg` via `extract-msg` (locked).

**Tasks:**
- [ ] `.eml` parser → headers (ordered, duplicates preserved), addresses (display/addr-spec split), subject/date, body parts, attachments.
- [ ] RFC 2047 encoded-word decoding for subject and display names.
- [ ] Auth extraction: SPF/DKIM/DMARC from `Authentication-Results` + `Received-SPF`.
- [ ] `Received` hop parsing → ordered routing path.
- [ ] Attachment handling: filename, declared type, **magic-byte detection**, size, MD5/SHA1/SHA256, structural flags (archive / macro-capable / extension mismatch / double extension). **No execution, no archive extraction.**
- [ ] `.msg` parser via `extract-msg`, normalized into the **same** `ParsedEmail` (note lossier auth data).
- [ ] Structural anomaly notes captured during parsing.
- [ ] Charset/encoding handling centralized in the parse layer.
- [ ] Tests: both formats → equivalent `ParsedEmail`; malformed input degrades gracefully (noted partial, no crash).

**DoD:** Both formats parse into identical-shape models; auth, routing, addresses, and attachment hashes verified against synthetic fixtures; malformed-email test passes.

---

## Phase 2 — IOC extraction & defang

**Objective:** Extract every indicator, unwrap protective wrappers offline, defang by default.

**Tasks:**
- [x] Extract addresses, URLs, domains, IPv4/IPv6, hashes (via `iocextract` + custom passes).
- [x] Wrapper unwrapping (string transform only, **never fetch**): Microsoft Safelinks; Proofpoint URL Defense v1/v2/v3. Retain both wrapped + unwrapped.
- [x] Detect-and-mark non-reversible wrappers (Mimecast/Barracuda/Cisco) as "wrapped, unresolved."
- [x] Defanger: URLs, IPs, emails (`hxxps`, `[.]`, `[at]`) for all human-facing output.
- [x] Dedup/normalize indicators; preserve provenance (source header/part).
- [x] Tests: known wrapped samples unwrap correctly; defang round-trips; provenance retained; extraction does zero network I/O.

**DoD:** Synthetic email with Safelinks + Proofpoint links yields correct unwrapped indicators, all defanged in output, each tagged with provenance.

---

## Phase 3 — Risk scoring

**Objective:** Transparent, tunable, source-tagged verdict with human-readable reasons.

**Decision gates:**
- [x] YAML-defined additive weighted rules (locked).
- [x] **Calibrate starting weights + verdict bands** against the synthetic fixture set (this is the right phase to set numbers).
- [x] Org-domain config ships now (PRD §12, locked).

**Tasks:**
- [x] Rule engine: each rule = `{id, description, weight, source: offline|enrichment, detector}`.
- [x] Implement offline detectors from the §8 catalog (auth, identity/spoofing, domain/URL incl. punycode + IDN homograph + lookalike, attachments, weak content signals).
- [x] YAML weights file + loader + override mechanism.
- [x] Scorer: sum triggered weights → 0–100 → verdict band; emit per-rule reasons with evidence; tag each by source.
- [x] Guards: no double-counting; offline verdict always computed independent of enrichment.
- [x] Calibrate weights/bands against fixtures; document rationale.
- [x] Tests: each detector fires on a crafted fixture and stays silent otherwise; benign sample scores low; crafted-malicious sample scores high.

**DoD:** Running the scorer on fixtures yields sensible verdicts with traceable reasons; weights editable via YAML; every reason cites its evidence and source.

---

## Phase 4 — Reporting  ⭐ **Offline MVP milestone**

**Objective:** The screenshot-worthy, self-contained HTML report plus CLI and JSON. This is the launch-able offline product.

**Decision gates:**
- [x] Approve report layout/visual direction before building the template (built with the `frontend-design` skill — light/dark-adaptive "forensic dossier": editorial-serif headings, monospace data, severity-keyed accent, CSS-only atmosphere, zero remote assets).

**Tasks:**
- [x] **HTML report** (Jinja2, autoescape on): self-contained single file, inline CSS, **zero network egress**, no remote images/fonts/scripts, defanged display, never inject raw HTML body. Sections: verdict banner, score breakdown w/ per-rule reasons, auth results, IOC tables, routing path, attachment table. Light/dark friendly.
- [x] **Rich CLI** summary: verdict banner, top reasons, IOC tables, auth results.
- [x] **JSON** output: complete structured result (defanged + clearly-labeled raw).
- [x] **PII redaction** mode (recipients, internal hosts/IPs, configured fields).
- [x] Security test: report built from a fixture containing hostile HTML/script in subject+body produces **no executable markup and no remote loads** when opened.
- [x] "Under 60s" path: `phishbowl analyze tests/fixtures/<sample>` → HTML report, zero keys.

**DoD:** One command on the bundled sample produces all three outputs; the HTML renders beautifully offline, beacons nothing, and passes the hostile-content security test; redaction mode verified. ✅ **Met** — `phishbowl analyze` renders the rich CLI summary and writes HTML/JSON; the offline pipeline needs zero API keys and runs well under 60s; hostile-content and redaction tests are green (`tests/test_report.py`).

> **Ship/announce candidate.** After Phase 4 the tool is independently valuable and demo-able. Consider a soft release here.

---

## Phase 5 — Enrichment connectors

**Objective:** Pluggable, key-gated enrichment that enhances (never gates) the verdict.

**Decision gates:**
- [x] Approve the `Connector` interface before writing connector #1. (ABC + normalized `EnrichmentResult` in `phishbowl/connectors/base.py`; authoring guide in `docs/CONNECTORS.md`.)
- [x] urlscan defaults to **private** scans (locked).

**Tasks:**
- [x] Define stable `Connector` ABC/Protocol + `EnrichmentResult` (normalized).
- [x] Discovery: in-repo registry **and** `phishbowl.connectors` entry-points.
- [x] On-disk cache keyed by `(connector, ioc_type, value)` with per-connector TTL.
- [x] Rate-limit handling (per documented free tiers) + backoff + global concurrency cap.
- [x] Graceful degrade: missing key → skipped w/ note; API/network error → soft-fail w/ note; never crash.
- [x] SSRF guard: connectors reach only their vendor's documented base URL; never fetch email URLs.
- [x] Connectors: WHOIS/RDAP (domain age), VirusTotal, AbuseIPDB, urlscan (private default), Shodan.
- [x] Wire enrichment signals into the scorer, each tagged `[enrichment]`; re-score after enrichment.
- [x] Report/CLI/JSON show enrichment status per connector (used / skipped / failed) and source-tag enrichment-derived points.
- [x] Tests: mocked connector responses; offline run still fully works with all connectors disabled; cache hit path; rate-limit/backoff path; SSRF guard rejects an email URL; secrets never leak.

**DoD:** With keys, enrichment adds source-tagged signals and visibly enhances the verdict; with no keys, the Phase 4 experience is unchanged; a contributor could write a connector from the interface docs alone. ✅ **Met** — `phishbowl analyze --enrich` augments the verdict with five allowlisted, key-gated OSINT connectors (RDAP, VirusTotal, AbuseIPDB, urlscan, Shodan), each tagged `[enrichment]` in the HTML/CLI/JSON; the offline path is byte-identical with `--enrich` absent; caching, rate-limit backoff, graceful degrade, the SSRF guard, and secret hygiene are all green (`tests/test_enrich.py`).

---

## Phase 6 — SOAR export

**Objective:** Export triage results as XSOAR and Sentinel playbook artifacts (draft/export only — no remediation execution).

**Tasks:**
- [x] Define export schema mapping `ParsedEmail` + verdict + IOCs → XSOAR playbook artifact.
- [x] Define export mapping → Microsoft Sentinel playbook artifact.
- [x] CLI flags to emit each; documented field mappings.
- [x] Reinforce in code/docs: export is a draft; Phishbowl never quarantines/blocks/acts.
- [x] Tests: exports validate against expected schema on a fixture.

**DoD:** Both exports generate from a fixture and validate; docs explain how to import into each platform. ✅ **Met** — `phishbowl analyze --xsoar` / `--sentinel` emit a Cortex XSOAR playbook (all-manual tasks) and a Microsoft Sentinel playbook (a disabled Logic App ARM template), both mapped from one prepared report view so defanging/redaction stay consistent. The never-acts invariant is enforced in code, in the disclaimer stamped into every artifact, **and** structurally by each export's bundled JSON Schema (`task.iscommand` is `const false`; workflow `state` is `const "Disabled"`). Each export validates against its schema on every fixture, the validator is proven non-vacuous (it rejects a tampered acting artifact), and `docs/SOAR_EXPORT.md` documents the field mappings and per-platform import steps (`tests/test_export.py`).

---

## Phase 7 — FastAPI upload UI (stretch)

**Objective:** Minimal browser upload → report, additive to the existing contract.

**Decision gates:**
- [x] Confirm we're doing the stretch and its scope. (Additive only: a thin
  `phishbowl/web/` FastAPI app behind an optional `web` extra; the offline core,
  CLI, and report layer are untouched.)

**Tasks:**
- [x] FastAPI app: upload `.eml`/`.msg` → run pipeline → render HTML report.
- [x] Reuse `ParsedEmail` + report layer unchanged (no logic fork). The upload
  bytes go through the same parse → extract → score → `build_report` →
  `render_html` path the CLI uses (via a shared `parse_bytes` dispatcher); a test
  asserts the served report is byte-identical to the CLI's (timestamps aside).
- [x] Upload hardening: size limit (`413`, bounded chunked read capped at
  `MAX_INPUT_BYTES`, never buffered whole) and type check (`415`, `.eml`/`.msg`
  only, checked before any parsing); **never** auto-opens/fetches/writes to disk;
  same no-egress report guarantees, reinforced with a strict `Content-Security-Policy`.
- [x] Tests: upload happy path + rejection of oversized/wrong-type input
  (`tests/test_web.py`).

**DoD:** Local server accepts a sample upload and renders the same report the CLI produces, with upload hardening verified. ✅ **Met** — `phishbowl serve` (or `uvicorn phishbowl.web:app`) exposes an upload form that runs the **same** offline pipeline and returns the identical self-contained, zero-egress report; the upload path is hardened against oversized (`413`) and wrong-type (`415`) input, analyzes bytes in memory only, and never sends/detonates/fetches/auto-remediates. Behind the optional `web` extra so the offline install is unchanged (`tests/test_web.py`).

---

## Cross-cutting / ongoing (every phase)

- [ ] **Safety invariants** stay enforced & tested: no send, no detonate, no fetch of email URLs, no auto-remediation, no report beaconing (PRD §4).
- [ ] **Secrets** never logged or written to outputs; `.env.example` kept current (PRD §11).
- [ ] **Fixtures** synthetic only; CONTRIBUTING reiterates the no-real-samples rule (PRD §4).
- [ ] **Tests** accompany each feature; `make test` green before advancing a phase.
- [ ] **Docs** kept in step: README, connector-authoring guide (by Phase 5), glossary, scoring-config guide.
- [ ] **PRD/CHECKLIST** updated as decisions land (these are living documents).
