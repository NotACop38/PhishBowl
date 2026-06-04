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
- [ ] **Calibrate starting weights + verdict bands** against the synthetic fixture set (this is the right phase to set numbers).
- [x] Org-domain config ships now (PRD §12, locked).

**Tasks:**
- [ ] Rule engine: each rule = `{id, description, weight, source: offline|enrichment, detector}`.
- [ ] Implement offline detectors from the §8 catalog (auth, identity/spoofing, domain/URL incl. punycode + IDN homograph + lookalike, attachments, weak content signals).
- [ ] YAML weights file + loader + override mechanism.
- [ ] Scorer: sum triggered weights → 0–100 → verdict band; emit per-rule reasons with evidence; tag each by source.
- [ ] Guards: no double-counting; offline verdict always computed independent of enrichment.
- [ ] Calibrate weights/bands against fixtures; document rationale.
- [ ] Tests: each detector fires on a crafted fixture and stays silent otherwise; benign sample scores low; crafted-malicious sample scores high.

**DoD:** Running the scorer on fixtures yields sensible verdicts with traceable reasons; weights editable via YAML; every reason cites its evidence and source.

---

## Phase 4 — Reporting  ⭐ **Offline MVP milestone**

**Objective:** The screenshot-worthy, self-contained HTML report plus CLI and JSON. This is the launch-able offline product.

**Decision gates:**
- [ ] Approve report layout/visual direction before building the template (use the `frontend-design` skill).

**Tasks:**
- [ ] **HTML report** (Jinja2, autoescape on): self-contained single file, inline CSS, **zero network egress**, no remote images/fonts/scripts, defanged display, never inject raw HTML body. Sections: verdict banner, score breakdown w/ per-rule reasons, auth results, IOC tables, routing path, attachment table. Light/dark friendly.
- [ ] **Rich CLI** summary: verdict banner, top reasons, IOC tables, auth results.
- [ ] **JSON** output: complete structured result (defanged + clearly-labeled raw).
- [ ] **PII redaction** mode (recipients, internal hosts/IPs, configured fields).
- [ ] Security test: report built from a fixture containing hostile HTML/script in subject+body produces **no executable markup and no remote loads** when opened.
- [ ] "Under 60s" path: `phishbowl analyze tests/fixtures/<sample>` → HTML report, zero keys.

**DoD:** One command on the bundled sample produces all three outputs; the HTML renders beautifully offline, beacons nothing, and passes the hostile-content security test; redaction mode verified.

> **Ship/announce candidate.** After Phase 4 the tool is independently valuable and demo-able. Consider a soft release here.

---

## Phase 5 — Enrichment connectors

**Objective:** Pluggable, key-gated enrichment that enhances (never gates) the verdict.

**Decision gates:**
- [ ] Approve the `Connector` interface before writing connector #1.
- [x] urlscan defaults to **private** scans (locked).

**Tasks:**
- [ ] Define stable `Connector` ABC/Protocol + `EnrichmentResult` (normalized).
- [ ] Discovery: in-repo registry **and** `phishbowl.connectors` entry-points.
- [ ] On-disk cache keyed by `(connector, ioc_type, value)` with per-connector TTL.
- [ ] Rate-limit handling (per documented free tiers) + backoff + global concurrency cap.
- [ ] Graceful degrade: missing key → skipped w/ note; API/network error → soft-fail w/ note; never crash.
- [ ] SSRF guard: connectors reach only their vendor's documented base URL; never fetch email URLs.
- [ ] Connectors: WHOIS/RDAP (domain age), VirusTotal, AbuseIPDB, urlscan (private default), Shodan.
- [ ] Wire enrichment signals into the scorer, each tagged `[enrichment]`; re-score after enrichment.
- [ ] Report/CLI/JSON show enrichment status per connector (used / skipped / failed) and source-tag enrichment-derived points.
- [ ] Tests: mocked connector responses; offline run still fully works with all connectors disabled; cache hit path; rate-limit/backoff path.

**DoD:** With keys, enrichment adds source-tagged signals and visibly enhances the verdict; with no keys, the Phase 4 experience is unchanged; a contributor could write a connector from the interface docs alone.

---

## Phase 6 — SOAR export

**Objective:** Export triage results as XSOAR and Sentinel playbook artifacts (draft/export only — no remediation execution).

**Tasks:**
- [ ] Define export schema mapping `ParsedEmail` + verdict + IOCs → XSOAR playbook artifact.
- [ ] Define export mapping → Microsoft Sentinel playbook artifact.
- [ ] CLI flags to emit each; documented field mappings.
- [ ] Reinforce in code/docs: export is a draft; Phishbowl never quarantines/blocks/acts.
- [ ] Tests: exports validate against expected schema on a fixture.

**DoD:** Both exports generate from a fixture and validate; docs explain how to import into each platform.

---

## Phase 7 — FastAPI upload UI (stretch)

**Objective:** Minimal browser upload → report, additive to the existing contract.

**Decision gates:**
- [ ] Confirm we're doing the stretch and its scope.

**Tasks:**
- [ ] FastAPI app: upload `.eml`/`.msg` → run pipeline → render HTML report.
- [ ] Reuse `ParsedEmail` + report layer unchanged (no logic fork).
- [ ] Upload hardening: size limits, type checks, **never** auto-open/fetch; same no-egress report guarantees.
- [ ] Tests: upload happy path + rejection of oversized/wrong-type input.

**DoD:** Local server accepts a sample upload and renders the same report the CLI produces, with upload hardening verified.

---

## Cross-cutting / ongoing (every phase)

- [ ] **Safety invariants** stay enforced & tested: no send, no detonate, no fetch of email URLs, no auto-remediation, no report beaconing (PRD §4).
- [ ] **Secrets** never logged or written to outputs; `.env.example` kept current (PRD §11).
- [ ] **Fixtures** synthetic only; CONTRIBUTING reiterates the no-real-samples rule (PRD §4).
- [ ] **Tests** accompany each feature; `make test` green before advancing a phase.
- [ ] **Docs** kept in step: README, connector-authoring guide (by Phase 5), glossary, scoring-config guide.
- [ ] **PRD/CHECKLIST** updated as decisions land (these are living documents).
