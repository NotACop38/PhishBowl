# Changelog

All notable changes to PhishBowl are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-06-05

Inaugural release. PhishBowl is a self-hostable, vendor-neutral,
**defensive-only** phishing-triage tool: drop in a suspicious `.eml`/`.msg`, and
it parses the message, extracts and defangs IOCs, optionally enriches them via
allowlisted OSINT APIs, computes a transparent risk score, and produces an
analyst-ready report. It is **offline-first** — the core pipeline
(parse → extract → defang → score → report) always yields a complete verdict
with zero API keys; enrichment only augments.

### Added

- **Email parsing** — normalize `.eml` (RFC 822/MIME) and `.msg` (Outlook OLE,
  via `extract-msg`) into a single `ParsedEmail` model: headers, addresses,
  routing/`Received` hops, authentication results (SPF/DKIM/DMARC), body parts,
  and attachment metadata. Malformed input degrades to a clean error, never a
  traceback. (Phases 0–1)
- **IOC extraction, unwrapping & defang** — pull URLs, domains, IPs, and emails;
  unwrap common link wrappers (e.g. Proofpoint, Safe Links) to reveal the true
  target; defang every indicator (`example[.]com`, `hxxps://…`) in all outputs
  so reports are safe to share. (Phase 2)
- **Transparent offline risk scoring** — a configurable, fully offline rule
  engine (`score/defaults.yaml`) producing a 0–100 score, a verdict, and a
  per-rule breakdown with evidence and weights — no black box. (Phase 3)
- **Analyst-ready reports** — a self-contained HTML "forensic dossier" (zero
  network egress when opened), machine-readable JSON, and a rich colorized CLI
  summary; plus opt-in PII redaction (`--redact`, `--redact-field`). (Phase 4)
- **Opt-in OSINT enrichment** — five allowlisted, key-gated connectors
  (VirusTotal, urlscan, AbuseIPDB, Shodan, RDAP) behind `--enrich`, reading
  secrets from the environment only, with on-disk caching and rate limiting.
  Every enrichment-derived point is tagged `[enrichment]`; the offline verdict
  is preserved alongside. (Phase 5)
- **SOAR export** — `--xsoar` and `--sentinel` emit Cortex XSOAR and Microsoft
  Sentinel playbook **drafts**. Every XSOAR task is manual and the Sentinel
  workflow ships disabled, so importing one triggers no automation; inertness is
  schema-enforced. (Phase 6)
- **CLI** — `phishbowl analyze <file>` with `--html`, `--json`, `--xsoar`,
  `--sentinel`, `--redact`, `--redact-field`, `--enrich`, `--urlscan-submit`.

### Security

- **Defensive invariants enforced in code and tests:** PhishBowl never sends,
  never detonates attachments, never fetches the analyzed email's URLs, and
  never auto-remediates. The HTML report performs zero network egress when
  opened — no remote images, fonts, scripts, or trackers. Only synthetic sample
  emails are committed.
- Pinned security floors for transitive dependencies (`cryptography`, `idna`) to
  keep a fresh install off versions with known CVEs.

### Fixed

- Declared `requests` as a runtime dependency. `iocextract` imports it
  unconditionally at module load but does not declare it, so a clean
  `pip install phishbowl` would otherwise fail on first import with
  `ModuleNotFoundError: No module named 'requests'`. The offline core never uses
  it to reach the network; the floor (`>=2.32.4`) picks up the
  CVE-2024-47081 `.netrc` credential-leak fix.

[0.1.0]: https://github.com/notacop38/phishbowl/releases/tag/v0.1.0
