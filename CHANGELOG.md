# Changelog

All notable changes to PhishBowl are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Stdin input** — `phishbowl analyze -` reads the email from stdin (PRD §6.1),
  so it can be piped straight from another tool (e.g.
  `curl … | phishbowl analyze -`). The format is sniffed from the bytes (OLE2
  magic → `.msg`, else `.eml`), the read is bounded by the same size cap as
  files and uploads, and an empty stream is a clean usage error.

### Security

- **SSRF guard now holds across redirects.** The connector HTTP client no
  longer delegates redirect-following to httpx (which re-checks nothing):
  redirects are followed hop-by-hop with the host allowlist re-applied to every
  redirect target before any connection, and a chain longer than 5 hops
  soft-fails. Previously a vendor 3xx could bounce the one redirect-following
  connector (RDAP) to a non-allowlisted host unchecked.
- **API keys are scrubbed from HTTP debug logs.** httpx logs every request URL
  at INFO/DEBUG, and Shodan's API key rides in the query string — with verbose
  logging enabled, the key landed in the operator's logs. Known key values
  (env *and* programmatic) are now scrubbed from the `httpx`/`httpcore` loggers
  for the duration of an enrichment run, and from connector crash tracebacks.
- **Enrichment cache entries are now private** (`0700` directories, `0600`
  files): they hold the analyzed email's indicators, which other local users on
  a shared host should not be able to read.
- **Received-hop text, address display names, and auth details are now
  defanged** in all outputs, closing the gap where a forged `Received` header
  or a URL-bearing display name could hand an analyst a live IP/URL on
  copy-paste (the view contract already promised this).
- Raised the `urllib3` transitive floor to `>=2.7.0` (PYSEC-2026-141/142).

### Fixed

- Defanging a `javascript:`/`data:`/`vbscript:` URI no longer doubles the
  colon (`javascript[:]:…` → `javascript[:]…`), restoring the documented
  lossless `refang` round-trip for those URIs.
- `make test` / `make lint` / `make format` now invoke pytest and ruff via
  `python3 -m …` instead of bare executables, so they always run from the
  interpreter that has PhishBowl's dependencies installed (a bare `pytest` on
  PATH may live in an unrelated, isolated tool environment).

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
  target; defang every indicator (`example[.]com`, `hxxps://…`) in the
  human-facing HTML and CLI so they are safe to read and share. The JSON output
  carries both the defanged value and a clearly-labelled raw field for tooling,
  so it is *not* defanged-only — strip or redact the `*_raw` fields before
  sharing JSON. (Phase 2)
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
- Pinned security floors for transitive dependencies (`cryptography`, `idna`,
  and `urllib3` via `requests`) to keep a fresh install off versions with known
  CVEs.

### Fixed

- Declared `requests` as a runtime dependency. `iocextract` imports it
  unconditionally at module load but does not declare it, so a clean
  `pip install phishbowl` would otherwise fail on first import with
  `ModuleNotFoundError: No module named 'requests'`. The offline core never uses
  it to reach the network; the floor (`>=2.33.0`) keeps fresh installs off the
  `extract_zipped_paths` temp-file CVE (CVE-2026-25645) and the earlier
  `.netrc` credential-leak (CVE-2024-47081). Because `requests` pulls `urllib3`
  into the runtime closure, a `urllib3>=2.6.0` floor was added too
  (CVE-2025-50181/50182 redirect handling, CVE-2025-66418 decompression DoS).

[0.1.0]: https://github.com/notacop38/phishbowl/releases/tag/v0.1.0
