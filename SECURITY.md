# Security Policy

Phishbowl is a **defensive-only** phishing-triage tool. It parses a suspicious
`.eml`/`.msg`, extracts and defangs indicators, scores the message, and produces
an analyst report — entirely offline by default. This document describes the
security model it guarantees, how those guarantees are tested, and how to report
a vulnerability.

## Defensive scope & invariants

The analyzed email is treated as hostile input from end to end. These invariants
are non-negotiable, enforced in code, and covered by the routine test suite
(`make test`) — see `tests/test_safety_invariants.py` and `tests/test_report.py`:

- **Never send.** No SMTP, no replies, no read receipts — no callback of any kind
  to the email's infrastructure.
- **Never detonate.** Attachments are hashed and inspected by metadata/magic
  bytes only; they are never executed and archives are never auto-extracted.
- **Never fetch the analyzed email's URLs.** Phishbowl never opens the suspicious
  links. Indicators are only ever submitted to allowlisted third-party APIs the
  operator has explicitly configured (the optional, key-gated enrichment layer).
- **Never auto-remediate.** Phishbowl produces a verdict and an optional playbook
  *draft*; it never quarantines, blocks, or acts.
- **Zero network egress from the report.** The self-contained HTML report loads
  no remote images, fonts, scripts, or trackers and beacons nothing — opening a
  report about a phishing email can never phone home to the attacker.
- **Secrets stay out of output.** Environment/secret values (e.g. enrichment API
  keys) are never logged and never written into any report, JSON, or log.
- **Synthetic samples only.** Only synthetic sample emails are ever committed;
  real phishing samples (live links, real PII, actual malware) must never be.

### How the invariants are tested

`tests/test_safety_invariants.py` exercises the whole offline pipeline
(parse → extract → score → report) over every bundled fixture and asserts, as
part of `make test`:

- **No egress:** an active guard fails the test the instant any outbound socket
  `connect` or SMTP call is attempted during a run.
- **Inert reports:** the generated HTML contains no remotely-loading or
  script-executing markup and no remote-load attribute/CSS fetch (autoescape
  plus defanging guarantee injected content lands as inert, escaped text).
- **No secret leakage:** with sentinel secrets seeded into the environment, no
  sentinel value appears in the HTML, JSON, CLI summary, or captured logs.

## Input hardening

The parser defends against malicious or malformed input (`phishbowl/parse/`):

- **Size limit:** inputs over `MAX_INPUT_BYTES` (50 MiB) are refused *before*
  being read into memory (`phishbowl/parse/limits.py`).
- **Structural caps:** MIME construction checks part and nesting limits before
  allocating each node. Later traversal also uses the part budget.
- **Graceful degradation:** a readable-but-malformed message degrades into a
  noted partial result (recorded as an `Anomaly`) and never crashes the run.

## Connector egress (SSRF guard)

The optional enrichment layer (`--enrich`) is the only path that reaches the
network, and it is deliberately narrow (`phishbowl/connectors/`):

- **Allowlisted egress only.** Each connector declares the vendor host(s) it may
  reach, and its HTTP client refuses any other host *before* connecting — so a
  connector can never be coerced into fetching a URL taken from the analyzed
  email (the SSRF guarantee). Redirects are never delegated to the HTTP library:
  they are followed hop-by-hop with the same allowlist check applied to every
  redirect target, so a vendor 3xx cannot bounce a request to a non-allowlisted
  host either. The one calibrated exception is RDAP's *bootstrap redirect*:
  `rdap.org`'s documented job is to designate the authoritative registry, so
  exactly one redirect it issues may leave the allowlist (https only), and the
  designated registry gets exactly one request — any further redirect (e.g. to
  a registrant-chosen registrar RDAP) is refused. urlscan, the one connector
  whose vendor can be
  asked to visit a URL, defaults to **private** and to passive search by domain;
  active submission is a separate, explicit opt-in (`--urlscan-submit`).
- **Key-gated, env-only secrets.** API keys are read from the environment only,
  never logged (key values are scrubbed even from the HTTP libraries' debug
  logs and from connector crash tracebacks), never written to an output or the
  on-disk cache, and defensively scrubbed from any retained vendor response.
  Cache entries are written `0600` in a `0700` tree, since they hold the
  analyzed email's indicators.
- **Graceful degrade.** A missing key skips a connector with a note; a network or
  API error soft-fails it with a note; nothing crashes the run. The offline
  verdict is always computed first and never depends on enrichment.

These are covered by `tests/test_enrich.py` (all with mocked HTTP — no live
calls): the SSRF guard rejects an email-derived URL, the cache and rate-limit
backoff paths behave, every connector degrades gracefully, and no seeded API key
ever appears in the HTML, JSON, or CLI output.

## Static & dependency scanning

Per the project's CI philosophy (`CLAUDE.md`), the routine gate is a fast
`pytest` run; the heavier security scanners are **run once, on demand — not wired
into `make test` and never in GitHub Actions**. Run them manually:

```sh
# Static analysis of the package (no findings expected).
bandit -r phishbowl

# Dependency vulnerability audit.
pip-audit
```

### Review check (2026-09-12)

The isolated development environment's dependency audit reported advisories only
for its bundled pip 25.0.1; pip was upgraded to 26.2.1, above all fix versions in
that audit. No runtime dependency findings were returned. This is a dated result,
not a guarantee that future installations or advisory databases are clean.

Bandit reported one existing silent exception handler around the report's routing
IP projection. The unnecessary catch was removed and the path is covered by the
report/workflow tests. MD5/SHA1 remain attachment identity fingerprints using
`usedforsecurity=False`, not cryptographic security controls.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via GitHub's **Security Advisories** for this repository
(*Security → Report a vulnerability*), which opens a private channel with the
maintainers. Include a description, affected version/commit, reproduction steps,
and impact. If your report involves a sample email, **synthesize a benign
reproduction** — never attach a real phishing sample, live link, or real PII.

We aim to acknowledge reports within a few days and will coordinate a fix and
disclosure timeline with you.

## Resource and evidence limits

The parser accepts at most 50 MiB, 2,000 MIME nodes, nesting depth 30, 100,000
lines and 64 KiB per line. IOC regex passes have a 150 ms budget per type/pattern and retain at most 1,000
indicators. The analysis examines up to 262,144 characters per
body representation. Limits produce an incomplete assessment, never a safety
verdict. All non-attachment body parts are combined before that analysis limit.
Outlook compressed RTF is not expanded. These are application budgets, not an
OS sandbox or a proof against all parser/dependency resource exhaustion.

The upload service counts request bytes before multipart parsing, permits one
file and two small fields, and limits requests to the message cap plus 64 KiB
of multipart overhead. Its upload spool stays in memory under this bound. One
upload/analysis is admitted per process; CPU work runs off the event loop. The
service defaults to loopback. Exposed deployments require operator-provided
access control, ingress/time limits and process resource limits. Host memory,
swap, crash dumps and the ASGI server are outside the memory-only upload claim.

Authentication results and Received IPs are unverified header claims. Scores are
uncalibrated heuristics. Redaction is selected-value removal, not anonymization.
Installed third-party connectors are trusted Python code with process authority;
the guarded HTTP client is not a plugin sandbox. RDAP's HTTPS bootstrap redirect
is an explicit exception to its initial vendor host allowlist.
