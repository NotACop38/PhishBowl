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
- **Structural caps:** the MIME walker yields at most `MAX_PARTS` parts, so a
  multipart "MIME bomb" is truncated rather than walked unbounded.
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

### Current status

- **bandit:** clean. The MD5/SHA1 used for attachment fingerprinting are IOC
  identity hashes (not a security control) and are marked `usedforsecurity=False`;
  the remaining `B105` matches are false positives (enum values, a Rich colour
  name, a Proofpoint run-token) annotated inline — Phishbowl holds no passwords
  in code, as API keys come only from the environment.
- **pip-audit:** the transitive dependencies in Phishbowl's runtime closure
  (`cryptography` via `extract-msg` → `msoffcrypto-tool`, `idna` via `httpx`, and
  `urllib3` via `requests`) are pinned to non-vulnerable floors in
  `pyproject.toml` (`urllib3>=2.7.0` covers PYSEC-2026-141/142). (`requests` is a
  direct dependency because `iocextract`
  imports it without declaring it; it pulls `urllib3` into the closure, hence the
  `urllib3` floor.) Any other findings in a given environment come from
  build/CI tooling (`pip`, `wheel`, `setuptools`) or unrelated pre-installed
  packages (`pyjwt`, `urllib3` via `conan`/`oauthlib`) that are **not** part of
  Phishbowl's dependency graph.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via GitHub's **Security Advisories** for this repository
(*Security → Report a vulnerability*), which opens a private channel with the
maintainers. Include a description, affected version/commit, reproduction steps,
and impact. If your report involves a sample email, **synthesize a benign
reproduction** — never attach a real phishing sample, live link, or real PII.

We aim to acknowledge reports within a few days and will coordinate a fix and
disclosure timeline with you.
