# Security policy

PhishBowl is a defensive-only phishing-triage tool. It parses a suspicious `.eml` or
`.msg`, extracts and defangs its indicators, scores the message, and writes an analyst
report, entirely offline unless an operator enables enrichment. This document describes
the guarantees it makes, how they are enforced and tested, the limits of those
guarantees, and how to report a vulnerability.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately through
GitHub Security Advisories for this repository (**Security → Report a vulnerability**).
Include a description, the affected version or commit, reproduction steps, and the
impact. If the report involves an email, **synthesize a harmless reproduction**; never
attach a real phishing sample, a live link, or real personal data.

We aim to acknowledge reports within a few days and to agree a fix and disclosure
timeline with you.

## Guarantees

The analyzed message is hostile input from end to end. These invariants are enforced in
code and covered by the routine test suite (`make test`):

- **Never sends.** No SMTP, no replies, no read receipts, no callback of any kind to
  the message's infrastructure.
- **Never detonates.** Attachments are hashed and typed by metadata and magic bytes;
  they are never executed, and archives are never extracted.
- **Never fetches the message's URLs.** Indicators go only to the allowlisted services an
  operator enables with `--enrich`.
- **Never remediates.** PhishBowl produces a verdict and optional playbook drafts; it
  never quarantines, blocks, or acts.
- **Reports make no network requests.** The HTML report loads no remote images, fonts,
  scripts, or styles.
- **Secrets stay out of outputs.** API keys are read from the environment and never
  appear in reports, JSON, logs, or the cache.
- **Synthetic samples only.** Only synthetic emails are committed to the repository.

`tests/test_safety_invariants.py` runs every fixture through the whole pipeline with a
guard that fails the test on any outbound socket connection or SMTP use, checks that
the HTML contains no executable or remotely loaded markup, and seeds sentinel secrets
into the environment to check that none reaches the HTML, JSON, terminal output, or
logs.

## Defenses

### Parsing hostile input

- **Bounded work.** Input over 50 MiB is refused before it is read into memory. MIME
  structure is limited to 2,000 parts and a nesting depth of 30, checked as the tree is
  built, and to 1,000,000 lines of at most 64 KiB, checked before parsing. A message over
  the MIME budget is analyzed from its first 1 MiB of headers only. Text analysis is
  limited to 262,144 characters per body representation, indicator extraction to 1,000
  indicators with a 150 ms time budget per pattern, and link unwrapping to five nested
  wrappers and 16 KiB per wrapped URL.
- **Linear matching.** The patterns that run over message text (extraction, unwrapping,
  redaction, header parsing) are written so they cannot backtrack catastrophically, and
  regression tests hold adversarial inputs to a time budget.
- **No forged verdicts.** RFC 2047 encoded-words are decoded only in unstructured headers
  and display names, so an encoded `Authentication-Results` value cannot become a result.
  `Authentication-Results` is split only at separators outside quoted strings and
  comments, and only headers from the topmost `authserv-id` are trusted; only the
  topmost `Received-SPF` is read.
- **Failures are contained and disclosed.** A part, attachment, or header that fails to
  parse is recorded as an analysis note and the rest of the message is still analyzed.
  When evidence is lost, the verdict is marked `(incomplete analysis)` and the CLI exits
  with status 3, so a partial analysis is never presented as a complete one.

### Reports

- The HTML report is one self-contained file: inline CSS, no scripts, Jinja2
  autoescaping on all message-derived content, and a Content-Security-Policy
  (`default-src 'none'`) as a second line of defense.
- The message's HTML is never rendered. The body preview is escaped plaintext.
- Indicators and every free-text field (subject, evidence, display names, routing hops,
  headers, authentication details) are defanged, and terminal control characters are
  stripped before anything reaches a terminal, an HTML page, or JSON.
- SOAR drafts cannot act on import: every XSOAR task is manual, and the Sentinel
  workflow deploys disabled with a manual trigger and inert actions. Both properties are
  enforced by bundled JSON Schemas. Values that XSOAR would evaluate as expressions, or
  that Sentinel or ARM would read as expressions, are withheld or encoded as literal
  data.

### Enrichment

Enrichment (`--enrich`) is the only feature that reaches the network.

- **Allowlisted, HTTPS-only egress.** Each connector's HTTP client refuses any host
  outside its declared allowlist, and any scheme but HTTPS, before connecting.
  Redirects are never delegated to the HTTP library: each hop is re-checked. The one
  exception is RDAP bootstrapping: `rdap.org` may redirect once to the authoritative
  registry, which must be a public DNS name (never an IP literal or a local name) over
  HTTPS, receives exactly one request with no retries, and may not redirect again.
- **Minimal disclosure.** Non-public IP addresses in any notation, local host names,
  hosts under the operator's `org_domains`, domains seen only in recipient headers, and
  email addresses are never sent, as indicators or as the host of a URL; each
  connector re-derives hosts the same way the filter does. A URL that passes is sent
  whole to URL-reputation services, path and query included. urlscan.io searches by
  host name unless the operator passes `--urlscan-submit`.
- **Secret hygiene.** Keys are read from the environment only, kept out of object
  representations, and scrubbed, longest first, from results, status notes, cached
  entries, connector tracebacks, and the `httpx`/`httpcore` loggers during a run.
- **Untrusted responses.** A non-JSON or malformed vendor response is a soft failure for
  that indicator; missing fields mean "unknown", never "benign". Rate-limit waits honor
  only a finite `Retry-After`, capped at 30 seconds, and a rate-limit error names only
  the host, never the indicator.
- **Contained failures.** Each connector runs in its own guard, including its
  construction, so a broken or hostile response affects only that connector. The
  offline score is computed first and never depends on enrichment.
- **Private, verified cache.** Cache files are created `0600` in `0700` directories,
  keyed by connector, connector version, indicator type, and value. An entry is used only
  if it is a regular file owned by the current user and records the exact key it was
  looked up by.

### Upload UI

The optional `phishbowl serve` app checks the declared size and type before parsing,
counts request bytes before multipart parsing, accepts one file and two small fields,
keeps the upload in memory, analyzes one upload at a time (a concurrent upload receives
`503` with `Retry-After`), and runs analysis off the event loop. Every response,
including error pages, carries a strict Content-Security-Policy, `X-Frame-Options:
DENY`, `Referrer-Policy: no-referrer`, and `X-Content-Type-Options: nosniff`, and
cross-origin form posts are refused. It binds to loopback by default and warns when bound
to any other interface.

## Limits of these guarantees

- **Heuristics, not verification.** Authentication results and `Received` IP addresses
  are header claims that PhishBowl does not verify. Scores are hand-set heuristics, not
  probabilities, and have no measured detection or false-positive rate on real mail.
- **Budgets are not a sandbox.** The limits above are application budgets, not an
  operating-system boundary. Parser dependencies (the standard library's `email`
  package, `extract-msg`, `olefile`) run in-process, and PhishBowl does not claim
  resistance to every resource-exhaustion attack against them. Compressed RTF bodies in
  Outlook items are not expanded; a missing body is disclosed as incomplete analysis.
- **Redaction removes known values; it does not anonymize.** It withholds recipients,
  internal topology, and named fields, but free text can still identify people. Review
  a report before sharing it. Redaction also cannot undo an enrichment query made
  earlier: complete public URLs sent to a vendor may contain sensitive tokens.
- **urlscan.io submissions contact the message's infrastructure.** `--urlscan-submit`
  makes urlscan visit the URL, which can alert the attacker and can disclose a
  per-victim token. Private visibility only hides the result page.
- **Installed connectors are trusted code.** A third-party connector package runs with
  PhishBowl's privileges. The HTTP allowlist governs the client PhishBowl hands it, not
  what arbitrary Python could do.
- **The upload UI is a single-analyst tool.** It has no authentication. An exposed
  deployment needs operator-provided access control, ingress and time limits, and
  process resource limits. Host memory, swap, crash dumps, and the ASGI server are
  outside the in-memory upload claim.
- **SOAR schemas are structural checks.** They prove the drafts cannot act; they do not
  certify that a given XSOAR or Azure version will import them.
- **Output aliasing checks prevent mistakes, not races.** The CLI refuses outputs that
  would overwrite the input, the scoring configuration, or each other, including through
  symlinks and hard links, but does not defend against concurrent hostile filesystem
  changes.

## Static and dependency scanning

The routine gate is the fast `pytest` suite. The heavier scanners run once, on demand,
never in `make test` or in CI:

```sh
python -m bandit -r phishbowl   # static analysis
python -m pip_audit             # dependency vulnerability audit
```

**Last run: 2026-09-26.** Bandit 1.9.4 reported no issues (its one previous finding, a
silent exception handler while listing attached emails, now logs the failure). pip-audit
2.10.1 reported no known vulnerabilities in the development environment after upgrading
its unused `setuptools` 79.0.1 (PYSEC-2026-3447) to 83. This is a dated result, not a
guarantee that future installations or advisory databases stay clean. MD5 and SHA-1
appear only as attachment identifiers, computed with `usedforsecurity=False`, never as
security controls.
