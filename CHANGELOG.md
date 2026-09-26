# Changelog

All notable changes to PhishBowl are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

A hardening and usability release. It adds the optional upload UI, inner-email triage,
and explicit incomplete-analysis reporting, and closes a series of hostile-input,
redaction, and enrichment gaps found in review.

### Breaking changes

- **Severity names:** the lowest severity is now `minimal` (was `benign`), and the
  default verdict wording no longer implies certainty: "Few signals — safety
  undetermined", "Low suspicion", "Suspicious — analyst review", "High suspicion",
  "Very high suspicion". Few signals is not proof of safety.
- **New exit status:** `phishbowl analyze` exits with `3` when some evidence could not
  be analyzed. A reached `--fail-on` threshold (status `1`) takes precedence. Status `2`
  now also covers an output that could not be written.
- **Scoring configuration is validated strictly.** Unknown keys and rule IDs (reported
  with the closest valid ID), weights that are not numbers from 0 to 100, and malformed
  bands are errors instead of silently changing verdicts. An empty `weights:` or
  `brands:` key is an error; an empty brand list removes that brand.
- **`identity.freemail_brand` is now `identity.freemail_role`:** it fires when a
  free-webmail sender presents as an organizational role from the new `role_keywords`
  list. Rename the key in any override.
- **The bundled `example` brand is removed** from `brands`.
- **Weight 0 means observe:** a rule weighted 0 still fires and lists its evidence at
  `+0`.
- **Python API:** `ParsedEmail.iocs` is removed (extraction returns indicators
  separately); `parse_auth(headers, *, from_domain=None)` returns
  `(Auth, anomalies)`; `list_embedded_emails(data)` no longer takes a filename and raises
  `MIMEBudgetError` when the message cannot be walked;
  `EnrichmentSettings.api_key_for()` takes the connector rather than its name; and
  `phishbowl.connectors.secrets.ENV_KEYS`, `env_var_for`, and `active_key_values` are
  replaced by the `Connector.api_key_env` attribute.
- **Connectors reach vendors over HTTPS only**, and enrichment cache entries are keyed by
  connector version, so entries written by earlier versions are ignored.

### Added

- **Upload UI** (`phishbowl serve`, behind the `web` extra): a local FastAPI app that runs
  the same pipeline and returns the same HTML report, with options for inner-email
  triage and redaction.
- **Inner-email triage:** `--inner` analyzes the email attached to a forward
  (`message/rfc822`, `.eml`, or an Outlook item) instead of the wrapper;
  `--inner-index N` picks among several and implies `--inner`. Outer reports note when
  attached emails are present.
- **Incomplete-analysis reporting:** every output carries `analysis_complete` and an
  assessment note; gaps are listed as *Not analyzed*, separately from informational
  notes, and the verdict gains the suffix `(incomplete analysis)`.
- **CLI:** `--version`; `--quiet`/`-q`; `--json -` for standard output; `-` to read the
  message from standard input, with the format sniffed; `--scoring-config`;
  `--connector` and `--disable-connector`; and `--fail-on` with a severity (`low`,
  `elevated`, `high`, `critical`) or a score from 0 to 100.
- **Rules:** `identity.multiple_from` (20), `identity.freemail_role` (12), `attach.html`
  (14), and `attach.archive` (10), plus the `role_keywords` configuration list.
- **Link wrappers:** Barracuda Link Protection and Cisco Secure Email links are decoded
  offline; Mimecast links stay wrapped but record their target domain.
- **Extraction:** links and resources from `srcset`, CSS `url()`, meta refresh, form
  actions, and `ping`; text hidden in `script`, `style`, and `template` elements; and
  inline text parts such as calendar invitations, which are also kept as hashed
  attachments.
- **Reports:** the full ordered header set, the best public sending-IP candidate, a
  plaintext preview of HTML-only bodies, an *Analysis notes* section, a print
  stylesheet, and a Content-Security-Policy in the HTML report.
- **Connector API:** `Connector.api_key_env` names a connector's key variable (so
  third-party connectors are key-gated and scrubbed like bundled ones),
  `Connector.prepare()` maps an indicator before lookup, and
  `phishbowl.connectors.http.json_object()` reads a vendor response defensively.
- **Documentation images:** `make screenshot` renders the HTML report and the terminal
  summary from a synthetic fixture.

### Changed

- **Authentication results are trusted only from the topmost receiving server** (its
  `authserv-id`); results from other servers are ignored and noted, and only the topmost
  `Received-SPF` is read. `Authentication-Results` is split only outside quoted strings
  and comments. With several DKIM signatures, the one aligned with From is reported.
- **RFC 2047 encoded-words are decoded only in unstructured headers and display names.**
- **Lookalike detection** recognizes folded look-alike characters, a brand embedded as a
  hyphenated part, and near-miss spellings (with adjacent transpositions counted as one
  edit), keeps the first letter fixed, and skips short names, reducing false positives.
- **Homograph detection** follows Unicode TR39: mixed scripts outside the highly
  restrictive profile, or non-ASCII labels that fold to a known brand or org name.
- **Domain comparisons** use registered domains from the Public Suffix List (private
  suffixes included) and treat Unicode and punycode spellings as equal.
- **Redaction** covers every recipient and delivery header (`Bcc`, `Resent-*`,
  `Delivered-To`, `X-Original-To`, `X-Apparently-To`, …) and `Received … for` clauses,
  and hides what is derived from a `--redact-field` header, including a hidden
  `Received` header's hosts and addresses in enrichment evidence. Values are replaced in
  place with typed placeholders, and text with nothing to withhold is left as written.
- **Redaction matching:** addresses, host names, and IP addresses are matched as whole
  tokens, through defanging (in any case), IDNA spellings, legacy IP notations, and
  percent-encoding; names are matched as whole words in any case or spacing, in prose
  only. Matching time is linear in the text, however many recipients a message names.
- **Redaction no longer withholds attacker indicators on the sender's say-so.** A
  recipient domain is withheld only when a delivery header or `Received … for` clause
  names it, not because `To` or `Cc` lists it; the visible sender headers' addresses and
  domains, public suffixes, and role names such as "Sales" are never withheld; short
  field values are not hunted in other text; and a link-protection wrapper that encodes
  a recipient is withheld without withholding the link it wraps. Set `org_domains` to
  withhold your own domains wherever they appear.
- **Enrichment:** VirusTotal's detection ratio counts only engines that returned a
  verdict; urlscan prefers malicious scans and weighs evidence about another page on the
  host at half; AbuseIPDB and VirusTotal report missing data as unknown rather than
  benign; RDAP queries the registered domain and treats a future registration date as
  unknown.
- **`--quiet`** now also silences write confirmations, and CLI help is plain text.
- **The terminal summary and HTML report** count enrichment rules separately from
  offline rules.

### Fixed

- Malformed `From` headers (an address as the display name, unquoted commas) no longer
  lose the sender; they are read as mail clients display them and noted.
- RFC 2231 parameters, surrogate escapes, overflowing dates, and unknown or dangerous
  charsets no longer crash parsing or produce invalid text.
- A part or attachment that fails to parse no longer loses the rest of the message; a
  message over the MIME budget is analyzed from its headers instead of not at all.
- Base64-encoded `message/rfc822` parts are decoded before being treated as emails.
- Strict email extraction no longer glues a preceding word onto an address; `mailto:`
  links yield their addresses.
- A link whose host is an IPv4 address in a legacy notation (`http://167772165/`,
  `http://0x7f.1/`) yields that address as an IP indicator, as a browser reads it,
  instead of a bogus domain or nothing.
- Proofpoint v3 links, trailing-dot hosts, and overlong or deeply nested wrappers unwrap
  correctly or are marked unresolved.
- Defanging is idempotent and neutralizes every non-web scheme; `javascript:`, `data:`,
  and `vbscript:` URIs no longer double their colon.
- `content.urgency_keywords` now scans HTML bodies.
- `make test`, `make lint`, and `make format` run tools through `python3 -m`, so they
  always use the interpreter that has PhishBowl's dependencies.

### Security

- Text-processing patterns avoid catastrophic backtracking (possessive or linear
  constructions, and time budgets on the indicator passes), with time-budget
  regression tests for adversarial input.
- The connector client re-checks the allowlist on every redirect, allows only HTTPS, and
  limits RDAP's bootstrap redirect to one HTTPS hop to a public DNS name: a bare GET
  without the connector's headers, and without retries.
- Enrichment never sends non-public IP addresses in any notation, local names, hosts
  under `org_domains`, recipient-only domains, or email addresses, as indicators or as
  URL hosts; urlscan reads a URL's host exactly as the filter does. Attachment hashes
  go first in the queue, but hash-shaped text cannot push links past a per-run limit.
- API keys are scrubbed, longest first and in percent-encoded form too, from results,
  notes, cache entries, tracebacks, and all `httpx`/`httpcore` loggers, and are kept
  out of object representations.
- Cache entries are private (`0600` files, `0700` directories) and used only when owned
  by the current user and recording the exact key.
- One failing connector, including one that cannot be constructed, no longer affects the
  others; vendor responses are parsed defensively, and a connector that stays
  rate-limited is not asked again for the rest of the run.
- XSOAR playbook inputs withhold values containing `,` or `${`; Sentinel drafts encode
  expression-like strings as literal data.
- Upload UI: request bytes are counted before multipart parsing, one analysis runs at a
  time, and every response, error pages included, carries anti-framing and
  content-security headers.
- Terminal control characters are stripped from every field, including attachment
  types; received-hop text, display names, and authentication details are defanged.
- The CLI refuses outputs that would overwrite the input (including a file redirected to
  standard input), the scoring configuration, or each other.
- Raised transitive floors: `urllib3>=2.7.0` (PYSEC-2026-141/142).

### Removed

- The VHS terminal-demo recording (`make demo`, `docs/assets/demo.gif`); `make
  screenshot` now renders a static terminal image instead.
- `docs/CRITICAL_REVIEW.md`; its findings are covered by this entry and by
  `SECURITY.md`.

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
