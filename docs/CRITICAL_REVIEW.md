# Critical review — 2026-09-12

PhishBowl earns its place as a local evidence organizer: normalize a suspicious
message, preserve indicator provenance, show why rules fired, and hand an analyst
an inert report. It does not establish that an email is safe. Calling the result
high confidence, promising zero risk, or treating redaction as anonymization was
unsupported by the implementation and synthetic test set.

The review covered all product Python modules, packaged templates/configuration
and export schemas, with focused inspection of tests and supporting documents.
The original 298 tests passed despite the defects below. Findings were reproduced
with synthetic inputs or traced through the relevant source; no analyzed URL,
live phishing sample, vendor credential, or production deployment was used.

## Changes

- Replaced overlapping HTML regexes with a shared bounded text parser. Quoted
  and unquoted links now reach extraction and anchor comparisons. Malformed URL
  syntax is recoverable. All ordinary MIME body parts contribute evidence.
- Enforced MIME part/depth limits during construction, with line budgets before
  parsing. Added text/indicator budgets and timeout-capable IOC regex passes;
  the underlying email regex also stalled on a small repeated-text input.
- Moved upload limits ahead of multipart consumption, kept bounded spools in
  memory, limited concurrent analysis, and moved CPU work off the event loop.
- Applied redaction to repeated sensitive values in subject/body, evidence,
  filenames, structured fields, wrappers and encoded URL values. Withheld vendor
  references under redaction because they can encode the original indicator.
- Escaped Sentinel's two expression-language boundaries. JSON serialization
  alone did not prevent email strings from becoming deployment expressions.
- Excluded non-public IPs, local URL hosts, configured organization domains and
  recipient-only domains from enrichment. Added attachment SHA-256 targets.
- Computed offline results before optional enrichment and retained them when
  enrichment fails. Corrupt cache entries become misses; writes use unique
  temporary files. Secret scrubbing covers result strings and cached results.
- Stopped labeling absent vendor reputation data benign. Validated score weights
  and bands, used the packaged Public Suffix List for domain comparisons, and
  made lookalike matching deterministic.
- Added explicit incomplete assessments and CLI exit 2 for missing/limited
  analysis. Replaced certainty claims with signal-based verdict wording and
  labeled authentication/routing information as unverified header evidence.

## Decisions retained and limits

Keep the offline core, transparent rules, shared report view, vendor-neutral
connectors, synthetic fixtures and manual SOAR drafts. These serve analyst review
without giving the application authority to send, detonate or remediate.

Keep the local upload UI as a convenience, not a multi-user service. Application
budgets are not an OS sandbox; exposed deployments need separate authentication,
ingress/time limits and process isolation. Parser dependencies, malformed OLE
containers and all possible HTML client interpretations are not exhaustively
qualified. Compressed Outlook RTF is deliberately not expanded; missing bodies
are disclosed as incomplete analysis.

Third-party connector packages are trusted executable code, not sandboxed
plugins. RDAP's HTTPS bootstrap redirect remains an explicit exception. Active
urlscan submission remains a separate operator choice that can cause third-party
contact with the email's infrastructure. Public URLs can contain victim tokens;
output redaction does not reverse an earlier enrichment disclosure.

Scores have no measured real-mail detection/false-positive rate. Header claims
are not cryptographic authentication. Redaction removes selected known values,
not every possible identity or encoding. Local SOAR schema tests do not certify
Azure/XSOAR import compatibility; no cloud deployment was performed.

Validation includes the full pytest gate, synthetic regressions for the defects,
local report rendering, package build, and a separate review before merge. The
routine gate remains `make test`; no hosted CI, coverage gate or type checker was
introduced.

The final review check passed 324 tests. Independent review also caught hidden
MIME-container defects, repeated defanging in redacted evidence, a routing-field
redaction omission, and public IPv6 URLs being filtered as DNS names. These were
corrected with targeted regression coverage. Chromium loaded the
updated report with zero HTTP requests and no horizontal overflow at 390 pixels.
The wheel and source distribution built successfully. The dependency audit found
only outdated pip tooling, upgraded to 26.2.1; Bandit's one existing silent catch
was removed. Tests use mocked vendor responses, not live service qualification.


## Follow-up review — evidence integrity

A second review of the merged implementation found remaining defects despite
324 passing tests. The fixes preserve the local evidence-organizer purpose:

- Bound hostname matching in anchor labels; long unbroken text no longer causes
  quadratic scoring work. A subprocess deadline guards the regression.
- Match Proofpoint host boundaries and version paths instead of substrings, so
  an attacker-owned hostname cannot masquerade as a gateway and hide its actual
  destination. Safelinks decoding preserves percent escapes belonging to the
  destination itself.
- Retain unsupported inline text formats (including calendar and RTF) as hashed
  attachment metadata and explicitly mark their body analysis incomplete.
- Reject CLI output aliases to source emails, scoring configuration, or other
  outputs before analysis or enrichment. Checks include symlinks and hardlinks;
  they prevent ordinary mistakes, not hostile concurrent filesystem changes.
- Bypass both cache reads and writes for explicit active urlscan submissions:
  passive reputation results cannot suppress an action, and submission receipts
  cannot replace passive evidence. Existing cache entries from older versions
  retain their original TTL; clear the cache if prior active receipts are present.

The PRD now treats evidence integrity, bounded analysis and analyst traceability
as success criteria. Attractive reports and repository popularity do not validate
phishing detection. The offline core and optional local UI remain appropriate;
adding a classifier, hosted service or automated remediation would expand the
trust boundary without evidence that it solves the current product's gaps.

Independent review caught and corrected a terminal-dot regression in hostname
matching before merge; sentence punctuation still permits mismatch detection.

Validation: 337 tests passed using the repository virtual environment, including
synthetic regressions; Ruff and whitespace checks passed. The system Python had
no pytest, so the gate was run as `make test PYTHON=.venv/bin/python`. No live
vendor requests or real messages were used. Existing dependency deprecation
warnings remain; this follow-up did not repeat the earlier dependency audit.
