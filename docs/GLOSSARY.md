# PhishBowl Glossary

Plain-English definitions for the terms PhishBowl uses in its reports, scoring
reasons, and docs. Aimed at a Tier-1 analyst (or a curious first-time user) — if
a term in a report sent you here, you should leave understanding it.

---

### IOC — Indicator of Compromise

A concrete, observable artifact that can identify malicious activity: a URL, a
domain, an IP address, a file hash, or an email address. PhishBowl extracts IOCs
from the message, **defangs** them, deduplicates them, and records the
*provenance* of each (which header or body part it came from). IOCs are the
currency of triage — they're what you pivot on, block, and hand to other tools.

### Defang

Rewriting an IOC so it can't be accidentally clicked, resolved, or executed when
it appears in a report, ticket, or chat — while staying human-readable.
PhishBowl defangs by default in all human-facing output:

| Original | Defanged |
|----------|----------|
| `https://evil.example/login` | `hxxps://evil[.]example/login` |
| `198.51.100.7` | `198[.]51[.]100[.]7` |
| `user@evil.example` | `user[at]evil[.]example` |
| `javascript:alert(1)` | `javascript[:]alert(1)` |

The JSON output carries both the defanged form (`value_display`) and the raw form
(`value_raw`) for tools. Defanging is a *display* convention — it does not change what
the indicator is, only how safe it is to look at.

### SPF — Sender Policy Framework

A DNS-published list of the mail servers allowed to send mail for a domain. The
receiving server checks whether the sending IP is on that list. Result states
PhishBowl reads from `Authentication-Results` / `Received-SPF`: `pass`, `fail`,
`softfail`, `neutral`, `none`, `temperror`, `permerror`. An SPF **fail** on a
message claiming to be from a real brand is a classic spoofing tell.

### DKIM — DomainKeys Identified Mail

A cryptographic signature added by the sending domain and verified by the
receiver against a public key in DNS. It proves the message wasn't altered in
transit and that the signing domain vouches for it. A DKIM **fail** (broken or
forged signature) or **none** (no signature at all) weakens the sender's
authenticity.

### DMARC — Domain-based Message Authentication, Reporting & Conformance

A policy layer built on SPF and DKIM. It requires that the domain in the visible
`From:` header *aligns* with an authenticated domain (from SPF or DKIM), and
tells receivers what to do when it doesn't (`p=none` / `quarantine` / `reject`).
A DMARC **fail** — especially with `p=reject` — is one of the strongest single
offline signals that a message is impersonating its claimed sender.

> **Why all three matter together:** SPF and DKIM each authenticate a *domain*;
> DMARC ties that authentication to the `From:` address the human actually sees.
> A spoofed brand email frequently fails all three at once.

### Authentication-Results

The header where a receiving mail server records the outcome of SPF, DKIM, and
DMARC checks (plus details like `header.from`, `smtp.mailfrom`, policy). Each server
that handles a message adds its own copy at the top, so the topmost copy is the one
your own mail system wrote; lower copies arrived with the message and can be forged.
PhishBowl therefore reads only the results from the topmost server (its
`authserv-id`) and notes any others it ignored. These are recorded *claims*:
PhishBowl does not re-check signatures or DNS itself. The header's **complete
absence** is a mild signal — most legitimate modern mail is authenticated.

### Received hop / routing path

Each mail server that handles a message stamps a `Received:` header as it passes
through. Read newest-to-oldest, these hops reconstruct the path the message took
(`from` / `by` / `with` / timestamp). Order and duplicates matter, so PhishBowl
preserves them. The routing path can expose an unexpected origin, but any hop below
your own servers' can be forged, so the sending IP PhishBowl highlights is a
candidate, not a verified origin.

### Safelinks (Microsoft Defender for Office 365)

A URL-rewriting protection: Microsoft replaces links in inbound mail with a
`*.safelinks.protection.outlook.com` wrapper that points back through Microsoft.
The real destination is encoded in the `url` query parameter. PhishBowl
**unwraps** Safelinks as a pure string transform — decoding that parameter to
reveal the true target — and **never by fetching the link**. It keeps both the
wrapped and unwrapped forms.

### URL Defense (Proofpoint) and other link wrappers

Proofpoint's equivalent link-rewriting protection (v1/v2/v3 encodings).
PhishBowl decodes v1–v3 offline to recover the original URL, again as a string
transform, retaining both forms. Barracuda wrappers carry the destination in a query
parameter and Cisco Secure Email wrappers at the end of the path; both are decoded
the same way. Mimecast wrappers are opaque
tokens that cannot be reversed offline: they are kept in wrapped form, marked
*"wrapped, unresolved,"* and the target domain is recorded when the wrapper names
it.

> A link that unwraps to a destination very different from how it looked is a
> meaningful signal — see `url.wrapped_divergence` in the
> [scoring guide](SCORING.md).

### Punycode / IDN homograph

**Punycode** (`xn--…`) is the ASCII encoding of an internationalized domain name
(IDN) that contains non-ASCII characters. Attackers exploit this for **homograph**
attacks: registering a domain using look-alike characters from other scripts
(e.g. a Cyrillic "а" in place of a Latin "a") so it reads like a trusted brand
but resolves somewhere else. PhishBowl decodes punycode, flags labels that mix
scripts outside Unicode TR39's highly restrictive profile, and flags non-ASCII
labels that fold to a known brand or org name once look-alike letters and accents
are normalized. Other punycode domains get the weaker punycode signal.

### Lookalike / typosquat

A domain that imitates a brand or one of your configured org domains without
using non-ASCII characters. PhishBowl recognizes three patterns: the same name
after folding ASCII look-alikes (`paypa1.com`, `micros0ft.com`), the name
hyphenated with a lure word (`paypal-secure.com`, known as combosquatting; a
brand's own `media-amazon.com` has no lure word and does not count), and a
near-miss spelling that keeps the first letter (`paypall.com`), measured as an
edit distance in which swapping two adjacent letters counts as one edit. Configure
your own domains in `org_domains` so impersonations of *you* are caught.

### Magic bytes

The signature at the start of a file that reveals its true type regardless of its
filename or declared content-type (e.g. `MZ` for a Windows executable, `PK` for a
ZIP/Office file). PhishBowl detects attachment types by magic bytes and flags a
**type mismatch** when the real type disagrees with the declared one — a common
malware trick (`invoice.pdf` that is actually an executable). Attachments are
**only ever inspected, never executed or extracted.**

### Double extension

A filename crafted to hide its real type: `invoice.pdf.exe` shows as a PDF if the
OS hides known extensions, but is an executable. A near-decisive structural red
flag on its own.

### Freemail

A free consumer webmail provider (gmail.com, outlook.com, yahoo.com, …). Normal
for individuals — but a message whose display name claims an organizational role
("IT Support", "Payroll", "Accounts Payable") while sending from a freemail address
is the classic business-email-compromise pattern.

### Provenance

For each extracted IOC, the record of *where* it came from — which header or body
part. Provenance lets an analyst judge weight (a URL in the `From` vs buried in a
quoted reply) and is shown alongside every indicator in the report.

### Verdict band and severity

The human-readable tier the numeric 0–100 score maps to. The defaults are *Few
signals — safety undetermined*, *Low suspicion*, *Suspicious — analyst review*,
*High suspicion*, and *Very high suspicion*. Bands are configurable in YAML; each
score also has a fixed **severity** name (`minimal`, `low`, `elevated`, `high`,
`critical`) for colors and automation. See [`SCORING.md`](SCORING.md).

### Incomplete analysis

When part of a message could not be analyzed (malformed structure, a part that
failed to parse, content beyond an analysis budget), PhishBowl says so rather than
presenting a partial result as whole: the verdict ends in *(incomplete analysis)*,
the gaps are listed under *Not analyzed*, and the score is a lower bound.
Informational notes that lose no evidence are listed separately.

### Enrichment

The optional layer that augments offline signals with external OSINT (VirusTotal,
urlscan, AbuseIPDB, Shodan, WHOIS/RDAP). It is **never a dependency**: the offline
verdict is always computed first, and enrichment-derived points are tagged
`[enrichment]` so you can always see what came from where.

### RDAP — Registration Data Access Protocol

The modern, structured, JSON-based successor to WHOIS for looking up domain and
IP registration data (registrar, creation date, contacts). PhishBowl's RDAP
connector uses it for **domain age** — a domain registered in the last 30 days is
a strong phishing signal. It queries the registered domain (`login.evil.example`
as `evil.example`) and is a *passive* lookup against the registry, never the
suspicious site.

### SOAR — Security Orchestration, Automation and Response

Platforms (e.g. Cortex XSOAR, Microsoft Sentinel) that automate incident
response with playbooks. PhishBowl can *export* its triage result as a playbook
**draft/artifact** for these systems (`--xsoar` / `--sentinel`; see
[`SOAR_EXPORT.md`](SOAR_EXPORT.md)) — but it never executes remediation itself:
the XSOAR draft is all manual tasks and the Sentinel draft ships disabled, so
importing one triggers no quarantine, no block, no action.

### SSRF — Server-Side Request Forgery

An attack where a service is tricked into making a request to an attacker-chosen
destination. For PhishBowl this is the connector threat model: a connector must
only ever reach **its own vendor's documented API**, and must **never** be
coerced into fetching a URL taken from the analyzed email. This guard is part of
the connector contract.

### PII redaction

An opt-in report mode (`--redact`) that withholds bystander data — every recipient
address with its display name and domain, hosts under your `org_domains`, non-public
IP addresses, and any headers you name with `--redact-field` — so a report can be
shared more safely. Values are replaced by typed placeholders such as
`[redacted:recipient]`. Attacker indicators stay in full. It removes known values;
it is not anonymization, so review free text before sharing.

### `ParsedEmail`

PhishBowl's single internal data contract (a Pydantic model). Both `.eml` and
`.msg` inputs normalize into it, so every stage after parsing — extraction,
scoring, reporting — is format-agnostic. See [`PRD.md` §7](PRD.md).
