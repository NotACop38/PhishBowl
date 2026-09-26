# Scoring guide

PhishBowl's risk score is transparent and tunable. There is no model to second-guess:
the score is the sum of named rules, every rule records the evidence that made it fire,
and every number lives in editable YAML. This guide explains how the score is computed,
what each rule means, and how to tune it.

The bundled configuration is
[`phishbowl/score/defaults.yaml`](../phishbowl/score/defaults.yaml). The design
rationale is in [`PRD.md` §8](PRD.md).

## How the score is computed

1. **Rules run** against the parsed message and its extracted indicators. Each rule
   has an ID, a description, a weight, and a source (`offline` or `enrichment`).
2. **Fired rules add their weight once.** A rule triggered by several indicators still
   counts once and lists every piece of evidence. Related rules do not score the same
   fact twice: a homograph domain fires `url.idn_homograph`, not also `url.punycode`,
   and a lookalike check skips domains the homograph rules own.
3. **The total is clamped to 0–100**, with halves rounded up. Clamping, not rescaling,
   keeps the model additive: each point traces to one rule, and adding a rule never
   dilutes the others.
4. **The score selects a band**, which gives the verdict text and a severity name.

```text
offline_score = clamp(0, 100, Σ weight(rule) for each fired offline rule)
score         = clamp(0, 100, offline total + Σ weight(signal) × magnitude for each enrichment signal)
verdict       = the first band whose max is ≥ score
```

A message that fires nothing scores 0. That means "few signals", not "safe".

### Observe mode: weight 0

A rule whose weight is 0 still fires and still lists its evidence, at `+0`. This is how
you switch a noisy rule off without hiding what it saw. It applies to enrichment
signals too.

### Incomplete analysis

When some of a message's evidence could not be analyzed (a malformed MIME structure, a
part that failed to parse, a truncated text budget, an extraction timeout), the score is
a lower bound. The verdict gains the suffix `(incomplete analysis)`,
`analysis_complete` is `false`, and `phishbowl analyze` exits with status 3 unless a
`--fail-on` threshold was reached (status 1).

## Verdict bands and severity

| Score | Default verdict | Severity |
|------:|-----------------|----------|
| 0–19 | Few signals — safety undetermined | `minimal` |
| 20–39 | Low suspicion | `low` |
| 40–64 | Suspicious — analyst review | `elevated` |
| 65–84 | High suspicion | `high` |
| 85–100 | Very high suspicion | `critical` |

The verdict text and band limits come from `bands` in the configuration. The severity
name comes from the fixed limits above, whatever the bands say, so colors and
automation stay stable when an operator rewords or re-bands verdicts. `--fail-on`
accepts a severity name (`low`, `elevated`, `high`, `critical`) or a score from 0 to 100.

## Rule catalog

The defaults below are hand-set heuristics, checked against the synthetic fixtures in
`tests/fixtures/` and not calibrated against real mail. Treat them as starting points.

### Authentication claims

These read the results the receiving mail servers recorded in `Authentication-Results`
(and, for SPF only, `Received-SPF`). PhishBowl trusts only the results written by the
topmost receiving server, because lower headers arrive with the message and can be
forged; it does not re-verify signatures or DNS records.

| Rule ID | Weight | Fires when |
|---------|------:|------------|
| `auth.spf_fail` | 15 | SPF failed. |
| `auth.spf_softfail` | 8 | SPF soft-failed. |
| `auth.dkim_fail` | 12 | DKIM failed. When a message carries several signatures, the one aligned with the From domain is used. |
| `auth.dkim_none` | 5 | The message carries no DKIM signature. |
| `auth.dmarc_fail` | 18 | DMARC failed. |
| `auth.results_missing` | 8 | No `Authentication-Results` header at all. Not raised for an Outlook item without transport headers, which cannot carry one. |

### Sender identity

| Rule ID | Weight | Fires when |
|---------|------:|------------|
| `identity.display_name_brand_mismatch` | 20 | The From display name names a brand from `brands`, but the From domain is not one of that brand's domains. |
| `identity.multiple_from` | 20 | The message has more than one From header. Mail clients disagree on which to show. |
| `identity.reply_to_mismatch` | 12 | Reply-To is under a different registered domain than From. |
| `identity.freemail_role` | 12 | A sender on a free-webmail domain presents as an organizational role from `role_keywords` ("IT Support", "Payroll"). |
| `identity.return_path_mismatch` | 10 | Return-Path is under a different registered domain than From. |
| `identity.sender_mismatch` | 8 | Sender is under a different registered domain than From. |
| `identity.display_name_is_email` | 8 | The From display name contains an email address other than the actual sender. |

Domain comparisons use registered domains from the Public Suffix List (so
`bounce.example.com` matches `example.com`, but two tenants of a hosting platform such as
`github.io` do not), and compare Unicode and punycode spellings as equal.

### Links and domains

| Rule ID | Weight | Fires when |
|---------|------:|------------|
| `url.idn_homograph` | 18 | A domain label (decoded from punycode) mixes writing systems outside Unicode TR39's highly restrictive profile, or is non-ASCII and folds to a brand or `org_domains` name once look-alike letters and accents are normalized (`раypal` with Cyrillic letters). |
| `url.lookalike` | 18 | A sender-side, link, or other non-recipient domain imitates a brand or `org_domains` entry: the same name after folding lookalike characters (`paypa1`), the name hyphenated with a lure word such as "secure", "login", or "support" (`paypal-secure`, `account-amazon`; the configured credential and role keywords count as lures), or a near-miss spelling that keeps the first letter (one edit for names up to 8 characters, two for longer ones). Names shorter than 5 characters (`fb`, `me`, `live`, `bofa`) are too short to compare, and 5-character names are checked only for the first two patterns. For an org domain without a public suffix (`acme.local`), the name compared is `acme`. |
| `url.anchor_href_mismatch` | 16 | A link's visible text names a different domain than the one it points to. Text that reads as a file name (`README.md`, `invoice.zip`, or a name in the link's own path) is not taken for a domain unless written with a scheme or `www.`. |
| `url.punycode` | 12 | A punycode (`xn--`) domain is present that the homograph rule did not already score. |
| `url.raw_ip_host` | 12 | A URL uses an IP address as its host, in any notation a browser accepts (`http://3232235777/`). |
| `url.wrapped_divergence` | 10 | A protected link unwraps to a domain unrelated to the sender. |
| `url.credential_keywords` | 8 | A URL path or query contains a phrase from `credential_keywords`. |
| `url.shortener` | 6 | A link uses a domain from `url_shorteners`. |

### Attachments

Attachments are typed by their content (magic bytes and markup sniffing), never opened
by an external program, and never extracted.

| Rule ID | Weight | Fires when |
|---------|------:|------------|
| `attach.double_extension` | 22 | A filename hides its real type (`invoice.pdf.exe`), including with Unicode direction-override characters. |
| `attach.executable` | 22 | An executable, script, shortcut, disk image (ISO, IMG, VHD), OneNote notebook, or other directly dangerous type (`.chm`, `.hta`, `.xll`, `.msix`, …). |
| `attach.type_mismatch` | 16 | The declared content type or the extension contradicts the detected content. |
| `attach.macro_capable` | 14 | A macro-capable Office document (`.docm`, `.xlsm`, `.pptm`, `.ppsm`, `.xlsb`, legacy `.doc`/`.xls`, and similar). |
| `attach.password_protected_archive` | 14 | An encrypted archive, which scanners cannot inspect. Such an archive does not also fire `attach.archive`. |
| `attach.html` | 14 | An HTML or SVG document, which opens in a browser (credential forms, HTML smuggling). |
| `attach.archive` | 10 | Any other archive (ZIP, RAR, 7z, …). |

### Content

| Rule ID | Weight | Fires when |
|---------|------:|------------|
| `content.urgency_keywords` | 4 | The subject or body contains a phrase from `urgency_keywords`. Deliberately weak: pressure language is common in legitimate mail. |

### Enrichment

Enrichment signals exist only when you run with `--enrich` and the connector has what it
needs. They are tagged `[enrichment]` in every output, add to the offline score, and
never replace it. Scaled signals multiply the weight by a 0–1 magnitude the connector
computes.

| Signal ID | Weight | Fires when |
|-----------|------:|------------|
| `enrichment.virustotal.detections` | 45 | VirusTotal engines flagged the URL, domain, or file hash. Scaled by the share of engines that returned a verdict and flagged it; timeouts and unsupported types are not counted. |
| `enrichment.abuseipdb.confidence` | 25 | AbuseIPDB's abuse confidence for an IP is at least 25%. Scaled by the confidence. |
| `enrichment.urlscan.malicious` | 20 | urlscan.io judged a prior scan malicious: in full when the scan was of the same URL, at half when it was of another page on the host. |
| `enrichment.rdap.young_domain` | 18 | The registered domain is less than 30 days old. |
| `enrichment.shodan.exposed` | 6 | An IP exposes remote-access, file-sharing, or database services. Scaled by how many (one third each, up to three). |

Signals from several indicators with the same ID count once, at the strongest
magnitude, with every indicator's evidence listed. Third-party connectors define their
own `enrichment.*` IDs; see [`CONNECTORS.md`](CONNECTORS.md).

## Configuration

| Key | Type | Purpose |
|-----|------|---------|
| `weights` | mapping | Rule ID to weight, a number from 0 to 100. |
| `bands` | list | `{max, verdict}` entries: integer limits, unique, ending at 100. |
| `freemail_domains` | list | Free webmail providers, for `identity.freemail_role`. Recipient addresses on these domains are redacted without redacting the shared domain. |
| `url_shorteners` | list | Shortener domains, for `url.shortener`. |
| `credential_keywords` | list | Phrases matched in URL paths and queries. |
| `urgency_keywords` | list | Pressure phrases matched in the subject and body. |
| `role_keywords` | list | Organizational roles matched as whole words in display names. |
| `brands` | mapping | Brand keyword to the domains that legitimately belong to it. An empty list removes a bundled brand. |
| `org_domains` | list | Your own domains: lookalikes of them fire `url.lookalike`, hosts under them are redacted as internal by `--redact`, and they are never sent to enrichment services, as indicators or as URL hosts. |

Matching is case-insensitive throughout.

### Overriding the defaults

Overrides are deep-merged over the bundled defaults, so you specify only what you change.
Sources are applied in this order, later ones winning:

1. the bundled `defaults.yaml`;
2. the file named by `$PHISHBOWL_SCORING_CONFIG`;
3. the file passed with `--scoring-config` (or `load_config(path=...)`);
4. a dictionary passed as `load_config(overrides=...)`.

Mappings (`weights`, `brands`) merge key by key; lists and scalars replace the default
wholesale. To extend a list, copy the default list and add to it.

```yaml
# site-scoring.yaml
org_domains:
  - acme-corp.example            # your domains: lookalikes of these fire url.lookalike
weights:
  content.urgency_keywords: 0    # observe only
  url.shortener: 10
brands:
  chase: []                      # remove a brand that matches too many senders
  acme payroll: [acme-corp.example]
```

```bash
phishbowl analyze reported.eml --scoring-config site-scoring.yaml
```

```python
from phishbowl.score import load_config

config = load_config(path="site-scoring.yaml", overrides={"weights": {"url.shortener": 8}})
```

### Validation

A configuration error stops the run with a message that names the problem, instead of
silently changing verdicts:

- an unknown top-level key;
- an unknown rule ID under `weights`, reported with the closest valid ID (IDs starting
  with `enrichment.` are accepted, since connectors define them);
- a weight that is not a number from 0 to 100 (booleans are rejected);
- a band whose `max` is not an integer, duplicate or out-of-range limits, a last band
  that does not end at 100, or an empty verdict;
- a scalar where a list belongs, anything but a mapping for `weights` or `brands`
  (`weights: []` would otherwise zero every rule), an empty `weights:` or `brands:`
  key, or a file that is not valid YAML.

## Tuning advice

- **Set `org_domains` first.** It points lookalike detection at the impersonations that
  target you, keeps your domains out of enrichment queries, and lets `--redact` hide
  your internal hosts.
- **Prune `brands`** to the brands your users actually receive mail from. Keywords that
  are also common words or names ("chase", "apple") can match unrelated senders.
- **Observe before removing.** Set a noisy rule to 0 and watch its evidence for a while.
- **Judge the combination.** Real phishing fires several rules; no single content signal
  should decide a verdict.
- **Re-run the tests** (`make test`) after changing the bundled defaults, and check a few
  synthetic samples that resemble your mail.
