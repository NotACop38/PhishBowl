# Scoring configuration guide

PhishBowl's risk score is **transparent and tunable**: there's no model to
second-guess, and every number that produces a verdict lives in editable YAML.
This guide explains how scoring works and how to tune it to your environment.

See also: [`PRD.md` §8](PRD.md) (the scoring model) and the bundled defaults at
[`phishbowl/score/defaults.yaml`](../phishbowl/score/defaults.yaml).

---

## How the score works

1. **Detectors run** against the `ParsedEmail` + extracted IOCs. Each *rule* is
   `{id, description, weight, source, detector}`.
2. **Fired rules sum their weights.** The score is the **sum of the weights of
   every rule that fired**, then **clamped to 0–100** (clamped, not rescaled —
   so every point still traces to exactly one named rule).
3. **The score maps to a verdict band** (Benign → Malicious).
4. **Every fired rule emits a reason and its evidence**, tagged by `source`
   (`offline` vs `[enrichment]`).

A clean email fires nothing and scores **0**. No single rule — and no missing
enrichment connector — can zero out or dominate a verdict by itself.

```
score = clamp(0, 100, Σ weight(rule) for each fired rule)
verdict = first band where score <= band.max
```

---

## The config file

Everything tunable lives in [`phishbowl/score/defaults.yaml`](../phishbowl/score/defaults.yaml):

| Key | What it controls |
|-----|------------------|
| `weights` | Per-rule point values. Set a rule to `0` to effectively disable it. |
| `bands` | Score→verdict thresholds (low-to-high; last `max` must be `100`). |
| `freemail_domains` | Free webmail providers (fuels `identity.freemail_brand`). |
| `url_shorteners` | Link-shortener domains (`url.shortener`). |
| `credential_keywords` | Substrings in a URL path/query that suggest credential harvest. |
| `urgency_keywords` | Pressure phrases in subject/body (`content.urgency_keywords`). |
| `brands` | Brand keyword → its legitimate domains (fuels brand-mismatch + lookalike). |
| `org_domains` | **Your** domains, so impersonations of *you* trip `url.lookalike`. |

> **`defaults.yaml` is the bundled baseline.** Don't edit it for a deployment —
> layer an override on top (next section) so you can pull upstream updates
> cleanly.

---

## Overriding the defaults

Overrides are a **deep merge**: load the bundled defaults, then layer your file
and/or a dict on top. You only specify the keys you want to change. Resolution
order, lowest → highest precedence:

1. bundled `defaults.yaml`
2. the file at `$PHISHBOWL_SCORING_CONFIG` (if set)
3. an explicit `path=` argument to `load_config()`
4. an explicit `overrides=` dict argument to `load_config()`

### From the CLI

The CLI reads the `PHISHBOWL_SCORING_CONFIG` environment variable:

```bash
export PHISHBOWL_SCORING_CONFIG=/etc/phishbowl/scoring.yaml
phishbowl analyze suspicious.eml --html report.html
```

### From Python

```python
from phishbowl.score import load_config

# A site file layered over the bundled defaults…
config = load_config(path="scoring.yaml")

# …and/or a programmatic override dict (highest precedence):
config = load_config(overrides={"weights": {"content.urgency_keywords": 6}})
```

### Merge semantics (important)

- **Mappings merge key-by-key.** Setting one weight leaves all other weights at
  their defaults.
- **Lists and scalars replace wholesale.** If you set `url_shorteners`, you get
  *exactly* your list — not your list appended to the defaults. To extend a
  list, copy the default and add to it.

A minimal site override that bumps a weight, adds an org domain, and loosens a
band:

```yaml
# scoring.yaml — only the keys you change
weights:
  content.urgency_keywords: 6      # nudge urgency a little higher

org_domains:
  - acme-corp.com                   # catch typosquats of us
  - acme.io

bands:
  - {max: 14, verdict: "Benign — no strong indicators"}
  - {max: 39, verdict: "Low suspicion"}
  - {max: 64, verdict: "Suspicious — analyst review"}
  - {max: 84, verdict: "Likely malicious"}
  - {max: 100, verdict: "Malicious — high confidence"}
```

---

## Rule catalog (offline)

Default weights from [`defaults.yaml`](../phishbowl/score/defaults.yaml). All are
`source: offline`. Weights were calibrated against the synthetic fixtures in
`tests/fixtures/` — treat them as sane starting points and tune for your mail.

### Authentication

| Rule ID | Default | Fires when |
|---------|:------:|------------|
| `auth.spf_fail` | 15 | SPF check failed. |
| `auth.spf_softfail` | 8 | SPF soft-failed (`~all`). |
| `auth.dkim_fail` | 12 | DKIM signature verification failed. |
| `auth.dkim_none` | 5 | No DKIM signature present. |
| `auth.dmarc_fail` | 18 | DMARC failed — strongest single auth signal. |
| `auth.results_missing` | 8 | No `Authentication-Results` header at all. |

### Identity / spoofing

| Rule ID | Default | Fires when |
|---------|:------:|------------|
| `identity.display_name_brand_mismatch` | 20 | From display name claims a brand whose domain it doesn't own. |
| `identity.return_path_mismatch` | 10 | Return-Path domain ≠ From domain. |
| `identity.reply_to_mismatch` | 12 | Reply-To domain ≠ From domain. |
| `identity.sender_mismatch` | 8 | Envelope sender ≠ From. |
| `identity.freemail_brand` | 12 | Freemail From while display/body claims a company. |
| `identity.display_name_is_email` | 8 | The display name is itself an email address. |

### Domain / URL

| Rule ID | Default | Fires when |
|---------|:------:|------------|
| `url.punycode` | 12 | A `xn--` punycode domain is present. |
| `url.idn_homograph` | 18 | Mixed-script / confusable (homograph) domain. |
| `url.lookalike` | 18 | Domain is a near-miss (edit distance) of a brand/org domain. |
| `url.anchor_href_mismatch` | 16 | Link anchor text domain ≠ the actual href domain. |
| `url.raw_ip_host` | 12 | A URL uses a raw IP as its host. |
| `url.shortener` | 6 | A known URL shortener is present. |
| `url.credential_keywords` | 8 | Credential-harvest keywords in a URL path/query. |
| `url.wrapped_divergence` | 10 | An unwrapped link points somewhere different-looking. |

### Attachments

| Rule ID | Default | Fires when |
|---------|:------:|------------|
| `attach.macro_capable` | 14 | Macro-capable Office doc (`.docm`/`.xlsm`/…). |
| `attach.double_extension` | 22 | Double extension (`invoice.pdf.exe`). |
| `attach.type_mismatch` | 16 | Declared content-type ≠ detected magic bytes. |
| `attach.executable` | 22 | Executable / script / LNK / ISO / disk-image attachment. |
| `attach.password_protected_archive` | 14 | Password-protected archive. |

### Content (deliberately weak)

| Rule ID | Default | Fires when |
|---------|:------:|------------|
| `content.urgency_keywords` | 4 | Urgency / financial-pressure phrases. Low weight on purpose — high false-positive rate, so it only ever *nudges*. |

### Enrichment (opt-in, key-gated)

These fire only when you run with `--enrich` and the relevant API key is set.
Every one is tagged `[enrichment]` in all outputs and only ever **adds** on top
of the offline base — the offline verdict is always computed independently
(PRD §8 combination rule), so a zero-key run is unaffected. A signal marked
*scaled* multiplies its base weight by a `0..1` factor the connector computes.

| Rule ID | Default | Fires when |
|---------|:------:|------------|
| `enrichment.virustotal.detections` | 45 | VirusTotal engines flag the URL/domain/hash (*scaled* by detection ratio). |
| `enrichment.urlscan.malicious` | 20 | urlscan judged a prior scan of the host malicious. |
| `enrichment.abuseipdb.confidence` | 25 | AbuseIPDB abuse confidence over threshold for the sending IP (*scaled* by confidence). |
| `enrichment.rdap.young_domain` | 18 | Domain registered < 30 days ago — a strong phishing signal. |
| `enrichment.shodan.exposed` | 6 | Related IP exposes admin/remote-access services (contextual). |

Disable any of them — like any rule — by setting its weight to `0`. See the
[connector-authoring guide](CONNECTORS.md) to add your own.

---

## Verdict bands (default)

| Score | Verdict |
|------:|---------|
| 0–19 | Benign — no strong indicators |
| 20–39 | Low suspicion |
| 40–64 | Suspicious — analyst review |
| 65–84 | Likely malicious |
| 85–100 | Malicious — high confidence |

Bands must be listed low-to-high and the last `max` must be `100` (the first band
whose `max` the score is `<=` wins).

---

## Tuning tips

- **Add your own domains to `org_domains`** first — it's the single highest-value
  change, turning lookalike detection toward the impersonations that target *you*.
- **Prune the `brands` list** to the brands your users actually receive mail from.
  `example` is included only so the synthetic fixtures exercise the no-fire path —
  remove it in production.
- **Don't chase a single number.** Real phishing trips several rules; weights are
  designed so no single content signal can convict on its own.
- **Disable a rule** by setting its weight to `0` rather than deleting it — that
  keeps the merge predictable and the intent explicit.
- **Re-validate after tuning** with `make test`, and eyeball a couple of your own
  (synthetic!) samples to confirm the bands still feel right.
