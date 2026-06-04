# Connector-authoring guide

Connectors are PhishBowl's community contribution surface. Enrichment is a
**layer, not a dependency**: the offline verdict is always computed first, and a
connector only ever *augments* it. With no API keys the offline experience is
unchanged.

This guide is complete and current — the interface is finalized (Phase 5). See
[`PRD.md` §9](PRD.md) for the design rationale and [`GLOSSARY.md`](GLOSSARY.md)
for terms (IOC, SSRF, RDAP, enrichment).

---

## Non-negotiable rules (enforced in code and tested)

A connector **must**:

1. **Reach only its vendor's documented API host(s).** It declares
   `allowed_hosts`, and the `EnrichContext.http` client physically refuses any
   other host — so a connector **cannot** be coerced into fetching a URL taken
   from the analyzed email. This is the SSRF guard, and it's load-bearing.
2. **Be key-gated and degrade gracefully.** Set `requires_api_key = True` and a
   missing key means the orchestrator *skips* you with a clear note. Raise a
   `ConnectorError` (or let an `httpx` error propagate) on failure → *soft-fail*
   with a note. A connector **never crashes the run**.
3. **Never leak secrets.** The API key arrives as `ctx.api_key` (read from env
   only). Never log it, never put it in an `EnrichmentResult` (references, raw,
   evidence). The orchestrator scrubs known key values from `raw` defensively,
   but the rule is: don't emit them.
4. **Let the orchestrator handle caching and rate limiting.** You just declare
   `cache_ttl` and `rate_limit_per_min`; results are cached on disk keyed by
   `(connector, ioc_type, value)`, requests are spaced, `429`/`503` are backed
   off, and a global concurrency cap is enforced — uniformly, for every connector.
5. **Return a normalized `EnrichmentResult`.** The scorer needs *no* per-vendor
   logic: it consumes the `EnrichmentSignal`s you emit.
6. **Emit `EnrichmentSignal`s whose `id` has a weight in the scoring YAML.** They
   are tagged `[enrichment]` everywhere, so a reader can always distinguish
   enrichment-derived points from offline heuristics — and an operator can tune
   (or disable, by setting the weight to `0`) each one without touching code.

> **urlscan is special.** Active submission causes the email's URL to be
> *visited* (on urlscan's infrastructure). It is strictly operator opt-in
> (`--urlscan-submit`), defaults to **private** visibility, and prefers passive
> search by *domain* (so a per-victim URL token never leaves). "Private" hides
> only the result page — the request to the host still happens. See
> [`PRD.md` §9](PRD.md).

---

## The interface

```python
from phishbowl.connectors import (
    Connector, EnrichContext, EnrichmentResult, EnrichmentSignal,
    EnrichmentVerdict, Indicator, register,
)
```

A connector subclasses `Connector`, sets declarative metadata, and implements one
coroutine:

| Attribute | Meaning |
|-----------|---------|
| `name` | Unique id. Also the cache namespace and (for key-gated connectors) the env-var lookup. |
| `version` | Connector version, surfaced in the report. |
| `supported_ioc_types` | Which of `ipv4`/`ipv6`/`domain`/`url`/`hash` you enrich. |
| `requires_api_key` | `True` → skipped (with a note) unless the key is set. |
| `allowed_hosts` | The only hosts your client may reach (the SSRF allowlist). |
| `base_url` | Your vendor's documented API base. |
| `cache_ttl` | Seconds a result stays fresh on disk. |
| `rate_limit_per_min` | Proactive request spacing for your free tier. |
| `max_indicators` | Cap on indicators enriched per run (protects quotas). |
| `follow_redirects` | Usually `False`; `True` only if the protocol requires it (RDAP). |

```python
async def enrich(self, indicator: Indicator, ctx: EnrichContext) -> EnrichmentResult: ...
```

- `indicator` — `.type` / `.value` / `.defanged` (use `.defanged` in evidence).
- `ctx.http` — the SSRF-guarded async client (`get`/`post`), bound to your
  `allowed_hosts`.
- `ctx.api_key` — your key (or `None`); present it however your vendor wants
  (header/param) and never log it.
- `ctx.now()` — the clock to compute ages against (testable).
- `ctx.settings` — run settings (e.g. `urlscan_visibility`, `urlscan_submit`).

### `EnrichmentResult` / `EnrichmentSignal`

```python
EnrichmentResult(
    connector=self.name,
    ioc_type=indicator.type,
    indicator=indicator.value,
    verdict=EnrichmentVerdict.MALICIOUS,        # at-a-glance label
    signals=(EnrichmentSignal(
        id="enrichment.myvendor.flagged",        # base weight lives in scoring YAML
        description="MyVendor flagged the indicator",
        magnitude=0.8,                           # 0..1 multiplier on the base weight
        evidence=f"MyVendor flagged {indicator.defanged}",  # already defanged
    ),),
    references=("https://myvendor.example/report/...",),  # defanged for display by the report
    raw={"score": 80},                            # retained, secret-free
)
```

The scorer's contribution for a signal is `base_weight(id) * magnitude`, summed
with the offline base and clamped to 0–100. Use `magnitude = 1.0` for a fixed
signal, or a ratio/confidence fraction for a scaled one.

---

## Discovery — two ways

**In-repo** (bundled connectors): decorate with `@register`.

```python
@register
class MyConnector(Connector):
    name = "myvendor"
    ...
```

**Third-party** (a pip package, no fork): advertise a `phishbowl.connectors`
entry-point. In your package's `pyproject.toml`:

```toml
[project.entry-points."phishbowl.connectors"]
myvendor = "my_package.connector:MyConnector"
```

`phishbowl.connectors.discover()` merges both. In-repo registrations win on a
name clash, and a broken third-party package is logged and skipped — never fatal.

---

## A worked example

A complete, passing connector against a hypothetical reputation API:

```python
from phishbowl.connectors import (
    Connector, EnrichContext, EnrichmentResult, EnrichmentSignal,
    EnrichmentVerdict, Indicator, register,
)
from phishbowl.connectors.errors import ConnectorError


@register
class AcmeRepConnector(Connector):
    name = "acmerep"
    version = "1.0.0"
    supported_ioc_types = frozenset({"domain"})
    requires_api_key = True
    allowed_hosts = frozenset({"api.acme-rep.example"})
    base_url = "https://api.acme-rep.example/v1"
    cache_ttl = 6 * 3600
    rate_limit_per_min = 60

    async def enrich(self, indicator: Indicator, ctx: EnrichContext) -> EnrichmentResult:
        resp = await ctx.http.get(
            f"{self.base_url}/domain/{indicator.value}",
            headers={"Authorization": f"Bearer {ctx.api_key or ''}"},
        )
        if resp.status_code == 404:
            return EnrichmentResult(self.name, indicator.type, indicator.value,
                                    verdict=EnrichmentVerdict.UNKNOWN)
        if resp.status_code != 200:
            raise ConnectorError(f"AcmeRep returned HTTP {resp.status_code}")

        score = int(resp.json().get("risk", 0))      # 0..100
        if score < 50:
            return EnrichmentResult(self.name, indicator.type, indicator.value,
                                    verdict=EnrichmentVerdict.BENIGN, raw={"risk": score})
        return EnrichmentResult(
            self.name, indicator.type, indicator.value,
            verdict=EnrichmentVerdict.MALICIOUS,
            signals=(EnrichmentSignal(
                id="enrichment.acmerep.risk",
                description="AcmeRep reports a high-risk domain",
                magnitude=min(1.0, score / 100.0),
                evidence=f"AcmeRep risk {score}/100 for {indicator.defanged}",
            ),),
            references=(f"https://acme-rep.example/lookup/{indicator.value}",),
            raw={"risk": score},
        )
```

Add a weight for its signal id to your scoring YAML (or the bundled
`defaults.yaml` for an in-repo connector):

```yaml
weights:
  enrichment.acmerep.risk: 20
```

### Testing it (mocked HTTP — no live calls)

```python
import httpx
from phishbowl.connectors import EnrichmentSettings, Indicator, run_enrichment

def handler(request):
    assert request.url.host == "api.acme-rep.example"   # SSRF guard already enforces this
    return httpx.Response(200, json={"risk": 90})

settings = EnrichmentSettings(
    enabled=True, transport=httpx.MockTransport(handler), cache_enabled=False,
    select=frozenset({"acmerep"}), api_keys={"acmerep": "test-key"},
)
report = run_enrichment([Indicator("domain", "evil.example", "evil[.]example")], settings)
status = report.status_for("acmerep")
assert status.results[0].signals[0].id == "enrichment.acmerep.risk"
```

`EnrichmentSettings` exposes test seams — `transport` (a mocked `httpx`
transport), `sleep` (a no-wait coroutine), `now` (a fixed clock), and `api_keys`
(inject keys without touching the environment) — so connectors are tested fully
offline.

---

## Planned / bundled connectors

| Connector | IOC types | API key | Notes |
|-----------|-----------|:-------:|-------|
| WHOIS / RDAP | domain | — | Domain age (< 30 days = strong signal); passive registry lookup. |
| VirusTotal | url · domain · hash | required | Passive reputation; detection ratio scales the weight. |
| AbuseIPDB | ip | required | Abuse confidence for the sending IP. |
| Shodan | ip | required | Exposed-service context for related IPs. |
| urlscan.io | url | required | Operator opt-in, **private** by default; prefers passive search. |

Their env-var names are in [`.env.example`](../.env.example). All read secrets
from the environment only.
