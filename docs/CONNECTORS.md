# Connector guide

Connectors add OSINT context to PhishBowl's offline verdict. Enrichment is a layer, not
a dependency: the offline score is always computed first, connectors only add
`[enrichment]`-tagged points on top, and with no API keys nothing changes. This guide
covers the bundled connectors and how to write, register, and test your own.

For the design rationale see [`PRD.md` §9](PRD.md); for terms such as SSRF and RDAP, see
[`GLOSSARY.md`](GLOSSARY.md).

## Bundled connectors

| Name | Looks up | API host | Key variable | Cache | Rate | Per run |
|------|----------|----------|--------------|------:|-----:|--------:|
| `rdap` | Registered domains | `rdap.org`, then the registry it designates | none | 24 h | 30/min | 12 |
| `virustotal` | URLs, domains, file hashes | `www.virustotal.com` | `VIRUSTOTAL_API_KEY` | 6 h | 4/min | 12 |
| `urlscan` | URLs, searched by domain | `urlscan.io` | `URLSCAN_API_KEY` | 6 h | 60/min | 8 |
| `abuseipdb` | IPv4 and IPv6 addresses | `api.abuseipdb.com` | `ABUSEIPDB_API_KEY` | 6 h | 60/min | 8 |
| `shodan` | IPv4 and IPv6 addresses | `api.shodan.io` | `SHODAN_API_KEY` | 12 h | 60/min | 8 |

The signals each one contributes, and their weights, are listed in
[`SCORING.md`](SCORING.md#enrichment). VirusTotal's free tier allows four requests a
minute, so a first, uncached run over many indicators takes several minutes.

Run them with `--enrich`, choose with `--connector NAME` or skip with
`--disable-connector NAME` (both repeatable), and set keys in the environment as shown in
[`.env.example`](../.env.example).

### What is sent

Connectors receive indicators, never the message. The orchestrator builds the list:
public sending IPs from the `Received` chain first, then attachment SHA-256 hashes, then
the extracted URLs, domains, and IP addresses. It never sends:

- non-public IP addresses (private, loopback, link-local, reserved), in any notation;
- local host names (single-label names and `.localhost`, `.local`, `.internal`,
  `.home.arpa`) or anything that is not a valid DNS name;
- hosts under the operator's `org_domains`;
- domains that appear only in recipient headers;
- email addresses.

**urlscan.io** searches by domain by default, so a per-victim token in a URL never leaves.
`--urlscan-submit` makes it submit URLs for scanning instead: urlscan then visits the URL,
which can alert the attacker, and a token in the URL reaches a third party. Submissions
are private, but private only hides the result page. Submissions bypass the cache in
both directions.

**RDAP** queries the registered domain (`login.evil.example` is looked up as
`evil.example`). `rdap.org` answers with a redirect to the authoritative registry; that
one redirect may leave the allowlist, only over HTTPS, only to a public DNS name (never an
IP literal or a local name), and the registry gets exactly one request with no retries.
A further redirect from the registry is refused.

## Rules every connector follows

The orchestrator enforces most of these for you; the rest are your connector's contract.

1. **Reach only your vendor.** Declare `allowed_hosts`. The client in `ctx.http` refuses
   any other host, and any scheme but HTTPS, before connecting, and re-checks every
   redirect it follows. A connector therefore cannot be made to fetch a URL from the
   analyzed message (the SSRF guard).
2. **Degrade, never crash.** Raise `ConnectorError` (or let an `httpx` error propagate)
   when you cannot answer for an indicator. The orchestrator records a soft failure and
   moves on. Any other exception, including one raised while your class is constructed,
   fails your connector alone; the rest of the run continues.
3. **Treat responses as untrusted.** A vendor can return an error page, a truncated body,
   or JSON of the wrong shape. Use `json_object(response, "Vendor")`, which turns a
   non-JSON body or a non-object document into a `ConnectorError`, and read fields
   defensively. Missing data means an `UNKNOWN` verdict, never `BENIGN`.
4. **Never leak the key.** It arrives as `ctx.api_key`. Do not log it or put it in a
   result. The orchestrator also scrubs every known key from results, notes, the cache,
   and the HTTP libraries' logs, as a backstop.
5. **Leave caching and pacing to the orchestrator.** Declare `cache_ttl`,
   `rate_limit_per_min`, and `max_indicators`; it does the rest (see
   [What the orchestrator does](#what-the-orchestrator-does)).
6. **Return normalized results.** Emit `EnrichmentSignal`s whose IDs start with
   `enrichment.` and have a weight in the scoring YAML. The scorer needs no
   vendor-specific logic, and operators tune each signal like any other rule.
7. **Put defanged values in evidence.** Use `indicator.defanged` in any text a person
   reads.

## The interface

```python
from phishbowl.connectors import (
    Connector,
    ConnectorError,
    EnrichContext,
    EnrichmentResult,
    EnrichmentSignal,
    EnrichmentVerdict,
    Indicator,
    register,
)
from phishbowl.connectors.http import json_object
```

A connector subclasses `Connector`, declares its metadata as class attributes, and
implements one coroutine:

```python
async def enrich(self, indicator: Indicator, ctx: EnrichContext) -> EnrichmentResult: ...
```

| Attribute | Default | Meaning |
|-----------|---------|---------|
| `name` | *(required)* | Unique ID, used on the command line, in reports, and as the cache namespace. |
| `version` | `"0.1.0"` | Shown in reports and part of the cache key: a new version never reads results from an old one. |
| `supported_ioc_types` | empty | Any of `ipv4`, `ipv6`, `domain`, `url`, `hash`. |
| `requires_api_key` | `True` | Without a key the connector is skipped, with a note. |
| `api_key_env` | `""` | The environment variable the key is read from, e.g. `"ACMEREP_API_KEY"`. |
| `allowed_hosts` | empty | Hosts the client may reach (subdomains included). |
| `base_url` | `""` | The vendor's documented API base URL. |
| `cache_ttl` | `3600` | Seconds a cached result stays fresh. |
| `rate_limit_per_min` | `60` | Most requests per minute. |
| `max_indicators` | `16` | Most indicators queried per run (the run-wide setting, 16, also applies). |
| `follow_redirects` | `False` | Follow redirects within `allowed_hosts`, re-checking every hop. |
| `bootstrap_redirect` | `False` | RDAP-style bootstrap: one redirect may leave the allowlist, as described above. Implies `follow_redirects`. |

`prepare(indicator)` runs before caching and de-duplication. Return a different
`Indicator` to query another form of it (RDAP maps a host to its registered domain), or
`None` to skip it. The default returns the indicator unchanged.

Inside `enrich`:

- `indicator.type`, `indicator.value`, `indicator.defanged` describe what to look up.
- `ctx.http.get(url, ...)` and `ctx.http.post(url, ...)` accept the usual `httpx`
  arguments and return an `httpx.Response`.
- `ctx.api_key` is the key, or `None` for a keyless connector.
- `ctx.now()` is the clock to compute ages against (fixed in tests).
- `ctx.settings` holds the run settings, such as `urlscan_submit`.

A signal's contribution is `weight(id) × magnitude`, where `magnitude` is between 0 and
1: use `1.0` for a fixed signal, or a ratio or confidence for a scaled one. Out-of-range
and non-finite magnitudes are clamped, so enrichment can only ever add.

## A worked example

A connector for a hypothetical reputation service that returns `{"risk": 0-100}` for a
domain:

```python
from urllib.parse import quote

from phishbowl.connectors import (
    Connector,
    ConnectorError,
    EnrichContext,
    EnrichmentResult,
    EnrichmentSignal,
    EnrichmentVerdict,
    Indicator,
    register,
)
from phishbowl.connectors.http import json_object


@register
class AcmeRepConnector(Connector):
    name = "acmerep"
    version = "1.0.0"
    supported_ioc_types = frozenset({"domain"})
    requires_api_key = True
    api_key_env = "ACMEREP_API_KEY"
    allowed_hosts = frozenset({"api.acme-rep.example"})
    base_url = "https://api.acme-rep.example/v1"
    cache_ttl = 6 * 3600
    rate_limit_per_min = 60

    async def enrich(self, indicator: Indicator, ctx: EnrichContext) -> EnrichmentResult:
        # Indicator values come from a hostile message: quote them into one path segment.
        response = await ctx.http.get(
            f"{self.base_url}/domain/{quote(indicator.value, safe='')}",
            headers={"Authorization": f"Bearer {ctx.api_key}"},
        )
        if response.status_code == 404:
            return self._result(indicator, EnrichmentVerdict.UNKNOWN)
        if response.status_code != 200:
            raise ConnectorError(f"AcmeRep returned HTTP {response.status_code}")

        risk = json_object(response, "AcmeRep").get("risk")
        if isinstance(risk, bool) or not isinstance(risk, int) or not 0 <= risk <= 100:
            return self._result(indicator, EnrichmentVerdict.UNKNOWN)  # no usable answer
        if risk < 50:
            return self._result(indicator, EnrichmentVerdict.BENIGN, risk=risk)
        signal = EnrichmentSignal(
            id="enrichment.acmerep.risk",
            description="AcmeRep reports a high-risk domain",
            magnitude=risk / 100,
            evidence=f"AcmeRep risk {risk}/100 for {indicator.defanged}",
        )
        return self._result(indicator, EnrichmentVerdict.MALICIOUS, signal, risk=risk)

    def _result(self, indicator, verdict, signal=None, risk=None) -> EnrichmentResult:
        return EnrichmentResult(
            connector=self.name,
            ioc_type=indicator.type,
            indicator=indicator.value,
            verdict=verdict,
            signals=(signal,) if signal else (),
            references=(f"https://acme-rep.example/lookup/{quote(indicator.value, safe='')}",),
            raw={"risk": risk} if risk is not None else None,
        )
```

Give its signal a weight in your scoring override (or in `defaults.yaml`, for a connector
that lives in this repository):

```yaml
weights:
  enrichment.acmerep.risk: 20
```

A signal with no configured weight still appears in reports, at `+0`.

## Registering a connector

**In this repository:** decorate the class with `@register` and import its module from
`phishbowl/connectors/builtin/__init__.py`. Registration rejects a class without a
`name` or with an unimplemented `enrich`.

**As a separate package:** advertise it in the `phishbowl.connectors` entry-point group;
no fork and no decorator are needed.

```toml
# your package's pyproject.toml
[project.entry-points."phishbowl.connectors"]
acmerep = "acmerep_phishbowl.connector:AcmeRepConnector"
```

`phishbowl.connectors.discover()` merges both sources. A bundled connector wins a name
clash, and an entry point that fails to import or does not name a usable `Connector`
subclass is logged and skipped.

> [!WARNING]
> An installed connector is ordinary Python code running with PhishBowl's privileges.
> The HTTP allowlist governs the client PhishBowl hands it, not what the code could do
> otherwise. Install only connectors you trust, as you would any dependency.

## What the orchestrator does

For each selected connector, `run_enrichment` (and the pipeline's `enrich_email`):

- **Key-gates:** a connector that requires a key and has none is skipped with a note
  naming `api_key_env`.
- **Selects and bounds work:** it keeps the connector's supported types, applies
  `prepare`, removes duplicates, and queries at most `min(max_indicators, 16)`
  indicators, noting how many were left out.
- **Caches:** results are stored on disk per `(connector, version, type, value)`, in
  files readable only by the current user. An entry is used only while fresh, only if it
  is a regular file owned by the current user, and only if it records the exact key it
  was looked up by; anything else is a cache miss. Set `PHISHBOWL_CACHE_DIR` to move the
  cache.
- **Paces:** requests are spaced to `rate_limit_per_min`, measured when each request is
  sent; at most four requests are in flight across all connectors; `429` and `503`
  responses are retried with exponential backoff (honoring a finite `Retry-After`, capped
  at 30 seconds) up to three times.
- **Contains failures:** each connector runs in its own guard, and its outcome is
  reported as `used`, `skipped`, or `failed`, with a note.

`run_enrichment` is synchronous and safe to call from code that is already inside an
event loop (a notebook, an async web handler); `run_enrichment_async` is the coroutine.

## Testing without the network

`EnrichmentSettings` has seams for fully offline tests: `transport` (an
`httpx.MockTransport`), `sleep` (a coroutine that does not wait), `now` (a fixed clock),
`api_keys` (keys by connector name, instead of the environment), and `cache_enabled`.

```python
import httpx

from phishbowl.connectors import EnrichmentSettings, Indicator, run_enrichment


def handler(request: httpx.Request) -> httpx.Response:
    assert request.url.host == "api.acme-rep.example"
    return httpx.Response(200, json={"risk": 90})


settings = EnrichmentSettings(
    enabled=True,
    select=frozenset({"acmerep"}),
    transport=httpx.MockTransport(handler),
    cache_enabled=False,
    api_keys={"acmerep": "test-key"},
)
report = run_enrichment([Indicator("domain", "evil.example", "evil[.]example")], settings)
result = report.status_for("acmerep").results[0]
assert result.signals[0].id == "enrichment.acmerep.risk"
```

Test the unhappy paths too: a `404`, a `500`, a non-JSON body, and a JSON document with
missing or mistyped fields should each produce an `UNKNOWN` result or a soft failure,
never an exception and never a `BENIGN` verdict.
