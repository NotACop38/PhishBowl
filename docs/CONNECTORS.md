# Connector-authoring guide

> [!IMPORTANT]
> **Placeholder.** The connector interface is **not finalized yet** — it lands in
> **Phase 5** ([`CHECKLIST.md`](CHECKLIST.md)), and writing connector #1 is gated
> on the lead approving the `Connector` ABC first. This document captures the
> *intended* shape and the **non-negotiable rules** so contributors can follow
> along and plan. Treat code snippets below as illustrative, not final API.

Connectors are PhishBowl's community contribution surface. Enrichment is a
**layer, not a dependency**: the offline verdict is always computed first, and a
connector only ever *augments* it. With no API keys, the offline experience is
unchanged.

See [`PRD.md` §9](PRD.md) for the full design and [`GLOSSARY.md`](GLOSSARY.md)
for terms (IOC, SSRF, RDAP, enrichment).

---

## Non-negotiable rules (these will not change)

A connector **must**:

1. **Reach only its vendor's documented API base URL.** It must **never** be
   coerced into fetching a URL taken from the analyzed email. This is the SSRF
   guard, and it's load-bearing — PhishBowl never fetches the suspicious links.
2. **Be key-gated and degrade gracefully.** Missing key → the connector is
   *skipped* with a clear report note (e.g. *"VirusTotal: skipped, no API key"*).
   A network/API error → *soft-fail* with a note. A connector must **never crash
   the run**.
3. **Never leak secrets.** API keys come from env vars / gitignored config, are
   never logged, and never written into any report or JSON output.
4. **Own its rate limiting and caching.** Respect the vendor's documented
   free-tier limits with backoff; results are cached on disk keyed by
   `(connector, ioc_type, value)` with a per-connector TTL.
5. **Return a normalized result.** The scorer must need *no* per-vendor logic —
   the connector translates its raw response into a common `EnrichmentResult`.
6. **Tag its contributions `[enrichment]`** so a reader can always distinguish
   enrichment-derived points from offline heuristics.

> **urlscan is special.** Active submission causes the email's URL to be
> *visited* (on urlscan's infrastructure). It is therefore strictly operator
> opt-in, defaults to **private**, and should prefer passive lookups. "Private"
> hides only the result page — the request to the (possibly attacker-controlled)
> host still happens. See [`PRD.md` §9](PRD.md).

---

## Intended interface (subject to change)

```python
# ILLUSTRATIVE — the real ABC lands in Phase 5.
from phishbowl.connectors import Connector, EnrichmentResult, EnrichContext

class MyConnector(Connector):
    name = "myvendor"
    version = "0.1.0"
    supported_ioc_types = {"domain", "url"}   # of: ip | domain | url | hash | email
    requires_api_key = True

    async def enrich(self, indicator, ctx: EnrichContext) -> EnrichmentResult:
        # 1. ctx gives you the (allowlisted) HTTP client, config, and cache.
        # 2. Query ONLY your vendor's documented API base URL.
        # 3. Normalize the response into an EnrichmentResult.
        return EnrichmentResult(
            connector=self.name,
            verdict="malicious",                 # normalized
            signals=[("vt.detections", 8)],      # → scored, tagged [enrichment]
            references=["https://www.virustotal.com/..."],
            raw=...,                             # retained, secret-free
        )
```

**Discovery** will support both:

- an **in-repo registry** (a decorator) for connectors shipped in this repo, and
- Python **entry-points** under the `phishbowl.connectors` group, so a third
  party can `pip install` a connector package that auto-registers without forking.

---

## Planned connectors (Phase 5)

| Connector | IOC types | API key | Notes |
|-----------|-----------|:-------:|-------|
| WHOIS / RDAP | domain | — | Domain age (< 30 days = strong signal); passive registry lookup. |
| VirusTotal | url · domain · hash | required | Passive reputation; detection ratio scales the weight. |
| AbuseIPDB | ip | required | Abuse confidence for the sending IP. |
| Shodan | ip | required | Exposed-service context for related IPs. |
| urlscan.io | url | required | Operator opt-in, **private** by default; prefer passive search. |

---

## How to help before Phase 5

- Read [`PRD.md` §9](PRD.md) and open a discussion if a rule above is unclear or
  you think the interface needs a capability it doesn't yet describe.
- Sketch the normalization for a vendor you know well (what raw fields map to
  `verdict` / `signals` / `references`?) — that input shapes the final ABC.
- **Do not** start a real connector against this placeholder; wait for the ABC to
  be approved so your work isn't invalidated.

When the interface is finalized, this document will be replaced with a complete,
worked walkthrough (a connector from empty file to passing test).
