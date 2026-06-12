"""Tests for the enrichment layer (PRD §9 — Phase 5).

Enrichment is a *layer, not a dependency*: it augments the offline verdict and
can never gate it. These tests pin the load-bearing guarantees, all with **mocked
HTTP — no live calls ever leave the process**:

- the offline run is byte-for-byte unchanged with enrichment off, and unchanged
  in *score* when it is on but every connector is disabled/keyless-skipped;
- the on-disk cache short-circuits a second lookup (no second network call);
- a rate-limited vendor is backed off (honoring ``Retry-After``) and, if it never
  relents, soft-failed — never hung, never crashed;
- the SSRF guard refuses any host that isn't the connector's vendor, so an
  email-derived URL can never be fetched;
- API keys never appear in any output (HTML, JSON, CLI), even when a vendor
  echoes one back;
- graceful degrade end to end: missing key → skipped; network/API error →
  soft-fail; an unexpected connector bug → soft-fail; the run always completes;
- discovery works via both the in-repo registry and ``phishbowl.connectors``
  entry-points;
- each bundled connector normalizes a mocked vendor response into the right
  signal, defanged.

Crafted inputs use reserved example-only values (RFC 2606 / RFC 5737) and
obviously-fake markers — never a real sample (CLAUDE.md).
"""

from __future__ import annotations

import io
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from rich.console import Console

from phishbowl.connectors import (
    Connector,
    EnrichmentReport,
    EnrichmentResult,
    EnrichmentSettings,
    EnrichmentVerdict,
    Indicator,
    build_targets,
    discover,
    enrich_email,
    run_enrichment,
)
from phishbowl.connectors import registry as registry_mod
from phishbowl.connectors.base import ConnectorOutcome, EnrichmentSignal
from phishbowl.connectors.cache import EnrichmentCache
from phishbowl.connectors.errors import SSRFGuardError
from phishbowl.connectors.http import AllowlistedClient
from phishbowl.connectors.secrets import ENV_KEYS, scrub_secrets
from phishbowl.connectors.targets import sending_ips
from phishbowl.extract import extract_iocs
from phishbowl.parse import parse, parse_eml
from phishbowl.report import build_report, render_cli, render_html, render_json
from phishbowl.score import RuleSource, load_config, score_email

FIXTURES = Path(__file__).parent / "fixtures"
MALICIOUS = FIXTURES / "crafted_malicious.eml"
BENIGN = FIXTURES / "benign_newsletter.eml"

# A fixed clock so RDAP domain-age math is deterministic.
NOW = datetime(2026, 6, 4, tzinfo=UTC)


def _fixed_now() -> datetime:
    return NOW


async def _nosleep(_delay: float) -> None:
    """Drop-in for asyncio.sleep that never actually waits (deterministic tests)."""


def make_settings(handler, **overrides) -> EnrichmentSettings:
    """EnrichmentSettings wired to a mocked transport, no real sleeps, test keys."""
    params = dict(
        enabled=True,
        transport=httpx.MockTransport(handler),
        sleep=_nosleep,
        now=_fixed_now,
        cache_enabled=False,
        api_keys={
            "virustotal": "vt-test-key",
            "urlscan": "us-test-key",
            "abuseipdb": "ab-test-key",
            "shodan": "sh-test-key",
        },
    )
    params.update(overrides)
    return EnrichmentSettings(**params)


def run_one(name: str, indicator: Indicator, handler, **overrides):
    """Run a single connector over one indicator; return its ConnectorStatus."""
    settings = make_settings(handler, select=frozenset({name}), **overrides)
    report = run_enrichment([indicator], settings)
    return report.status_for(name)


# --- vendor response helpers ------------------------------------------------


def rdap_response(registered: str | None = "2026-05-30T00:00:00Z", *, status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        if status != 200:
            return httpx.Response(status)
        events = [{"eventAction": "registration", "eventDate": registered}] if registered else []
        return httpx.Response(200, json={"events": events})

    return handler


# --------------------------------------------------------------------------- #
# 1. Offline run is unchanged                                                  #
# --------------------------------------------------------------------------- #


def test_disabled_enrichment_is_a_noop_and_offline_is_identical() -> None:
    parsed = parse(MALICIOUS)
    iocs = extract_iocs(parsed)
    config = load_config()
    baseline = score_email(parsed, iocs, config)

    report = enrich_email(parsed, iocs, EnrichmentSettings(enabled=False))
    assert report.enabled is False
    assert report.statuses == ()

    rescored = score_email(parsed, iocs, config, enrichment=report)
    assert rescored.score == baseline.score
    assert rescored.fired == baseline.fired
    assert rescored.by_source(RuleSource.ENRICHMENT) == ()


def test_default_settings_keep_enrichment_off() -> None:
    # The safe default: no network, no connectors, ever — until explicitly enabled.
    parsed = parse(BENIGN)
    iocs = extract_iocs(parsed)
    report = enrich_email(parsed, iocs)  # no settings at all
    assert report.enabled is False


def test_enrich_with_no_keys_skips_gated_connectors_and_score_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for var in ENV_KEYS.values():
        monkeypatch.delenv(var, raising=False)
    parsed = parse(MALICIOUS)
    iocs = extract_iocs(parsed)
    config = load_config()
    baseline = score_email(parsed, iocs, config)

    # Enabled, but no keys at all. RDAP is keyless, so mock it to return nothing;
    # the four key-gated connectors must skip themselves with a clear note.
    settings = make_settings(rdap_response(registered=None), api_keys={}, cache_dir=tmp_path)
    report = enrich_email(parsed, iocs, settings)
    rescored = score_email(parsed, iocs, config, enrichment=report)

    assert rescored.score == baseline.score  # enrichment added nothing
    gated = {"virustotal", "urlscan", "abuseipdb", "shodan"}
    for name in gated:
        status = report.status_for(name)
        assert status is not None and status.outcome is ConnectorOutcome.SKIPPED
        assert "no API key" in status.note


# --------------------------------------------------------------------------- #
# 2. Cache-hit path                                                            #
# --------------------------------------------------------------------------- #


def test_cache_hit_avoids_a_second_network_call(tmp_path: Path) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(
            200,
            json={"events": [{"eventAction": "registration", "eventDate": "2026-05-30T00:00:00Z"}]},
        )

    target = Indicator("domain", "fresh-phish.example", "fresh-phish[.]example")
    settings = make_settings(
        handler, select=frozenset({"rdap"}), cache_enabled=True, cache_dir=tmp_path
    )

    first = run_enrichment([target], settings)
    assert calls["n"] == 1
    assert first.status_for("rdap").cache_hits == 0

    # Same indicator, same cache dir → served from disk, no new request.
    second = run_enrichment([target], settings)
    assert calls["n"] == 1  # unchanged: the network was not touched again
    status = second.status_for("rdap")
    assert status.cache_hits == 1
    assert status.outcome is ConnectorOutcome.USED
    assert status.results[0].cached is True
    # The cached result is equivalent: same young-domain signal.
    assert status.results[0].signals[0].id == "enrichment.rdap.young_domain"


def test_cache_respects_ttl(tmp_path: Path) -> None:
    clock = {"t": NOW}
    cache = EnrichmentCache(tmp_path, enabled=True, now=lambda: clock["t"])
    result = EnrichmentResult(
        connector="rdap",
        ioc_type="domain",
        indicator="d.example",
        verdict=EnrichmentVerdict.BENIGN,
    )
    cache.put(result)
    # Fresh immediately after storing...
    assert cache.get("rdap", "domain", "d.example", ttl=3600) is not None
    # ...stale once it ages past the TTL...
    clock["t"] = NOW + timedelta(hours=2)
    assert cache.get("rdap", "domain", "d.example", ttl=3600) is None
    # ...but still served under a longer TTL.
    assert cache.get("rdap", "domain", "d.example", ttl=24 * 3600) is not None
    # A different key misses.
    assert cache.get("rdap", "domain", "other.example", ttl=24 * 3600) is None


def test_cache_entries_are_private_to_the_operator(tmp_path: Path) -> None:
    # The cache holds the analyzed email's indicators; on a shared host another
    # local user must not be able to read which samples were triaged. The tree
    # we own is 0700 and each entry 0600.
    import stat

    cache = EnrichmentCache(tmp_path / "enrichment", enabled=True, now=_fixed_now)
    cache.put(
        EnrichmentResult(
            connector="rdap",
            ioc_type="domain",
            indicator="d.example",
            verdict=EnrichmentVerdict.BENIGN,
        )
    )

    entry = next((tmp_path / "enrichment").rglob("*.json"))
    assert stat.S_IMODE(entry.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "enrichment").stat().st_mode) == 0o700
    assert stat.S_IMODE(entry.parent.stat().st_mode) == 0o700


# --------------------------------------------------------------------------- #
# 3. Rate-limit / backoff path                                                 #
# --------------------------------------------------------------------------- #


def test_rate_limit_is_backed_off_then_succeeds(tmp_path: Path) -> None:
    calls = {"n": 0}
    sleeps: list[float] = []

    async def record_sleep(delay: float) -> None:
        sleeps.append(delay)

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "2"})
        return httpx.Response(
            200,
            json={"events": [{"eventAction": "registration", "eventDate": "2026-05-30T00:00:00Z"}]},
        )

    target = Indicator("domain", "rl.example", "rl[.]example")
    settings = make_settings(handler, select=frozenset({"rdap"}), sleep=record_sleep)
    report = run_enrichment([target], settings)

    assert calls["n"] == 2  # one 429, one success
    assert sleeps == [2.0]  # honored Retry-After exactly once
    assert report.status_for("rdap").outcome is ConnectorOutcome.USED


def test_persistent_rate_limit_soft_fails_after_exhausting_retries() -> None:
    sleeps: list[float] = []

    async def record_sleep(delay: float) -> None:
        sleeps.append(delay)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429)  # never relents

    target = Indicator("domain", "rl.example", "rl[.]example")
    settings = make_settings(handler, select=frozenset({"rdap"}), sleep=record_sleep, max_retries=3)
    report = run_enrichment([target], settings)

    status = report.status_for("rdap")
    assert status.outcome is ConnectorOutcome.FAILED
    assert "rate-limited" in status.note
    assert len(sleeps) == 3  # exhausted the retry budget, then gave up (no hang)


def test_backoff_uses_exponential_delays_without_retry_after() -> None:
    sleeps: list[float] = []

    async def record_sleep(delay: float) -> None:
        sleeps.append(delay)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)  # transient, no Retry-After header

    target = Indicator("domain", "x.example", "x[.]example")
    settings = make_settings(handler, select=frozenset({"rdap"}), sleep=record_sleep, max_retries=3)
    run_enrichment([target], settings)
    assert sleeps == [1.0, 2.0, 4.0]  # 2**0, 2**1, 2**2


# --------------------------------------------------------------------------- #
# 4. SSRF guard                                                                #
# --------------------------------------------------------------------------- #


def test_ssrf_guard_rejects_an_email_derived_url() -> None:
    # The load-bearing guarantee: a connector's client can reach ONLY its vendor.
    import asyncio

    transport = httpx.MockTransport(lambda r: httpx.Response(200, json={}))
    client = AllowlistedClient(allowed_hosts=frozenset({"www.virustotal.com"}), transport=transport)

    async def go() -> None:
        # A hostile, per-victim-tokened URL straight from the email is refused —
        # before any connection, and without leaking the token in the message.
        email_url = "https://login.evil-phish.example/account?token=victim-PII-9f3c"
        with pytest.raises(SSRFGuardError) as excinfo:
            await client.get(email_url)
        assert "victim-PII-9f3c" not in str(excinfo.value)
        assert "evil-phish.example" in str(excinfo.value)

        # An https URL whose host merely *resembles* the vendor is still refused
        # (proves it's a host allowlist, not a substring/scheme check).
        with pytest.raises(SSRFGuardError):
            await client.get("https://www.virustotal.com.evil.example/x")

        # Non-web schemes are refused outright.
        with pytest.raises(SSRFGuardError):
            await client.get("file:///etc/passwd")

        # An unparseable URL fails closed (never silently allowed out).
        with pytest.raises(SSRFGuardError):
            await client.get("https://[bad-ipv6")

        # The vendor's own API is allowed.
        ok = await client.get("https://www.virustotal.com/api/v3/domains/x")
        assert ok.status_code == 200
        await client.aclose()

    asyncio.run(go())


def test_redirect_to_non_allowlisted_host_is_blocked() -> None:
    # The allowlist must hold across the WHOLE redirect chain: httpx's internal
    # following would chase a 3xx without re-checking, so redirects are followed
    # hop-by-hop with the guard re-run on every target. A vendor 302 pointing at
    # a non-allowlisted host (here the cloud metadata endpoint) is refused
    # before any connection attempt.
    import asyncio

    seen_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.url.host)
        return httpx.Response(
            302, headers={"Location": "https://169.254.169.254/latest/meta-data/"}
        )

    client = AllowlistedClient(
        allowed_hosts=frozenset({"rdap.org"}),
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )

    async def go() -> None:
        with pytest.raises(SSRFGuardError) as excinfo:
            await client.get("https://rdap.org/domain/x.example")
        assert "169.254.169.254" in str(excinfo.value)
        await client.aclose()

    asyncio.run(go())
    # The hostile redirect target was never contacted.
    assert seen_hosts == ["rdap.org"]


def test_redirect_within_allowlist_is_followed() -> None:
    # Legitimate vendor chains (RDAP bootstrap → authoritative registry) still
    # work: every hop passes the guard, so the chain completes.
    import asyncio

    seen_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.url.host)
        if request.url.host == "rdap.org":
            return httpx.Response(
                302, headers={"Location": "https://rdap.verisign.com/com/v1/domain/x"}
            )
        return httpx.Response(200, json={"events": []})

    client = AllowlistedClient(
        allowed_hosts=frozenset({"rdap.org", "rdap.verisign.com"}),
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )

    async def go() -> None:
        response = await client.get("https://rdap.org/domain/x.example")
        assert response.status_code == 200
        await client.aclose()

    asyncio.run(go())
    assert seen_hosts == ["rdap.org", "rdap.verisign.com"]


def test_redirect_chain_past_cap_soft_fails() -> None:
    # An endless (even allowlisted) redirect loop is given up on with a clean
    # ConnectorError — a soft-fail note, never a hang or a crash.
    import asyncio

    from phishbowl.connectors.errors import ConnectorError
    from phishbowl.connectors.http import _MAX_REDIRECTS

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://rdap.org/loop"})

    client = AllowlistedClient(
        allowed_hosts=frozenset({"rdap.org"}),
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )

    async def go() -> None:
        with pytest.raises(ConnectorError):
            await client.get("https://rdap.org/domain/x.example")
        await client.aclose()

    asyncio.run(go())
    assert len(calls) == _MAX_REDIRECTS + 1


def test_rdap_bootstrap_redirect_to_registry_completes_the_lookup() -> None:
    # The real RDAP flow: rdap.org answers with a cross-host 302 to the
    # authoritative registry (off the static allowlist). With
    # bootstrap_redirect, that one vendor-designated https hop is followed and
    # the lookup completes — the regression a strict per-hop allowlist would
    # otherwise cause (every RDAP lookup soft-failing).
    seen_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.url.host)
        if request.url.host == "rdap.org":
            return httpx.Response(
                302,
                headers={"Location": f"https://rdap.registry.example{request.url.path}"},
            )
        return httpx.Response(
            200,
            json={"events": [{"eventAction": "registration", "eventDate": "2026-05-30T00:00:00Z"}]},
        )

    target = Indicator("domain", "fresh-phish.example", "fresh-phish[.]example")
    status = run_one("rdap", target, handler)

    assert seen_hosts == ["rdap.org", "rdap.registry.example"]
    assert status.outcome is ConnectorOutcome.USED
    assert status.results[0].signals[0].id == "enrichment.rdap.young_domain"


def test_bootstrap_designated_host_may_not_redirect_again() -> None:
    # The registry got its one request; a second hop (e.g. to the
    # registrant-chosen registrar's RDAP) is exactly the attacker-influenced
    # path the guard exists to block.
    seen_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.url.host)
        if request.url.host == "rdap.org":
            return httpx.Response(302, headers={"Location": "https://rdap.registry.example/d"})
        return httpx.Response(
            302, headers={"Location": "https://rdap.attacker-registrar.example/d"}
        )

    client = AllowlistedClient(
        allowed_hosts=frozenset({"rdap.org"}),
        transport=httpx.MockTransport(handler),
        bootstrap_redirect=True,
    )

    async def go() -> None:
        with pytest.raises(SSRFGuardError):
            await client.get("https://rdap.org/domain/x.example")
        await client.aclose()

    import asyncio

    asyncio.run(go())
    # The registrar host was never contacted.
    assert seen_hosts == ["rdap.org", "rdap.registry.example"]


def test_bootstrap_redirect_must_be_https() -> None:
    # A plaintext designated host would be MITM-able; refuse it outright.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "http://rdap.registry.example/d"})

    client = AllowlistedClient(
        allowed_hosts=frozenset({"rdap.org"}),
        transport=httpx.MockTransport(handler),
        bootstrap_redirect=True,
    )

    async def go() -> None:
        with pytest.raises(SSRFGuardError):
            await client.get("https://rdap.org/domain/x.example")
        await client.aclose()

    import asyncio

    asyncio.run(go())


def test_redirects_not_followed_unless_opted_in() -> None:
    # Connectors that don't declare follow_redirects get the 3xx back verbatim —
    # nothing is chased on their behalf.
    import asyncio

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://anywhere.example/"})

    client = AllowlistedClient(
        allowed_hosts=frozenset({"rdap.org"}),
        transport=httpx.MockTransport(handler),
    )

    async def go() -> None:
        response = await client.get("https://rdap.org/domain/x.example")
        assert response.status_code == 302
        await client.aclose()

    asyncio.run(go())


def test_connector_only_reaches_its_vendor_never_the_email_host() -> None:
    seen_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.url.host)
        return httpx.Response(200, json={"results": []})

    # Hand urlscan a hostile, tokened URL; it must only ever talk to urlscan.io,
    # querying by *domain* (so the per-victim token never leaves either).
    target = Indicator(
        "url",
        "https://attacker-host.example/p?token=victim-PII-123",
        "hxxps://attacker-host[.]example/p?token=victim-PII-123",
    )
    status = run_one("urlscan", target, handler)
    assert seen_hosts == ["urlscan.io"]
    assert status.outcome is ConnectorOutcome.USED


def test_a_connector_that_tries_to_fetch_the_email_url_is_blocked_and_soft_fails() -> None:
    # A (badly written) connector that naively fetches the indicator's own URL is
    # stopped by the guard, soft-failing rather than performing the fetch.
    blocked_hosts: list[str] = []

    class _NaiveConnector(Connector):
        name = "naive-test"
        supported_ioc_types = frozenset({"url"})
        requires_api_key = False
        allowed_hosts = frozenset({"api.naive.example"})

        async def enrich(self, indicator: Indicator, ctx) -> EnrichmentResult:
            await ctx.http.get(indicator.value)  # the email's URL — must be refused
            raise AssertionError("SSRF guard failed to block the email URL")

    def handler(request: httpx.Request) -> httpx.Response:
        blocked_hosts.append(request.url.host)
        return httpx.Response(200)

    target = Indicator("url", "https://evil.example/x", "hxxps://evil[.]example/x")
    settings = make_settings(handler)
    import asyncio

    from phishbowl.connectors.engine import _run_one_connector

    async def go():
        import asyncio as _asyncio

        return await _run_one_connector(
            _NaiveConnector(),
            [target],
            settings,
            EnrichmentCache(enabled=False),
            _asyncio.Semaphore(2),
            frozenset(),
        )

    status = asyncio.run(go())
    assert status.outcome is ConnectorOutcome.FAILED
    assert blocked_hosts == []  # the request never went out


# --------------------------------------------------------------------------- #
# 5. Secret hygiene                                                            #
# --------------------------------------------------------------------------- #

_SENTINEL = "phishbowl-enrich-secret-DEADBEEF-do-not-leak"


def _seed_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    for i, var in enumerate(ENV_KEYS.values()):
        monkeypatch.setenv(var, f"{_SENTINEL}-{i}")


def test_api_keys_never_leak_into_any_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _seed_keys(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "www.virustotal.com":
            return httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {"last_analysis_stats": {"malicious": 8, "harmless": 50}}
                    }
                },
            )
        if host == "api.abuseipdb.com":
            return httpx.Response(
                200, json={"data": {"abuseConfidenceScore": 95, "totalReports": 12}}
            )
        if host == "api.shodan.io":
            return httpx.Response(200, json={"ports": [3389]})
        if host == "urlscan.io":
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "result": "https://urlscan.io/result/x/",
                            "verdicts": {"overall": {"malicious": True, "score": 90}},
                        }
                    ]
                },
            )
        return httpx.Response(
            200,
            json={"events": [{"eventAction": "registration", "eventDate": "2026-05-30T00:00:00Z"}]},
        )

    parsed = parse(MALICIOUS)
    iocs = extract_iocs(parsed)
    config = load_config()
    # Read keys from the (seeded) environment — api_keys override left empty.
    settings = make_settings(handler, api_keys={}, cache_dir=tmp_path)
    report = enrich_email(parsed, iocs, settings)
    result = score_email(parsed, iocs, config, enrichment=report)
    view = build_report(parsed, iocs, result, config=config, enrichment=report)

    html = render_html(view)
    payload = render_json(view)
    buf = io.StringIO()
    render_cli(view, Console(file=buf, width=120, highlight=False))
    cli_out = buf.getvalue()

    for channel, text in (("html", html), ("json", payload), ("cli", cli_out)):
        assert _SENTINEL not in text, f"secret leaked into {channel}"
    # And enrichment really did run (so the assertions aren't vacuous).
    assert report.status_for("abuseipdb").outcome is ConnectorOutcome.USED


def test_api_keys_never_leak_into_cache_files_or_logs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # The path that actually handles the secret — connector request, scrub,
    # cache write, logging — must never persist or log it, even when the vendor
    # echoes the key back in its response body.
    import logging

    monkeypatch.setenv("SHODAN_API_KEY", _SENTINEL)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ports": [3389], "echoed_key": _SENTINEL})

    target = Indicator("ipv4", "8.8.8.8", "8[.]8[.]8[.]8")
    with caplog.at_level(logging.DEBUG):
        status = run_one(
            "shodan", target, handler, api_keys={}, cache_enabled=True, cache_dir=tmp_path
        )

    assert status.outcome is ConnectorOutcome.USED
    entries = list(tmp_path.rglob("*.json"))
    assert entries  # non-vacuous: a result really was cached
    for entry in entries:
        assert _SENTINEL not in entry.read_text(encoding="utf-8")
    assert _SENTINEL not in caplog.text


def test_connector_crash_log_never_carries_a_secret(caplog: pytest.LogCaptureFixture) -> None:
    # The last-resort crash log keeps the traceback for debuggability — but if a
    # buggy connector embeds its key in the exception message, the log is
    # scrubbed before it is emitted (PRD §11: secrets are never logged).
    import asyncio
    import logging

    from phishbowl.connectors.engine import _run_one_connector

    class _LeakyBoomConnector(Connector):
        name = "leaky-boom-test"
        supported_ioc_types = frozenset({"domain"})
        requires_api_key = False
        allowed_hosts = frozenset({"api.boom.example"})

        async def enrich(self, indicator: Indicator, ctx) -> EnrichmentResult:
            raise RuntimeError(f"request failed: key={_SENTINEL}")

    async def go():
        return await _run_one_connector(
            _LeakyBoomConnector(),
            [Indicator("domain", "d.example", "d[.]example")],
            make_settings(lambda r: httpx.Response(200)),
            EnrichmentCache(enabled=False),
            asyncio.Semaphore(2),
            frozenset({_SENTINEL}),
        )

    with caplog.at_level(logging.WARNING):
        status = asyncio.run(go())

    assert status.outcome is ConnectorOutcome.FAILED
    assert "RuntimeError" in caplog.text  # the traceback is retained…
    assert _SENTINEL not in caplog.text  # …but the key never is


def test_descendant_http_logger_records_are_scrubbed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Filters on a parent logger do NOT apply to records emitted through child
    # loggers (httpcore.http11, httpcore.connection, …) — each descendant gets
    # the filter, so a child trace carrying the key is scrubbed too.
    import logging

    from phishbowl.connectors.engine import _scrubbed_http_logs

    # Materialize a child logger the way httpcore does at import time.
    child = logging.getLogger("httpcore.http11")
    with caplog.at_level(logging.DEBUG):
        with _scrubbed_http_logs(frozenset({_SENTINEL})):
            child.debug("send_request_headers.started target=/host?key=%s", _SENTINEL)

    assert "send_request_headers" in caplog.text  # the trace itself survives…
    assert _SENTINEL not in caplog.text  # …the key does not


def test_scrub_secrets_strips_an_echoed_key() -> None:
    secrets = frozenset({_SENTINEL})
    raw = {"token": _SENTINEL, "nested": [f"prefix-{_SENTINEL}-suffix"], "safe": "ok"}
    cleaned = scrub_secrets(raw, secrets)
    assert _SENTINEL not in str(cleaned)
    assert cleaned["safe"] == "ok"
    assert cleaned["token"] == "[redacted]"


def test_orchestrator_scrubs_a_secret_a_vendor_echoes_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Even if a vendor reflected the key into its body and a connector retained
    # it raw, the orchestrator scrubs known key values out (defense in depth).
    monkeypatch.setenv("SHODAN_API_KEY", _SENTINEL)

    def handler(request: httpx.Request) -> httpx.Response:
        # Shodan stores `ports` in raw; smuggle the key in as if echoed.
        return httpx.Response(200, json={"ports": [3389], "echoed_key": _SENTINEL})

    target = Indicator("ipv4", "8.8.8.8", "8[.]8[.]8[.]8")
    status = run_one("shodan", target, handler, api_keys={})
    assert status.outcome is ConnectorOutcome.USED
    # Nothing the connector retained contains the secret.
    assert _SENTINEL not in str(status.results[0].raw)


# --------------------------------------------------------------------------- #
# 6. Graceful degrade                                                          #
# --------------------------------------------------------------------------- #


def test_network_error_soft_fails_without_crashing() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    target = Indicator("domain", "d.example", "d[.]example")
    status = run_one("rdap", target, handler)
    assert status.outcome is ConnectorOutcome.FAILED
    assert "network error" in status.note


def test_api_error_status_soft_fails() -> None:
    target = Indicator("domain", "d.example", "d[.]example")
    status = run_one("rdap", target, lambda r: httpx.Response(500))
    assert status.outcome is ConnectorOutcome.FAILED


def test_unexpected_connector_bug_is_contained() -> None:
    # A connector that raises something unexpected must be caught — the run
    # completes and the connector is marked failed, never propagating the error.
    class _BoomConnector(Connector):
        name = "boom-test"
        supported_ioc_types = frozenset({"domain"})
        requires_api_key = False
        allowed_hosts = frozenset({"api.boom.example"})

        async def enrich(self, indicator: Indicator, ctx) -> EnrichmentResult:
            raise ValueError("kaboom")

    import asyncio

    from phishbowl.connectors.engine import _run_one_connector

    async def go():
        return await _run_one_connector(
            _BoomConnector(),
            [Indicator("domain", "d.example", "d[.]example")],
            make_settings(lambda r: httpx.Response(200)),
            EnrichmentCache(enabled=False),
            asyncio.Semaphore(2),
            frozenset(),
        )

    status = asyncio.run(go())
    assert status.outcome is ConnectorOutcome.FAILED
    assert "unexpected" in status.note


def test_no_matching_indicators_is_skipped() -> None:
    # VirusTotal doesn't enrich raw IPs → nothing to do → skipped, not failed.
    status = run_one(
        "virustotal", Indicator("ipv4", "8.8.8.8", "8[.]8[.]8[.]8"), lambda r: httpx.Response(200)
    )
    assert status.outcome is ConnectorOutcome.SKIPPED
    assert "no matching indicators" in status.note


# --------------------------------------------------------------------------- #
# 7. Discovery: registry + entry-points                                        #
# --------------------------------------------------------------------------- #


def test_registry_discovers_all_bundled_connectors() -> None:
    classes = discover()
    assert {"rdap", "virustotal", "abuseipdb", "urlscan", "shodan"} <= set(classes)
    for cls in classes.values():
        assert issubclass(cls, Connector)
        assert cls.name


class _ThirdPartyConnector(Connector):
    name = "thirdparty-vendor"
    supported_ioc_types = frozenset({"domain"})
    requires_api_key = False
    allowed_hosts = frozenset({"api.thirdparty.example"})

    async def enrich(self, indicator: Indicator, ctx) -> EnrichmentResult:  # pragma: no cover
        return EnrichmentResult(self.name, indicator.type, indicator.value)


def test_entry_point_connector_is_discovered(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_ep = types.SimpleNamespace(name="thirdparty", load=lambda: _ThirdPartyConnector)
    monkeypatch.setattr(registry_mod, "_iter_entry_points", lambda: [fake_ep])
    classes = discover()
    # A pip-installed connector auto-registers without forking the repo.
    assert classes.get("thirdparty-vendor") is _ThirdPartyConnector
    # Built-ins are still present alongside it.
    assert "rdap" in classes


def test_broken_entry_point_is_skipped_not_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom():
        raise ImportError("third-party package is broken")

    bad_ep = types.SimpleNamespace(name="broken", load=_boom)
    monkeypatch.setattr(registry_mod, "_iter_entry_points", lambda: [bad_ep])
    classes = discover()  # must not raise
    assert "rdap" in classes  # discovery still yields the built-ins


def test_in_repo_registration_wins_over_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    # A third party can't shadow a bundled connector by squatting its name.
    class _FakeRdap(Connector):
        name = "rdap"
        supported_ioc_types = frozenset({"domain"})

        async def enrich(self, indicator, ctx):  # pragma: no cover
            return EnrichmentResult(self.name, indicator.type, indicator.value)

    fake_ep = types.SimpleNamespace(name="rdap", load=lambda: _FakeRdap)
    monkeypatch.setattr(registry_mod, "_iter_entry_points", lambda: [fake_ep])
    from phishbowl.connectors.builtin.rdap import RDAPConnector

    assert discover()["rdap"] is RDAPConnector


# --------------------------------------------------------------------------- #
# 8. Targets builder (incl. the sending IP)                                    #
# --------------------------------------------------------------------------- #


def test_sending_ips_picks_public_routing_ips_and_skips_internal() -> None:
    raw = (
        "Received: from mail.evil.example (mail.evil.example [8.8.8.8])\r\n"
        "\tby mx.example.org with ESMTP id ABC for <a@example.org>;\r\n"
        "\tWed, 03 Jun 2026 03:33:09 +0000\r\n"
        "Received: from internal (internal [10.0.0.5])\r\n"
        "\tby relay.example.org with ESMTP id DEF;\r\n"
        "\tWed, 03 Jun 2026 03:33:08 +0000\r\n"
        "From: a@example.com\r\nSubject: hi\r\n\r\nbody\r\n"
    )
    parsed = parse_eml(raw.encode("utf-8"), filename="hops.eml")
    ips = sending_ips(parsed)
    values = [i.value for i in ips]
    assert "8.8.8.8" in values  # public sender IP surfaced
    assert "10.0.0.5" not in values  # RFC 1918 internal topology omitted
    assert all(i.type == "ipv4" for i in ips)


def test_build_targets_unions_iocs_and_dedupes() -> None:
    parsed = parse(MALICIOUS)
    iocs = extract_iocs(parsed)
    targets = build_targets(parsed, iocs)
    keys = {(t.type, t.value) for t in targets}
    assert len(keys) == len(targets)  # de-duplicated
    types_present = {t.type for t in targets}
    assert "domain" in types_present and "url" in types_present
    # No email-address indicators are enriched (often recipient PII).
    assert "email" not in types_present


# --------------------------------------------------------------------------- #
# 9. Scorer integration: [enrichment] tags, aggregation, re-score             #
# --------------------------------------------------------------------------- #


def _report_with_signals(*signals: EnrichmentSignal) -> EnrichmentReport:
    from phishbowl.connectors.base import ConnectorStatus

    result = EnrichmentResult(
        connector="test",
        ioc_type="domain",
        indicator="d.example",
        verdict=EnrichmentVerdict.MALICIOUS,
        signals=tuple(signals),
    )
    status = ConnectorStatus(
        connector="test",
        version="1.0.0",
        outcome=ConnectorOutcome.USED,
        note="1 enriched",
        results=(result,),
    )
    return EnrichmentReport(enabled=True, statuses=(status,))


def test_enrichment_points_are_tagged_and_added_on_top() -> None:
    parsed = parse(BENIGN)
    iocs = extract_iocs(parsed)
    config = load_config()
    offline = score_email(parsed, iocs, config)

    report = _report_with_signals(
        EnrichmentSignal("enrichment.rdap.young_domain", "Young domain", 1.0, "registered 3d ago")
    )
    enriched = score_email(parsed, iocs, config, enrichment=report)

    assert enriched.offline_score == offline.score  # offline base untouched
    assert enriched.score > offline.score  # enrichment lifted the total
    fired = enriched.by_source(RuleSource.ENRICHMENT)
    assert [f.id for f in fired] == ["enrichment.rdap.young_domain"]
    assert fired[0].weight == config.weight("enrichment.rdap.young_domain")
    assert "[+18, enrichment]" in fired[0].reason


def test_same_signal_across_indicators_counts_once_at_max_magnitude() -> None:
    parsed = parse(BENIGN)
    iocs = extract_iocs(parsed)
    config = load_config()

    report = _report_with_signals(
        EnrichmentSignal("enrichment.virustotal.detections", "VT", 0.2, "5/25 on a.example"),
        EnrichmentSignal("enrichment.virustotal.detections", "VT", 0.6, "15/25 on b.example"),
    )
    enriched = score_email(parsed, iocs, config, enrichment=report)
    fired = enriched.by_source(RuleSource.ENRICHMENT)
    assert len(fired) == 1  # aggregated by id — no double-count
    # Weight uses the strongest magnitude (0.6), and both evidence lines are kept.
    assert fired[0].weight == pytest.approx(config.weight("enrichment.virustotal.detections") * 0.6)
    assert len(fired[0].evidence) == 2


def test_enrichment_weight_is_tunable_via_yaml() -> None:
    parsed = parse(BENIGN)
    iocs = extract_iocs(parsed)
    # Setting an enrichment weight to 0 disables that signal's contribution.
    config = load_config(overrides={"weights": {"enrichment.rdap.young_domain": 0}})
    report = _report_with_signals(
        EnrichmentSignal("enrichment.rdap.young_domain", "Young domain", 1.0, "registered 3d ago")
    )
    enriched = score_email(parsed, iocs, config, enrichment=report)
    young = [f for f in enriched.fired if f.id == "enrichment.rdap.young_domain"]
    assert young and young[0].weight == 0
    assert enriched.score == enriched.offline_score


# --------------------------------------------------------------------------- #
# 10. Per-connector normalization (mocked vendor responses)                    #
# --------------------------------------------------------------------------- #


def test_virustotal_flags_a_detected_domain() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "www.virustotal.com"
        assert request.headers.get("x-apikey")  # key travels as a header to VT only
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 12, "harmless": 60, "undetected": 18}
                    }
                }
            },
        )

    status = run_one("virustotal", Indicator("domain", "evil.example", "evil[.]example"), handler)
    signal = status.results[0].signals[0]
    assert signal.id == "enrichment.virustotal.detections"
    assert "12" in signal.evidence and "evil[.]example" in signal.evidence
    assert status.results[0].verdict is EnrichmentVerdict.MALICIOUS


def test_virustotal_unknown_indicator_produces_no_signal() -> None:
    status = run_one(
        "virustotal", Indicator("hash", "deadbeef", "deadbeef"), lambda r: httpx.Response(404)
    )
    assert status.outcome is ConnectorOutcome.USED  # queried fine
    assert status.results[0].signals == ()  # but VT had never seen it
    assert status.results[0].verdict is EnrichmentVerdict.UNKNOWN


def test_abuseipdb_fires_only_over_threshold() -> None:
    high = run_one(
        "abuseipdb",
        Indicator("ipv4", "8.8.8.8", "8[.]8[.]8[.]8"),
        lambda r: httpx.Response(
            200, json={"data": {"abuseConfidenceScore": 90, "totalReports": 7}}
        ),
    )
    assert high.results[0].signals[0].id == "enrichment.abuseipdb.confidence"
    assert high.results[0].signals[0].magnitude == pytest.approx(0.9)

    low = run_one(
        "abuseipdb",
        Indicator("ipv4", "8.8.8.8", "8[.]8[.]8[.]8"),
        lambda r: httpx.Response(
            200, json={"data": {"abuseConfidenceScore": 3, "totalReports": 1}}
        ),
    )
    assert low.results[0].signals == ()  # below the noise threshold


def test_rdap_flags_young_domain_and_clears_old_one() -> None:
    young = run_one(
        "rdap",
        Indicator("domain", "new.example", "new[.]example"),
        rdap_response("2026-05-30T00:00:00Z"),
    )
    assert young.results[0].signals[0].id == "enrichment.rdap.young_domain"

    old = run_one(
        "rdap",
        Indicator("domain", "old.example", "old[.]example"),
        rdap_response("1998-01-01T00:00:00Z"),
    )
    assert old.results[0].signals == ()
    assert old.results[0].verdict is EnrichmentVerdict.BENIGN


def test_shodan_flags_exposed_admin_services() -> None:
    status = run_one(
        "shodan",
        Indicator("ipv4", "8.8.8.8", "8[.]8[.]8[.]8"),
        lambda r: httpx.Response(200, json={"ports": [80, 3389, 22]}),
    )
    signal = status.results[0].signals[0]
    assert signal.id == "enrichment.shodan.exposed"
    assert "RDP" in signal.evidence and "SSH" in signal.evidence
    # A host exposing nothing notable doesn't fire.
    quiet = run_one(
        "shodan",
        Indicator("ipv4", "8.8.8.8", "8[.]8[.]8[.]8"),
        lambda r: httpx.Response(200, json={"ports": [80, 443]}),
    )
    assert quiet.results[0].signals == ()


def test_urlscan_passive_search_flags_known_malicious() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "urlscan.io"
        # It searches by domain, never submitting the full (tokened) URL.
        assert request.url.params.get("q", "").startswith("page.domain:")
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "result": "https://urlscan.io/result/abc/",
                        "verdicts": {"overall": {"malicious": True, "score": 100}},
                    }
                ]
            },
        )

    status = run_one(
        "urlscan",
        Indicator("url", "https://evil.example/a?t=1", "hxxps://evil[.]example/a?t=1"),
        handler,
    )
    assert status.results[0].signals[0].id == "enrichment.urlscan.malicious"
    assert status.results[0].verdict is EnrichmentVerdict.MALICIOUS


def test_urlscan_active_submission_is_private_by_default() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "urlscan.io"
        assert request.url.path.endswith("/scan/")
        import json as _json

        captured.update(_json.loads(request.content))
        return httpx.Response(200, json={"result": "https://urlscan.io/result/xyz/"})

    status = run_one(
        "urlscan",
        Indicator("url", "https://evil.example/a", "hxxps://evil[.]example/a"),
        handler,
        urlscan_submit=True,
    )
    assert captured["visibility"] == "private"  # never public by default (PRD §9)
    assert status.outcome is ConnectorOutcome.USED


# --------------------------------------------------------------------------- #
# 11. Report rendering with enrichment, end to end                             #
# --------------------------------------------------------------------------- #


def _enriched_view(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "www.virustotal.com":
            return httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {"last_analysis_stats": {"malicious": 30, "harmless": 40}}
                    }
                },
            )
        if host == "api.abuseipdb.com":
            return httpx.Response(
                200, json={"data": {"abuseConfidenceScore": 88, "totalReports": 20}}
            )
        if host == "api.shodan.io":
            return httpx.Response(200, json={"ports": [3389]})
        if host == "urlscan.io":
            return httpx.Response(200, json={"results": []})
        return httpx.Response(
            200,
            json={"events": [{"eventAction": "registration", "eventDate": "2026-05-29T00:00:00Z"}]},
        )

    parsed = parse(MALICIOUS)
    iocs = extract_iocs(parsed)
    config = load_config()
    report = enrich_email(parsed, iocs, make_settings(handler, cache_dir=tmp_path))
    result = score_email(parsed, iocs, config, enrichment=report)
    return build_report(parsed, iocs, result, config=config, enrichment=report), report


def test_html_shows_enrichment_and_stays_inert(tmp_path: Path) -> None:
    view, _ = _enriched_view(tmp_path)
    html = render_html(view)
    low = html.lower()
    assert "enrichment" in low
    # Same hard report invariants hold with enrichment present.
    assert "<script" not in low
    assert "http://" not in low and "https://" not in low  # references defanged
    assert "</html>" in low


def test_json_carries_enrichment_status_with_raw_references(tmp_path: Path) -> None:
    import json

    view, _ = _enriched_view(tmp_path)
    data = json.loads(render_json(view))
    assert data["enrichment"]["enabled"] is True
    connectors = {c["connector"]: c for c in data["enrichment"]["connectors"]}
    assert connectors["abuseipdb"]["outcome"] == "used"
    # Defanged display + clearly-labelled raw references, like the IOC tables.
    refs = connectors["abuseipdb"]["references"]
    raw_refs = connectors["abuseipdb"]["references_raw"]
    assert refs and "hxxps" in refs[0]
    assert raw_refs and raw_refs[0].startswith("https://")


def test_cli_summary_includes_enrichment_panel(tmp_path: Path) -> None:
    view, _ = _enriched_view(tmp_path)
    buf = io.StringIO()
    render_cli(view, Console(file=buf, width=120, highlight=False))
    out = buf.getvalue()
    assert "Enrichment" in out
    assert "abuseipdb" in out


def test_cli_enrich_flag_wires_enrichment_into_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    # Exercise the real CLI command with --enrich, but stub the network-touching
    # enrichment so the test stays fully offline. This pins the flag → enrich →
    # re-score → render wiring end to end.
    from typer.testing import CliRunner

    from phishbowl import cli
    from phishbowl.connectors.base import ConnectorStatus

    captured: dict = {}

    def fake_enrich(parsed, iocs, settings):
        captured["enabled"] = settings.enabled
        captured["submit"] = settings.urlscan_submit
        status = ConnectorStatus(
            connector="rdap",
            version="1.0.0",
            outcome=ConnectorOutcome.USED,
            note="1 indicator(s) enriched; 1 flagged",
            queried=1,
            results=(
                EnrichmentResult(
                    connector="rdap",
                    ioc_type="domain",
                    indicator="account-secure.example",
                    verdict=EnrichmentVerdict.SUSPICIOUS,
                    signals=(
                        EnrichmentSignal(
                            "enrichment.rdap.young_domain",
                            "Young domain",
                            1.0,
                            "RDAP: account-secure[.]example registered 4 day(s) ago",
                        ),
                    ),
                    references=("https://rdap.org/domain/account-secure.example",),
                ),
            ),
        )
        return EnrichmentReport(enabled=True, statuses=(status,))

    monkeypatch.setattr(cli, "enrich_email", fake_enrich)
    result = CliRunner().invoke(cli.app, ["analyze", str(MALICIOUS), "--enrich"])

    assert result.exit_code == 0, result.stdout
    assert captured == {"enabled": True, "submit": False}  # flag flowed into settings
    assert "Enrichment" in result.stdout
    assert "rdap" in result.stdout
    # The enrichment-derived point is shown and source-tagged.
    assert "enrichment" in result.stdout
