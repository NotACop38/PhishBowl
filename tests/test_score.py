"""Tests for the risk-scoring rule engine (PRD §8 — Phase 3).

Covers the Phase 3 definition of done:

- each offline detector from the §8 catalog **fires** on a crafted fixture and
  **stays silent** otherwise;
- the benign fixture scores low and a crafted-malicious fixture scores high;
- weights/bands are editable via YAML with a working override mechanism;
- the scorer is transparent: every fired rule cites evidence and a source, no
  signal is double-counted, and the offline verdict is always computed.

Crafted inputs are tiny synthetic ``.eml`` blobs or directly-built models, using
reserved example-only values (RFC 2606 / RFC 5737) and obviously-fake markers —
never a real sample (CLAUDE.md).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from phishbowl.extract import extract_iocs
from phishbowl.models import (
    IOC,
    Address,
    Addresses,
    Attachment,
    AttachmentFlag,
    EmailFormat,
    IOCs,
    IOCType,
    ParsedEmail,
    Source,
)
from phishbowl.parse import parse, parse_eml
from phishbowl.score import (
    OFFLINE_DETECTORS,
    RuleSource,
    ScoreResult,
    build_rules,
    load_config,
    score_email,
    verdict_for,
)

FIXTURES = Path(__file__).parent / "fixtures"


# --- helpers ---------------------------------------------------------------


def _score_fixture(name: str) -> ScoreResult:
    parsed = parse(FIXTURES / name)
    return score_email(parsed, extract_iocs(parsed))


def _score_raw(raw: str) -> ScoreResult:
    parsed = parse_eml(raw.encode("utf-8"), filename="crafted.eml")
    return score_email(parsed, extract_iocs(parsed))


def _fired(result: ScoreResult) -> set[str]:
    return {f.id for f in result.fired}


def _model_email(
    *,
    from_addr: Address | None = None,
    attachments: list[Attachment] | None = None,
) -> ParsedEmail:
    """A minimal directly-built ParsedEmail for detector unit tests."""
    return ParsedEmail(
        source=Source(format=EmailFormat.EML, parser_version="test"),
        addresses=Addresses(from_=from_addr),
        attachments=attachments or [],
    )


# A passing-auth header block so URL/identity probes aren't drowned out by the
# auth detectors (lets each test isolate the signal it's about).
_AUTH_PASS = (
    "Authentication-Results: mx.example.org;\r\n"
    "\tspf=pass smtp.mailfrom=example.com;\r\n"
    "\tdkim=pass header.d=example.com;\r\n"
    "\tdmarc=pass header.from=example.com\r\n"
)


def _html_eml(html_body: str, *, frm: str = '"Test" <test@example.com>') -> str:
    return (
        f"{_AUTH_PASS}"
        f"From: {frm}\r\n"
        "To: Analyst <analyst@example.org>\r\n"
        "Subject: neutral subject line\r\n"
        'Content-Type: text/html; charset="utf-8"\r\n'
        "\r\n"
        f"{html_body}\r\n"
    )


# --- config loading & override mechanism (PRD §8, §11) ---------------------


def test_default_config_loads_weights_and_bands() -> None:
    cfg = load_config()
    # Every catalog detector has a weight defined in the bundled YAML.
    for spec in OFFLINE_DETECTORS:
        assert spec.id in cfg.weights, f"missing weight for {spec.id}"
    # Bands are ordered low-to-high and saturate at 100 (PRD §8).
    assert [b.max for b in cfg.bands] == sorted(b.max for b in cfg.bands)
    assert cfg.bands[-1].max == 100
    # Starting weights track the PRD §8 catalog.
    assert cfg.weight("auth.dmarc_fail") == 18
    assert cfg.weight("content.urgency_keywords") == 4


def test_override_dict_changes_a_weight() -> None:
    base = load_config()
    overridden = load_config(overrides={"weights": {"auth.dmarc_fail": 99}})
    assert base.weight("auth.dmarc_fail") == 18
    assert overridden.weight("auth.dmarc_fail") == 99
    # Deep merge: untouched weights survive the override.
    assert overridden.weight("auth.spf_fail") == base.weight("auth.spf_fail")


def test_override_file_and_env_layer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    site = tmp_path / "site.yaml"
    site.write_text("weights:\n  auth.spf_fail: 1\n", encoding="utf-8")
    # An explicit path overrides the default...
    via_path = load_config(path=site)
    assert via_path.weight("auth.spf_fail") == 1

    # ...as does $PHISHBOWL_SCORING_CONFIG, and an explicit override dict wins last.
    monkeypatch.setenv("PHISHBOWL_SCORING_CONFIG", str(site))
    via_env = load_config()
    assert via_env.weight("auth.spf_fail") == 1
    precedence = load_config(overrides={"weights": {"auth.spf_fail": 7}})
    assert precedence.weight("auth.spf_fail") == 7


def test_org_domains_override_enables_lookalike() -> None:
    # With acme-corp.com configured as an org domain, a near-miss typosquat fires.
    cfg = load_config(overrides={"org_domains": ["acme-corp.com"]})
    res = score_email(
        *(_make := _prep("https://acme-c0rp.com/login")),
        config=cfg,
    )
    assert "url.lookalike" in _fired(res)


def _prep(url_in_body: str):
    raw = _html_eml(f'<p>see <a href="{url_in_body}">here</a></p>')
    parsed = parse_eml(raw.encode("utf-8"), filename="c.eml")
    return parsed, extract_iocs(parsed)


# --- authentication detectors (PRD §8) -------------------------------------


def test_spf_fail_fires_and_silent_on_pass() -> None:
    assert "auth.spf_fail" in _fired(_score_fixture("auth_fail_spoofed.eml"))
    assert "auth.spf_fail" not in _fired(_score_fixture("benign_newsletter.eml"))


def test_spf_softfail_fires() -> None:
    raw = (
        "Authentication-Results: mx.example.org; spf=softfail smtp.mailfrom=example.com\r\n"
        "From: A <a@example.com>\r\nSubject: hi\r\n\r\nbody\r\n"
    )
    fired = _fired(_score_raw(raw))
    assert "auth.spf_softfail" in fired
    assert "auth.spf_fail" not in fired


def test_dkim_fail_and_dmarc_fail_fire() -> None:
    fired = _fired(_score_fixture("auth_fail_spoofed.eml"))
    assert "auth.dkim_fail" in fired
    assert "auth.dmarc_fail" in fired


def test_dkim_none_fires_only_when_results_present() -> None:
    # wrapped_links has an Authentication-Results header with dkim=none.
    fired = _fired(_score_fixture("wrapped_links.eml"))
    assert "auth.dkim_none" in fired
    # ...and NOT the "results missing" rule (no double-count of the same gap).
    assert "auth.results_missing" not in fired
    # benign has dkim=pass -> neither fires.
    benign = _fired(_score_fixture("benign_newsletter.eml"))
    assert "auth.dkim_none" not in benign


def test_results_missing_fires_when_header_absent() -> None:
    raw = "From: A <a@example.com>\r\nSubject: hi\r\n\r\nbody\r\n"
    fired = _fired(_score_raw(raw))
    assert "auth.results_missing" in fired
    # With the header absent, dkim_none must NOT also fire (guarded).
    assert "auth.dkim_none" not in fired


def test_results_missing_silent_for_lossy_msg_format() -> None:
    # A .msg drops Authentication-Results (lossy, noted) — that's not a "missing
    # header" signal, so the rule must stay silent (the guard against penalizing
    # format lossiness).
    fired = _fired(_score_fixture("synthetic_phish.msg"))
    assert "auth.results_missing" not in fired


# --- identity / spoofing detectors (PRD §8) --------------------------------


def test_address_mismatches_fire_on_spoof_silent_on_benign() -> None:
    spoof = _fired(_score_fixture("auth_fail_spoofed.eml"))
    assert {
        "identity.return_path_mismatch",
        "identity.reply_to_mismatch",
        "identity.sender_mismatch",
    } <= spoof
    benign = _fired(_score_fixture("benign_newsletter.eml"))
    assert "identity.return_path_mismatch" not in benign
    assert "identity.reply_to_mismatch" not in benign
    assert "identity.sender_mismatch" not in benign


def test_display_name_brand_mismatch_fires_and_respects_legit_domain() -> None:
    spoof = _score_raw(
        'From: "Microsoft Account Team" <security@evil.example>\r\nSubject: hi\r\n\r\nbody\r\n'
    )
    assert "identity.display_name_brand_mismatch" in _fired(spoof)
    # A brand display name whose From domain (or a subdomain of it) owns the
    # brand must NOT fire.
    legit = _score_raw(
        'From: "Microsoft Account Team" <account@accountprotection.microsoft.com>\r\n'
        "Subject: hi\r\n\r\nbody\r\n"
    )
    assert "identity.display_name_brand_mismatch" not in _fired(legit)
    assert "identity.display_name_brand_mismatch" not in _fired(
        _score_fixture("benign_newsletter.eml")
    )


def test_display_name_brand_mismatch_catches_brand_stuffing() -> None:
    # A sender that legitimately owns ONE claimed brand must not be able to mask a
    # second, unowned brand stuffed into the same display name.
    stuffed = _score_raw(
        'From: "PayPal Apple Support" <service@paypal.com>\r\nSubject: hi\r\n\r\nbody\r\n'
    )
    fired = [f for f in stuffed.fired if f.id == "identity.display_name_brand_mismatch"]
    assert fired, "brand stuffing slipped past the detector"
    # It fires for the unowned brand (apple), not the legitimately-owned one
    # (paypal, which only appears as the From domain, never as a claimed brand).
    evidence = " ".join(fired[0].evidence).lower()
    assert 'claims "apple"' in evidence
    assert 'claims "paypal"' not in evidence
    # A sender claiming only the brand it owns stays silent.
    legit = _score_raw('From: "PayPal" <service@paypal.com>\r\nSubject: hi\r\n\r\nbody\r\n')
    assert "identity.display_name_brand_mismatch" not in _fired(legit)


def test_freemail_role_fires_for_organizational_claims() -> None:
    raw = 'From: "IT Support Desk" <it.helpdesk.team@gmail.com>\r\nSubject: hi\r\n\r\nbody\r\n'
    fired = {f.id: f for f in _score_raw(raw).fired}
    assert "identity.freemail_role" in fired
    assert "(support)" in fired["identity.freemail_role"].evidence[0]
    # A personal gmail with no organizational claim does not fire.
    plain = 'From: "Jordan Lee" <jordan.lee@gmail.com>\r\nSubject: hi\r\n\r\nbody\r\n'
    assert "identity.freemail_role" not in _fired(_score_raw(plain))


def test_freemail_brand_claim_is_counted_once() -> None:
    # "PayPal Support" from gmail is one fact — a brand the sender does not own —
    # so only the brand-mismatch rule scores it.
    raw = 'From: "PayPal Support" <paypalhelp@gmail.com>\r\nSubject: hi\r\n\r\nbody\r\n'
    fired = _fired(_score_raw(raw))
    assert "identity.display_name_brand_mismatch" in fired
    assert "identity.freemail_role" not in fired


def test_display_name_is_email_fires() -> None:
    raw = 'From: "security@example.com" <attacker@evil.example>\r\nSubject: hi\r\n\r\nbody\r\n'
    assert "identity.display_name_is_email" in _fired(_score_raw(raw))
    assert "identity.display_name_is_email" not in _fired(_score_fixture("benign_newsletter.eml"))


# --- domain / URL detectors (PRD §8) ---------------------------------------


def test_punycode_fires() -> None:
    res = _score_raw(_html_eml('<a href="http://xn--mple-0na.com/">x</a>'))
    assert "url.punycode" in _fired(res)
    assert "url.punycode" not in _fired(_score_fixture("benign_newsletter.eml"))


def test_idn_homograph_fires_on_mixed_script() -> None:
    # 'pаypal' uses a Cyrillic 'а' (U+0430) among Latin letters.
    res = _score_raw(_html_eml('<a href="https://pаypal.com/">x</a>'))
    fired = _fired(res)
    assert "url.idn_homograph" in fired
    # Mixed-script owns this domain; lookalike must not also claim it.
    assert "url.lookalike" not in fired
    assert "url.idn_homograph" not in _fired(_score_fixture("benign_newsletter.eml"))


@pytest.mark.parametrize(
    ("host", "reason"),
    [
        ("paypa1.com", "confusable characters"),  # digit one for "l"
        ("arnazon.com", "confusable characters"),  # "rn" reads as "m"
        ("login.rnicrosoft.net", "confusable characters"),
        ("paypal-secure.net", 'embeds the name "paypal"'),  # combosquatting
        ("login.secure-paypa1-verify.com", 'embeds the name "paypal"'),
        ("mircosoft.com", "edit distance 1"),  # transposed letters
        ("docusing.com", "edit distance 1"),
    ],
)
def test_lookalike_fires_on_brand_imitations(host: str, reason: str) -> None:
    res = _score_raw(_html_eml(f'<a href="https://{host}/">x</a>'))
    fired = {f.id: f for f in res.fired}
    assert "url.lookalike" in fired
    assert reason in fired["url.lookalike"].evidence[0]


@pytest.mark.parametrize(
    "host",
    [
        "paypal.com",  # the brand itself
        "www.paypal.com",  # a subdomain of the brand
        "amazon.ca",  # same name under another suffix: a variant, not a typo
        "life.com",  # "live" is too short a label to compare
        "ymail.com",  # a known freemail provider, not an imitation of gmail
        "email.com",  # different first letter from "gmail"
        "amazing.com",  # two edits from a six-letter brand
        "example.com",
    ],
)
def test_lookalike_stays_silent_on_legitimate_neighbours(host: str) -> None:
    res = _score_raw(_html_eml(f'<a href="https://{host}/">x</a>'))
    assert "url.lookalike" not in _fired(res)


def test_anchor_href_mismatch_fires() -> None:
    res = _score_raw(_html_eml('<a href="http://evil.example/go">www.paypal.com</a>'))
    assert "url.anchor_href_mismatch" in _fired(res)
    # benign anchor text/href agree (both example.com) -> silent.
    assert "url.anchor_href_mismatch" not in _fired(_score_fixture("benign_newsletter.eml"))


def test_anchor_mismatch_does_not_double_count_raw_ip_href() -> None:
    # A disguised link to a raw IP (text shows a domain) is owned by
    # url.raw_ip_host; the anchor-mismatch rule must NOT also fire on it.
    res = _score_raw(_html_eml('<a href="http://198.51.100.23/login">www.paypal.com</a>'))
    fired = _fired(res)
    assert "url.raw_ip_host" in fired
    assert "url.anchor_href_mismatch" not in fired


def test_raw_ip_host_fires() -> None:
    res = _score_raw(_html_eml('<a href="http://198.51.100.23/payload">x</a>'))
    assert "url.raw_ip_host" in _fired(res)
    assert "url.raw_ip_host" not in _fired(_score_fixture("benign_newsletter.eml"))


def test_shortener_fires() -> None:
    res = _score_raw(_html_eml('<a href="https://bit.ly/abc123">x</a>'))
    assert "url.shortener" in _fired(res)
    assert "url.shortener" not in _fired(_score_fixture("benign_newsletter.eml"))


def test_credential_keywords_fire() -> None:
    res = _score_raw(_html_eml('<a href="https://portal.example/secure/login">x</a>'))
    assert "url.credential_keywords" in _fired(res)
    assert "url.credential_keywords" not in _fired(_score_fixture("benign_newsletter.eml"))


def test_credential_keywords_skips_malformed_url_without_crashing() -> None:
    # A malformed URL IOC (invalid bracketed host) must not crash scoring — the
    # detector degrades gracefully and just skips it (PRD §11). We feed the IOC
    # directly since such a URL would otherwise be rejected upstream.
    bad = IOC(
        type=IOCType.URL,
        value="http://[bad]/secure/login",
        defanged="hxxp://[bad]/secure/login",
    )
    parsed = _model_email(from_addr=Address(addr_spec="a@example.com", domain="example.com"))
    res = score_email(parsed, IOCs(items=[bad]))  # must not raise
    assert isinstance(res.score, int)
    assert "url.credential_keywords" not in _fired(res)


def test_wrapped_divergence_fires() -> None:
    # wrapped_links unwraps a Proofpoint link to a domain unrelated to the sender.
    assert "url.wrapped_divergence" in _fired(_score_fixture("wrapped_links.eml"))
    assert "url.wrapped_divergence" not in _fired(_score_fixture("benign_newsletter.eml"))


# --- attachment detectors (PRD §8) -----------------------------------------


def _att(filename: str, *flags: AttachmentFlag) -> Attachment:
    return Attachment(filename=filename, flags=list(flags))


@pytest.mark.parametrize(
    ("rule_id", "flag", "filename"),
    [
        ("attach.macro_capable", AttachmentFlag.MACRO_CAPABLE, "budget.xls"),
        ("attach.double_extension", AttachmentFlag.DOUBLE_EXTENSION, "invoice.pdf.exe"),
        ("attach.type_mismatch", AttachmentFlag.TYPE_MISMATCH, "invoice.pdf"),
        ("attach.executable", AttachmentFlag.EXECUTABLE, "setup.exe"),
        ("attach.password_protected_archive", AttachmentFlag.PASSWORD_PROTECTED, "docs.zip"),
        ("attach.archive", AttachmentFlag.ARCHIVE, "invoice.zip"),
    ],
)
def test_attachment_detectors_fire_on_flag(
    rule_id: str, flag: AttachmentFlag, filename: str
) -> None:
    parsed = _model_email(attachments=[_att(filename, flag)])
    fired = _fired(score_email(parsed, IOCs()))
    assert rule_id in fired
    # A clean attachment (no flags) fires no attachment rule.
    clean = _model_email(attachments=[_att("report.pdf")])
    assert rule_id not in _fired(score_email(clean, IOCs()))


# --- weak content detector (PRD §8) ----------------------------------------


def test_urgency_keywords_fire_at_low_weight() -> None:
    res = _score_fixture("auth_fail_spoofed.eml")
    fired = [f for f in res.fired if f.id == "content.urgency_keywords"]
    assert fired and fired[0].weight == 4  # deliberately low (PRD §8)
    assert "content.urgency_keywords" not in _fired(_score_fixture("benign_newsletter.eml"))


# --- calibration & verdict bands (PRD §8) ----------------------------------


def test_benign_fixture_scores_low() -> None:
    res = _score_fixture("benign_newsletter.eml")
    assert res.score == 0
    assert res.verdict.startswith("Few signals")
    assert res.fired == ()


def test_spoofed_fixture_scores_high() -> None:
    res = _score_fixture("auth_fail_spoofed.eml")
    assert res.score >= 65
    assert res.verdict in {"High suspicion", "Very high suspicion"}


def test_crafted_malicious_fixture_scores_high() -> None:
    res = _score_fixture("crafted_malicious.eml")
    assert res.score >= 85
    assert res.verdict == "Very high suspicion"
    # It exercises a broad spread of the catalog, not one lucky rule.
    assert len(res.fired) >= 8


def test_verdict_bands_cover_the_range() -> None:
    cfg = load_config()
    assert verdict_for(0, cfg).startswith("Few signals")
    assert verdict_for(19, cfg).startswith("Few signals")
    assert verdict_for(20, cfg) == "Low suspicion"
    assert verdict_for(50, cfg).startswith("Suspicious")
    assert verdict_for(70, cfg) == "High suspicion"
    assert verdict_for(100, cfg).startswith("Very high suspicion")


def test_score_is_clamped_to_100() -> None:
    res = _score_fixture("crafted_malicious.eml")
    assert 0 <= res.score <= 100


# --- engine invariants (PRD §8) --------------------------------------------


def test_no_double_counting_each_rule_counts_once() -> None:
    # The crafted-malicious URLs trip several URL rules across multiple links;
    # the total must equal the sum of DISTINCT fired-rule weights (each once).
    res = _score_fixture("crafted_malicious.eml")
    ids = [f.id for f in res.fired]
    assert len(ids) == len(set(ids)), "a rule fired more than once"
    raw_sum = sum(f.weight for f in res.fired)
    assert res.score == min(100, round(raw_sum))


def test_every_fired_rule_is_tagged_and_cites_evidence() -> None:
    res = _score_fixture("auth_fail_spoofed.eml")
    assert res.fired
    for f in res.fired:
        assert f.source is RuleSource.OFFLINE
        assert f.evidence, f"{f.id} fired with no evidence"
        assert f"+{f.weight:g}" in f.reason
        assert f.description in f.reason


def test_offline_verdict_always_computed() -> None:
    # Phase 3 is offline-only: the offline score equals the total and the result
    # is meaningful with zero enrichment (PRD §8 combination rule).
    res = _score_fixture("crafted_malicious.eml")
    assert res.offline_score == res.score
    assert res.by_source(RuleSource.OFFLINE) == res.fired
    assert res.by_source(RuleSource.ENRICHMENT) == ()


def test_build_rules_binds_weights_from_config() -> None:
    cfg = load_config(overrides={"weights": {"auth.dmarc_fail": 50}})
    rules = {r.id: r for r in build_rules(cfg)}
    assert rules["auth.dmarc_fail"].weight == 50
    assert all(r.source is RuleSource.OFFLINE for r in rules.values())


def test_disabling_a_rule_via_zero_weight() -> None:
    # Setting a weight to 0 keeps the rule firing (it still appears with evidence)
    # but contributes nothing — the config-only way to neutralize a rule.
    cfg = load_config(overrides={"weights": {"auth.dmarc_fail": 0}})
    res = score_email(
        parse(FIXTURES / "auth_fail_spoofed.eml"),
        extract_iocs(parse(FIXTURES / "auth_fail_spoofed.eml")),
        config=cfg,
    )
    dmarc = [f for f in res.fired if f.id == "auth.dmarc_fail"]
    assert dmarc and dmarc[0].weight == 0


def test_scoring_does_no_network_io(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    parsed = parse(FIXTURES / "crafted_malicious.eml")
    iocs = extract_iocs(parsed)

    def _boom(*args: object, **kwargs: object):
        raise AssertionError("scoring attempted network I/O")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    monkeypatch.setattr(socket, "getaddrinfo", _boom)

    res = score_email(parsed, iocs)
    assert res.score > 0


# --- Rules added in the quality review -----------------------------------------


def test_multiple_from_headers_fire() -> None:
    raw = (
        f"{_AUTH_PASS}"
        'From: "IT Support" <it@example.com>\r\n'
        'From: "PayPal" <service@paypal.com>\r\n'
        "Subject: hi\r\n\r\nbody\r\n"
    )
    fired = {f.id: f for f in _score_raw(raw).fired}
    assert "identity.multiple_from" in fired
    assert fired["identity.multiple_from"].evidence[0].startswith("2 From headers")
    assert "identity.multiple_from" not in _fired(_score_fixture("benign_newsletter.eml"))


def test_html_attachment_rule_fires() -> None:
    parsed = _model_email(
        from_addr=Address(addr_spec="a@example.com", domain="example.com"),
        attachments=[Attachment(filename="Remittance.html", flags=[AttachmentFlag.HTML])],
    )
    fired = {f.id: f for f in score_email(parsed, IOCs()).fired}
    assert fired["attach.html"].evidence == [
        "HTML/SVG document attachment (opens in a browser): Remittance.html"
    ]


# --- Strict config validation -------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"weights": {"auth.spf_fial": 20}}, "did you mean 'auth.spf_fail'"),
        ({"weights": {"auth.spf_fail": "high"}}, "must be a number"),
        ({"org_domains": "acme.com"}, "'org_domains' must be a list"),
        ({"brands": {"acme": "acme.com"}}, "'brands.acme' must be a list"),
        ({"bands": [{"max": 100}]}, "integer 'max' and a 'verdict'"),
        ({"brand": {}}, "unknown scoring config key(s): brand"),
    ],
)
def test_invalid_config_is_rejected_with_the_offending_key(overrides, message) -> None:
    with pytest.raises(ValueError, match=re.escape(message)):
        load_config(overrides=overrides)


def test_enrichment_weights_accept_connector_defined_ids() -> None:
    config = load_config(overrides={"weights": {"enrichment.acmerep.risk": 20}})
    assert config.weight("enrichment.acmerep.risk") == 20


def test_malformed_yaml_is_a_value_error(tmp_path: Path) -> None:
    site = tmp_path / "site.yaml"
    site.write_text("weights: [unclosed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid YAML"):
        load_config(path=site)


def test_incomplete_analysis_keeps_its_band_in_the_verdict() -> None:
    raw = (
        "From: a@example.com\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n"
        "--x\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
    )
    result = _score_raw(raw)
    assert not result.analysis_complete
    assert result.verdict == f"{verdict_for(result.score, load_config())} (incomplete analysis)"


# --- Homographs, raw IPs, anchors: precision fixes ---------------------------


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("аррӏе.com", "imitates 'apple'"),  # every letter Cyrillic
        ("xn--80ak6aa92e.com", "imitates 'apple'"),  # the same domain, encoded
        ("pаypal.com", "imitates 'paypal'"),  # one Cyrillic letter
        ("pàypal.com", "imitates 'paypal'"),  # an accent on a Latin letter
        ("gооgle-lоgin.com", "mixed-script"),  # mixed scripts, no exact brand fold
    ],
)
def test_idn_homographs_are_detected(host: str, expected: str) -> None:
    fired = {f.id: f for f in _score_raw(_html_eml(f'<a href="https://{host}/">x</a>')).fired}
    assert expected in fired["url.idn_homograph"].evidence[0]
    assert "url.punycode" not in fired  # one domain, one rule
    assert "url.lookalike" not in fired


@pytest.mark.parametrize("host", ["việtnam.vn", "abcショップ.jp", "xn--mnchen-3ya.de"])
def test_legitimate_idns_are_not_homographs(host: str) -> None:
    fired = _fired(_score_raw(_html_eml(f'<a href="https://{host}/">x</a>')))
    assert "url.idn_homograph" not in fired


def test_punycode_evidence_shows_the_decoded_name() -> None:
    fired = {
        f.id: f for f in _score_raw(_html_eml('<a href="https://xn--mnchen-3ya.de/">x</a>')).fired
    }
    assert fired["url.punycode"].evidence == [
        "punycode/xn-- domain present: xn--mnchen-3ya[.]de (münchen.de)"
    ]


@pytest.mark.parametrize("url", ["http://3405803785/verify", "http://0xcb007109/verify"])
def test_legacy_ipv4_notations_are_raw_ip_hosts(url: str) -> None:
    assert "url.raw_ip_host" in _fired(_score_raw(_html_eml(f'<a href="{url}">x</a>')))


@pytest.mark.parametrize("label", ["Download statement.pdf", "setup.exe", "invoice.zip", "Node.js"])
def test_file_names_in_link_text_are_not_hosts(label: str) -> None:
    raw = _html_eml(f'<a href="https://files.example.com/dl/123">{label}</a>')
    assert "url.anchor_href_mismatch" not in _fired(_score_raw(raw))


def test_explicit_zip_host_in_link_text_still_counts() -> None:
    raw = _html_eml('<a href="https://files.example.com/dl/123">https://invoice.zip/view</a>')
    assert "url.anchor_href_mismatch" in _fired(_score_raw(raw))


def test_display_name_repeating_the_address_is_not_suspicious() -> None:
    same = 'From: "alice@example.com" <alice@example.com>\r\nSubject: hi\r\n\r\nbody\r\n'
    assert "identity.display_name_is_email" not in _fired(_score_raw(same))


def test_encrypted_archive_is_scored_once() -> None:
    parsed = _model_email(
        from_addr=Address(addr_spec="a@example.com", domain="example.com"),
        attachments=[
            Attachment(
                filename="invoice.zip",
                flags=[AttachmentFlag.ARCHIVE, AttachmentFlag.PASSWORD_PROTECTED],
            )
        ],
    )
    fired = _fired(score_email(parsed, IOCs()))
    assert "attach.password_protected_archive" in fired
    assert "attach.archive" not in fired


def test_same_organization_subdomains_are_not_mismatches() -> None:
    raw = (
        f"{_AUTH_PASS}From: news@example.com\r\nReturn-Path: <bounce@em.example.com>\r\n"
        "Sender: mailer@mail.example.com\r\nSubject: hi\r\n\r\nbody\r\n"
    )
    fired = _fired(_score_raw(raw))
    assert "identity.return_path_mismatch" not in fired
    assert "identity.sender_mismatch" not in fired


@pytest.mark.parametrize("display", ["Wells Fargo Online", "Bank of America Alerts"])
def test_multi_word_brands_match_display_names(display: str) -> None:
    raw = f'From: "{display}" <alerts@notify.example>\r\nSubject: hi\r\n\r\nbody\r\n'
    assert "identity.display_name_brand_mismatch" in _fired(_score_raw(raw))


def test_enrichment_magnitudes_are_clamped_and_never_subtract() -> None:
    from phishbowl.connectors import EnrichmentReport, EnrichmentSignal
    from phishbowl.connectors.base import ConnectorOutcome, ConnectorStatus, EnrichmentResult

    def report(magnitude: float) -> EnrichmentReport:
        signal = EnrichmentSignal("enrichment.rdap.young_domain", "Young", magnitude, "x")
        result = EnrichmentResult("rdap", "domain", "d.example", signals=(signal,))
        status = ConnectorStatus("rdap", "1", ConnectorOutcome.USED, "ok", results=(result,))
        return EnrichmentReport(enabled=True, statuses=(status,))

    parsed = parse(FIXTURES / "auth_fail_spoofed.eml")
    iocs = extract_iocs(parsed)
    base = score_email(parsed, iocs).score
    assert score_email(parsed, iocs, enrichment=report(-0.5)).score == base
    assert score_email(parsed, iocs, enrichment=report(float("nan"))).score == base
    young = [
        f
        for f in score_email(parsed, iocs, enrichment=report(3.0)).fired
        if f.id.startswith("enrichment")
    ]
    assert young[0].weight == load_config().weight("enrichment.rdap.young_domain")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"weights": {"auth.dmarc_fail": True}}, "must be a number"),
        ({"weights": {"auth.dmarc_fail": 1e308}}, "between 0 and 100"),
        ({"bands": [{"max": 19.9, "verdict": "a"}, {"max": 100, "verdict": "b"}]}, "integer 'max'"),
        ({"weights": None}, "'weights' is empty"),
    ],
)
def test_more_invalid_config_is_rejected(overrides, message) -> None:
    with pytest.raises(ValueError, match=re.escape(message)):
        load_config(overrides=overrides)


def test_an_empty_brand_list_removes_the_brand() -> None:
    config = load_config(overrides={"brands": {"apple": []}})
    assert "apple" not in config.brands
    raw = 'From: "Apple Farm Newsletter" <news@orchard.example>\r\nSubject: hi\r\n\r\nbody\r\n'
    parsed = parse_eml(raw.encode(), filename="c.eml")
    fired = {f.id for f in score_email(parsed, extract_iocs(parsed), config).fired}
    assert "identity.display_name_brand_mismatch" not in fired
