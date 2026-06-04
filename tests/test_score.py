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

from pathlib import Path

import pytest

from phishbowl.extract import extract_iocs
from phishbowl.models import (
    Address,
    Addresses,
    Attachment,
    AttachmentFlag,
    EmailFormat,
    IOCs,
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
    # A brand display name whose From domain legitimately owns it must NOT fire
    # (the bundled "example" brand owns example.com).
    legit = _score_fixture("benign_newsletter.eml")
    assert "identity.display_name_brand_mismatch" not in _fired(legit)


def test_freemail_brand_fires() -> None:
    raw = 'From: "PayPal Support" <paypalhelp@gmail.com>\r\nSubject: hi\r\n\r\nbody\r\n'
    assert "identity.freemail_brand" in _fired(_score_raw(raw))
    # A personal gmail with no brand claim does not fire.
    plain = 'From: "Jordan Lee" <jordan.lee@gmail.com>\r\nSubject: hi\r\n\r\nbody\r\n'
    assert "identity.freemail_brand" not in _fired(_score_raw(plain))


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


def test_lookalike_fires_on_edit_distance() -> None:
    # examp1e.com (digit one) is edit-distance 1 from the bundled example.com brand.
    res = _score_raw(_html_eml('<a href="https://examp1e.com/">x</a>'))
    assert "url.lookalike" in _fired(res)
    # The genuine example.com is not a lookalike of itself.
    assert "url.lookalike" not in _fired(_score_fixture("benign_newsletter.eml"))


def test_anchor_href_mismatch_fires() -> None:
    res = _score_raw(_html_eml('<a href="http://evil.example/go">www.paypal.com</a>'))
    assert "url.anchor_href_mismatch" in _fired(res)
    # benign anchor text/href agree (both example.com) -> silent.
    assert "url.anchor_href_mismatch" not in _fired(_score_fixture("benign_newsletter.eml"))


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
    assert res.verdict.startswith("Benign")
    assert res.fired == ()


def test_spoofed_fixture_scores_high() -> None:
    res = _score_fixture("auth_fail_spoofed.eml")
    assert res.score >= 65
    assert res.verdict in {"Likely malicious", "Malicious — high confidence"}


def test_crafted_malicious_fixture_scores_high() -> None:
    res = _score_fixture("crafted_malicious.eml")
    assert res.score >= 85
    assert res.verdict == "Malicious — high confidence"
    # It exercises a broad spread of the catalog, not one lucky rule.
    assert len(res.fired) >= 8


def test_verdict_bands_cover_the_range() -> None:
    cfg = load_config()
    assert verdict_for(0, cfg).startswith("Benign")
    assert verdict_for(19, cfg).startswith("Benign")
    assert verdict_for(20, cfg) == "Low suspicion"
    assert verdict_for(50, cfg).startswith("Suspicious")
    assert verdict_for(70, cfg) == "Likely malicious"
    assert verdict_for(100, cfg).startswith("Malicious")


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
