"""Tests for IOC extraction, wrapper unwrapping & defang (PRD §6.2 — Phase 2).

Covers the Phase 2 definition of done: a synthetic email with Safelinks +
Proofpoint links yields correct unwrapped indicators, every indicator is
defanged in output, and each is tagged with provenance. Plus the load-bearing
safety guarantee — extraction performs **zero network I/O** (it never fetches
the email's URLs; unwrapping is a pure string transform).
"""

from __future__ import annotations

import socket
from base64 import urlsafe_b64encode
from pathlib import Path

import pytest

from phishbowl.extract import (
    defang,
    defang_domain,
    defang_email,
    defang_ipv4,
    defang_ipv6,
    defang_url,
    detect_wrapper,
    extract_iocs,
    refang,
    unwrap_proofpoint,
    unwrap_safelinks,
    unwrap_url,
)
from phishbowl.models import IOCType, ParsedEmail
from phishbowl.parse import parse

FIXTURES = Path(__file__).parent / "fixtures"


def _parse(name: str) -> ParsedEmail:
    return parse(FIXTURES / name)


def _values(iocs, ioc_type: IOCType) -> set[str]:
    return {i.value for i in iocs.by_type(ioc_type)}


def _one(iocs, ioc_type: IOCType, value: str):
    matches = [i for i in iocs.by_type(ioc_type) if i.value == value]
    assert len(matches) == 1, f"expected exactly one {ioc_type}={value!r}, got {len(matches)}"
    return matches[0]


# --- Wrapper unwrapping (pure string transform) ----------------------------


def test_safelinks_unwraps_url_param() -> None:
    wrapped = (
        "https://nam12.safelinks.protection.outlook.com/?url="
        "https%3A%2F%2Faccount-verify.example%2Flogin%3Fid%3D42"
        "&data=05%7C01%7C&sdata=Xyz&reserved=0"
    )
    assert unwrap_safelinks(wrapped) == "https://account-verify.example/login?id=42"
    result = unwrap_url(wrapped)
    assert result is not None
    assert result.wrapper == "safelinks"
    assert result.unresolved is False
    assert result.value == "https://account-verify.example/login?id=42"
    assert result.wrapped == wrapped


def test_proofpoint_v1_unwraps() -> None:
    wrapped = (
        "https://urldefense.proofpoint.com/v1/url?u=https%3A%2F%2Fwww.evil.example%2Fa%26b&k=7p"
    )
    assert unwrap_proofpoint(wrapped) == "https://www.evil.example/a&b"


def test_proofpoint_v2_unwraps_dash_underscore_encoding() -> None:
    # v2 encodes ':'->-3A, '/'->_, and a literal '-'->-2D.
    wrapped = (
        "https://urldefense.proofpoint.com/v2/url?"
        "u=https-3A__secure-2Dupdate.example_portal&d=DwMFaQ&c=AbCd&e="
    )
    assert unwrap_proofpoint(wrapped) == "https://secure-update.example/portal"


def test_proofpoint_v3_unwraps_single_token() -> None:
    # A single '*' token consumes one char from the base64 trailer ('Kw' -> '+').
    wrapped = "https://urldefense.com/v3/__https://reset-portal.example/p?q=a*b__;Kw!!DOx!t$"
    assert unwrap_proofpoint(wrapped) == "https://reset-portal.example/p?q=a+b"


def test_proofpoint_v3_unwraps_run_token() -> None:
    # A '**x' run token expands to (b64index(x)+2) chars; '**A' -> 2 chars.
    trailer = urlsafe_b64encode(b"++").decode().rstrip("=")
    wrapped = f"https://urldefense.com/v3/__https://evil.example/p?q=a**Ab__;{trailer}!!D!t$"
    assert unwrap_proofpoint(wrapped) == "https://evil.example/p?q=a++b"


def test_plain_url_is_not_treated_as_wrapped() -> None:
    assert detect_wrapper("https://www.example.com/normal") is None
    assert unwrap_url("https://www.example.com/normal") is None


# --- Non-reversible wrappers: kept wrapped, flagged "wrapped, unresolved" ---


@pytest.mark.parametrize(
    ("url", "wrapper"),
    [
        ("https://protect.mimecast.com/s/aB12CdEf34?domain=phish.example", "mimecast"),
        ("https://linkprotect.cudasvc.com/url?a=https%3a%2f%2fevil.example&c=E,1,x", "barracuda"),
        ("https://secure-web.cisco.com/1abcDEF/https%3A%2F%2Fevil.example%2F", "cisco"),
    ],
)
def test_non_reversible_wrappers_marked_unresolved(url: str, wrapper: str) -> None:
    result = unwrap_url(url)
    assert result is not None
    assert result.wrapper == wrapper
    assert result.unresolved is True
    # The wrapped form is retained unchanged as the value (nothing was decoded).
    assert result.value == url
    assert result.wrapped == url


# --- Defang (all human-facing output) --------------------------------------


def test_defang_by_type() -> None:
    assert defang_url("https://evil.example/a.b") == "hxxps://evil[.]example/a[.]b"
    assert defang_url("http://evil.example") == "hxxp://evil[.]example"
    assert defang_ipv4("198.51.100.23") == "198[.]51[.]100[.]23"
    assert defang_ipv6("2001:db8::1") == "2001[:]db8[:][:]1"
    assert defang_email("user@evil.example") == "user[at]evil[.]example"
    assert defang_domain("evil.example") == "evil[.]example"


def test_defang_dispatch_matches_typed_helpers() -> None:
    assert defang("https://evil.example", IOCType.URL) == defang_url("https://evil.example")
    assert defang("a@b.example", IOCType.EMAIL) == defang_email("a@b.example")
    # Hashes carry nothing auto-linkable, so they pass through untouched.
    digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert defang(digest, IOCType.HASH) == digest


@pytest.mark.parametrize(
    ("value", "ioc_type"),
    [
        ("https://evil.example/login?next=/a.b&id=7", IOCType.URL),
        ("http://198.51.100.23/payload", IOCType.URL),
        ("198.51.100.23", IOCType.IPV4),
        ("2001:db8::6660", IOCType.IPV6),
        ("user@evil.example", IOCType.EMAIL),
        ("evil.example", IOCType.DOMAIN),
        # Dangerous code/data URI schemes: the colon is bracketed once (never
        # doubled), and the round-trip recovers the original exactly.
        ("javascript:alert(1)", IOCType.URL),
        ("data:text/html;base64,AAAA", IOCType.URL),
        ("vbscript:MsgBox(1)", IOCType.URL),
    ],
)
def test_defang_round_trips(value: str, ioc_type: IOCType) -> None:
    # Defang then refang must recover the original indicator exactly.
    assert refang(defang(value, ioc_type)) == value


def test_dangerous_scheme_defang_brackets_the_colon_once() -> None:
    assert defang_url("javascript:alert(1)") == "javascript[:]alert(1)"
    assert defang_url("data:text/html;base64,AAAA") == "data[:]text/html;base64,AAAA"


# --- End-to-end extraction over the synthetic fixture ----------------------


def test_fixture_unwraps_safelinks_and_proofpoint_retaining_both_forms() -> None:
    iocs = extract_iocs(_parse("wrapped_links.eml"))
    urls = _values(iocs, IOCType.URL)

    # Safelinks and Proofpoint v2/v3 all unwrapped to their real targets...
    assert "https://account-verify.example/login?id=42" in urls
    assert "https://secure-update.example/portal" in urls
    assert "https://reset-portal.example/p?q=a+b" in urls

    # ...and each retains BOTH forms: unwrapped value + original wrapped string.
    safelink = _one(iocs, IOCType.URL, "https://account-verify.example/login?id=42")
    assert safelink.wrapper == "safelinks"
    assert safelink.unresolved is False
    assert safelink.wrapped is not None
    assert "safelinks.protection.outlook.com" in safelink.wrapped


def test_fixture_keeps_non_reversible_wrapper_wrapped_and_flagged() -> None:
    iocs = extract_iocs(_parse("wrapped_links.eml"))
    mimecast = _one(
        iocs,
        IOCType.URL,
        "https://protect.mimecast.com/s/aB12CdEf34?domain=phish-portal.example",
    )
    assert mimecast.wrapper == "mimecast"
    assert mimecast.unresolved is True


def test_fixture_extracts_addresses_ips_and_hashes() -> None:
    iocs = extract_iocs(_parse("wrapped_links.eml"))

    assert "support@account-verify.example" in _values(iocs, IOCType.EMAIL)
    assert "198.51.100.23" in _values(iocs, IOCType.IPV4)
    assert "2001:db8::6660" in _values(iocs, IOCType.IPV6)
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in _values(
        iocs, IOCType.HASH
    )
    # The unwrapped target's real domain surfaces as a domain IOC, not the gateway's.
    assert "account-verify.example" in _values(iocs, IOCType.DOMAIN)
    assert "reset-portal.example" in _values(iocs, IOCType.DOMAIN)


def test_every_extracted_ioc_is_defanged() -> None:
    iocs = extract_iocs(_parse("wrapped_links.eml"))
    for ioc in iocs:
        assert ioc.defanged == defang(ioc.value, ioc.type)
        if ioc.type in {IOCType.URL, IOCType.IPV4, IOCType.DOMAIN}:
            # No *bare* dot survives — every dot is bracketed as "[.]".
            assert "." not in ioc.defanged.replace("[.]", "")
        if ioc.type is IOCType.EMAIL:
            assert "@" not in ioc.defanged


def test_provenance_is_retained_and_merged() -> None:
    iocs = extract_iocs(_parse("wrapped_links.eml"))

    # An address indicator is tagged with the exact header it came from.
    assert _one(iocs, IOCType.EMAIL, "support@account-verify.example").provenance == ["header:From"]
    assert _one(iocs, IOCType.EMAIL, "analyst@example.org").provenance == ["header:To"]

    # A domain seen in several places merges provenance (no duplicate IOC).
    from_domain = _one(iocs, IOCType.DOMAIN, "account-verify.example")
    assert "header:From" in from_domain.provenance
    assert "body:text" in from_domain.provenance
    assert "body:html" in from_domain.provenance


def test_indicators_are_deduplicated_and_normalized() -> None:
    iocs = extract_iocs(_parse("wrapped_links.eml"))

    # Dedup: each (type, value) pair appears exactly once across all sources.
    keys = [(i.type, i.value) for i in iocs]
    assert len(keys) == len(set(keys))

    # Normalize: emails and domains are case-folded.
    for ioc in iocs:
        if ioc.type in {IOCType.EMAIL, IOCType.DOMAIN, IOCType.HASH}:
            assert ioc.value == ioc.value.casefold()


# --- Defensive invariant: extraction never touches the network -------------


def test_extraction_performs_zero_network_io(monkeypatch: pytest.MonkeyPatch) -> None:
    # Parse first (Phase 1, network-free and separately tested), then make ANY
    # socket use explode and prove extraction still produces a full IOC set.
    parsed = _parse("wrapped_links.eml")

    def _boom(*args: object, **kwargs: object):
        raise AssertionError("extraction attempted network I/O")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    monkeypatch.setattr(socket, "getaddrinfo", _boom)

    iocs = extract_iocs(parsed)

    # It still did real work — wrappers unwrapped, indicators found — with no I/O.
    assert len(iocs) > 0
    assert "https://account-verify.example/login?id=42" in _values(iocs, IOCType.URL)
