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
    defang_text,
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


def test_mimecast_is_kept_wrapped_but_discloses_its_target_domain() -> None:
    url = "https://protect-us.mimecast.com/s/aB12CdEf34?domain=phish.example"
    result = unwrap_url(url)
    assert result is not None
    assert (result.wrapper, result.unresolved) == ("mimecast", True)
    # The wrapped form is retained unchanged as the value (nothing was decoded).
    assert result.value == result.wrapped == url
    assert result.target_domain == "phish.example"


@pytest.mark.parametrize(
    ("url", "wrapper", "target"),
    [
        (
            "https://linkprotect.cudasvc.com/url?a=https%3a%2f%2fevil.example%2flogin&c=E,1,x",
            "barracuda",
            "https://evil.example/login",
        ),
        (
            "https://secure-web.cisco.com/1abcDEF/https%3A%2F%2Fevil.example%2Flogin",
            "cisco",
            "https://evil.example/login",
        ),
        (
            "https://urldefense.com/v3/__https:/evil.example/login__;!!AbCdEf!GhIjKl$",
            "proofpoint",
            "https://evil.example/login",  # the collapsed "https:/" is restored
        ),
        (
            "https://nam12.safelinks.protection.outlook.com./?url=https%3A%2F%2Fevil.example%2F",
            "safelinks",
            "https://evil.example/",  # a trailing-dot wrapper host is still a wrapper
        ),
    ],
)
def test_reversible_wrappers_unwrap_offline(url: str, wrapper: str, target: str) -> None:
    result = unwrap_url(url)
    assert result is not None
    assert (result.wrapper, result.unresolved, result.value) == (wrapper, False, target)


def test_proofpoint_v3_tokens_beyond_the_trailer_are_unresolved() -> None:
    result = unwrap_url("https://urldefense.com/v3/__https://evil.example/a*b*c__;!!x!y$")
    assert result is not None and result.unresolved


def test_wrappers_nested_past_the_depth_budget_are_unresolved() -> None:
    from urllib.parse import quote

    url = "https://evil.example/"
    for _ in range(7):
        url = "https://x.safelinks.protection.outlook.com/?url=" + quote(url, safe="")
    result = unwrap_url(url)
    assert result is not None and result.unresolved


def test_hostile_proofpoint_links_decode_in_linear_time() -> None:
    import time

    started = time.perf_counter()
    unwrap_url("https://urldefense.com/v3/__" + "v3/__" * 40_000)
    unwrap_url("https://urldefense.proofpoint.com/v2/url?" + "u=" * 40_000)
    assert time.perf_counter() - started < 1.0


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


def test_fake_proofpoint_host_keeps_actual_destination():
    wrapped = (
        "https://urldefense.com.attacker.example/urldefense.com/v1/"
        "?u=https%3A%2F%2Fexample.org%2F&k=unused"
    )
    assert unwrap_url(wrapped) is None


def test_proofpoint_version_must_be_in_wrapper_path():
    wrapped = (
        "https://urldefense.com/other/urldefense.com/v1/?u=https%3A%2F%2Fexample.org%2F&k=unused"
    )
    assert unwrap_url(wrapped).unresolved


def test_safelinks_preserves_destination_percent_encoding():
    from urllib.parse import quote

    target = "https://sample.example/a%2Fb?token=a%26b%3Dc"
    wrapped = "https://safelinks.protection.outlook.com/?url=" + quote(target, safe="")
    assert unwrap_safelinks(wrapped) == target


@pytest.mark.parametrize("host", ["urldefense.com", "safelinks.protection.outlook.com"])
def test_backslash_authority_cannot_masquerade_as_wrapper(host):
    url = (
        "https://attacker.example\\@"
        + host
        + "/v1/?u=https%3A%2F%2Fexample.org%2F&k=unused"
        + "&url=https%3A%2F%2Fexample.org%2F"
    )
    assert unwrap_url(url) is None


# --- HTML link targets are classified by what they can reach -------------------


def _html_iocs(markup: str) -> dict[str, set[str]]:
    from phishbowl.parse import parse_eml

    parsed = parse_eml(
        b"From: a@example.com\r\nContent-Type: text/html\r\n\r\n" + markup.encode("utf-8")
    )
    found: dict[str, set[str]] = {}
    for ioc in extract_iocs(parsed):
        found.setdefault(ioc.type.value, set()).add(ioc.value)
    return found


def test_non_network_link_targets_are_not_url_indicators() -> None:
    found = _html_iocs(
        '<a href="#top">top</a><a href="/relative/path">r</a><a href="tel:+15555550100">t</a>'
        '<img src="cid:image001.png@01D2B9"><img src="data:image/png;base64,iVBORw0KGgo=">'
        '<a href="https://ok.example.com/x">ok</a>'
    )
    assert found["url"] == {"https://ok.example.com/x"}


def test_mailto_links_contribute_their_addresses() -> None:
    found = _html_iocs('<a href="mailto:boss%40example.net?cc=cfo@example.net">mail</a>')
    assert {"boss@example.net", "cfo@example.net"} <= found["email"]
    assert "url" not in found


def test_script_and_inline_document_navigation_is_surfaced() -> None:
    found = _html_iocs(
        '<a href="javascript:alert(1)">js</a><a href="data:text/html;base64,PGgxPg==">doc</a>'
    )
    assert found["url"] == {"javascript:alert(1)", "data:text/html;base64,PGgxPg=="}


def test_resource_urls_srcset_and_meta_refresh_are_extracted() -> None:
    found = _html_iocs(
        '<meta http-equiv="Refresh" content="0; url=https://redirect.example/go">'
        '<img srcset="https://cdn.example/a.png 1x, https://cdn.example/b.png 2x">'
        '<img src="//pixel.example/t.gif">'
    )
    assert {
        "https://redirect.example/go",
        "https://cdn.example/a.png",
        "https://cdn.example/b.png",
        "//pixel.example/t.gif",
    } <= found["url"]
    assert "pixel.example" in found["domain"]


# --- Extraction regressions (quality review) -----------------------------------


def _eml_iocs(raw: bytes) -> dict[str, set[str]]:
    from phishbowl.parse import parse_eml

    found: dict[str, set[str]] = {}
    for ioc in extract_iocs(parse_eml(raw)):
        found.setdefault(ioc.type.value, set()).add(ioc.value)
    return found


def test_unparseable_url_text_is_kept_not_fatal() -> None:
    raw = "From: a@example.com\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
    raw += "see http://a.example .＠b now\r\n"
    found = _eml_iocs(raw.encode("utf-8"))  # iocextract's refang raises ValueError here
    assert "email" in found


def test_times_and_mac_addresses_are_not_ipv6_indicators() -> None:
    found = _eml_iocs(
        b"From: a@example.com\r\n\r\nat 10:30:00 from 00:1a:2b:3c:4d:5e via 2001:db8::1\r\n"
    )
    assert found["ipv6"] == {"2001:db8::1"}


def test_the_indicator_cap_never_evicts_hashes_or_links() -> None:
    import base64

    padding = " ".join(f"10.{i // 250}.{i % 250}.1" for i in range(1200))
    raw = (
        b"From: a@example.com\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n"
        b"--b\r\nContent-Type: text/plain\r\n\r\n" + padding.encode() + b"\r\n"
        b'--b\r\nContent-Type: text/html\r\n\r\n<a href="https://login.evil.example/">x</a>\r\n'
        b"--b\r\nContent-Type: application/octet-stream; name=a.bin\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n" + base64.encodebytes(b"payload") + b"--b--\r\n"
    )
    found = _eml_iocs(raw)
    assert "https://login.evil.example/" in found["url"]
    assert found["hash"]


def test_ip_literal_link_hosts_are_ip_indicators() -> None:
    found = _eml_iocs(
        b'From: a@example.com\r\nContent-Type: text/html\r\n\r\n<a href="http://198.51.100.7/login">x</a>'
    )
    assert "198.51.100.7" in found["ipv4"]


def test_mimecast_links_contribute_their_target_domain() -> None:
    found = _eml_iocs(
        b"From: a@example.com\r\nContent-Type: text/html\r\n\r\n"
        b'<a href="https://protect-us.mimecast.com/s/aB12?domain=phish.example">x</a>'
    )
    assert "phish.example" in found["domain"]


def test_hidden_markup_and_styles_are_scanned_but_not_shown() -> None:
    from phishbowl.html_analysis import inspect_html

    html = (
        "<style>.x{background:url('https://track.example/p.gif')}</style>"
        '<script>var c2 = "https://c2.example/beacon";</script>'
        '<p style="background:url(https://bg.example/i.png)">Visible</p>'
        '<svg><a xlink:href="https://svg.example/go">s</a></svg>'
        '<a href="https://ok.example/" ping="https://ping.example/p">Click</a>'
    )
    analysis = inspect_html(html)
    assert "c2.example" not in analysis.text and "Visible" in analysis.text
    found = _eml_iocs(b"From: a@example.com\r\nContent-Type: text/html\r\n\r\n" + html.encode())
    assert {
        "https://track.example/p.gif",
        "https://c2.example/beacon",
        "https://bg.example/i.png",
        "https://svg.example/go",
        "https://ping.example/p",
    } <= found["url"]


def test_inline_html_part_with_a_file_name_is_read_as_body() -> None:
    found = _eml_iocs(
        b"From: a@example.com\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n"
        b'--b\r\nContent-Type: text/html; name="message.html"\r\n\r\n'
        b'<a href="https://inline.example/x">x</a>\r\n--b--\r\n'
    )
    assert "https://inline.example/x" in found["url"]


@pytest.mark.parametrize(
    ("text", "defanged"),
    [
        ("see_www.evil.example/login", "see_www[.]evil[.]example/login"),
        ("id_192.0.2.1 x", "id_192[.]0[.]2[.]1 x"),
        ("version 1.2.3.4.5", "version 1.2.3.4.5"),
        ("Invoice_https://evil.example/pay", "Invoice_hxxps://evil[.]example/pay"),
    ],
)
def test_glued_indicators_in_text_are_defanged(text: str, defanged: str) -> None:
    assert defang_text(text) == defanged


@pytest.mark.parametrize("url", ["java\tscript:alert(1)", "\x01javascript:alert(1)"])
def test_scheme_is_read_the_way_browsers_read_it(url: str) -> None:
    assert defang_url(url) == "javascript[:]alert(1)"


def test_defanging_is_idempotent() -> None:
    for value in ("hxxp://203[.]0[.]113[.]9/login", "user[at]evil[.]example", "2001[:]db8[:][:]1"):
        assert defang_text(value) == value
    assert defang_ipv6("2001[:]db8::1") == "2001[:]db8[:][:]1"
