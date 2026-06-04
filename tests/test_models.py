"""Tests for the ``ParsedEmail`` contract (PRD §7).

Two things matter at Phase 0: the model round-trips losslessly to/from JSON
(it's the interchange format for the JSON report and the FastAPI stretch), and
the From/Return-Path/Reply-To comparison helpers behave (mismatch is a core
scoring signal, PRD §8).
"""

from __future__ import annotations

from datetime import UTC, datetime

from phishbowl.models import (
    IOC,
    Address,
    Addresses,
    Anomaly,
    Attachment,
    AttachmentFlag,
    Auth,
    AuthResult,
    AuthResultState,
    Body,
    EmailFormat,
    Header,
    Headers,
    IOCs,
    IOCType,
    ParsedEmail,
    ReceivedHop,
    Routing,
    Source,
)


def _full_parsed_email() -> ParsedEmail:
    """A fully-populated model exercising every field and sub-model."""
    return ParsedEmail(
        source=Source(
            filename="benign_newsletter.eml",
            format=EmailFormat.EML,
            parsed_at=datetime(2026, 6, 2, 9, 15, 4, tzinfo=UTC),
            parser_version="0.1.0",
        ),
        headers=Headers(
            items=[
                Header(name="Received", value="from a.example.com"),
                Header(name="Received", value="from b.example.com"),
                Header(name="From", value='"Example" <newsletter@example.com>'),
                Header(name="Subject", value="weekly digest"),
            ]
        ),
        auth=Auth(
            spf=AuthResult(result=AuthResultState.PASS, detail="smtp.mailfrom=example.com"),
            dkim=AuthResult(result=AuthResultState.PASS, detail="header.d=example.com"),
            dmarc=AuthResult(result=AuthResultState.PASS, detail="header.from=example.com"),
        ),
        routing=Routing(
            hops=[
                ReceivedHop(
                    raw="from a.example.com by mx.example.org with ESMTPS",
                    from_="a.example.com",
                    by="mx.example.org",
                    with_="ESMTPS",
                    timestamp=datetime(2026, 6, 2, 9, 15, 4, tzinfo=UTC),
                ),
                ReceivedHop(raw="from b.example.com by a.example.com with ESMTP"),
            ]
        ),
        addresses=Addresses(
            from_=Address(
                display_name="Example", addr_spec="newsletter@example.com", domain="example.com"
            ),
            reply_to=Address(
                display_name="Support", addr_spec="support@example.com", domain="example.com"
            ),
            return_path=Address(addr_spec="newsletter@example.com", domain="example.com"),
            sender=Address(addr_spec="newsletter@example.com", domain="example.com"),
            to=[
                Address(
                    display_name="Analyst", addr_spec="analyst@example.org", domain="example.org"
                )
            ],
            cc=[Address(addr_spec="team@example.org", domain="example.org")],
        ),
        subject="Your weekly Example.com community digest",
        date=datetime(2026, 6, 2, 9, 15, 0, tzinfo=UTC),
        body=Body(text="Hello", html_raw="<p>Hello</p>", has_html=True),
        attachments=[
            Attachment(
                filename="agenda.pdf",
                declared_type="application/pdf",
                detected_type="application/pdf",
                size=1234,
                md5="d41d8cd98f00b204e9800998ecf8427e",
                sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
                sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                flags=[AttachmentFlag.ARCHIVE],
            )
        ],
        iocs=IOCs(
            items=[
                IOC(
                    type=IOCType.URL,
                    value="https://www.example.com/community/digest",
                    defanged="hxxps://www[.]example[.]com/community/digest",
                    provenance=["body:html", "body:text"],
                ),
                IOC(
                    type=IOCType.IPV4,
                    value="192.0.2.10",
                    defanged="192[.]0[.]2[.]10",
                    provenance=["header:Received"],
                ),
            ]
        ),
        anomalies=[Anomaly(code="none", message="no structural anomalies")],
    )


def test_round_trips_to_and_from_json() -> None:
    original = _full_parsed_email()

    as_json = original.model_dump_json()
    restored = ParsedEmail.model_validate_json(as_json)

    assert restored == original
    # And again via by-alias serialization (the "from" key, not "from_").
    aliased = original.model_dump_json(by_alias=True)
    assert ParsedEmail.model_validate_json(aliased) == original


def test_round_trip_preserves_header_order_and_duplicates() -> None:
    restored = ParsedEmail.model_validate_json(_full_parsed_email().model_dump_json())

    assert restored.headers.names() == ["Received", "Received", "From", "Subject"]
    assert restored.headers.get_all("Received") == [
        "from a.example.com",
        "from b.example.com",
    ]
    # Case-insensitive first-value accessor.
    assert restored.headers.get("from") == '"Example" <newsletter@example.com>'
    assert "subject" in restored.headers


def test_address_comparison_helpers() -> None:
    from_ = Address(addr_spec="ceo@example.com", domain="example.com")
    same = Address(addr_spec="noreply@example.com", domain="Example.com")  # case differs
    other = Address(addr_spec="attacker@evil.example", domain="evil.example")
    no_domain = Address(addr_spec="weird")

    # domain_matches is case-insensitive and false on missing data.
    assert from_.domain_matches(same)
    assert not from_.domain_matches(other)
    assert not from_.domain_matches(no_domain)
    assert not from_.domain_matches(None)


def test_addresses_mismatch_properties() -> None:
    # All same domain -> no mismatches fire.
    aligned = Addresses(
        from_=Address(addr_spec="ceo@example.com", domain="example.com"),
        reply_to=Address(addr_spec="ceo@example.com", domain="EXAMPLE.com"),
        return_path=Address(addr_spec="bounce@example.com", domain="example.com"),
        sender=Address(addr_spec="ceo@example.com", domain="example.com"),
    )
    assert not aligned.reply_to_mismatch
    assert not aligned.return_path_mismatch
    assert not aligned.sender_mismatch

    # Divergent reply-to / return-path / sender each fire independently.
    spoofed = Addresses(
        from_=Address(addr_spec="ceo@example.com", domain="example.com"),
        reply_to=Address(addr_spec="ceo@evil.example", domain="evil.example"),
        return_path=Address(addr_spec="bounce@evil.example", domain="evil.example"),
        sender=Address(addr_spec="relay@evil.example", domain="evil.example"),
    )
    assert spoofed.reply_to_mismatch
    assert spoofed.return_path_mismatch
    assert spoofed.sender_mismatch

    # Missing fields never raise a false mismatch.
    sparse = Addresses(from_=Address(addr_spec="ceo@example.com", domain="example.com"))
    assert not sparse.reply_to_mismatch
    assert not sparse.return_path_mismatch
    assert not sparse.sender_mismatch
