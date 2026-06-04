"""Tests for the ``.eml`` parser (PRD §6.1 — Phase 1).

Covers the four paths the parser must handle:

- a **clean** message (headers ordered + deduped, auth pass, routing, body),
- an **auth-failing / spoofed** message (SPF/DKIM/DMARC fail, RFC 2047 decode of
  subject + display name, Return-Path / Reply-To / Sender mismatch),
- a message **with attachments** (hashes, magic-byte detection, structural flags),
- **malformed** input (degrades to a noted partial result, never crashes).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from phishbowl.models import (
    AttachmentFlag,
    AuthResultState,
    EmailFormat,
    ParsedEmail,
)
from phishbowl.parse import parse, parse_eml
from phishbowl.parse.attachments import _flags

FIXTURES = Path(__file__).parent / "fixtures"


def _parse(name: str) -> ParsedEmail:
    return parse(FIXTURES / name)


def _flags_for(filename: str, declared: str = "application/octet-stream") -> list[AttachmentFlag]:
    """Structural flags for a filename with empty content (extension-driven)."""
    return _flags(filename, declared, None, b"")


# --- Clean path ------------------------------------------------------------


def test_clean_email_headers_order_and_duplicates_preserved() -> None:
    parsed = _parse("benign_newsletter.eml")

    assert parsed.source.format is EmailFormat.EML
    # Order preserved and duplicate Received headers both kept.
    assert parsed.headers.names()[:3] == ["Return-Path", "Received", "Received"]
    assert len(parsed.headers.get_all("Received")) == 2
    assert parsed.subject == "Your weekly Example.com community digest"
    assert parsed.anomalies == []


def test_clean_email_addresses_split_and_aligned() -> None:
    parsed = _parse("benign_newsletter.eml")
    addrs = parsed.addresses

    assert addrs.from_ is not None
    assert addrs.from_.display_name == "Example Newsletter"
    assert addrs.from_.addr_spec == "newsletter@example.com"
    assert addrs.from_.domain == "example.com"
    # All aligned -> no mismatch signals fire.
    assert not addrs.reply_to_mismatch
    assert not addrs.return_path_mismatch
    assert not addrs.sender_mismatch
    assert [a.addr_spec for a in addrs.to] == ["analyst@example.org"]
    assert [a.addr_spec for a in addrs.cc] == ["team@example.org"]


def test_clean_email_auth_routing_and_body() -> None:
    parsed = _parse("benign_newsletter.eml")

    assert parsed.auth.spf.result is AuthResultState.PASS
    assert parsed.auth.dkim.result is AuthResultState.PASS
    assert parsed.auth.dmarc.result is AuthResultState.PASS
    assert parsed.auth.spf.detail == "smtp.mailfrom=example.com"

    # Two hops, top-to-bottom, with best-effort from/by/with/timestamp.
    assert len(parsed.routing) == 2
    top = parsed.routing.hops[0]
    assert top.from_ == "mail.example.com"
    assert top.by == "mx.example.org"
    assert top.with_ == "ESMTPS"
    assert top.timestamp is not None

    assert parsed.body.text is not None
    assert "community digest" in parsed.body.text
    assert parsed.body.has_html is True
    assert parsed.body.html_raw is not None


# --- Auth-failing / spoofed path -------------------------------------------


def test_auth_failing_email_results() -> None:
    parsed = _parse("auth_fail_spoofed.eml")

    assert parsed.auth.spf.result is AuthResultState.FAIL
    assert parsed.auth.dkim.result is AuthResultState.FAIL
    assert parsed.auth.dmarc.result is AuthResultState.FAIL
    # Detail text is retained for the report.
    assert parsed.auth.dmarc.detail and "p=reject" in parsed.auth.dmarc.detail


def test_spoofed_email_decodes_encoded_words() -> None:
    parsed = _parse("auth_fail_spoofed.eml")

    # RFC 2047 encoded-words decoded in both subject and the From display name.
    assert parsed.subject == "Account suspended — verify now"
    assert parsed.addresses.from_ is not None
    assert parsed.addresses.from_.display_name == "Examplé Security Team"


def test_spoofed_email_address_mismatches_fire() -> None:
    parsed = _parse("auth_fail_spoofed.eml")
    addrs = parsed.addresses

    assert addrs.from_.domain == "example.com"
    # Reply-To / Return-Path / Sender all diverge from the From domain.
    assert addrs.reply_to_mismatch
    assert addrs.return_path_mismatch
    assert addrs.sender_mismatch


# --- Attachment path -------------------------------------------------------


def test_attachment_hashes_and_clean_pdf() -> None:
    parsed = _parse("with_attachment.eml")
    by_name = {a.filename: a for a in parsed.attachments}

    pdf = by_name["report.pdf"]
    assert pdf.declared_type == "application/pdf"
    assert pdf.detected_type == "application/pdf"
    assert pdf.flags == []
    assert pdf.size == 144
    # Hashes are over the transfer-decoded bytes.
    assert pdf.md5 == "14b78e7e399a894cf4dd975ded2edc3b"
    assert pdf.sha1 == "03efdca17b151695ec2968cccd65cb8754f0e977"
    assert pdf.sha256 == ("59daf924a4fe50e7f838ff7d0489c5e3ced4dd888db3ad4e98fa14ec3cbe3010")
    assert len({pdf.md5, pdf.sha1, pdf.sha256}) == 3  # three distinct digests


def test_attachment_double_extension_executable_flags() -> None:
    parsed = _parse("with_attachment.eml")
    by_name = {a.filename: a for a in parsed.attachments}

    exe = by_name["ledger-update.pdf.exe"]
    # Magic-byte detection sees the 'MZ' header despite the octet-stream type.
    assert exe.declared_type == "application/octet-stream"
    assert exe.detected_type == "application/x-dosexec"
    assert AttachmentFlag.EXECUTABLE in exe.flags
    assert AttachmentFlag.DOUBLE_EXTENSION in exe.flags


def test_attachments_are_never_executed_or_extracted() -> None:
    # A regression guard for the defensive invariant: parsing only ever reads
    # bytes to hash/sniff. The detected type proves we inspected, not ran it.
    parsed = _parse("with_attachment.eml")
    assert len(parsed.attachments) == 2
    assert all(a.sha256 for a in parsed.attachments)


def test_legacy_office_extensions_flagged_macro_capable() -> None:
    # Legacy OLE Office formats (.doc/.xls/.ppt) can carry VBA macros and have
    # no macro-free variant, so they must flag MACRO_CAPABLE...
    for filename in ("budget.xls", "memo.doc", "deck.ppt"):
        att = _flags_for(filename)
        assert AttachmentFlag.MACRO_CAPABLE in att

    # ...while a modern .docx (which cannot contain macros) must not, and is not
    # mistaken for an archive despite being a zip container.
    docx = _flags_for("modern.docx")
    assert AttachmentFlag.MACRO_CAPABLE not in docx
    assert AttachmentFlag.ARCHIVE not in docx


def test_attached_eml_captured_as_one_attachment() -> None:
    parsed = _parse("forwarded_eml.eml")

    # The message/rfc822 part is captured whole (filename + hashes), not
    # descended into.
    attached = [a for a in parsed.attachments if a.declared_type == "message/rfc822"]
    assert len(attached) == 1
    assert attached[0].filename == "reported.eml"
    assert attached[0].sha256 and attached[0].size > 0

    # The inner email's body must NOT leak into the outer message body.
    assert parsed.body.text is not None
    assert "forwarded the attached message" in parsed.body.text
    assert "won a prize" not in parsed.body.text
    assert "claim your synthetic prize" not in parsed.body.text


def test_inline_text_part_stays_in_body_not_attachment() -> None:
    # Content-Disposition: inline on a text part is a body part, not attachment.
    raw = (
        b"From: a@example.com\r\n"
        b"Subject: hi\r\n"
        b'Content-Type: text/plain; charset="utf-8"\r\n'
        b"Content-Disposition: inline\r\n"
        b"\r\n"
        b"inline body text here\r\n"
    )
    parsed = parse_eml(raw, filename="inline.eml")
    assert parsed.body.text is not None
    assert "inline body text here" in parsed.body.text
    assert parsed.attachments == []


# --- Malformed path --------------------------------------------------------


def test_malformed_email_degrades_to_partial_with_anomaly() -> None:
    parsed = _parse("malformed.eml")

    assert isinstance(parsed, ParsedEmail)
    # Partial result: what could be parsed is still here...
    assert parsed.addresses.from_ is not None
    assert parsed.addresses.from_.addr_spec == "sender@example.com"
    # ...and the structural defect is noted rather than raised.
    assert parsed.anomalies
    assert any(a.code == "mime_defect" for a in parsed.anomalies)
    # No phantom attachment from the unsplit multipart body.
    assert parsed.attachments == []


def test_random_bytes_never_crash() -> None:
    parsed = parse_eml(b"\x00\x01\x02 not an email at all \xff\xfe", filename="junk.eml")

    assert isinstance(parsed, ParsedEmail)
    assert parsed.source.filename == "junk.eml"
    # No From in garbage input -> noted, not raised.
    assert any(a.code == "missing_from" for a in parsed.anomalies)


def test_charset_handling_is_centralized_and_total() -> None:
    # A part declaring a bogus charset still decodes (lenient fallback), proving
    # charset handling lives in the parse layer and never escapes as an error.
    raw = (
        b"From: a@example.com\r\n"
        b"Subject: hi\r\n"
        b'Content-Type: text/plain; charset="definitely-not-a-charset"\r\n'
        b"\r\n"
        b"body bytes\r\n"
    )
    parsed = parse_eml(raw, filename="weird.eml")
    assert parsed.body.text is not None
    assert "body bytes" in parsed.body.text


def test_parse_dispatch_unsupported_suffix_raises() -> None:
    with pytest.raises(ValueError):
        parse(FIXTURES / "nope.txt")


def test_parse_dispatch_msg_degrades_gracefully(tmp_path: Path) -> None:
    msg = tmp_path / "outlook.msg"
    msg.write_bytes(b"not really a msg")
    parsed = parse(msg)

    assert parsed.source.format is EmailFormat.MSG
    assert any(a.code == "unsupported_format" for a in parsed.anomalies)


def test_attachment_digests_are_consistent_with_each_other() -> None:
    # The three digests over the same bytes must all be valid hex of the right
    # width and mutually distinct — a cheap integrity cross-check.
    parsed = _parse("with_attachment.eml")
    pdf = next(a for a in parsed.attachments if a.filename == "report.pdf")

    assert len(pdf.md5) == len(hashlib.md5(b"").hexdigest())
    assert len(pdf.sha1) == len(hashlib.sha1(b"").hexdigest())
    assert len(pdf.sha256) == len(hashlib.sha256(b"").hexdigest())
    assert all(int(h, 16) >= 0 for h in (pdf.md5, pdf.sha1, pdf.sha256))
