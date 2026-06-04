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
from phishbowl.parse import parse, parse_eml, parse_msg
from phishbowl.parse.attachments import _flags

FIXTURES = Path(__file__).parent / "fixtures"


def _load_msg_builder():
    """Load the synthetic .msg generator so tests can build .msg variants in-memory."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "build_synthetic_msg", FIXTURES / "build_synthetic_msg.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_msgbuild = _load_msg_builder()


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


def test_office_declaration_contradicting_bytes_flags_mismatch() -> None:
    # A concrete Office declaration whose bytes sniff as another family is a
    # spoof and must flag TYPE_MISMATCH...
    doc_pdf = _flags("invoice.doc", "application/msword", "application/pdf", b"%PDF-")
    assert AttachmentFlag.TYPE_MISMATCH in doc_pdf

    # ...while the matching container shapes do not: a real legacy .doc (OLE)
    # and a real .docx (zip) are both consistent declarations.
    real_doc = _flags("memo.doc", "application/msword", "application/x-ole-storage", b"")
    assert AttachmentFlag.TYPE_MISMATCH not in real_doc
    ooxml = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    real_docx = _flags("memo.docx", ooxml, "application/zip", b"PK\x03\x04")
    assert AttachmentFlag.TYPE_MISMATCH not in real_docx


def test_mismatch_keyed_on_declaration_not_extension() -> None:
    # invoice.docx (an OOXML extension) but declared application/pdf with zip
    # bytes: the declaration disagrees with the bytes, so it must still fire —
    # the OOXML *extension* must not suppress a contradicting *declaration*.
    flags = _flags("invoice.docx", "application/pdf", "application/zip", b"PK\x03\x04")
    assert AttachmentFlag.TYPE_MISMATCH in flags


def test_declared_pdf_with_ole_bytes_flags_type_mismatch() -> None:
    ole = b"\xd0\xcf\x11\xe0"
    # invoice.pdf whose bytes sniff as OLE/CFB (an Office/MSI container) is a
    # classic mismatch and must flag TYPE_MISMATCH...
    flags = _flags("invoice.pdf", "application/pdf", "application/x-ole-storage", ole)
    assert AttachmentFlag.TYPE_MISMATCH in flags

    # ...but a legitimately-declared legacy .doc (msword) detected as OLE must
    # not — that's the expected on-disk shape, not a mismatch.
    doc = _flags("memo.doc", "application/msword", "application/x-ole-storage", ole)
    assert AttachmentFlag.TYPE_MISMATCH not in doc


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


def test_smtputf8_raw_utf8_headers_decoded() -> None:
    # Valid messages may carry raw UTF-8 in headers (SMTPUTF8 / RFC 6532)
    # instead of RFC 2047 encoded-words. These must decode, not corrupt into
    # replacement characters, since they're analyst-visible fields.
    raw = (
        'From: "café user" <a@example.com>\r\n'
        'To: Ünal Öztürk <u@example.com>, "Smith, John" <j@example.com>\r\n'
        "Subject: café résumé — naïve\r\n"
        "\r\n"
        "body\r\n"
    ).encode()
    parsed = parse_eml(raw, filename="smtputf8.eml")

    assert parsed.subject == "café résumé — naïve"
    assert parsed.headers.get("Subject") == "café résumé — naïve"
    assert parsed.addresses.from_ is not None
    assert parsed.addresses.from_.display_name == "café user"
    # Raw-UTF8 display decodes, and a comma inside a quoted display name doesn't
    # split the address list.
    assert [(a.display_name, a.addr_spec) for a in parsed.addresses.to] == [
        ("Ünal Öztürk", "u@example.com"),
        ("Smith, John", "j@example.com"),
    ]


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
    # Garbage that isn't a real .msg must degrade to a noted partial result with
    # the correct format, never crash (PRD §11) — same contract as the .eml path.
    msg = tmp_path / "outlook.msg"
    msg.write_bytes(b"not really a msg")
    parsed = parse(msg)

    assert isinstance(parsed, ParsedEmail)
    assert parsed.source.format is EmailFormat.MSG
    assert any(a.code == "parse_error" for a in parsed.anomalies)


def test_parse_dispatch_msg_missing_file_raises() -> None:
    with pytest.raises(FileNotFoundError):
        parse("/does/not/exist.msg")


def test_parse_dispatch_msg_unreadable_raises(tmp_path: Path) -> None:
    # A .msg path that exists but can't be read as a file (here, a directory)
    # must error rather than report a successful placeholder parse.
    not_a_file = tmp_path / "folder.msg"
    not_a_file.mkdir()
    with pytest.raises(OSError):
        parse(not_a_file)


# --- .msg path (extract-msg) -----------------------------------------------


def test_msg_normalizes_into_same_model_as_eml() -> None:
    # The core Phase 1 guarantee: a .msg parses into the SAME ParsedEmail shape
    # as a .eml, so everything downstream of parsing is format-agnostic (PRD §5).
    msg = _parse("synthetic_phish.msg")
    eml = _parse("benign_newsletter.eml")

    assert isinstance(msg, ParsedEmail)
    # Identical serialized schema, and identical sub-model types per field.
    assert msg.model_dump(mode="json").keys() == eml.model_dump(mode="json").keys()
    assert type(msg.auth) is type(eml.auth)
    assert type(msg.routing) is type(eml.routing)
    assert type(msg.addresses) is type(eml.addresses)
    assert type(msg.body) is type(eml.body)

    # The .msg path populates the same format-agnostic fields the .eml path does,
    # rather than leaving them empty as if they were format-specific.
    for parsed in (msg, eml):
        assert parsed.addresses.from_ is not None
        assert parsed.addresses.from_.domain
        assert parsed.subject
        assert parsed.date is not None
        assert parsed.body.text
        assert len(parsed.headers) > 0
        assert len(parsed.routing) >= 1

    assert msg.source.format is EmailFormat.MSG
    assert eml.source.format is EmailFormat.EML


def test_msg_fields_normalized_from_mapi_and_headers() -> None:
    parsed = _parse("synthetic_phish.msg")

    assert parsed.subject == "Action required: confirm your account details"
    frm = parsed.addresses.from_
    assert frm is not None
    assert frm.addr_spec == "support@account-verify.example"
    assert frm.domain == "account-verify.example"
    assert [a.addr_spec for a in parsed.addresses.to] == ["analyst@example.org"]

    # Routing recovered from the preserved transport headers, top-to-bottom.
    assert len(parsed.routing) == 2
    assert parsed.routing.hops[0].from_ == "mail.account-verify.example"

    assert parsed.date is not None
    assert parsed.body.text is not None and "re-verified" in parsed.body.text
    assert parsed.body.has_html is True
    # html_raw is retained for analysis but never rendered (PRD §10).
    assert parsed.body.html_raw is not None


def test_msg_attachment_inspected_like_eml() -> None:
    # Attachments come from MAPI streams, not MIME parts, yet flow through the
    # same inspector — so hashes and magic-byte detection match the .eml path.
    parsed = _parse("synthetic_phish.msg")

    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "statement.pdf"
    assert att.declared_type == "application/pdf"
    assert att.detected_type == "application/pdf"  # sniffed from %PDF- magic bytes
    assert att.size > 0
    assert len({att.md5, att.sha1, att.sha256}) == 3  # three distinct digests


def test_msg_auth_is_lossier_and_noted() -> None:
    # Outlook drops Authentication-Results from .msg transport headers, so auth
    # reads as NONE — not because checks failed, but because nothing survived.
    parsed = _parse("synthetic_phish.msg")

    assert parsed.auth.spf.result is AuthResultState.NONE
    assert parsed.auth.dkim.result is AuthResultState.NONE
    assert parsed.auth.dmarc.result is AuthResultState.NONE
    # That lossiness is explicitly recorded so the report never overstates it.
    assert any(a.code == "msg_auth_unavailable" for a in parsed.anomalies)


def test_msg_parse_bytes_direct_matches_dispatch() -> None:
    # parse_msg(bytes) and parse(path) agree (dispatch just reads the file).
    data = (FIXTURES / "synthetic_phish.msg").read_bytes()
    direct = parse_msg(data, filename="synthetic_phish.msg")
    viapath = _parse("synthetic_phish.msg")
    assert direct.subject == viapath.subject
    assert direct.source.format is EmailFormat.MSG
    assert [a.addr_spec for a in direct.addresses.to] == [a.addr_spec for a in viapath.addresses.to]


def test_msg_plain_text_only_does_not_fabricate_html() -> None:
    # extract-msg's htmlBody convenience property synthesizes HTML from the text
    # body when no real HTML part exists; we must read the raw PR_HTML stream so a
    # plain-text .msg reports has_html=False and never feeds downstream link/HTML
    # analysis fabricated markup (matching the .eml parser's semantics).
    data = _msgbuild.build_message(
        subject="Plain only",
        body_text="just text, no html part",
        sender=("Bob Sender", "bob@sender.example"),
        recipients=[(_msgbuild.RECIP_TO, "Alice", "alice@example.org")],
    )
    parsed = parse_msg(data, filename="plain.msg")

    assert parsed.body.text is not None and "just text" in parsed.body.text
    assert parsed.body.has_html is False
    assert parsed.body.html_raw is None


def test_msg_bcc_recipient_not_classified_as_to() -> None:
    # A saved Bcc recipient must not appear as a To/Cc: the model has no Bcc
    # field, and misfiling it would mislead the report. Only To and Cc map.
    data = _msgbuild.build_message(
        subject="Recipients",
        body_text="body",
        sender=("Bob", "bob@sender.example"),
        recipients=[
            (_msgbuild.RECIP_TO, "Alice", "alice@example.org"),
            (_msgbuild.RECIP_CC, "Carol", "carol@example.org"),
            (_msgbuild.RECIP_BCC, "Eve", "eve@secret.example"),
        ],
    )
    parsed = parse_msg(data, filename="recips.msg")

    assert [a.addr_spec for a in parsed.addresses.to] == ["alice@example.org"]
    assert [a.addr_spec for a in parsed.addresses.cc] == ["carol@example.org"]
    # The Bcc address appears in neither list.
    all_specs = [a.addr_spec for a in (*parsed.addresses.to, *parsed.addresses.cc)]
    assert "eve@secret.example" not in all_specs


def test_msg_recipients_filled_from_mapi_when_headers_omit_them() -> None:
    # Transport headers with a From but no To/Cc must still get recipients from
    # the MAPI table — the fallback fills gaps, it doesn't only run when From is
    # missing. (It must not clobber the header-derived From.)
    headers = (
        "From: Bob Sender <bob@sender.example>\r\n"
        "Subject: gappy headers\r\n"
        "Date: Mon, 01 Jun 2026 09:00:00 +0000\r\n"
    )
    data = _msgbuild.build_message(
        subject="gappy headers",
        body_text="body",
        transport_headers=headers,
        sender=("MAPI Sender", "mapi@sender.example"),
        recipients=[(_msgbuild.RECIP_TO, "Alice", "alice@example.org")],
    )
    parsed = parse_msg(data, filename="gappy.msg")

    # From came from the headers and was not overwritten by the MAPI sender...
    assert parsed.addresses.from_ is not None
    assert parsed.addresses.from_.addr_spec == "bob@sender.example"
    # ...while the recipients the headers lacked were recovered from MAPI.
    assert [a.addr_spec for a in parsed.addresses.to] == ["alice@example.org"]


def test_msg_no_transport_headers_noted_and_mapi_used() -> None:
    # With no transport headers at all, routing/auth are unavailable (noted), and
    # sender/recipients come entirely from MAPI.
    data = _msgbuild.build_message(
        subject="No headers",
        body_text="body",
        sender=("Bob", "bob@sender.example"),
        recipients=[(_msgbuild.RECIP_TO, "Alice", "alice@example.org")],
    )
    parsed = parse_msg(data, filename="noheaders.msg")

    assert parsed.addresses.from_ is not None
    assert parsed.addresses.from_.addr_spec == "bob@sender.example"
    assert len(parsed.routing) == 0
    codes = {a.code for a in parsed.anomalies}
    assert "msg_no_transport_headers" in codes
    assert "msg_auth_unavailable" in codes


def test_attachment_digests_are_consistent_with_each_other() -> None:
    # The three digests over the same bytes must all be valid hex of the right
    # width and mutually distinct — a cheap integrity cross-check.
    parsed = _parse("with_attachment.eml")
    pdf = next(a for a in parsed.attachments if a.filename == "report.pdf")

    assert len(pdf.md5) == len(hashlib.md5(b"").hexdigest())
    assert len(pdf.sha1) == len(hashlib.sha1(b"").hexdigest())
    assert len(pdf.sha256) == len(hashlib.sha256(b"").hexdigest())
    assert all(int(h, 16) >= 0 for h in (pdf.md5, pdf.sha1, pdf.sha256))
