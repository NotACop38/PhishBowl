"""Generate the synthetic ``.msg`` fixture (``synthetic_phish.msg``).

A ``.msg`` is an OLE/CFB compound document carrying MAPI property streams, not
an RFC 822 text file — so unlike the ``.eml`` fixtures we can't hand-author it
in a text editor. This script builds one **from scratch and entirely
synthetically** (CLAUDE.md: only synthetic samples are ever committed — no real
message, no live links, no PII, no malware) and writes the bytes to
``synthetic_phish.msg`` next to it.

It is committed for provenance/reproducibility: anyone can re-run
``python tests/fixtures/build_synthetic_msg.py`` to regenerate the exact fixture
and audit that it is fabricated. The output is deterministic.

The message mirrors the shape of the ``.eml`` fixtures (sender/recipient,
subject, body, one PDF attachment, transport ``Received`` headers) so the parse
layer can be proven format-agnostic — *but it deliberately omits
``Authentication-Results``*, which is the common real-world lossiness of ``.msg``
(Outlook frequently drops auth results from the saved transport headers). That
exercises the ".msg auth is lossier" anomaly note in the parser.

Two small builders live here:

- :func:`write_cfb` — a minimal Compound File Binary (CFB / OLE2) writer.
  ``olefile`` (which ``extract-msg`` reads through) can only rewrite same-size
  streams in an existing container, never create one, so we emit the structure
  ourselves: header, FAT, MiniFAT + mini stream, and a directory red-black tree.
- :func:`build_msg` — lays out the MAPI streams/storages ``extract-msg`` expects
  (``__properties_version1.0``, ``__substg1.0_*`` property streams, and the
  ``__recip``/``__attach`` storages).

This is a test-fixture generator, not part of the shipped package.
"""

from __future__ import annotations

import math
import struct
from datetime import UTC, datetime
from pathlib import Path

# --- Minimal CFB / OLE2 writer ---------------------------------------------

_SECTOR = 512
_MINI = 64
_MINI_CUTOFF = 4096

_FREE = 0xFFFFFFFF
_END = 0xFFFFFFFE
_FATSECT = 0xFFFFFFFD
_NOSTREAM = 0xFFFFFFFF


class _Entry:
    """One CFB directory entry — a storage (type 1), stream (2), or root (5)."""

    def __init__(self, name: str, etype: int) -> None:
        self.name = name
        self.etype = etype
        self.left = _NOSTREAM
        self.right = _NOSTREAM
        self.child = _NOSTREAM
        self.start = _END
        self.size = 0
        self.data = b""


def _cfb_key(name: str) -> tuple[int, str]:
    # CFB orders directory siblings by UTF-16 name length first, then by
    # uppercased name ([MS-CFB] §2.6.4).
    return (len(name), name.upper())


def _build_tree(child_indices: list[int], entries: list[_Entry]) -> int:
    """Link ``child_indices`` into a balanced BST; return the subtree root index."""
    if not child_indices:
        return _NOSTREAM
    ordered = sorted(child_indices, key=lambda i: _cfb_key(entries[i].name))

    def rec(lo: int, hi: int) -> int:
        if lo > hi:
            return _NOSTREAM
        mid = (lo + hi) // 2
        entry = entries[ordered[mid]]
        entry.left = rec(lo, mid - 1)
        entry.right = rec(mid + 1, hi)
        return ordered[mid]

    return rec(0, len(ordered) - 1)


def _flatten(tree: dict, entries: list[_Entry], parent: _Entry) -> None:
    """Recursively add ``tree`` (dict=storage, bytes=stream) under ``parent``."""
    children: list[int] = []
    for name, value in tree.items():
        if isinstance(value, dict):
            entry = _Entry(name, 1)
            entries.append(entry)
            children.append(len(entries) - 1)
            _flatten(value, entries, entry)
        else:
            entry = _Entry(name, 2)
            entry.data = value
            entry.size = len(value)
            entries.append(entry)
            children.append(len(entries) - 1)
    parent.child = _build_tree(children, entries)


def write_cfb(tree: dict) -> bytes:
    """Serialize a nested ``{name: bytes | {...}}`` tree into CFB/OLE2 bytes."""
    entries: list[_Entry] = [_Entry("Root Entry", 5)]
    _flatten(tree, entries, entries[0])

    # MiniFAT + mini stream: every stream smaller than the 4096-byte cutoff
    # lives in 64-byte mini-sectors inside the root's mini stream.
    mini_sectors: list[bytes] = []
    minifat: list[int] = []

    def mini_alloc(data: bytes) -> int:
        count = (len(data) + _MINI - 1) // _MINI
        start = len(mini_sectors)
        padded = data.ljust(count * _MINI, b"\x00")
        for k in range(count):
            mini_sectors.append(padded[k * _MINI : (k + 1) * _MINI])
            minifat.append(_END if k == count - 1 else start + k + 1)
        return start

    big_streams: list[_Entry] = []
    for entry in entries:
        if entry.etype == 2:
            if 0 < entry.size < _MINI_CUTOFF:
                entry.start = mini_alloc(entry.data)
            elif entry.size >= _MINI_CUTOFF:
                big_streams.append(entry)
            else:
                entry.start = _END
    mini_stream = b"".join(mini_sectors)

    # Big (regular 512-byte) sectors and the FAT that chains them.
    fat: list[int] = []
    sectors: list[bytes] = []

    def alloc(data: bytes) -> int:
        if not data:
            return _END
        count = (len(data) + _SECTOR - 1) // _SECTOR
        start = len(sectors)
        padded = data.ljust(count * _SECTOR, b"\x00")
        for k in range(count):
            sectors.append(padded[k * _SECTOR : (k + 1) * _SECTOR])
            fat.append(_END if k == count - 1 else start + k + 1)
        return start

    for entry in big_streams:
        entry.start = alloc(entry.data)
    entries[0].start = alloc(mini_stream)
    entries[0].size = len(mini_stream)

    directory = b"".join(_pack_direntry(e) for e in entries)
    dir_start = alloc(directory)

    while len(minifat) % (_SECTOR // 4):
        minifat.append(_FREE)
    minifat_bytes = b"".join(struct.pack("<I", x) for x in minifat)
    num_minifat = len(minifat_bytes) // _SECTOR
    minifat_start = alloc(minifat_bytes) if minifat_bytes else _END

    # Reserve FAT sectors (which themselves must be accounted for in the FAT).
    nsect = len(sectors)
    nfat = 1
    while math.ceil((nsect + nfat) / (_SECTOR // 4)) > nfat:
        nfat += 1
    fat_start = len(sectors)
    for _ in range(nfat):
        fat.append(_FATSECT)
        sectors.append(b"")
    while len(fat) % (_SECTOR // 4):
        fat.append(_FREE)
    fat_bytes = b"".join(struct.pack("<I", x) for x in fat)
    for k in range(nfat):
        sectors[fat_start + k] = fat_bytes[k * _SECTOR : (k + 1) * _SECTOR]

    header = bytearray(_SECTOR)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<H", header, 24, 0x3E)  # minor version
    struct.pack_into("<H", header, 26, 0x03)  # major version (512-byte sectors)
    struct.pack_into("<H", header, 28, 0xFFFE)  # little-endian byte order
    struct.pack_into("<H", header, 30, 9)  # sector shift -> 512
    struct.pack_into("<H", header, 32, 6)  # mini sector shift -> 64
    struct.pack_into("<I", header, 44, nfat)
    struct.pack_into("<I", header, 48, dir_start)
    struct.pack_into("<I", header, 56, _MINI_CUTOFF)
    struct.pack_into("<I", header, 60, minifat_start)
    struct.pack_into("<I", header, 64, num_minifat)
    struct.pack_into("<I", header, 68, _END)  # first DIFAT sector (none)
    for i in range(109):  # DIFAT array in the header
        struct.pack_into("<I", header, 76 + i * 4, fat_start + i if i < nfat else _FREE)

    return bytes(header) + b"".join(sectors)


def _pack_direntry(entry: _Entry) -> bytes:
    name = entry.name.encode("utf-16-le") + b"\x00\x00"
    name = name[:64].ljust(64, b"\x00")
    return (
        name
        + struct.pack("<H", (len(entry.name) + 1) * 2)
        + struct.pack("<BB", entry.etype, 1)  # object type, color=black
        + struct.pack("<III", entry.left, entry.right, entry.child)
        + b"\x00" * 16  # CLSID
        + b"\x00" * 4  # state bits
        + b"\x00" * 8  # creation time
        + b"\x00" * 8  # modified time
        + struct.pack("<I", entry.start)
        + struct.pack("<Q", entry.size)
    )


# --- MAPI property helpers --------------------------------------------------


def _unistr(text: str) -> bytes:
    """A PtypString (``...001F``) stream payload: UTF-16-LE, no terminator."""
    return text.encode("utf-16-le")


def _fixed_prop(prop_id: int, prop_type: int, value: bytes) -> bytes:
    """One 16-byte fixed-length property entry for a ``__properties`` stream."""
    return (
        struct.pack("<H", prop_type)
        + struct.pack("<H", prop_id)
        + struct.pack("<I", 0x06)  # flags: readable | writable
        + value.ljust(8, b"\x00")[:8]
    )


def _filetime(dt: datetime) -> bytes:
    """A PtypTime value: FILETIME (100-ns ticks since 1601-01-01), as int64 LE."""
    epoch = datetime(1601, 1, 1, tzinfo=UTC)
    ticks = int((dt - epoch).total_seconds() * 10_000_000)
    return struct.pack("<q", ticks)


def _message_properties(rc: int, ac: int, props: bytes) -> bytes:
    # Top-level message __properties: 32-byte header then 16-byte entries.
    header = (
        b"\x00" * 8
        + struct.pack("<I", rc + 1)  # next recipient id
        + struct.pack("<I", ac + 1)  # next attachment id
        + struct.pack("<I", rc)  # recipient count
        + struct.pack("<I", ac)  # attachment count
        + b"\x00" * 8
    )
    return header + props


def _sub_properties(props: bytes) -> bytes:
    # Recipient/attachment __properties: 8-byte reserved header then entries.
    return b"\x00" * 8 + props


# --- Fixture content (entirely synthetic) ----------------------------------

_SUBJECT = "Action required: confirm your account details"

_BODY_TEXT = (
    "Hello,\r\n\r\n"
    "Our records show your account needs to be re-verified within 24 hours.\r\n"
    "Please review the attached statement and confirm your details.\r\n\r\n"
    "Account Services\r\n"
)

_BODY_HTML = (
    b"<html><body><p>Hello,</p>"
    b"<p>Our records show your account needs to be re-verified within 24 hours.</p>"
    b"<p>Account Services</p></body></html>"
)

# Transport headers as Outlook would persist them — note there is NO
# Authentication-Results header (the realistic .msg auth lossiness).
_TRANSPORT_HEADERS = (
    "Received: from mail.account-verify.example (mail.account-verify.example "
    "[203.0.113.10])\r\n"
    "\tby mx.example.org (Postfix) with ESMTPS id 4ABCD1234\r\n"
    "\tfor <analyst@example.org>; Mon, 01 Jun 2026 09:30:00 +0000\r\n"
    "Received: from web01.account-verify.example (web01.account-verify.example "
    "[203.0.113.20])\r\n"
    "\tby mail.account-verify.example (Postfix) with ESMTP id 1234ABCD;\r\n"
    "\tMon, 01 Jun 2026 09:29:58 +0000\r\n"
    'From: "Account Services" <support@account-verify.example>\r\n'
    "To: Security Analyst <analyst@example.org>\r\n"
    "Subject: Action required: confirm your account details\r\n"
    "Date: Mon, 01 Jun 2026 09:29:55 +0000\r\n"
    "Message-ID: <synthetic-0001@account-verify.example>\r\n"
    "MIME-Version: 1.0\r\n"
    'Content-Type: multipart/mixed; boundary="synthetic-boundary"\r\n'
)

# A tiny, inert synthetic PDF (header + trailer only) — not a real document.
_PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"

_DATE = datetime(2026, 6, 1, 9, 29, 55, tzinfo=UTC)


# RecipientType MAPI values (PR_RECIPIENT_TYPE, 0x0C15): To / Cc / Bcc.
RECIP_TO = 1
RECIP_CC = 2
RECIP_BCC = 3

# The named-properties storage. Modern extract-msg (>=0.48) requires the
# GUID/entry/names streams to be present to open the file at all; an empty set of
# all three is the valid "no named properties" state.
_EMPTY_NAMEID = {
    "__substg1.0_00020102": b"",  # GUID stream
    "__substg1.0_00030102": b"",  # entry stream
    "__substg1.0_00040102": b"",  # names stream
}


def build_message(
    *,
    subject: str | None = None,
    body_text: str | None = None,
    html: bytes | None = None,
    transport_headers: str | None = None,
    sender: tuple[str, str] | None = None,
    recipients: list[tuple[int, str, str]] | None = None,
    attachments: list[tuple[str, str, bytes]] | None = None,
    date: datetime | None = None,
) -> bytes:
    """Assemble a synthetic ``.msg`` from high-level parts and serialize to bytes.

    Everything is optional so tests can exercise specific paths (e.g. a
    plain-text-only message, or one with no transport headers). ``sender`` is a
    ``(name, smtp)`` pair; ``recipients`` are ``(RECIP_*, name, smtp)`` triples;
    ``attachments`` are ``(filename, mimetype, data)`` triples.
    """
    recipients = recipients or []
    attachments = attachments or []

    props = _fixed_prop(0x340D, 0x0003, struct.pack("<I", 0x40000))  # STORE_UNICODE_OK
    if date is not None:
        props += _fixed_prop(0x0E06, 0x0040, _filetime(date))  # delivery time
        props += _fixed_prop(0x0E07, 0x0003, struct.pack("<I", 0x01))  # msg flags: read

    tree: dict = {
        "__nameid_version1.0": dict(_EMPTY_NAMEID),
        "__properties_version1.0": _message_properties(
            rc=len(recipients), ac=len(attachments), props=props
        ),
        "__substg1.0_001A001F": _unistr("IPM.Note"),  # message class (a mail item)
    }
    if subject is not None:
        tree["__substg1.0_0037001F"] = _unistr(subject)
    if body_text is not None:
        tree["__substg1.0_1000001F"] = _unistr(body_text)
    if html is not None:
        tree["__substg1.0_10130102"] = html
    if transport_headers is not None:
        tree["__substg1.0_007D001F"] = _unistr(transport_headers)
    if sender is not None:
        name, smtp = sender
        tree["__substg1.0_0C1A001F"] = _unistr(name)
        tree["__substg1.0_5D01001F"] = _unistr(smtp)
        tree["__substg1.0_0C1F001F"] = _unistr(smtp)

    for i, (rtype, name, smtp) in enumerate(recipients):
        tree[f"__recip_version1.0_#{i:08X}"] = {
            "__properties_version1.0": _sub_properties(
                _fixed_prop(0x0C15, 0x0003, struct.pack("<I", rtype)),
            ),
            "__substg1.0_3001001F": _unistr(name),
            "__substg1.0_39FE001F": _unistr(smtp),
            "__substg1.0_3003001F": _unistr(smtp),
        }

    for i, (filename, mimetype, data) in enumerate(attachments):
        tree[f"__attach_version1.0_#{i:08X}"] = {
            "__properties_version1.0": _sub_properties(
                _fixed_prop(0x3705, 0x0003, struct.pack("<I", 1)),  # ATTACH_BY_VALUE
            ),
            "__substg1.0_37010102": data,  # attachment data (binary)
            "__substg1.0_3704001F": _unistr(filename),  # short filename
            "__substg1.0_3707001F": _unistr(filename),  # long filename
            "__substg1.0_370E001F": _unistr(mimetype),  # mime type
        }

    return write_cfb(tree)


def build_msg() -> bytes:
    """The committed synthetic phishing fixture (sender, recipient, body, PDF)."""
    return build_message(
        subject=_SUBJECT,
        body_text=_BODY_TEXT,
        html=_BODY_HTML,
        transport_headers=_TRANSPORT_HEADERS,
        sender=("Account Services", "support@account-verify.example"),
        recipients=[(RECIP_TO, "Security Analyst", "analyst@example.org")],
        attachments=[("statement.pdf", "application/pdf", _PDF)],
        date=_DATE,
    )


def main() -> None:
    out = Path(__file__).parent / "synthetic_phish.msg"
    out.write_bytes(build_msg())
    print(f"wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
