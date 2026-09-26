"""Attachment inspection (PRD §6.1 / §7 — *Attachments*).

Attachments are described by **metadata and hashes only**. PhishBowl never
executes an attachment and never extracts an archive (AGENTS.md defensive
invariants): we read the bytes, hash them, sniff a handful of magic-byte
signatures, and set structural red-flags from the filename + declared type +
detected type. Nothing here opens, runs, or unpacks anything.

Flags set (mirrors :class:`AttachmentFlag`):

- ``ARCHIVE`` — detected as a real archive container (zip/rar/7z/gz/…), but not
  an Office Open XML document (those are zip-based yet aren't "archives").
- ``MACRO_CAPABLE`` — macro-enabled Office extension (``.docm`` / ``.xlsm`` / …).
- ``EXECUTABLE`` — executable / script / installer / LNK / ISO / disk-image, by
  magic bytes or extension.
- ``TYPE_MISMATCH`` — declared content-type disagrees with the detected family.
- ``DOUBLE_EXTENSION`` — a disguised extension: ``invoice.pdf.exe``-style
  trailing dangerous extension, or a bidirectional-override character that makes
  the name display with a different extension.
- ``PASSWORD_PROTECTED`` — a zip entry with its encryption bit set (read from
  the central directory; best-effort).
- ``HTML`` — an HTML-family document a browser renders (HTML, SVG, MHT), by
  extension, declared type, or leading markup.
"""

from __future__ import annotations

import binascii
import hashlib
import io
import struct
from email.generator import BytesGenerator
from email.message import Message

from phishbowl.models import Attachment, AttachmentFlag

from .charset import decode_mime_words
from .limits import MAX_PARTS

# Every OLE2 / Compound File Binary container (legacy Office, MSI, Outlook
# ``.msg``) opens with this signature; no RFC 822 message can.
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# --- Magic-byte signatures -------------------------------------------------
# (prefix, detected content-type). Order matters: more specific first. We only
# ever read the leading bytes; we never interpret or run the content.
_SIGNATURES: list[tuple[bytes, str]] = [
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"\x7fELF", "application/x-executable"),
    (b"MZ", "application/x-dosexec"),
    (b"PK\x03\x04", "application/zip"),
    (b"PK\x05\x06", "application/zip"),  # empty archive
    (b"Rar!\x1a\x07", "application/x-rar-compressed"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (b"\x1f\x8b", "application/gzip"),
    (b"BZh", "application/x-bzip2"),
    (b"\xfd7zXZ\x00", "application/x-xz"),
    (OLE_MAGIC, "application/x-ole-storage"),
    (b"{\\rtf", "application/rtf"),
]

# Browser-rendered markup, sniffed from the leading bytes (after an optional
# UTF-8 BOM and whitespace). Only unambiguous document openers are matched.
_MARKUP_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"<!doctype html", "text/html"),
    (b"<html", "text/html"),
    (b"<svg", "image/svg+xml"),
)
_MARKUP_SNIFF_BYTES = 1024

# Detected types that are archive containers.
_ARCHIVE_TYPES = {
    "application/zip",
    "application/x-rar-compressed",
    "application/x-7z-compressed",
    "application/gzip",
    "application/x-bzip2",
    "application/x-xz",
}

# Detected types that are executable / runnable.
_EXECUTABLE_TYPES = {"application/x-dosexec", "application/x-executable"}

# Extensions that make an attachment directly dangerous (executable / script /
# installer / shortcut / disk image), used for the EXECUTABLE and
# DOUBLE_EXTENSION flags (PRD §8).
_DANGEROUS_EXTS = {
    "exe",
    "scr",
    "com",
    "pif",
    "bat",
    "cmd",
    "msi",
    "dll",
    "cpl",
    "js",
    "jse",
    "vbs",
    "vbe",
    "wsf",
    "wsh",
    "hta",
    "ps1",
    "psm1",
    "jar",
    "lnk",
    "iso",
    "img",
    "vhd",
    "vhdx",
    # Also directly dangerous, and common in recent campaigns: OneNote
    # notebooks, Excel add-ins, compiled help, shortcuts to remote content,
    # registry and management-console files, app packages, scriptlets.
    "one",
    "onepkg",
    "xll",
    "chm",
    "url",
    "scf",
    "reg",
    "msc",
    "inf",
    "sct",
    "wsc",
    "appx",
    "appxbundle",
    "msix",
    "msixbundle",
    "application",
    "gadget",
    "iqy",
    "slk",
    "settingcontent-ms",
    "library-ms",
    "search-ms",
}

# HTML-family documents a browser renders. Attached HTML/SVG files are a common
# credential-phishing and HTML-smuggling vector (AttachmentFlag.HTML).
_HTML_EXTS = {"html", "htm", "shtml", "xhtml", "mht", "mhtml", "svg", "svgz"}
_HTML_TYPES = {
    "text/html",
    "application/xhtml+xml",
    "image/svg+xml",
    "multipart/related",
    "message/rfc822+mhtml",
}

# Macro-enabled Office Open XML (zip-based) extensions.
_OOXML_MACRO_EXTS = {
    "docm",
    "dotm",
    "xlsm",
    "xltm",
    "xlam",
    "pptm",
    "potm",
    "ppam",
    "ppsm",
    "sldm",
    # Excel binary workbooks are zip containers that can carry VBA macros.
    "xlsb",
}

# Legacy OLE (CFB) Office extensions — these can all carry VBA macros too, and
# unlike the modern non-``m`` Open XML formats there is no macro-free variant.
_LEGACY_MACRO_EXTS = {
    "doc",
    "dot",
    "xls",
    "xlt",
    "xla",
    "ppt",
    "pot",
    "pps",
    "ppa",
}

# Any macro-capable Office extension (PRD §8 — MACRO_CAPABLE flag).
_MACRO_EXTS = _OOXML_MACRO_EXTS | _LEGACY_MACRO_EXTS

# Office Open XML (zip-based) extensions — zip magic on these is expected and
# must NOT be flagged ARCHIVE or as a type mismatch. Legacy OLE formats are
# excluded: they are CFB containers, not zips.
_OOXML_EXTS = {
    "docx",
    "dotx",
    "xlsx",
    "xltx",
    "pptx",
    "potx",
    "ppsx",
} | _OOXML_MACRO_EXTS

# Map declared content-types and detected types to a coarse "family" for the
# mismatch check. ``None`` means "ambiguous — don't judge".
_DECLARED_FAMILY = {
    "application/pdf": "pdf",
    "application/rtf": "rtf",
    "text/rtf": "rtf",
    "image/png": "image",
    "image/jpeg": "image",
    "image/gif": "image",
    "application/zip": "zip",
    "application/x-zip-compressed": "zip",
    "application/gzip": "archive",
    "application/x-rar-compressed": "archive",
    "application/x-7z-compressed": "archive",
    # Legacy Office (OLE/CFB containers): a declaration of these whose bytes
    # sniff as something else (PDF, PE, …) is a spoof.
    "application/msword": "ole",
    "application/vnd.ms-excel": "ole",
    "application/vnd.ms-powerpoint": "ole",
    "application/vnd.ms-office": "ole",
    # Modern Office Open XML (zip containers) — declaring these is consistent
    # with zip magic on disk, so that pairing must NOT count as a mismatch.
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "zip",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "zip",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "zip",
    "application/vnd.ms-word.document.macroenabled.12": "zip",
    "application/vnd.ms-excel.sheet.macroenabled.12": "zip",
    "application/vnd.ms-powerpoint.presentation.macroenabled.12": "zip",
    "text/html": "html",
    "application/xhtml+xml": "html",
    "image/svg+xml": "html",
}
_DETECTED_FAMILY = {
    "application/pdf": "pdf",
    "application/rtf": "rtf",
    "image/png": "image",
    "image/jpeg": "image",
    "image/gif": "image",
    "application/zip": "zip",
    "application/x-rar-compressed": "archive",
    "application/x-7z-compressed": "archive",
    "application/gzip": "archive",
    "application/x-bzip2": "archive",
    "application/x-xz": "archive",
    "application/x-dosexec": "executable",
    "application/x-executable": "executable",
    # OLE/CFB container (legacy Office, MSI, …). A file declared e.g.
    # application/pdf whose bytes sniff as OLE is a classic mismatch.
    "application/x-ole-storage": "ole",
    # Markup declared as a PDF or image is the HTML-smuggling disguise.
    "text/html": "html",
    "image/svg+xml": "html",
}


def is_other_inline_text(part: Message) -> bool:
    """True for an inline body part in a text format other than plain text/HTML.

    ``text/calendar`` invitations are the common case. Such a part is both
    listed with the attachments (so its hashes are kept) and scanned as plain
    text for indicators.
    """
    return (
        part.get_content_maintype() == "text"
        and part.get_content_type() not in {"text/plain", "text/html"}
        and part.get_content_disposition() != "attachment"
        and part.get_filename() is None
    )


def is_attachment(part: Message) -> bool:
    """True if ``part`` is an attachment rather than a body part.

    A part counts as an attachment when it is an attached message
    (``message/rfc822``), explicitly dispositioned as one, carries a filename,
    or is a leaf other than text/plain or text/html. Multipart containers and
    supported text body parts — including ``Content-Disposition: inline`` text — are not.
    """
    maintype = part.get_content_maintype()
    # An attached email is an attachment to capture, not a container to descend
    # into (the stdlib reports message/rfc822 as multipart). Handled first so
    # the is_multipart() guard below doesn't swallow it.
    if maintype == "message":
        return True
    if part.is_multipart():
        return False
    # A part that declares multipart but failed to split (malformed boundary)
    # is a parse artifact, not a real attachment.
    if maintype == "multipart":
        return False
    disposition = part.get_content_disposition()
    if disposition == "attachment":
        return True
    if part.get_filename() is not None:
        return True
    # Unsupported text formats remain visible as metadata-only attachments.
    return part.get_content_type() not in {"text/plain", "text/html"}


def iter_parts(part: Message, *, max_parts: int | None = None, include_containers: bool = False):
    """Walk a message, treating ``message/*`` parts as opaque attachment leaves.

    Unlike :meth:`email.message.Message.walk`, this does not descend into an
    attached ``message/rfc822``: the enclosed email is yielded whole (so it is
    hashed as one attachment) and its inner parts never leak into the outer
    body or attachment set. Parts are yielded in document order (depth-first,
    pre-order).

    Defensive cap: the walk is **iterative** (no recursion) and counts *every*
    node it visits — multipart containers included — toward ``max_parts``, then
    stops. That bounds both a high-fan-out tree and a deeply *nested* one (a
    "MIME bomb"), neither of which can drive unbounded work or blow the recursion
    limit (see :mod:`phishbowl.parse.limits`). ``max_parts`` defaults to
    :data:`~phishbowl.parse.limits.MAX_PARTS`; :func:`~phishbowl.parse.mime.bounded_message`
    already refuses larger trees, so this is a second, independent bound.
    """
    limit = MAX_PARTS if max_parts is None else max_parts
    visited = 0
    stack: list[Message] = [part]
    while stack:
        node = stack.pop()
        visited += 1
        if visited > limit:
            return
        if node.get_content_maintype() == "message":
            # Opaque attachment leaf — yield whole, never descend into it.
            yield node
            continue
        if node.is_multipart():
            if include_containers:
                yield node
            payload = node.get_payload()
            if isinstance(payload, list):
                # Push children reversed so popping restores document order.
                stack.extend(reversed(payload))
                continue
        yield node


def detect_type(data: bytes) -> str | None:
    """Sniff a content-type from leading magic bytes, or ``None`` if unknown."""
    for prefix, content_type in _SIGNATURES:
        if data.startswith(prefix):
            return content_type
    head = data[:_MARKUP_SNIFF_BYTES].removeprefix(b"\xef\xbb\xbf").lstrip().lower()
    if head.startswith(b"<?xml"):
        # An XML prolog (and comments) may precede an SVG root element.
        head = head[head.find(b"?>") + 2 :].lstrip() if b"?>" in head else b""
        if head.startswith(b"<!--") and b"-->" in head:
            head = head[head.find(b"-->") + 3 :].lstrip()
    for prefix, content_type in _MARKUP_SIGNATURES:
        if head.startswith(prefix):
            return content_type
    return None


# Unicode bidirectional controls. In a file name they reorder what the reader
# sees ("invoice\u202efdp.exe" displays as "invoiceexe.pdf").
_BIDI_CONTROLS = frozenset("\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")

# Where a file-name extension implies a detected content family, for the
# extension-vs-content half of the TYPE_MISMATCH check.
_EXTENSION_FAMILY = {
    "pdf": "pdf",
    "png": "image",
    "jpg": "image",
    "jpeg": "image",
    "gif": "image",
    "doc": "ole",
    "xls": "ole",
    "ppt": "ole",
    "rtf": "rtf",
    "html": "html",
    "htm": "html",
    "svg": "html",
}


def _extensions(filename: str | None) -> list[str]:
    """Lowercased extension tokens of ``filename`` (``a.pdf.exe`` → pdf, exe).

    Trailing dots and spaces are dropped first, as Windows does when it saves
    the file: ``invoice.pdf.js .`` is ``invoice.pdf.js`` on disk.
    """
    if not filename:
        return []
    name = filename.strip().rstrip(". \t")
    parts = name.split(".")
    return [p.strip().casefold() for p in parts[1:]] if len(parts) > 1 else []


# Most zip entries whose flags are read, and how far from the end the
# end-of-central-directory record may sit (22 bytes plus a 64 KiB comment).
_MAX_ZIP_ENTRIES = 10_000
_EOCD_SEARCH = 22 + 0xFFFF


def _zip_is_encrypted(data: bytes) -> bool:
    """Best-effort: does any zip entry have its encryption bit set?

    Walks the central directory (found from the end-of-central-directory
    record, so a prefixed or self-extracting zip still counts), reading each
    entry's general-purpose flag — never inflating or extracting anything.
    Falls back to the first local file header when there is no directory.
    """
    eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - _EOCD_SEARCH))
    if eocd >= 0 and len(data) >= eocd + 22:
        count, size, offset = struct.unpack_from("<HII", data, eocd + 10)
        start = eocd - size  # tolerate a prefix: the directory ends at the EOCD
        if start < 0:
            start = offset
        position = start
        for _ in range(min(count, _MAX_ZIP_ENTRIES)):
            if data[position : position + 4] != b"PK\x01\x02" or len(data) < position + 46:
                break
            (flags,) = struct.unpack_from("<H", data, position + 8)
            if flags & 0x0001:
                return True
            name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, position + 28)
            position += 46 + name_len + extra_len + comment_len
    if data.startswith(b"PK\x03\x04") and len(data) >= 8:
        (flags,) = struct.unpack_from("<H", data, 6)
        return bool(flags & 0x0001)
    return False


def _has_zip_directory(data: bytes) -> bool:
    """True if ``data`` ends with a zip central directory (e.g. a prefixed zip)."""
    return data.rfind(b"PK\x05\x06", max(0, len(data) - _EOCD_SEARCH)) >= 0


def _flags(
    filename: str | None,
    declared_type: str | None,
    detected_type: str | None,
    data: bytes,
) -> list[AttachmentFlag]:
    flags: list[AttachmentFlag] = []
    exts = _extensions(filename)
    last_ext = exts[-1] if exts else None
    is_ooxml = bool(exts) and last_ext in _OOXML_EXTS

    # ARCHIVE — a real archive container, but not a zip-based Office document.
    if detected_type in _ARCHIVE_TYPES and not is_ooxml:
        flags.append(AttachmentFlag.ARCHIVE)
    elif last_ext in {"zip", "rar", "7z", "gz", "tar", "bz2", "xz", "cab"}:
        flags.append(AttachmentFlag.ARCHIVE)

    # MACRO_CAPABLE — macro-enabled Office extension.
    if last_ext in _MACRO_EXTS:
        flags.append(AttachmentFlag.MACRO_CAPABLE)

    # EXECUTABLE — by magic bytes or by dangerous extension.
    if detected_type in _EXECUTABLE_TYPES or last_ext in _DANGEROUS_EXTS:
        flags.append(AttachmentFlag.EXECUTABLE)

    # HTML — a browser-rendered document, by extension, declaration, or content.
    declared = (declared_type or "").casefold()
    if (
        last_ext in _HTML_EXTS
        or declared in _HTML_TYPES
        or detected_type in {"text/html", "image/svg+xml"}
    ):
        flags.append(AttachmentFlag.HTML)

    # DOUBLE_EXTENSION — two-plus extensions ending in a dangerous or markup one
    # (``invoice.pdf.exe``, ``remittance.pdf.html``), or a bidi override that
    # makes the displayed extension differ from the real one.
    disguised = any(c in _BIDI_CONTROLS for c in filename or "")
    if disguised or (len(exts) >= 2 and (last_ext in _DANGEROUS_EXTS or last_ext in _HTML_EXTS)):
        flags.append(AttachmentFlag.DOUBLE_EXTENSION)

    # TYPE_MISMATCH — declared family known and contradicts the detected family.
    # Keyed on the DECLARED content-type (not the filename extension): OOXML and
    # legacy Office types map to the container they're expected to be on disk
    # (zip / ole), so a real ``.docx`` (declared OOXML, zip bytes) is consistent,
    # while ``invoice.docx`` declared ``application/pdf`` with zip bytes still
    # fires because the *declaration* (pdf) disagrees with the bytes (zip).
    # The extension is checked the same way: a PE named "invoice.pdf" with a
    # generic declared type is still a mismatch.
    declared_family = _DECLARED_FAMILY.get(declared)
    detected_family = _DETECTED_FAMILY.get(detected_type or "")
    extension_family = _EXTENSION_FAMILY.get(last_ext or "")
    if detected_family and any(
        family and family != detected_family for family in (declared_family, extension_family)
    ):
        flags.append(AttachmentFlag.TYPE_MISMATCH)

    # PASSWORD_PROTECTED — encrypted zip (best-effort, header flag only).
    if _zip_is_encrypted(data):
        flags.append(AttachmentFlag.PASSWORD_PROTECTED)

    return flags


def message_part_bytes(part: Message) -> bytes:
    """The enclosed email of a ``message/*`` part, as bytes.

    The stdlib parses an attached message into a sub-message, discarding its
    original header folding, so it is re-serialized: no header re-wrapping, no
    ``From`` mangling, CRLF line endings — the most wire-faithful form it can
    reproduce. A part that (against RFC 2046) is base64 or quoted-printable
    encoded stays a string payload; it is transfer-decoded instead. Never raises.
    """
    try:
        payload = part.get_payload()
        if isinstance(payload, list) and payload:
            payload = payload[0]
        if isinstance(payload, Message):
            buf = io.BytesIO()
            BytesGenerator(buf, mangle_from_=False, maxheaderlen=0).flatten(payload, linesep="\r\n")
            data = buf.getvalue()
        elif isinstance(payload, str):
            data = payload.encode("utf-8", errors="replace")
        else:
            return b""
        # The parser read an encoded body as a header-less "message"; undo the
        # transfer encoding to recover the enclosed email.
        encoding = str(part.get("Content-Transfer-Encoding", "")).strip().casefold()
        if encoding == "base64":
            return binascii.a2b_base64(data.strip())
        if encoding == "quoted-printable":
            return binascii.a2b_qp(data)
        return data
    except Exception:
        return b""


def _attachment_bytes(part: Message) -> bytes:
    """Transfer-decoded bytes of an attachment part (for hashing/sniffing).

    For an attached ``message/*`` part, ``get_payload(decode=True)`` returns
    ``None`` (it's a container), so the enclosed message is serialized instead —
    still just reading bytes, never executing or extracting anything.
    """
    if part.get_content_maintype() == "message":
        return message_part_bytes(part)
    try:
        data = part.get_payload(decode=True)
    except Exception:
        data = None
    return data if data is not None else b""


def build_attachment_from_bytes(
    filename: str | None, declared_type: str | None, data: bytes
) -> Attachment:
    """Hash and inspect raw attachment ``data`` into an :class:`Attachment`.

    The format-agnostic core of attachment inspection: it works purely from a
    filename, a declared content-type, and the bytes, so both the ``.eml`` (MIME
    part) and ``.msg`` (MAPI stream) paths produce identical :class:`Attachment`
    shapes — same hashes, same magic-byte detection, same structural flags.
    Reads the bytes only to hash and sniff them — never executes, never extracts.
    """
    detected_type = detect_type(data) if data else None
    if detected_type is None and data and _has_zip_directory(data):
        detected_type = "application/zip"  # a zip behind a prefix is still a zip
    return Attachment(
        filename=filename,
        declared_type=declared_type,
        detected_type=detected_type,
        size=len(data),
        # MD5/SHA1/SHA256 here are file-identity *IOC fingerprints* for
        # threat-intel lookup and reporting — never a security/auth control — so
        # the weak-hash concern doesn't apply. usedforsecurity=False states that
        # intent explicitly (and resolves bandit B324).
        md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
        sha1=hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        sha256=hashlib.sha256(data, usedforsecurity=False).hexdigest(),
        flags=_flags(filename, declared_type, detected_type, data),
    )


def build_attachment(part: Message) -> Attachment:
    """Hash and inspect one MIME attachment ``part`` into an :class:`Attachment`.

    Reads the bytes to hash and sniff them — never executes, never extracts.
    """
    return build_attachment_from_bytes(
        filename=decode_mime_words(part.get_filename()),
        declared_type=part.get_content_type(),
        data=_attachment_bytes(part),
    )
