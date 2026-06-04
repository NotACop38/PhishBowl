"""Attachment inspection (PRD §6.1 / §7 — *Attachments*).

Attachments are described by **metadata and hashes only**. Phishbowl never
executes an attachment and never extracts an archive (CLAUDE.md defensive
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
- ``DOUBLE_EXTENSION`` — ``invoice.pdf.exe``-style trailing dangerous extension.
- ``PASSWORD_PROTECTED`` — zip with its encryption bit set (best-effort).
"""

from __future__ import annotations

import hashlib
import io
import struct
from email.generator import BytesGenerator
from email.message import Message

from phishbowl.models import Attachment, AttachmentFlag

from .charset import decode_mime_words
from .limits import MAX_PARTS

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
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),
    (b"{\\rtf", "application/rtf"),
]

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
    "sldm",
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
}


def is_attachment(part: Message) -> bool:
    """True if ``part`` is an attachment rather than a body part.

    A part counts as an attachment when it is an attached message
    (``message/rfc822``), explicitly dispositioned as one, carries a filename,
    or is a non-text leaf (e.g. an inline image). Multipart containers and
    text body parts — including ``Content-Disposition: inline`` text — are not.
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
    # Inline (or undeclared) text parts are body; any non-text leaf — e.g. an
    # inline image — is an attachment.
    return maintype != "text"


def iter_parts(part: Message, *, max_parts: int | None = None):
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
    :data:`MAX_PARTS`, read dynamically so tests can lower it.
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
            payload = node.get_payload()
            if isinstance(payload, list):
                # Push children reversed so popping restores document order.
                stack.extend(reversed(payload))
                continue
        yield node


def parts_exceed_budget(part: Message, *, max_parts: int | None = None) -> bool:
    """True if the MIME tree visits more than ``max_parts`` nodes.

    Mirrors :func:`iter_parts`' node accounting exactly, so it answers "did (or
    would) the walk truncate?" — letting the parser record a structural anomaly
    when parts are dropped rather than silently losing them. Bounded and
    iterative: it stops counting one past the cap.
    """
    limit = MAX_PARTS if max_parts is None else max_parts
    visited = 0
    stack: list[Message] = [part]
    while stack:
        node = stack.pop()
        visited += 1
        if visited > limit:
            return True
        if node.get_content_maintype() == "message":
            continue
        if node.is_multipart():
            payload = node.get_payload()
            if isinstance(payload, list):
                stack.extend(payload)
    return False


def detect_type(data: bytes) -> str | None:
    """Sniff a content-type from leading magic bytes, or ``None`` if unknown."""
    for prefix, content_type in _SIGNATURES:
        if data.startswith(prefix):
            return content_type
    return None


def _extensions(filename: str | None) -> list[str]:
    """Lowercased extension tokens of ``filename`` (``a.pdf.exe`` → pdf, exe)."""
    if not filename:
        return []
    name = filename.strip().rstrip(".")
    parts = name.split(".")
    return [p.casefold() for p in parts[1:]] if len(parts) > 1 else []


def _zip_is_encrypted(data: bytes) -> bool:
    """Best-effort: is bit 0 of the zip local-file general-purpose flag set?

    We only read the fixed local file header — never inflate or extract.
    """
    if not data.startswith(b"PK\x03\x04") or len(data) < 8:
        return False
    try:
        (flags,) = struct.unpack_from("<H", data, 6)
    except struct.error:
        return False
    return bool(flags & 0x0001)


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

    # DOUBLE_EXTENSION — two-plus extensions ending in a dangerous one.
    if len(exts) >= 2 and last_ext in _DANGEROUS_EXTS:
        flags.append(AttachmentFlag.DOUBLE_EXTENSION)

    # TYPE_MISMATCH — declared family known and contradicts the detected family.
    # Keyed on the DECLARED content-type (not the filename extension): OOXML and
    # legacy Office types map to the container they're expected to be on disk
    # (zip / ole), so a real ``.docx`` (declared OOXML, zip bytes) is consistent,
    # while ``invoice.docx`` declared ``application/pdf`` with zip bytes still
    # fires because the *declaration* (pdf) disagrees with the bytes (zip).
    declared_family = _DECLARED_FAMILY.get((declared_type or "").casefold())
    detected_family = _DETECTED_FAMILY.get(detected_type or "")
    if declared_family and detected_family and declared_family != detected_family:
        flags.append(AttachmentFlag.TYPE_MISMATCH)

    # PASSWORD_PROTECTED — encrypted zip (best-effort, header flag only).
    if _zip_is_encrypted(data):
        flags.append(AttachmentFlag.PASSWORD_PROTECTED)

    return flags


def _attachment_bytes(part: Message) -> bytes:
    """Transfer-decoded bytes of an attachment part (for hashing/sniffing).

    For an attached ``message/rfc822``, ``get_payload(decode=True)`` returns
    ``None`` (it's a container), so we serialize the enclosed message instead —
    still just reading bytes, never executing or extracting anything.

    The enclosed message is flattened with no header re-wrapping, no ``From``
    mangling, and CRLF line endings — the most wire-faithful form the stdlib
    can reproduce. (Exact original bytes aren't recoverable once the email
    package has parsed the sub-message, since it discards the original header
    folding; this serialization is stable and content-complete.)
    """
    try:
        data = part.get_payload(decode=True)
    except Exception:
        data = None
    if data is not None:
        return data
    if part.get_content_maintype() == "message":
        try:
            payload = part.get_payload()
            if isinstance(payload, list) and payload:
                buf = io.BytesIO()
                BytesGenerator(buf, mangle_from_=False, maxheaderlen=0).flatten(
                    payload[0], linesep="\r\n"
                )
                return buf.getvalue()
        except Exception:
            return b""
    return b""


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
