"""Ingest & parse (PRD §6.1).

Turn ``.eml`` (stdlib ``email``) and ``.msg`` (``extract-msg``) into a fully
populated :class:`~phishbowl.models.ParsedEmail`, format-agnostic downstream.
Charset/encoding handling is centralized here (:mod:`phishbowl.parse.charset`).
Attachments are hashed and inspected by metadata/magic bytes only — never
executed, never extracted.

Both paths are implemented: ``.eml`` via the stdlib ``email`` package, ``.msg``
via ``extract-msg``, each normalizing into the **same** :class:`ParsedEmail` so
nothing downstream needs to know the source format. :func:`parse` dispatches on
file suffix and always returns a model — an unreadable input raises like a
normal file error, but a malformed (yet readable) message degrades into a noted
partial result rather than crashing (PRD §11).
"""

from __future__ import annotations

from pathlib import Path

from phishbowl.models import ParsedEmail

from .eml import parse_eml
from .eml import parse_file as parse_eml_file
from .msg import parse_file as parse_msg_file
from .msg import parse_msg

__all__ = ["parse", "parse_eml", "parse_msg"]

_EML_SUFFIXES = {".eml"}
_MSG_SUFFIXES = {".msg"}


def parse(path: str | Path) -> ParsedEmail:
    """Parse a ``.eml``/``.msg`` file into a :class:`ParsedEmail`.

    Dispatches on suffix to the matching parser; both normalize into the same
    model, so the caller never has to branch on format. A readable-but-malformed
    message degrades into a noted partial result rather than raising (PRD §11).
    """
    p = Path(path)
    suffix = p.suffix.casefold()

    if suffix in _EML_SUFFIXES:
        return parse_eml_file(p)

    if suffix in _MSG_SUFFIXES:
        return parse_msg_file(p)

    raise ValueError(f"unsupported input '{p.suffix}'; expected one of: .eml, .msg")
