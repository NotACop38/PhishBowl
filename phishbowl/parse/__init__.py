"""Ingest & parse (PRD §6.1).

Turn ``.eml`` (stdlib ``email``) and ``.msg`` (``extract-msg``) into a fully
populated :class:`~phishbowl.models.ParsedEmail`, format-agnostic downstream.
Charset/encoding handling is centralized here (:mod:`phishbowl.parse.charset`).
Attachments are hashed and inspected by metadata/magic bytes only — never
executed, never extracted.

Phase 1 implements the ``.eml`` path; ``.msg`` (via ``extract-msg``) lands as a
later task in this phase. :func:`parse` dispatches on file suffix and always
returns a model — an unsupported or unreadable input degrades into a noted
partial result rather than raising (PRD §11).
"""

from __future__ import annotations

from pathlib import Path

from phishbowl import __version__
from phishbowl.models import Anomaly, EmailFormat, ParsedEmail, Source

from .eml import parse_eml, parse_file

__all__ = ["parse", "parse_eml", "parse_file"]

_EML_SUFFIXES = {".eml"}
_MSG_SUFFIXES = {".msg"}


def parse(path: str | Path) -> ParsedEmail:
    """Parse a ``.eml``/``.msg`` file into a :class:`ParsedEmail`.

    Dispatches on suffix. ``.eml`` is parsed in full; ``.msg`` parsing is not
    yet wired up (a later Phase 1 task) and returns a partial model with an
    anomaly note rather than raising — the run never crashes (PRD §11).
    """
    p = Path(path)
    suffix = p.suffix.casefold()

    if suffix in _EML_SUFFIXES:
        return parse_file(p)

    if suffix in _MSG_SUFFIXES:
        # Validate the input exists/reads before returning the placeholder, so a
        # missing path errors like the .eml path rather than reporting success.
        if not p.is_file():
            raise FileNotFoundError(f"no such file: {p}")
        # .msg normalization (extract-msg) is a later Phase 1 task; until then,
        # degrade gracefully instead of pretending to parse it.
        parsed = ParsedEmail(
            source=Source(filename=p.name, format=EmailFormat.MSG, parser_version=__version__),
        )
        parsed.anomalies.append(
            Anomaly(code="unsupported_format", message=".msg parsing is not implemented yet")
        )
        return parsed

    raise ValueError(f"unsupported input '{p.suffix}'; expected one of: .eml, .msg")
