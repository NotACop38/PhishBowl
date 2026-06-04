"""JSON report renderer (PRD §10).

Serializes the :class:`~phishbowl.report.view.ReportView` into a complete,
machine-readable result. The view already carries, for every indicator and
address, both a **defanged** ``*_display`` field and a clearly-labelled raw
``*_raw`` field — so the JSON satisfies "defanged plus clearly-labelled raw" by
construction, from a single source of truth, with no risk of the two channels
diverging from what the HTML and CLI show.

Field aliases (e.g. ``from``) are emitted by alias so the JSON reads naturally;
the output is deterministic and well-formed UTF-8 JSON.
"""

from __future__ import annotations

from .view import ReportView


def render_json(view: ReportView, *, indent: int | None = 2) -> str:
    """Render the report view as a JSON string (well-formed, UTF-8, by alias)."""
    return view.model_dump_json(by_alias=True, indent=indent)
