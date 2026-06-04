"""Reporting (PRD §6.4, §10) — the offline MVP's analyst-facing outputs.

Three renderers over one prepared view-model:

* :func:`render_html` — a single self-contained HTML file (Jinja2 autoescape on,
  inline CSS, **zero network egress**, never injects the raw HTML body);
* :func:`render_json` — a complete structured result (defanged plus
  clearly-labelled raw);
* :func:`render_cli` — a rich terminal summary.

:func:`build_report` does all the defanging, control-stripping, and PII
redaction once, so the renderers stay pure presentation and can never disagree
about what is safe to show. Everything is defanged in display by default;
``--redact`` (:class:`RedactionPolicy`) additionally withholds bystander PII.
"""

from .cli_render import render_cli
from .html import render_html
from .json_output import render_json
from .redact import RedactionPolicy
from .view import ReportView, build_report, severity_for

__all__ = [
    "build_report",
    "ReportView",
    "severity_for",
    "render_html",
    "render_json",
    "render_cli",
    "RedactionPolicy",
]
