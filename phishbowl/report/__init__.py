"""Reporting (PRD §6.4, §10).

Analyst-facing outputs: a self-contained HTML report (Jinja2 autoescape on,
inline CSS, zero network egress, never inject the raw HTML body), a rich CLI
summary, and complete JSON. Everything defanged in display by default.

Scaffold: implemented in Phase 4 (the offline MVP milestone).
"""
