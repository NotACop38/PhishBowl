"""HTML report renderer (PRD §10).

Renders a :class:`~phishbowl.report.view.ReportView` into a single, self-contained
HTML file via Jinja2 with **autoescape forced on**. The renderer never reaches
the network, and the template never injects raw email markup or references a
remote asset — both guarantees are asserted by the security tests.

The Jinja environment is configured deliberately:

* ``autoescape=True`` (not the extension-sniffing default) so escaping is on no
  matter what the template file is called — every email-derived value is HTML
  escaped, neutralizing hostile ``<script>`` / markup in subjects and bodies.
* ``PackageLoader`` reads the bundled template only; there is no filesystem or
  network template resolution and the analyzed message can't influence it.
"""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, select_autoescape

from .view import ReportView

# select_autoescape with no negative cases ⇒ autoescape is ON for every template
# name. Belt-and-suspenders with the explicit list below, but it documents intent.
_ENV = Environment(
    loader=PackageLoader("phishbowl.report", "templates"),
    autoescape=select_autoescape(default=True, default_for_string=True),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_html(view: ReportView) -> str:
    """Render the report view into a complete, self-contained HTML document."""
    template = _ENV.get_template("report.html.j2")
    return template.render(r=view)
