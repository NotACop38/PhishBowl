"""Bounded, offline HTML inspection shared by extraction, scoring and preview.

This is a text parser, not a browser or sanitizer: it records the visible text,
the link targets, and the resource URLs a renderer *would* request, and never
requests anything itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser

MAX_TEXT_CHARS = 256 * 1024

# Attributes whose value is a navigation target (a click or form submission).
_NAVIGATION_ATTRS = frozenset({"href", "xlink:href", "action", "formaction"})
# Attributes whose value a renderer fetches automatically (images, frames, ...),
# or on click without navigating (``ping``).
_RESOURCE_ATTRS = frozenset({"src", "poster", "background", "data", "ping"})
# ``<meta http-equiv="refresh" content="0; url=...">`` redirects on open.
_REFRESH_URL = re.compile(r"^\s*\d*\s*[;,]?\s*url\s*=\s*['\"]?\s*([^'\"\s]+)", re.IGNORECASE)
# CSS ``url(...)`` references in style attributes and <style> blocks.
_CSS_URL = re.compile(r"url\(\s*['\"]?\s*([^'\")\s]+)", re.IGNORECASE)
# Elements whose text is never displayed. (Scripts never run in mail clients,
# so <noscript> content *is* displayed and stays visible text.)
_HIDDEN_ELEMENTS = frozenset({"script", "style", "template"})


@dataclass(frozen=True)
class HTMLAnalysis:
    """What an HTML body contains, without rendering it.

    ``text`` is what a reader sees; ``hidden_text`` is text a renderer never
    displays (script, style, template contents), kept so its indicators are
    still extracted. ``links`` are navigation targets (``href``, form actions,
    meta refresh); ``resources`` are URLs a renderer would load automatically
    (``src``, ``srcset``, CSS ``url()``, ...). ``anchors`` pairs each
    ``<a href>`` with its visible text. ``complete`` is ``False`` when the
    input exceeded the analysis budget or the parser gave up.
    """

    text: str
    links: tuple[str, ...]
    anchors: tuple[tuple[str, str], ...]
    resources: tuple[str, ...] = ()
    complete: bool = True
    hidden_text: str = ""


class _Inspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.hidden: list[str] = []
        self.links: list[str] = []
        self.resources: list[str] = []
        self.anchors: list[tuple[str, str]] = []
        self.anchor: tuple[str, int] | None = None
        self.hidden_depth = 0
        self.in_style = False

    def handle_starttag(self, tag, attrs):
        if tag in _HIDDEN_ELEMENTS:
            self.hidden_depth += 1
            self.in_style = self.in_style or tag == "style"
        self.text.append(" ")
        for name, value in attrs:
            if not value:
                continue
            if name in _NAVIGATION_ATTRS:
                self.links.append(value.strip())
            elif name in _RESOURCE_ATTRS:
                self.resources.append(value.strip())
            elif name == "srcset":
                # "a.png 1x, b.png 2x" — the URL is the first token of each candidate.
                self.resources.extend(
                    candidate.split()[0] for candidate in value.split(",") if candidate.split()
                )
            elif name == "style":
                self.resources.extend(_CSS_URL.findall(value))
        if tag == "meta":
            fields = {name: (value or "") for name, value in attrs}
            if fields.get("http-equiv", "").strip().casefold() == "refresh":
                match = _REFRESH_URL.match(fields.get("content", ""))
                if match:
                    self.links.append(match.group(1))
        if tag == "a":
            self.handle_endtag("a")
            href = next((value for name, value in attrs if name == "href" and value), None)
            if href:
                self.anchor = (href.strip(), len(self.text))

    def handle_endtag(self, tag):
        if tag == "a" and self.anchor:
            href, start = self.anchor
            self.anchors.append((href, "".join(self.text[start:]).strip()))
            self.anchor = None
        if tag in _HIDDEN_ELEMENTS and self.hidden_depth:
            self.hidden_depth -= 1
            if tag == "style":
                self.in_style = False
        self.text.append(" ")

    def handle_data(self, data):
        if self.hidden_depth:
            self.hidden.append(data)
            if self.in_style:
                self.resources.extend(_CSS_URL.findall(data))
            return
        self.text.append(data)


def inspect_html(value: str) -> HTMLAnalysis:
    """Inspect at most :data:`MAX_TEXT_CHARS` of ``value`` as HTML."""
    parser = _Inspector()
    complete = len(value) <= MAX_TEXT_CHARS
    try:
        parser.feed(value[:MAX_TEXT_CHARS])
        parser.close()
    except (AssertionError, ValueError):
        complete = False
        # Preserve text for IOC scanning; renderers escape all such content.
        parser.text.append(value[:MAX_TEXT_CHARS])
    parser.handle_endtag("a")
    return HTMLAnalysis(
        text="".join(parser.text),
        links=tuple(parser.links),
        anchors=tuple(parser.anchors),
        resources=tuple(parser.resources),
        complete=complete,
        hidden_text=" ".join(parser.hidden),
    )
