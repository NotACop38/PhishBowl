"""Bounded, offline HTML inspection shared by extraction, scoring and preview.

This is a text parser, not a browser or sanitizer. No resources are fetched.
"""

from dataclasses import dataclass
from html.parser import HTMLParser

MAX_TEXT_CHARS = 256 * 1024


@dataclass(frozen=True)
class HTMLAnalysis:
    text: str
    links: tuple[str, ...]
    anchors: tuple[tuple[str, str], ...]


class _Inspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.links: list[str] = []
        self.anchors: list[tuple[str, str]] = []
        self.anchor: tuple[str, int] | None = None

    def handle_starttag(self, tag, attrs):
        self.text.append(" ")
        for name, value in attrs:
            if name in {"href", "src", "action", "formaction", "poster", "background"} and value:
                self.links.append(value.strip())
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
        self.text.append(" ")

    def handle_data(self, data):
        self.text.append(data)


def inspect_html(value: str) -> HTMLAnalysis:
    parser = _Inspector()
    parser.feed(value[:MAX_TEXT_CHARS])
    parser.close()
    parser.handle_endtag("a")
    return HTMLAnalysis("".join(parser.text), tuple(parser.links), tuple(parser.anchors))
