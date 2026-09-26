"""Script mixing and look-alike characters in domain labels (after Unicode TR39).

Two IDN tricks matter for phishing triage:

* **Mixed-script labels** — one label combining alphabets, as in ``pаypal`` with
  a Cyrillic ``а``. Mixing is judged against TR39's "highly restrictive"
  profile: Latin may combine with Han, Hiragana, Katakana, Bopomofo or Hangul
  (common in Japanese, Chinese and Korean names), but not with Cyrillic, Greek
  or other alphabets whose letters imitate Latin ones.
* **Whole-script and diacritic look-alikes** — a label written entirely in one
  script (``аррӏе``, all Cyrillic) or in accented Latin (``pàypal``) whose
  characters fold to a brand's name.

Punycode (``xn--``) labels are decoded first, so the encoded and displayed
forms of a domain get the same verdict. The character tables are a compact,
curated subset of the TR39 confusables data covering letters that imitate
lowercase ASCII; they are not exhaustive.
"""

from __future__ import annotations

import codecs
import unicodedata

# ASCII look-alike sequences folded before comparing labels: ``rn`` reads as
# ``m``, ``0`` as ``o``, ``1``/``i`` as ``l``. Multi-character sequences first.
_ASCII_SEQUENCES = (("rn", "m"), ("vv", "w"), ("cl", "d"))
_ASCII_CHARS = str.maketrans({"0": "o", "1": "l", "i": "l", "|": "l", "5": "s", "$": "s"})

# Script names recognized in Unicode character names.
_SCRIPTS = frozenset(
    {
        "LATIN",
        "CYRILLIC",
        "GREEK",
        "ARMENIAN",
        "GEORGIAN",
        "CHEROKEE",
        "COPTIC",
        "HEBREW",
        "ARABIC",
        "SYRIAC",
        "THAANA",
        "DEVANAGARI",
        "BENGALI",
        "TAMIL",
        "THAI",
        "LAO",
        "TIBETAN",
        "HIRAGANA",
        "KATAKANA",
        "BOPOMOFO",
        "HANGUL",
        "ETHIOPIC",
    }
)

# Script combinations TR39's "highly restrictive" profile allows in one label.
_ALLOWED_MIXES = (
    frozenset({"Latin", "Han", "Hiragana", "Katakana"}),
    frozenset({"Latin", "Han", "Bopomofo"}),
    frozenset({"Latin", "Han", "Hangul"}),
)

# Non-ASCII letters that render like a lowercase ASCII letter.
_TO_LATIN = str.maketrans(
    {
        # Cyrillic
        "а": "a",
        "е": "e",
        "ё": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "ѕ": "s",
        "і": "i",
        "ї": "i",
        "ј": "j",
        "һ": "h",
        "ԁ": "d",
        "ԛ": "q",
        "ԝ": "w",
        "ӏ": "l",
        "ҫ": "c",
        "ү": "y",
        "ԍ": "g",
        # Greek
        "α": "a",
        "ο": "o",
        "ρ": "p",
        "ν": "v",
        "ι": "i",
        "κ": "k",
        "τ": "t",
        "υ": "u",
        "χ": "x",
        "ε": "e",
        "ϲ": "c",
        "ϳ": "j",
        # Armenian
        "օ": "o",
        "ս": "u",
        "հ": "h",
        "ո": "n",
        "ց": "g",
        "զ": "q",
        # Latin letters that imitate other Latin letters
        "ı": "i",
        "ɑ": "a",
        "ɡ": "g",
        "ɩ": "i",
        "ʟ": "l",
    }
)


def confusable_skeleton(label: str) -> str:
    """Fold visually confusable ASCII so ``rnicros0ft`` and ``microsoft`` match."""
    for sequence, replacement in _ASCII_SEQUENCES:
        label = label.replace(sequence, replacement)
    return label.translate(_ASCII_CHARS)


def script_of(char: str) -> str | None:
    """The script of a letter (``"Latin"``, ``"Cyrillic"``, ``"Han"``, ...), else ``None``."""
    if not char.isalpha():
        return None
    if char.isascii():
        return "Latin"
    name = unicodedata.name(char, "")
    if "CJK" in name or "IDEOGRAPH" in name:
        return "Han"
    for word in name.replace("-", " ").split():
        if word in _SCRIPTS:
            return word.title()
    return name.split(" ", 1)[0].title() or "Unknown"


def decode_label(label: str) -> str:
    """A ``xn--`` label decoded to Unicode (unchanged when not valid punycode).

    A label over DNS's 63-character limit is not decoded (Python's punycode
    decoder is quadratic), and neither is one that decodes to a lone surrogate,
    which no real domain contains and no renderer can output.
    """
    if not label.startswith("xn--") or len(label) > 63:
        return label
    try:
        decoded = codecs.decode(label[4:].encode("ascii"), "punycode")
        decoded.encode("utf-8")  # rejects lone surrogates
    except (UnicodeError, ValueError):
        return label
    return decoded


def is_suspicious_mix(label: str) -> bool:
    """True if ``label`` mixes scripts outside TR39's highly-restrictive profile."""
    scripts = {s for s in (script_of(c) for c in label) if s}
    if len(scripts) < 2:
        return False
    return not any(scripts <= allowed for allowed in _ALLOWED_MIXES)


def latin_skeleton(label: str) -> str:
    """Fold look-alike letters, accents and ASCII confusables to one comparable form."""
    folded = unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", label).casefold())
    folded = "".join(c for c in folded if not unicodedata.combining(c)).translate(_TO_LATIN)
    return confusable_skeleton(folded)
