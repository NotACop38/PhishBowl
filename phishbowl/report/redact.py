"""PII redaction for analyst outputs (PRD §10, §11).

Triage reports are routinely pasted into tickets, shared with vendors, and
attached to threat-intel submissions. ``--redact`` withholds the bystander data
that has no business leaving the organization while keeping the attacker's
indicators — the point of the report — intact.

What is protected when the policy is active:

* **Recipients.** Every address the message names as a recipient — ``To``,
  ``Cc``, ``Bcc``, ``Resent-*``, the delivery headers mail systems add
  (``Delivered-To``, ``X-Original-To``, ``X-Apparently-To``, …) and
  ``Received … for <addr>`` clauses — wherever it appears, plus recipients'
  display names in prose. A recipient *domain* is protected only when a
  delivery header or ``Received … for`` clause names it: the sender writes
  ``To`` and ``Cc``, and could otherwise list their own domain there to have it
  withheld. A domain indicator seen only in ``To``/``Cc`` is still withheld.
* **Internal topology.** Hosts under an operator ``org_domain`` (from the
  scoring config), addresses at those hosts, and non-public IP addresses in any
  notation a browser accepts.
* **Operator-named fields.** Each header the operator lists, with what was
  parsed from it: its addresses, domains and display names; the routing hosts
  and IP addresses of a hidden ``Received``; the authentication results of a
  hidden ``Authentication-Results``; and its value wherever it recurs in prose.

Never protected: the addresses and domains of the visible sender headers
(``From``, ``Reply-To``, ``Return-Path``, ``Sender``), however often a message
repeats them among its recipients; free-webmail domains and public suffixes,
which identify no one; and display names made only of role words ("Sales",
"IT Support"), which would only blank out ordinary words.

Matching is exact and linear in the text. Addresses, hosts and IP addresses are
looked up in sets (domains together with their subdomains, in IDNA form), and
names are matched as whole-word sequences in any case and spacing, in prose
only, never inside a link, host, or address. Matching sees through defanging
(``alice[at]corp[.]example``) and percent-encoding. Each match is replaced in
place by a typed ``[redacted:…]`` placeholder, so the report still shows *that*
something was present and *why* it is hidden, and text with nothing to protect
comes back unchanged. Only when a protected value survives inside
percent-encoding, where cutting it out would leave a usable, altered link, is
the whole token around it withheld.

Redaction is selected-value removal, not anonymization: free text can still
identify people in ways no list anticipates. Review before sharing.
"""

from __future__ import annotations

import ipaddress
import re
from bisect import bisect_left, bisect_right
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import NamedTuple
from urllib.parse import unquote

from phishbowl.domains import ascii_host, registrable_domain, registrable_label, web_ipv4
from phishbowl.models import Address, ParsedEmail
from phishbowl.parse.addresses import parse_address_list
from phishbowl.parse.auth import authserv_id
from phishbowl.score import ScoringConfig

# Typed placeholders. Kept distinct so a reader (and a downstream tool consuming
# the JSON) can tell *what kind* of value was withheld.
REDACTED_RECIPIENT = "[redacted:recipient]"
REDACTED_INTERNAL_HOST = "[redacted:internal-host]"
REDACTED_INTERNAL_IP = "[redacted:internal-ip]"
REDACTED_FIELD = "[redacted:field]"

# Recipient headers the sender composes, and so can fill with anything.
_COMPOSED_RECIPIENT_HEADERS = frozenset({"to", "cc", "bcc", "resent-to", "resent-cc", "resent-bcc"})
# Recipient headers that receiving systems add at delivery (lower-case). Their
# values are not always address lists ("addr; date", space-separated lists), so
# addresses are found in them by pattern.
_DELIVERY_HEADERS = frozenset(
    {
        "delivered-to",
        "x-delivered-to",
        "x-original-to",
        "envelope-to",
        "x-envelope-to",
        "apparently-to",
        "x-apparently-to",
        "x-forwarded-to",
        "x-forwarded-for",
        "x-rcpt-to",
        "x-resolved-to",
        "original-recipient",
        "x-original-recipient",
        "x-ms-exchange-organization-originalenveloperecipients",
    }
)
# Every header that names a recipient of the message (lower-case).
RECIPIENT_HEADERS = _COMPOSED_RECIPIENT_HEADERS | _DELIVERY_HEADERS

# The sender headers, with the parsed attribute holding each one's mailbox.
_SENDER_HEADERS = {
    "from": "from_",
    "reply-to": "reply_to",
    "return-path": "return_path",
    "sender": "sender",
}

# Domain indicators seen only here name the message's recipients.
_RECIPIENT_PROVENANCE = frozenset({"header:To", "header:Cc"})

# Words that name a role or a group rather than a person. A display name made
# only of these ("Sales", "IT Support", "Accounts Payable") is not hidden in
# prose; the operator's ``role_keywords`` extend the list.
_ROLE_WORDS = frozenset(
    """
    accounting accounts admin administration administrator alerts all and billing
    careers compliance contact customer customers department dept desk enquiries
    everyone finance for group hello help helpdesk hr human info information
    inquiries invoice invoices it jobs legal mail mailbox marketing news newsletter
    no noreply notifications of office operations ops orders payable payments
    payroll postmaster press procurement purchasing receivable reception recruiting
    reply resources sales security service services staff support team the
    webmaster
    """.split()
)
# A recipient display name needs this many word characters to be hidden in
# prose ("IT", "HR" and initials are too generic), a hidden field's value one
# more ("1", "yes" and "low" are).
_MIN_NAME_CHARS = 3
_MIN_VALUE_CHARS = 4
# Longer names and values are not matched as phrases.
_MAX_PHRASE_WORDS = 16
# Longest textual IP address ("ffff:…:255.255.255.255").
_MAX_IP_CHARS = 45

# Candidate tokens, each matched only from the start of a run and with
# possessive quantifiers, so a failed match never backtracks: redaction stays
# linear even on hostile text.
_EMAIL_TOKEN = re.compile(r"(?<![\w.%+\-])[\w.%+\-]++@[\w\-]++(?:\.[\w\-]++)++")
_HOST_TOKEN = re.compile(r"(?<![\w.\-])[\w\-]++(?:\.[\w\-]++)++")
_IPV4_TOKEN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
# Postfix and Sendmail write an IPv6 peer as "[IPv6:fd12::25]".
_IPV6_TOKEN = re.compile(r"(?:(?<=[Ii][Pp][Vv]6:)|(?<![\w:.]))[0-9A-Fa-f:.]{2,}+(?![\w:.])")
# A URL with a scheme (browsers read "\" as "/"); group 1 is its authority.
_URL_TOKEN = re.compile(
    r"(?<![\w+.\-])[A-Za-z][\w+.\-]*+:[/\\]{2}([^\s/\\?#<>\"'`]*+)[^\s<>\"'`]*+"
)
# A host with any path after it: text in which names are never matched.
_HOST_ZONE = re.compile(r"(?<![\w.\-])[\w\-]++(?:\.[\w\-]++)++(?:[/\\?#][^\s<>\"'`]*+)?")
_WORD = re.compile(r"\w+")
_CHUNK = re.compile(r"\S+")
_DNS_NAME = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)+")
# The recipient named by a Received header's "for <addr>" clause.
_RECEIVED_FOR = re.compile(r"\bfor\s++<?+([^\s<>;@]++@[^\s<>;]++)", re.IGNORECASE)

# Defanging undone before matching: the brackets PhishBowl emits and the
# spellings seen in the wild ("[at]", "(dot)", "{.}", "hxxp://"), in any case
# and with the spaces around them that the extractor also accepts.
_DEFANGED = re.compile(
    r"\s?[\[({]\s?(?:at|@)\s?[\])}]\s?"
    r"|\s?[\[({]\s?(?:dot|\.)\s?[\])}]\s?"
    r"|\[:\]"
    r"|(?<![A-Za-z])hxxp(?=s?(?::|\[:\])//)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RedactionPolicy:
    """What an output should hide (PRD §10).

    The default (``enabled=False``) is a no-op: full fidelity. With ``enabled``
    set, the category toggles decide what is stripped, and ``extra_fields``
    names additional headers to withhold by name (case-insensitive).
    """

    enabled: bool = False
    recipients: bool = True
    internal: bool = True
    extra_fields: tuple[str, ...] = ()

    @classmethod
    def disabled(cls) -> RedactionPolicy:
        return cls(enabled=False)

    @classmethod
    def standard(cls, extra_fields: tuple[str, ...] = ()) -> RedactionPolicy:
        """The ``--redact`` default: recipients + internal topology + extras."""
        return cls(enabled=True, recipients=True, internal=True, extra_fields=extra_fields)


class _Span(NamedTuple):
    """A protected stretch of text and what replaces it."""

    start: int
    end: int
    placeholder: str
    category: str


# What a protected value is replaced by, and the category the audit note names.
_Protection = tuple[str, str]
_RECIPIENT: _Protection = (REDACTED_RECIPIENT, "recipients")
_INTERNAL_HOST: _Protection = (REDACTED_INTERNAL_HOST, "internal hosts")
_INTERNAL_IP: _Protection = (REDACTED_INTERNAL_IP, "internal IPs")
_FIELD: _Protection = (REDACTED_FIELD, "operator fields")
_ENCODED: _Protection = (REDACTED_FIELD, "encoded values")


class _Layer:
    """One pass of refanging, with a map back to its input's offsets."""

    def __init__(self, original: str) -> None:
        pieces: list[str] = []
        # (view start, view end, original start, original end) of each token.
        self.marks: list[tuple[int, int, int, int]] = []
        position = length = 0
        for match in _DEFANGED.finditer(original):
            restored = _restore(match.group(0))
            pieces.append(original[position : match.start()])
            length += match.start() - position
            self.marks.append((length, length + len(restored), match.start(), match.end()))
            pieces.append(restored)
            length += len(restored)
            position = match.end()
        pieces.append(original[position:])
        self.text = "".join(pieces)
        self._starts = [mark[0] for mark in self.marks]

    def _locate(self, index: int) -> tuple[int, int]:
        """The input span behind the output character at ``index``."""
        k = bisect_right(self._starts, index) - 1
        if k < 0:
            return index, index + 1
        view_start, view_end, start, end = self.marks[k]
        if index < view_end:
            return start, end
        offset = end + index - view_end
        return offset, offset + 1

    def original(self, start: int, end: int) -> tuple[int, int]:
        """The input span behind the (non-empty) output span ``[start, end)``."""
        return self._locate(start)[0], self._locate(end - 1)[1]


class _Refanged:
    """``text`` with defanging undone, mapped back to the original's offsets.

    Up to three passes, so defanging applied more than once is undone too.
    """

    def __init__(self, original: str) -> None:
        self._layers: list[_Layer] = []
        self.text = original
        for _ in range(3):
            layer = _Layer(self.text)
            if not layer.marks:
                break
            self._layers.append(layer)
            self.text = layer.text

    def original(self, start: int, end: int) -> tuple[int, int]:
        """The original span behind the (non-empty) view span ``[start, end)``."""
        for layer in reversed(self._layers):
            start, end = layer.original(start, end)
        return start, end


def _restore(token: str) -> str:
    folded = token.casefold()
    if folded.startswith("hxxp"):
        return "http"
    if folded == "[:]":
        return ":"
    return "@" if "at" in folded or "@" in folded else "."


def _unquote_all(value: str) -> str:
    """Undo percent-encoding, including double encoding."""
    for _ in range(3):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


def _words(value: str) -> tuple[str, ...]:
    """The case-folded words of a name or value: its phrase key."""
    return tuple(word.casefold() for word in _WORD.findall(value))


def _address_key(addr_spec: str) -> str | None:
    """``local@domain`` normalized for lookup: case-folded, domain in IDNA form."""
    spec = addr_spec.strip().strip("<>").strip()
    local, at, domain = spec.rpartition("@")
    if not at or not local or not domain:
        return None
    return f"{local.casefold()}@{ascii_host(domain)}"


def _address_keys(token: str) -> Iterator[str]:
    """Lookup keys for an address found in text: as written, then shorter.

    The pattern reads the longest dotted domain, so ``alice@corp.example.eml``
    (a file name) is tried as ``alice@corp.example`` too. Only real address
    lengths are tried that way: a 64-character local part, a 253-character
    domain.
    """
    key = _address_key(token)
    if key is None:
        return
    yield key
    local, _, domain = key.rpartition("@")
    if len(local) > 64:
        return
    position = domain.rfind(".", 0, 254)
    while position > 0:
        yield f"{local}@{domain[:position]}"
        position = domain.rfind(".", 0, position)


def _suffixes(host: str, limit: int) -> Iterator[str]:
    """``host`` and its parent domains in IDNA form, shortest first, up to ``limit`` long."""
    suffix = ""
    # A DNS name has at most 127 labels; the rest of a longer token is never read.
    for label in reversed(host.casefold().rstrip(".").rsplit(".", 127)):
        if not label.isascii():
            if len(label) > 63:
                return
            try:
                label = label.encode("idna").decode("ascii")
            except UnicodeError:
                return
        suffix = f"{label}.{suffix}" if suffix else label
        if len(suffix) > limit:
            return
        yield suffix


def _url_host(match: re.Match[str]) -> tuple[int, int]:
    """The span of the host in a :data:`_URL_TOKEN` match (userinfo and port excluded)."""
    start, end = match.span(1)
    start = max(start, match.string.rfind("@", start, end) + 1)
    if match.string.startswith("[", start):
        close = match.string.find("]", start, end)
        return start, (close + 1 if close >= 0 else end)
    colon = match.string.find(":", start, end)
    return start, (colon if colon >= 0 else end)


def _merge(spans: Iterable[_Span]) -> list[_Span]:
    """Overlapping spans joined, earliest first; the longest one's placeholder wins.

    Overlaps are never resolved by dropping one side, so every protected
    character stays covered.
    """
    merged: list[_Span] = []
    for span in sorted(spans, key=lambda s: (s.start, -s.end)):
        if merged and span.start < merged[-1].end:
            last = merged[-1]
            keep = span if span.end - span.start > last.end - last.start else last
            merged[-1] = _Span(last.start, max(last.end, span.end), *keep[2:])
        else:
            merged.append(span)
    return merged


def _free_words(words: list[tuple[int, int, str]], zones: list[tuple[int, int]]) -> list[bool]:
    """For each word, whether it lies outside every zone (link, host, address)."""
    merged: list[list[int]] = []
    for start, end in sorted(zones):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    free: list[bool] = []
    k = 0
    for start, end, _word in words:
        while k < len(merged) and merged[k][1] <= start:
            k += 1
        free.append(not (k < len(merged) and merged[k][0] < end))
    return free


class Redactor:
    """Applies a :class:`RedactionPolicy` to values drawn from one message.

    Construct once per report: it collects the protected addresses, domains,
    hosts, IP addresses and phrases up front, so each value is then redacted in
    time linear in its length, however many recipients the message names. Every
    method is a safe no-op when the policy is disabled. The categories actually
    redacted are recorded in :attr:`triggered` for the report's audit note.
    """

    def __init__(self, policy: RedactionPolicy, parsed: ParsedEmail, config: ScoringConfig):
        self.policy = policy
        self.triggered: set[str] = set()
        self._fields = frozenset(f.strip().casefold() for f in policy.extra_fields if f.strip())
        self._addresses: dict[str, _Protection] = {}  # exact, normalized addresses
        self._domains: dict[str, _Protection] = {}  # IDNA domains, with their subdomains
        self._hosts: dict[str, _Protection] = {}  # exact IDNA host names
        self._ips: dict[str, _Protection] = {}  # canonical IP addresses
        self._phrases: dict[tuple[str, ...], _Protection] = {}
        self._phrase_lengths: dict[str, tuple[int, ...]] = {}  # first word → lengths
        self._longest_domain = 0
        if not policy.enabled:
            return

        self._freemail = frozenset(ascii_host(d) for d in config.freemail_domains)
        self._role_words = _ROLE_WORDS | {w for kw in config.role_keywords for w in _words(kw)}
        senders = [
            address
            for name, attr in _SENDER_HEADERS.items()
            if name not in self._fields and (address := getattr(parsed.addresses, attr)) is not None
        ]
        self._sender_addresses = {
            key for a in senders if a.addr_spec and (key := _address_key(a.addr_spec))
        }
        self._sender_domains = {ascii_host(a.domain) for a in senders if a.domain}
        self._sender_registered = {registrable_domain(d) for d in self._sender_domains}
        self._sender_names = {_words(a.display_name) for a in senders if a.display_name}

        if policy.internal:
            for domain in config.org_domains:
                self._protect_domain(domain, _INTERNAL_HOST, check=False)
        if policy.recipients:
            self._collect_recipients(parsed)
        if self._fields:
            self._collect_fields(parsed)
        self._phrase_lengths = {
            first: tuple(sorted(lengths, reverse=True))
            for first, lengths in self._phrase_lengths.items()
        }

    # --- collection --------------------------------------------------------- #

    def _collect_recipients(self, parsed: ParsedEmail) -> None:
        composed: list[Address] = [*parsed.addresses.to, *parsed.addresses.cc]
        delivered: list[str] = []
        for header in parsed.headers.items:
            name = header.name.casefold()
            if name in _COMPOSED_RECIPIENT_HEADERS and name not in {"to", "cc"}:
                composed.extend(parse_address_list([header.value]))
            elif name in _DELIVERY_HEADERS:
                delivered.extend(m.group(0) for m in _EMAIL_TOKEN.finditer(header.value))
            elif name == "received":
                delivered.extend(m.group(1) for m in _RECEIVED_FOR.finditer(header.value))
        for address in composed:
            if address.addr_spec:
                self._protect_address(address.addr_spec, _RECIPIENT)
            if address.display_name:
                self._protect_name(address.display_name, _RECIPIENT)
        # Only receiving systems vouch for a recipient's domain; To and Cc are
        # the sender's words.
        for addr_spec in delivered:
            self._protect_address(addr_spec, _RECIPIENT)
            self._protect_domain(addr_spec.rpartition("@")[2], _RECIPIENT)

    def _collect_fields(self, parsed: ParsedEmail) -> None:
        # Mailboxes parsed from hidden address headers (an Outlook item may
        # carry them in MAPI properties rather than headers).
        mailboxes: list[Address] = []
        for name, attr in _SENDER_HEADERS.items():
            address = getattr(parsed.addresses, attr)
            if name in self._fields and address is not None:
                mailboxes.append(address)
        for name in ("to", "cc"):
            if name in self._fields:
                mailboxes.extend(getattr(parsed.addresses, name))
        for header in parsed.headers.items:
            name = header.name.casefold()
            value = header.value
            if name not in self._fields or not value.strip():
                continue
            if name in _SENDER_HEADERS or name in _COMPOSED_RECIPIENT_HEADERS:
                mailboxes.extend(parse_address_list([value]))
            elif name in _DELIVERY_HEADERS:
                for match in _EMAIL_TOKEN.finditer(value):
                    self._protect_address(match.group(0), _FIELD)
                    self._protect_domain(match.group(0).rpartition("@")[2], _FIELD)
            elif name == "received":
                self._collect_hop(value)
            elif name == "authentication-results":
                # The view withholds its results; the reporting server's name
                # (the authserv-id) is withheld wherever it recurs.
                self._protect_host(authserv_id(value), _FIELD)
            elif name != "received-spf":
                self._protect_value(value, _FIELD)
        for address in mailboxes:
            if address.addr_spec:
                self._protect_address(address.addr_spec, _FIELD)
                if address.domain:
                    self._protect_domain(address.domain, _FIELD)
            if address.display_name:
                self._protect_name(address.display_name, _FIELD)

    def _collect_hop(self, value: str) -> None:
        """A hidden Received header: its hosts, IP addresses and recipients."""
        for match in _HOST_TOKEN.finditer(value):
            if not _IPV4_TOKEN.fullmatch(match.group(0)):
                self._protect_host(match.group(0), _FIELD)
        for match in _IPV4_TOKEN.finditer(value):
            self._protect_ip(match.group(0), _FIELD)
        for match in _IPV6_TOKEN.finditer(value):
            self._protect_ip(match.group(0), _FIELD)
        for match in _RECEIVED_FOR.finditer(value):
            self._protect_address(match.group(1), _FIELD)

    def _protect_value(self, value: str, protection: _Protection) -> None:
        """Any other hidden header: its value in prose, its addresses and IPs anywhere."""
        self._protect_phrase(value, protection, _MIN_VALUE_CHARS)
        for match in _EMAIL_TOKEN.finditer(value):
            self._protect_address(match.group(0), protection)
        for match in _IPV4_TOKEN.finditer(value):
            self._protect_ip(match.group(0), protection)
        for match in _IPV6_TOKEN.finditer(value):
            self._protect_ip(match.group(0), protection)

    def _sender_side(self, host: str) -> bool:
        """True if ``host`` is, contains, or shares a registered domain with a sender domain."""
        if registrable_domain(host) in self._sender_registered:
            return True
        return any(
            host == s or s.endswith("." + host) or host.endswith("." + s)
            for s in self._sender_domains
        )

    def _protect_address(self, addr_spec: str, protection: _Protection) -> None:
        key = _address_key(addr_spec)
        if key is not None and key not in self._sender_addresses:
            self._addresses.setdefault(key, protection)

    def _protect_domain(self, domain: str, protection: _Protection, *, check: bool = True) -> None:
        """Protect ``domain`` and its subdomains, unless it identifies no one.

        Unchecked for the operator's own ``org_domains``; otherwise free-webmail
        domains, public suffixes, and the visible senders' domains stay visible.
        """
        host = ascii_host(domain)
        if not _DNS_NAME.fullmatch(host):
            return
        if check and (
            host in self._freemail or not registrable_label(host) or self._sender_side(host)
        ):
            return
        self._domains.setdefault(host, protection)
        self._longest_domain = max(self._longest_domain, len(host))

    def _protect_host(self, host: str, protection: _Protection) -> None:
        name = ascii_host(host)
        if _DNS_NAME.fullmatch(name) and not self._sender_side(name):
            self._hosts.setdefault(name, protection)

    def _protect_ip(self, value: str, protection: _Protection) -> None:
        try:
            ip = ipaddress.ip_address(value.strip().strip("[]").rstrip("."))
        except ValueError:
            return
        self._ips.setdefault(str(ip), protection)

    def _protect_name(self, name: str, protection: _Protection) -> None:
        """A display name, unless it is an address, a role, or a visible sender's name."""
        key = _words(name)
        if "@" in name or key in self._sender_names or all(w in self._role_words for w in key):
            return
        self._protect_phrase(name, protection, _MIN_NAME_CHARS)

    def _protect_phrase(self, value: str, protection: _Protection, min_chars: int) -> None:
        key = _words(value)
        if not key or len(key) > _MAX_PHRASE_WORDS or sum(map(len, key)) < min_chars:
            return
        if key not in self._phrases:
            self._phrases[key] = protection
            lengths = self._phrase_lengths.get(key[0], ())
            if len(key) not in lengths:
                self._phrase_lengths[key[0]] = (*lengths, len(key))

    # --- lookup ------------------------------------------------------------- #

    def _for_host(self, host: str) -> _Protection | None:
        if self._hosts and len(host) <= 253:
            found = self._hosts.get(ascii_host(host))
            if found is not None:
                return found
        if self._domains:
            for suffix in _suffixes(host, self._longest_domain):
                found = self._domains.get(suffix)
                if found is not None:
                    return found
        return None

    def _for_address(self, token: str) -> _Protection | None:
        # An exact address, else its domain decides for the whole address (an
        # internal colleague's local part is PII too).
        if self._addresses:
            for key in _address_keys(token):
                found = self._addresses.get(key)
                if found is not None:
                    return found
        return self._for_host(token.rpartition("@")[2])

    def _for_ip(self, value: str) -> _Protection | None:
        if len(value) > _MAX_IP_CHARS:
            return None
        try:
            ip = ipaddress.ip_address(value.strip().strip("[]"))
        except ValueError:
            return None
        if self.policy.internal and (not ip.is_global or ip.is_multicast):
            return _INTERNAL_IP
        return self._ips.get(str(ip))

    def _for_url_host(self, host: str) -> _Protection | None:
        """A URL's host written as an IP address, in any notation a browser accepts."""
        if host.startswith("["):
            return self._for_ip(host[1:-1])
        try:
            ip = web_ipv4(host)
        except ValueError:
            return None
        return self._for_ip(ip) if ip else None

    # --- matching ----------------------------------------------------------- #

    def _spans(self, text: str) -> list[_Span]:
        """Every protected span in ``text`` (defanging already undone), unmerged."""
        spans: list[_Span] = []
        zones: list[tuple[int, int]] | None = [] if self._phrases else None
        if self._addresses or self._domains or self._hosts or zones is not None:
            for match in _EMAIL_TOKEN.finditer(text):
                if zones is not None:
                    zones.append(match.span())
                found = self._for_address(match.group(0))
                if found is not None:
                    spans.append(_Span(*match.span(), *found))
        if self._domains or self._hosts:
            for match in _HOST_TOKEN.finditer(text):
                found = self._for_host(match.group(0))
                if found is not None:
                    spans.append(_Span(*match.span(), *found))
        check_ips = self.policy.internal or bool(self._ips)
        if check_ips or zones is not None:
            for match in _URL_TOKEN.finditer(text):
                if zones is not None:
                    zones.append(match.span())
                if check_ips:
                    start, end = _url_host(match)
                    found = self._for_url_host(text[start:end])
                    if found is not None:
                        spans.append(_Span(start, end, *found))
        if check_ips:
            for match in _IPV4_TOKEN.finditer(text):
                found = self._for_ip(match.group(0))
                if found is not None:
                    spans.append(_Span(*match.span(), *found))
            for match in _IPV6_TOKEN.finditer(text):
                token = match.group(0).rstrip(".")
                if ":" in token and (found := self._for_ip(token)) is not None:
                    spans.append(_Span(match.start(), match.start() + len(token), *found))
        if zones is not None:
            zones.extend(match.span() for match in _HOST_ZONE.finditer(text))
            spans.extend(self._phrase_spans(text, zones))
        return spans

    def _phrase_spans(self, text: str, zones: list[tuple[int, int]]) -> Iterator[_Span]:
        """Protected names and values: whole-word sequences outside every zone."""
        words = [(m.start(), m.end(), m.group(0).casefold()) for m in _WORD.finditer(text)]
        free = _free_words(words, zones)
        i = 0
        while i < len(words):
            lengths = self._phrase_lengths.get(words[i][2]) if free[i] else None
            matched = 0
            for length in lengths or ():
                stop = i + length
                if stop <= len(words) and all(free[i:stop]):
                    found = self._phrases.get(tuple(w[2] for w in words[i:stop]))
                    if found is not None:
                        yield _Span(words[i][0], words[stop - 1][1], *found)
                        matched = length
                        break
            i += matched or 1

    def _encoded_spans(self, text: str, spans: list[_Span]) -> list[_Span]:
        """Whole tokens whose percent-decoding reveals a protected value.

        A value found only once decoded cannot be cut out without leaving a
        usable, altered link, so the whole whitespace-delimited token goes.
        Values also found in the plain text are redacted in place instead.
        """
        starts = [span.start for span in spans]
        withheld: list[_Span] = []
        for chunk in _CHUNK.finditer(text):
            token = chunk.group(0)
            if "%" not in token:
                continue
            decoded = _unquote_all(token)
            if decoded == token:
                continue
            hidden = Counter(
                decoded[s.start : s.end].casefold() for s in _merge(self._spans(decoded))
            )
            if not hidden:
                continue
            lo, hi = bisect_left(starts, chunk.start()), bisect_left(starts, chunk.end())
            seen = Counter(text[s.start : s.end].casefold() for s in spans[lo:hi])
            if hidden - seen:
                withheld.append(_Span(*chunk.span(), *_ENCODED))
        return withheld

    def _redact(self, value: str) -> tuple[str, set[str]]:
        """``value`` with every protected span replaced, and the categories replaced."""
        view = _Refanged(value)
        found = self._spans(view.text)
        spans = _merge(found)
        if "%" in view.text:
            encoded = self._encoded_spans(view.text, spans)
            if encoded:
                found.extend(encoded)
                spans = _merge([*spans, *encoded])
        if not spans:
            return value, set()
        pieces: list[str] = []
        position = 0
        for span in spans:
            start, end = view.original(span.start, span.end)
            if end <= position:
                continue  # already covered: both sat in one defanged token
            pieces.append(value[position : max(start, position)])
            pieces.append(span.placeholder)
            position = end
        pieces.append(value[position:])
        return "".join(pieces), {span.category for span in found}

    # --- public API --------------------------------------------------------- #

    @property
    def active(self) -> bool:
        return self.policy.enabled

    def _note(self, category: str) -> None:
        self.triggered.add(category)

    def hides_field(self, name: str) -> bool:
        return self.active and name.strip().casefold() in self._fields

    def field(self, name: str, value: str | None) -> str | None:
        """Redact a header *value* if the operator listed its *name* as sensitive."""
        if not self.active or value is None:
            return value
        if name.strip().casefold() in self._fields:
            self._note("operator fields")
            return REDACTED_FIELD
        return value

    def recipient_address(self, addr: Address | None) -> Address | None:
        """Blank a recipient mailbox to a placeholder (display name included)."""
        if not self.active or not self.policy.recipients or addr is None:
            return addr
        self._note("recipients")
        return Address(display_name=None, addr_spec=REDACTED_RECIPIENT, domain=None)

    def text(self, value: str | None) -> str | None:
        """Redact free text in place; unchanged text is returned as given.

        Only the protected spans change: the rest of the value, defanging
        included, is kept exactly as written.
        """
        if not self.active or not value:
            return value
        redacted, categories = self._redact(value)
        self.triggered.update(categories)
        return redacted

    def classify_ioc(self, ioc_type: str, value: str, provenance: Iterable[str] = ()) -> str | None:
        """Return the display text for a PII indicator, or ``None`` to keep it.

        ``value`` is the raw (un-defanged) indicator. A protected address,
        domain or IP address is replaced by its placeholder, and a URL
        containing one is shown with that part redacted. A domain indicator
        seen only in ``To``/``Cc`` names the recipients and is withheld. An
        attacker indicator returns ``None`` and is kept verbatim.
        """
        if not self.active:
            return None
        provenance = set(provenance)
        if (
            ioc_type == "domain"
            and self.policy.recipients
            and provenance
            and provenance <= _RECIPIENT_PROVENANCE
        ):
            self._note("recipients")
            return REDACTED_RECIPIENT
        if ioc_type in {"ipv4", "ipv6"}:
            found = self._for_ip(value)
            if found is None:
                return None
        else:
            # An address is looked up directly too: one on a dotless domain
            # ("a@com") is never matched as a token in text.
            found = self._for_address(value) if ioc_type == "email" else None
            if found is None:
                redacted = self.text(value)
                return None if redacted == value else redacted
        self._note(found[1])
        return found[0]
