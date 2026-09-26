"""PII redaction for analyst outputs (PRD §10, §11).

Triage reports are routinely pasted into tickets, shared with vendors, and
attached to threat-intel submissions. ``--redact`` withholds the bystander data
that has no business leaving the organization while keeping the attacker's
indicators — the point of the report — intact.

Three categories are redacted when the policy is active:

* **Recipients** — every address the message was delivered to: ``To``/``Cc``/
  ``Bcc``, the delivery headers mail systems add (``Delivered-To``,
  ``X-Original-To``, ``Envelope-To``, ``Resent-*``, …) and ``Received … for
  <addr>`` clauses, together with their display names and domains (free-webmail
  domains excepted: ``gmail.com`` identifies no one).
* **Internal hosts / IPs** — host names under an operator ``org_domain`` (from
  the scoring config), addresses at those hosts, and non-public IP addresses.
* **Operator-configured fields** — any extra header names the operator lists,
  plus everything parsed from them (a hidden ``Authentication-Results`` header
  hides its result details; a hidden ``Received`` header hides the routing).

Matching is case-insensitive on whole tokens, over text with PhishBowl's own
defanging undone, so ``alice[at]corp[.]example`` is caught like
``alice@corp.example`` and "IT" never matches inside "submit". Values are
replaced in place by a typed ``[redacted:…]`` placeholder, so the report still
shows *that* something was present and *why* it is hidden. Only when a
protected value survives inside percent-encoding (where it cannot be cut out
without leaving a usable, altered URL) is the whole value withheld.

Redaction is selected-value removal, not anonymization: free text can still
identify people in ways no list anticipates. Review before sharing.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import quote, quote_plus, unquote

from phishbowl.domains import in_domain
from phishbowl.extract import refang
from phishbowl.models import Address, ParsedEmail
from phishbowl.parse.addresses import parse_address_list
from phishbowl.score import ScoringConfig

# Typed placeholders. Kept distinct so a reader (and a downstream tool consuming
# the JSON) can tell *what kind* of value was withheld.
REDACTED_RECIPIENT = "[redacted:recipient]"
REDACTED_INTERNAL_HOST = "[redacted:internal-host]"
REDACTED_INTERNAL_IP = "[redacted:internal-ip]"
REDACTED_FIELD = "[redacted:field]"

# Headers that name a recipient of the message (lower-case).
RECIPIENT_HEADERS = frozenset(
    {
        "to",
        "cc",
        "bcc",
        "delivered-to",
        "x-original-to",
        "envelope-to",
        "x-envelope-to",
        "apparently-to",
        "resent-to",
        "resent-cc",
        "resent-bcc",
        "x-forwarded-to",
        "x-rcpt-to",
    }
)

# Headers holding a single sender-side mailbox (for operator field redaction).
_ADDRESS_HEADERS = RECIPIENT_HEADERS | {"from", "reply-to", "return-path", "sender"}

# A Received header's "for <addr>" clause names the recipient.
_RECEIVED_FOR = re.compile(r"\bfor\s+<?([^\s<>;@]+@[^\s<>;]+?)>?(?=[\s;]|$)", re.IGNORECASE)

# Display names shorter than this are too generic to redact ("IT", "HR").
_MIN_DISPLAY_NAME = 3

# Candidate tokens, all matched with possessive quantifiers so a failed match
# never backtracks: redaction stays linear even on hostile text.
_EMAIL_TOKEN = re.compile(r"(?<![\w.%+\-])[\w.%+\-]++@([\w\-]++(?:\.[\w\-]++)++)")
_HOST_TOKEN = re.compile(r"(?<![\w.\-])[\w\-]++(?:\.[\w\-]++)++")
_IPV4_TOKEN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
_IPV6_TOKEN = re.compile(r"(?<![\w:.])[0-9A-Fa-f:.]{2,}+(?![\w:.])")


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


def _is_internal_ip(value: str) -> bool:
    """True for a private/loopback/link-local IP literal (internal topology)."""
    try:
        ip = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return False
    return not ip.is_global or ip.is_multicast


def _refang_all(value: str) -> str:
    """Undo defanging, including defanging applied more than once."""
    for _ in range(3):
        restored = refang(value)
        if restored == value:
            break
        value = restored
    return value


def _unquote_all(value: str) -> str:
    """Undo percent-encoding, including double encoding."""
    for _ in range(3):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


def _literal_pattern(value: str) -> re.Pattern[str]:
    """Whole-token, case-insensitive matcher for ``value`` and its URL encodings."""
    variants = {value, quote(value, safe=""), quote_plus(value)}
    body = "|".join(re.escape(v) for v in sorted(variants, key=len, reverse=True))
    return re.compile(rf"(?<![\w\-])(?:{body})(?![\w\-])", re.IGNORECASE)


def recipient_addresses(parsed: ParsedEmail) -> list[Address]:
    """Every recipient the message names, from address and delivery headers."""
    recipients = [*parsed.addresses.to, *parsed.addresses.cc]
    for header in parsed.headers.items:
        name = header.name.casefold()
        if name in RECIPIENT_HEADERS and name not in {"to", "cc"}:
            recipients.extend(parse_address_list([header.value]))
        elif name == "received":
            recipients.extend(
                Address(addr_spec=match, domain=match.rsplit("@", 1)[1].casefold())
                for match in _RECEIVED_FOR.findall(header.value)
            )
    return [a for a in recipients if a.addr_spec or a.display_name]


class Redactor:
    """Applies a :class:`RedactionPolicy` to values drawn from one message.

    Construct once per report; it pre-computes the recipient and operator-field
    patterns and the operator's internal-domain set so per-value checks stay
    cheap. Every method is a safe no-op when the policy is disabled. The
    categories it actually redacted are recorded in :attr:`triggered` for the
    report's audit note.
    """

    def __init__(self, policy: RedactionPolicy, parsed: ParsedEmail, config: ScoringConfig):
        self.policy = policy
        self.triggered: set[str] = set()
        self._org_domains = frozenset(config.org_domains)
        self._extra_fields = frozenset(
            f.strip().casefold() for f in policy.extra_fields if f.strip()
        )

        recipients = recipient_addresses(parsed)
        self._recipient_addrs = frozenset(
            a.addr_spec.strip().casefold() for a in recipients if a.addr_spec
        )
        self._recipient_domains = frozenset(
            a.domain.strip().casefold().rstrip(".")
            for a in recipients
            if a.domain and a.domain.casefold() not in config.freemail_domains
        )

        literals: list[tuple[str, str, str]] = []
        if policy.recipients:
            for address in recipients:
                literals.extend(
                    (value, REDACTED_RECIPIENT, "recipients")
                    for value in self._protected_parts(address)
                )
        field_domains: set[str] = set()
        for header in parsed.headers.items:
            name = header.name.casefold()
            if name not in self._extra_fields or not header.value.strip():
                continue
            literals.append((header.value.strip(), REDACTED_FIELD, "operator fields"))
            if name in _ADDRESS_HEADERS:
                for address in parse_address_list([header.value]):
                    literals.extend(
                        (value, REDACTED_FIELD, "operator fields")
                        for value in self._protected_parts(address)
                    )
                    domain = (address.domain or "").strip().casefold().rstrip(".")
                    if domain and domain not in config.freemail_domains:
                        field_domains.add(domain)
        # A hidden address header hides its domains wherever they appear
        # (mismatch evidence, domain indicators, links), like recipients do.
        self._field_domains = frozenset(field_domains)
        # A hidden authentication header hides the results parsed from it.
        auth_fields = {"authentication-results": ("spf", "dkim", "dmarc"), "received-spf": ("spf",)}
        for field_name, mechanisms in auth_fields.items():
            if field_name in self._extra_fields:
                for mechanism in mechanisms:
                    detail = getattr(parsed.auth, mechanism).detail
                    if detail:
                        literals.append((detail, REDACTED_FIELD, "operator fields"))
        if "date" in self._extra_fields and parsed.date:
            literals.append((parsed.date.isoformat(), REDACTED_FIELD, "operator fields"))

        # Longest first, so "alice@corp.example" is replaced before "corp.example".
        seen: set[str] = set()
        self._literals: list[tuple[re.Pattern[str], str, str]] = []
        for value, replacement, category in sorted(literals, key=lambda item: -len(item[0])):
            key = value.casefold()
            if key in seen:
                continue
            seen.add(key)
            self._literals.append((_literal_pattern(value), replacement, category))

    @staticmethod
    def _protected_parts(address: Address) -> list[str]:
        """An address's literal parts. Its domain is matched as a host instead."""
        parts = [address.addr_spec]
        if address.display_name and len(address.display_name.strip()) >= _MIN_DISPLAY_NAME:
            parts.append(address.display_name.strip())
        return [part for part in parts if part]

    @property
    def active(self) -> bool:
        return self.policy.enabled

    def _note(self, category: str) -> None:
        self.triggered.add(category)

    def _is_internal_host(self, host: str) -> bool:
        return bool(self._org_domains) and in_domain(host, self._org_domains)

    def _host_placeholder(self, host: str) -> tuple[str, str] | None:
        """``(placeholder, category)`` for a protected host, else ``None``."""
        if self.policy.internal and self._is_internal_host(host):
            return REDACTED_INTERNAL_HOST, "internal hosts"
        if (
            self.policy.recipients
            and self._recipient_domains
            and in_domain(host, self._recipient_domains)
        ):
            return REDACTED_RECIPIENT, "recipients"
        if self._field_domains and in_domain(host, self._field_domains):
            return REDACTED_FIELD, "operator fields"
        return None

    def hides_field(self, name: str) -> bool:
        return self.active and name.strip().casefold() in self._extra_fields

    def field(self, name: str, value: str | None) -> str | None:
        """Redact a header *value* if the operator listed its *name* as sensitive."""
        if not self.active or value is None:
            return value
        if name.strip().casefold() in self._extra_fields:
            self._note("operator fields")
            return REDACTED_FIELD
        return value

    def recipient_address(self, addr: Address | None) -> Address | None:
        """Blank a recipient mailbox to a placeholder (display name included)."""
        if not self.active or not self.policy.recipients or addr is None:
            return addr
        self._note("recipients")
        return Address(display_name=None, addr_spec=REDACTED_RECIPIENT, domain=None)

    def _redact(self, text: str, *, record: bool = True) -> str:
        """Replace every protected token in plain (refanged) ``text``."""

        def note(category: str) -> None:
            if record:
                self._note(category)

        for pattern, replacement, category in self._literals:
            text, count = pattern.subn(replacement, text)
            if count:
                note(category)

        def host(match: re.Match[str]) -> str:
            # For an address the domain decides, and the whole address goes
            # (an internal colleague's local part is PII too).
            found = self._host_placeholder(match.group(match.lastindex or 0))
            if found is None:
                return match.group(0)
            note(found[1])
            return found[0]

        text = _EMAIL_TOKEN.sub(host, text)
        text = _HOST_TOKEN.sub(host, text)
        if not self.policy.internal:
            return text

        def ip(match: re.Match[str]) -> str:
            token = match.group(0).rstrip(".")
            if (":" not in token or token.count(":") >= 2) and _is_internal_ip(token):
                note("internal IPs")
                return REDACTED_INTERNAL_IP + match.group(0)[len(token) :]
            return match.group(0)

        text = _IPV4_TOKEN.sub(ip, text)
        return _IPV6_TOKEN.sub(ip, text)

    def text(self, value: str | None) -> str | None:
        """Redact free text in place; withhold it whole only for encoded PII.

        The result has PhishBowl's defanging undone (callers defang what they
        display), so a protected value is caught however it was written.
        """
        if not self.active or not value:
            return value
        redacted = self._redact(_refang_all(value))
        decoded = _unquote_all(redacted)
        if decoded != redacted and self._redact(decoded, record=False) != decoded:
            # A protected value hides inside percent-encoding: cutting it out
            # would leave a usable, altered URL, so the whole value is withheld.
            self._note("encoded values")
            return REDACTED_FIELD
        return redacted

    def classify_ioc(self, ioc_type: str, value: str) -> str | None:
        """Return the display text for a PII indicator, or ``None`` to keep it.

        ``value`` is the raw (un-defanged) indicator. A recipient or internal
        address/domain/IP is replaced by its placeholder; a URL containing one
        is shown with that part redacted. An external attacker indicator
        returns ``None`` and is kept verbatim.
        """
        if not self.active:
            return None
        v = value.strip().casefold().rstrip(".")
        if self.policy.recipients:
            if ioc_type == "email" and v in self._recipient_addrs:
                self._note("recipients")
                return REDACTED_RECIPIENT
            if ioc_type == "domain" and v in self._recipient_domains:
                self._note("recipients")
                return REDACTED_RECIPIENT
        if self.policy.internal:
            if ioc_type in {"ipv4", "ipv6"} and _is_internal_ip(value):
                self._note("internal IPs")
                return REDACTED_INTERNAL_IP
            if ioc_type == "domain" and self._is_internal_host(value):
                self._note("internal hosts")
                return REDACTED_INTERNAL_HOST
        redacted = self.text(value)
        return None if redacted == value else redacted
