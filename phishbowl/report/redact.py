"""PII redaction for analyst outputs (PRD §10, §11).

Triage reports are routinely pasted into tickets, shared with vendors, and
attached to threat-intel submissions. ``--redact`` strips the bystander PII that
has no business leaving the org while keeping every attacker-controlled
indicator — the whole point of the report — fully intact.

Three categories are redacted when the policy is active:

* **Recipients** — the ``To``/``Cc`` addresses (and the IOCs derived from them):
  who *received* the phish is internal PII, not an indicator of the threat.
* **Internal hosts / IPs** — ``Received`` hops and IOCs that name an operator
  ``org_domain`` (from the scoring config) or a private/loopback IP (RFC 1918 /
  RFC 4193 / link-local / loopback): internal topology, not attacker infra.
* **Operator-configured fields** — any extra header names the operator lists.

Redaction replaces a value with a typed ``[redacted:…]`` placeholder rather than
deleting it, so the report still shows *that* something was present and *why it
is hidden — the structure of the analysis is preserved.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import quote, quote_plus, unquote

from phishbowl.extract import defang_text
from phishbowl.models import Address, ParsedEmail
from phishbowl.score import ScoringConfig

# Typed placeholders. Kept distinct so a reader (and a downstream tool consuming
# the JSON) can tell *what kind* of value was withheld.
REDACTED_RECIPIENT = "[redacted:recipient]"
REDACTED_INTERNAL_HOST = "[redacted:internal-host]"
REDACTED_INTERNAL_IP = "[redacted:internal-ip]"
REDACTED_FIELD = "[redacted:field]"


@dataclass(frozen=True)
class RedactionPolicy:
    """What an output should hide (PRD §10).

    The default (``enabled=False``) is a no-op: full fidelity. With ``enabled``
    set, the three category toggles decide what is stripped, and ``extra_fields``
    names additional headers to blank out by name (case-insensitive).
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
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return not ip.is_global or ip.is_multicast


class Redactor:
    """Applies a :class:`RedactionPolicy` to values drawn from one message.

    Construct once per report; it pre-computes the recipient address/domain sets
    and the operator's internal-domain set so per-value checks stay cheap. Every
    method is a safe no-op when the policy is disabled. The set of categories it
    actually touched is recorded in :attr:`triggered` for the report's audit note.
    """

    def __init__(self, policy: RedactionPolicy, parsed: ParsedEmail, config: ScoringConfig):
        self.policy = policy
        self._org_domains = frozenset(config.org_domains)
        self._extra_fields = frozenset(
            f.strip().casefold() for f in policy.extra_fields if f.strip()
        )
        self.triggered: set[str] = set()

        recipients = [*parsed.addresses.to, *parsed.addresses.cc]
        self._recipient_addrs = frozenset(
            a.addr_spec.strip().casefold() for a in recipients if a.addr_spec
        )
        self._recipient_domains = frozenset(
            a.domain.strip().casefold().rstrip(".") for a in recipients if a.domain
        )

        replacements = []
        if policy.recipients:
            replacements.extend(
                (v, REDACTED_RECIPIENT, "recipients")
                for a in recipients
                for v in (a.addr_spec, a.display_name, a.domain)
                if v
            )
        for h in parsed.headers.items:
            if h.name.casefold() in self._extra_fields and h.value:
                replacements.append((h.value, REDACTED_FIELD, "operator fields"))
        self._replacements = []
        for value, replacement, category in sorted(replacements, key=lambda item: -len(item[0])):
            variants = {
                value,
                defang_text(value),
                value.replace(".", "[.]"),
                quote(value, safe=""),
                quote_plus(value),
            }
            pattern = re.compile(
                "|".join(re.escape(v) for v in sorted(variants, key=len, reverse=True) if v), re.I
            )
            self._replacements.append((pattern, replacement, category))

    @property
    def active(self) -> bool:
        return self.policy.enabled

    def _note(self, category: str) -> None:
        self.triggered.add(category)

    def _is_internal_host(self, host: str) -> bool:
        host = host.strip().casefold().rstrip(".")
        if not host:
            return False
        return any(host == d or host.endswith("." + d) for d in self._org_domains)

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

    def hop_text(self, text: str | None) -> str | None:
        """Apply the same policy to free text and every derived representation."""
        if not self.active or not text:
            return text
        if self.policy.internal:

            def internal_host(m):
                if self._is_internal_host(m.group()):
                    self._note("internal hosts")
                    return REDACTED_INTERNAL_HOST
                return m.group()

            text = re.sub(r"(?<![A-Za-z0-9.-])[A-Za-z0-9.-]+\.[A-Za-z]{2,}", internal_host, text)
        for pattern, replacement, category in self._replacements:
            text, count = pattern.subn(lambda m, replacement=replacement: replacement, text)
            if count:
                self._note(category)
        if self.policy.internal:

            def host(m):
                if self._is_internal_host(m.group()):
                    self._note("internal hosts")
                    return REDACTED_INTERNAL_HOST
                return m.group()

            def ip(m):
                if _is_internal_ip(m.group()):
                    self._note("internal IPs")
                    return REDACTED_INTERNAL_IP
                return m.group()

            text = re.sub(r"(?<![A-Za-z0-9.-])[A-Za-z0-9.-]+\.[A-Za-z]{2,}", host, text)
            text = re.sub(r"(?<![\w:])(?:[0-9A-Fa-f]*:){2,}[0-9A-Fa-f:.]*(?![\w:])", ip, text)
            text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", ip, text)
        return text

    def text(self, value: str | None) -> str | None:
        if not self.active or not value:
            return value
        # Inspect common percent encodings before rendering. Any changed encoded
        # value is withheld whole: redaction must not create a usable altered URL.
        decoded = value
        for _ in range(3):
            new = unquote(decoded)
            if new == decoded:
                break
            decoded = new
        if decoded != value and self.hop_text(decoded) != decoded:
            return REDACTED_FIELD
        return self.hop_text(value)

    def classify_ioc(self, ioc_type: str, value: str) -> str | None:
        """Return a placeholder if this IOC value is PII, else ``None`` (keep it).

        ``value`` is the raw (un-defanged) indicator. Recipients win first, then
        internal topology; an external attacker indicator returns ``None`` and is
        kept verbatim.
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
        if self.text(value) != value:
            return REDACTED_FIELD
        return None
