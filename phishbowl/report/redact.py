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
from dataclasses import dataclass

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
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


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
        """Redact recipient and internal host/IP tokens inside a ``Received`` hop.

        ``Received`` headers routinely carry the envelope recipient (``for
        <user@org>``) and the org's own hostnames/IPs. With redaction active we
        scrub recipient addresses and internal-topology tokens here too, so PII
        cannot leak through the routing path. Attacker/external infra in the same
        hop is left visible — that is the part an analyst needs.
        """
        if not self.active or not text:
            return text
        import re

        if self.policy.recipients and self._recipient_addrs:
            pattern = re.compile(
                "|".join(re.escape(a) for a in self._recipient_addrs), re.IGNORECASE
            )

            def _sub_recipient(m: re.Match[str]) -> str:
                self._note("recipients")
                return REDACTED_RECIPIENT

            text = pattern.sub(_sub_recipient, text)

        if not self.policy.internal:
            return text

        def _sub_host(m: re.Match[str]) -> str:
            tok = m.group(0)
            if self._is_internal_host(tok):
                self._note("internal hosts")
                return REDACTED_INTERNAL_HOST
            return tok

        def _sub_ip(m: re.Match[str]) -> str:
            tok = m.group(0)
            if _is_internal_ip(tok):
                self._note("internal IPs")
                return REDACTED_INTERNAL_IP
            return tok

        text = re.sub(r"[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", _sub_host, text)
        text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", _sub_ip, text)
        text = re.sub(r"\b[0-9A-Fa-f:]{2,}:[0-9A-Fa-f:]+\b", _sub_ip, text)
        return text

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
        return None
