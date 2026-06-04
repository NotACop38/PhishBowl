"""IOC extraction, wrapper unwrapping & defang (PRD §6.2).

Extract addresses, URLs, domains, IPs, and hashes from a parsed message; unwrap
protective wrappers (Safelinks, Proofpoint URL Defense) as a pure string
transform — **never** by fetching; and defang everything in human-facing output
by default. Deduplicated, normalized, and provenance-tagged.

Nothing in this package touches the network: the analyzed email's URLs are
pattern-matched and string-decoded, never opened (CLAUDE.md defensive invariants).
"""

from __future__ import annotations

from .defang import (
    defang,
    defang_domain,
    defang_email,
    defang_ipv4,
    defang_ipv6,
    defang_url,
    refang,
)
from .extract import extract_iocs
from .unwrap import (
    UnwrapResult,
    detect_wrapper,
    unwrap_proofpoint,
    unwrap_safelinks,
    unwrap_url,
)

__all__ = [
    "extract_iocs",
    # Defang
    "defang",
    "defang_url",
    "defang_ipv4",
    "defang_ipv6",
    "defang_email",
    "defang_domain",
    "refang",
    # Unwrap
    "unwrap_url",
    "unwrap_safelinks",
    "unwrap_proofpoint",
    "detect_wrapper",
    "UnwrapResult",
]
