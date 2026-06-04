"""IOC extraction, wrapper unwrapping & defang (PRD §6.2).

Extract addresses, URLs, domains, IPs, and hashes; unwrap protective wrappers
(Safelinks, Proofpoint URL Defense) as a pure string transform — never by
fetching; and defang everything in human-facing output by default.

Scaffold: implemented in Phase 2.
"""
