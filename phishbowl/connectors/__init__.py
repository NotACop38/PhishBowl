"""Enrichment connectors (PRD §6.5, §9).

Pluggable, key-gated OSINT enrichment that augments — never gates — the
verdict. A stable connector interface (registry + ``phishbowl.connectors``
entry-points) with per-connector caching, rate limiting, graceful degrade, and
an allowlisted-egress SSRF guard: connectors reach only their vendor's
documented API and never fetch a URL taken from the email.

Scaffold: implemented in Phase 5.
"""
