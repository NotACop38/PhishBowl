"""Phishbowl — a self-hostable, defensive-only phishing triage tool.

Parse a suspicious ``.eml``/``.msg`` → extract and defang IOCs → risk-score it
→ produce an analyst-ready report. Offline-first: the core pipeline always
yields a complete verdict with zero API keys; OSINT enrichment only augments.

See ``docs/PRD.md`` (product spec, source of truth) and ``docs/CHECKLIST.md``
(phased build order — all phases complete for v0.1).
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
