"""Bundled enrichment connectors (PRD §9).

Importing this package registers every in-repo connector via the
:func:`~phishbowl.connectors.registry.register` decorator, which is exactly what
:func:`~phishbowl.connectors.registry.discover` does to find them. Each connector
is key-gated (except keyless WHOIS/RDAP), reaches only its vendor's documented
API (SSRF-guarded), and never logs or returns its API key.

Add a bundled connector by creating a module here and importing it below; ship a
third-party connector instead as a ``phishbowl.connectors`` entry-point — no fork
required (PRD §9).
"""

from __future__ import annotations

from .abuseipdb import AbuseIPDBConnector
from .rdap import RDAPConnector
from .shodan import ShodanConnector
from .urlscan import UrlscanConnector
from .virustotal import VirusTotalConnector

__all__ = [
    "RDAPConnector",
    "VirusTotalConnector",
    "AbuseIPDBConnector",
    "UrlscanConnector",
    "ShodanConnector",
]
