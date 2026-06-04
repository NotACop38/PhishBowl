"""Risk scoring (PRD §6.3, §8).

Transparent over clever: the score is the sum of triggered, YAML-weighted
rules normalized to 0–100, each emitting a human-readable reason with its
evidence and tagged by source (offline | enrichment). The offline verdict is
always computed independent of enrichment.

Scaffold: implemented in Phase 3.
"""
