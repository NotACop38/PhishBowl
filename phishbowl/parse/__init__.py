"""Ingest & parse (PRD §6.1).

Turn ``.eml`` (stdlib ``email``) and ``.msg`` (``extract-msg``) into a fully
populated ``ParsedEmail``, format-agnostic downstream. Charset/encoding
handling is centralized here. Attachments are hashed and inspected by
metadata/magic bytes only — never executed, never extracted.

Scaffold: implemented in Phase 1.
"""
