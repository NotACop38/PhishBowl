"""Shared Pydantic base for the model layer.

Centralizes config so every sub-model behaves the same way: aliases such as
``from`` (a Python keyword) can be populated by either the field name or the
alias, and unknown keys are rejected so a malformed payload surfaces loudly
rather than silently dropping data.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class PhishbowlModel(BaseModel):
    """Base model for the ``ParsedEmail`` contract."""

    model_config = ConfigDict(
        populate_by_name=True,
        extra="forbid",
    )
