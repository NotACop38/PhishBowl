"""Shared Pydantic base for the model layer.

Centralizes config so every sub-model behaves the same way: aliases such as
``from`` (a Python keyword) can be populated by either the field name or the
alias, and unknown keys are rejected so a malformed payload surfaces loudly
rather than silently dropping data.

It also guarantees that no text field holds a lone UTF-16 surrogate. Python
produces them when it decodes hostile bytes leniently (``surrogateescape``, some
codecs), and JSON serialization, UTF-8 file writes and terminals all reject
them, so one stray byte in an email would otherwise crash every renderer.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator

_SURROGATES = re.compile(r"[\ud800-\udfff]")


def _without_surrogates(value: Any) -> Any:
    """``value`` with lone surrogates in its strings replaced by U+FFFD."""
    if isinstance(value, str):
        return _SURROGATES.sub("�", value) if _SURROGATES.search(value) else value
    if isinstance(value, (list, tuple)):
        cleaned = [_without_surrogates(item) for item in value]
        if any(new is not old for new, old in zip(cleaned, value, strict=True)):
            return type(value)(cleaned)
    return value


class PhishbowlModel(BaseModel):
    """Base model for the ``ParsedEmail`` contract."""

    model_config = ConfigDict(
        populate_by_name=True,
        extra="forbid",
    )

    @field_validator("*", mode="after")
    @classmethod
    def _no_lone_surrogates(cls, value: Any) -> Any:
        return _without_surrogates(value)
