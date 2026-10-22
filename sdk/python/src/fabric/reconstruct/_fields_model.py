# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Model-call field extraction (spec 050 §3.13 table): pure functions over the stored,
reassembled request and response bytes, returning field sets with JSON-pointer locators.

WP-01 freezes the interface; :func:`extract_model_fields` extracts nothing
(``not_parsed``). WP-33 implements the dialects (OpenAI chat, responses, completions,
embeddings; Anthropic messages; document and SSE) reusing ``_stitch``'s decoders. It never
raises: malformed, compressed or truncated input gives ``parse_failed`` fields.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from ._stitch import ParseStatus, WireApi


@dataclass(frozen=True, slots=True)
class FieldValue:
    """One field wrapper's evidence: a coverage status, an optional value (META, LABEL,
    DIGEST or mapped ID only) and locators into the stored objects (never content)."""

    field_id: str
    status: str
    reason: str | None = None
    value: Any = None
    locators: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ModelFields:
    parse_status: ParseStatus
    fields: Mapping[str, FieldValue] = field(default_factory=lambda: MappingProxyType({}))


def extract_model_fields(
    api: WireApi, *, request: bytes | None, response: bytes | None,
    request_encoding: str | None = None, response_encoding: str | None = None,
    request_media_type: str | None = None, response_media_type: str | None = None,
) -> ModelFields:  # fmt: skip
    """The model-call fields of one exchange. ``not_parsed`` with no fields until WP-33."""
    return ModelFields("not_parsed")


__all__ = ["FieldValue", "ModelFields", "extract_model_fields"]
