# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Evidence-object decoding for the projection (spec 050 §3.4a item 6): a stored
``record.evidence`` object is checked against its registered type schema and mapped to
field wrappers through the registry's field-key -> JSON-pointer map.

WP-01 freezes the interface; :func:`decode_evidence` decodes nothing. WP-32 implements it;
an invalid item makes the fields it carries ``not_captured(parse_failed)``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal

from ._fields_model import FieldValue

DecodeStatus = Literal["ok", "parse_failed", "unknown_type", "not_decoded"]


@dataclass(frozen=True, slots=True)
class EvidenceDecode:
    status: DecodeStatus
    evidence_type: str | None = None
    fields: Mapping[str, FieldValue] = field(default_factory=lambda: MappingProxyType({}))


def decode_evidence(
    data: bytes, *, evidence_types: Mapping[str, Any], provenance: str, capture_point: str
) -> EvidenceDecode:
    """Decode one stored evidence object into field values. ``not_decoded`` until WP-32."""
    return EvidenceDecode("not_decoded")


__all__ = ["DecodeStatus", "EvidenceDecode", "decode_evidence"]
