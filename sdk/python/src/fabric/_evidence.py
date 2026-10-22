# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The structured evidence carrier (spec 050 §3.4a): bounds checked before serialising (R9).

WP-01 lands the bound check :class:`~fabric._capture_types.EvidenceDoc.build` relies on;
WP-11a adds canonical serialisation on the capture worker (:func:`encode`) and PROTECT of
the object under its role's mode. Content never enters evidence: values are bounded ints,
bools, short strings and nested containers of them, and every type schema is closed.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from ._capture_types import (
    EVIDENCE_MAX_DEPTH,
    EVIDENCE_MAX_ITEMS,
    EVIDENCE_MAX_STRING,
    EVIDENCE_ROLE,
    UUID4_RE,
    EvidenceContinuation,
    EvidenceDoc,
    EvidenceRef,
    RecordsMisuseError,
)

EVIDENCE_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+/v[1-9][0-9]{0,3}$")
# PLACEHOLDER (WP-00): the registered evidence types of field-registry-v1.json
# `evidence_types`; P1 registers only the test type. WP-00 replaces this with the
# generated list (the Python twin of E/evidence_types_generated.go).
REGISTERED_EVIDENCE_TYPES: frozenset[str] = frozenset({"fabric.test.items/v1"})
_INT_MIN, _INT_MAX = -(1 << 63), (1 << 63) - 1


class _OverBound(Exception):  # noqa: N818 - internal control flow, never raised out
    pass


def _misuse(what: str) -> RecordsMisuseError:
    return RecordsMisuseError(f"records API misuse: evidence {what}")


def _check_value(value: Any, depth: int) -> None:
    """``depth`` is the depth of the container holding ``value`` (an item is depth 1)."""
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not _INT_MIN <= value <= _INT_MAX:
            raise _misuse("int outside int64")
        return
    if isinstance(value, str):
        if len(value) > EVIDENCE_MAX_STRING:
            raise _OverBound
        return
    if isinstance(value, Mapping):
        _check_object(value, depth + 1)
        return
    if isinstance(value, (list, tuple)):
        if depth + 1 > EVIDENCE_MAX_DEPTH:
            raise _OverBound
        if len(value) > EVIDENCE_MAX_ITEMS:
            raise _OverBound
        for element in value:
            _check_value(element, depth + 1)
        return
    raise _misuse("value class (floats, bytes and objects are refused)")


def _check_object(item: Mapping[Any, Any], depth: int) -> None:
    if depth > EVIDENCE_MAX_DEPTH:
        raise _OverBound
    if len(item) > EVIDENCE_MAX_ITEMS:
        raise _OverBound
    for key, value in item.items():
        if not isinstance(key, str) or not key:
            raise _misuse("key (non-empty str only)")
        if len(key) > EVIDENCE_MAX_STRING:
            raise _OverBound
        _check_value(value, depth)


def _check_ref(ref: object) -> None:
    if not isinstance(ref, EvidenceRef) or not UUID4_RE.fullmatch(str(ref.object_id)):
        raise _misuse("ref (EvidenceRef with a uuid4 object_id)")
    if ref.byte_range is not None:
        low, high = ref.byte_range
        if type(low) is not int or type(high) is not int or not 0 <= low <= high:
            raise _misuse("ref byte_range")


def check_evidence(doc: EvidenceDoc) -> bool:
    """``True`` when ``doc`` is within every §3.4a bound; ``False`` when an item-count,
    depth or string-length bound is exceeded (the record then carries a descriptor-only
    ``record.evidence``). Raises :class:`RecordsMisuseError` for a malformed document: an
    unregistered or malformed type, a float, bytes, a non-string key, a bad ref or
    continuation. Runs before anything is serialised."""
    if not isinstance(doc.evidence_type, str) or not EVIDENCE_TYPE_RE.fullmatch(
        doc.evidence_type
    ):  # fmt: skip
        raise _misuse("type id")
    if doc.evidence_type not in REGISTERED_EVIDENCE_TYPES:
        raise _misuse("type is not registered")
    continuation = doc.continuation
    if continuation is not None and (
        not isinstance(continuation, EvidenceContinuation)
        or type(continuation.index) is not int
        or continuation.index < 0
        or type(continuation.final) is not bool
    ):  # fmt: skip
        raise _misuse("continuation")
    for ref in doc.refs:
        _check_ref(ref)
    if len(doc.items) > EVIDENCE_MAX_ITEMS:
        return False
    try:
        for item in doc.items:
            if not isinstance(item, Mapping):
                raise _misuse("item (objects only)")
            _check_object(item, 1)
    except _OverBound:
        return False
    return True


def encode(doc: EvidenceDoc) -> bytes:
    """Spec-029 canonical JSON of ``doc`` (on the capture worker). WP-11a."""
    raise NotImplementedError("evidence serialisation lands in WP-11a")


__all__ = [
    "EVIDENCE_ROLE", "EVIDENCE_TYPE_RE", "REGISTERED_EVIDENCE_TYPES", "check_evidence",
    "encode",
]  # fmt: skip
