# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The structured evidence carrier (spec 050 §3.4a): bounds checked before serialising (R9).

:meth:`~fabric._capture_types.EvidenceDoc.build` calls :func:`check_evidence` on the
application thread (counts, depth and string lengths only; nothing is serialised there);
the capture worker serialises the document with :func:`encode` as spec-029 canonical JSON
and PROTECTs it under the ``record.evidence`` role's mode (``wire/_pipeline.py``). Content
never enters evidence: values are bounded ints, bools, short strings and nested containers
of them, and every type schema is closed.

The envelope constants and :data:`REGISTERED_EVIDENCE_TYPES` are the Python twin of the
generated ``E/evidence_types_generated.go`` (from ``field-registry-v1.json``
``evidence_types``); ``tests/test_record_evidence.py`` pins them to both, so the agent
never writes a type the Node's pre-acknowledgement check refuses.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from ._capture_types import (
    EVIDENCE_MAX_BYTES,
    EVIDENCE_MAX_DEPTH,
    EVIDENCE_MAX_ITEMS,
    EVIDENCE_MAX_STRING,
    EVIDENCE_MEDIA_TYPE,
    EVIDENCE_ROLE,
    EVIDENCE_SCHEMA_VERSION,
    UUID4_RE,
    EvidenceContinuation,
    EvidenceDoc,
    EvidenceRef,
    RecordsMisuseError,
)
from ._seal import canonical_bytes

# --- the twin of E/evidence_types_generated.go (pinned by test) ------------------------------
EVIDENCE_MAX_REFS = 64
# The closed top-level keys of the envelope (True: required).
EVIDENCE_ENVELOPE_KEYS: Mapping[str, bool] = {
    "schema_version": True, "evidence_type": True, "items": True, "continuation": False,
    "refs": False,
}  # fmt: skip
# Every registered evidence type (P1 registers only the test type; 053/054 add theirs).
REGISTERED_EVIDENCE_TYPES: frozenset[str] = frozenset({"fabric.test.items/v1"})
# ---------------------------------------------------------------------------------------------

EVIDENCE_TYPE_RE = re.compile(r"^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+/v[1-9][0-9]{0,3}$")
POINTER_RE = re.compile(r"^(/([^~/]|~[01]){0,64}){0,16}$")
_INT_MIN, _INT_MAX = -(1 << 63), (1 << 63) - 1


class _OverBound(Exception):  # noqa: N818 - internal control flow, never raised out
    pass


def _misuse(what: str) -> RecordsMisuseError:
    return RecordsMisuseError(f"records API misuse: evidence {what}")


def _check_string(value: str) -> None:
    if len(value) > EVIDENCE_MAX_STRING:
        raise _OverBound


def _check_value(value: Any, depth: int) -> None:
    """``depth`` is the depth of the container holding ``value`` (an item is depth 1)."""
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not _INT_MIN <= value <= _INT_MAX:
            raise _misuse("int outside int64")
        return
    if isinstance(value, str):
        _check_string(value)
        return
    if isinstance(value, Mapping):
        _check_object(value, depth + 1)
        return
    if isinstance(value, (list, tuple)):
        if depth + 1 > EVIDENCE_MAX_DEPTH or len(value) > EVIDENCE_MAX_ITEMS:
            raise _OverBound
        for element in value:
            _check_value(element, depth + 1)
        return
    raise _misuse("value class (floats, bytes and objects are refused)")


def _check_object(item: Mapping[Any, Any], depth: int) -> None:
    if depth > EVIDENCE_MAX_DEPTH or len(item) > EVIDENCE_MAX_ITEMS:
        raise _OverBound
    for key, value in item.items():
        if not isinstance(key, str) or not key:
            raise _misuse("key (non-empty str only)")
        _check_string(key)
        _check_value(value, depth)


def _check_ref(ref: object) -> None:
    if not isinstance(ref, EvidenceRef) or not UUID4_RE.fullmatch(str(ref.object_id)):
        raise _misuse("ref (EvidenceRef with a uuid4 object_id)")
    if not isinstance(ref.role, str) or not ref.role:
        raise _misuse("ref role")
    if ref.pointer is not None and (
        not isinstance(ref.pointer, str) or not POINTER_RE.fullmatch(ref.pointer)
    ):  # fmt: skip
        raise _misuse("ref pointer (an RFC 6901 pointer)")
    if ref.byte_range is not None:
        low, high = ref.byte_range
        if type(low) is not int or type(high) is not int or not 0 <= low <= high:
            raise _misuse("ref byte_range")
    _check_string(ref.role)
    if ref.pointer is not None:
        _check_string(ref.pointer)


def check_evidence(doc: EvidenceDoc) -> bool:
    """``True`` when ``doc`` is within every §3.4a bound; ``False`` when an item-count,
    ref-count, depth or string-length bound is exceeded (the record then carries a
    descriptor-only ``record.evidence``). Raises :class:`RecordsMisuseError` for a
    malformed document: an unregistered or malformed type, a float, bytes, a non-string
    key, a bad ref or continuation. Runs before anything is serialised. The 1 MiB byte cap
    is checked after serialisation, on the capture worker."""
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
        or not 0 <= continuation.index <= _INT_MAX
        or type(continuation.final) is not bool
    ):  # fmt: skip
        raise _misuse("continuation")
    try:
        for ref in doc.refs:
            _check_ref(ref)
        if len(doc.refs) > EVIDENCE_MAX_REFS or len(doc.items) > EVIDENCE_MAX_ITEMS:
            return False
        for item in doc.items:
            if not isinstance(item, Mapping):
                raise _misuse("item (objects only)")
            _check_object(item, 1)
    except _OverBound:
        return False
    return True


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str.__str__(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, str):
        return str.__str__(value)
    return value


def document(doc: EvidenceDoc) -> dict[str, Any]:
    """The ``fabric.record-evidence/v1`` document of ``doc``; ``refs`` and
    ``continuation`` only when present."""
    out: dict[str, Any] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION, "evidence_type": doc.evidence_type,
        "items": [_plain(item) for item in doc.items],
    }  # fmt: skip
    if doc.continuation is not None:
        out["continuation"] = {"index": doc.continuation.index,
                               "final": doc.continuation.final}  # fmt: skip
    if doc.refs:
        refs = []
        for ref in doc.refs:
            entry: dict[str, Any] = {"object_id": ref.object_id, "role": ref.role}
            if ref.pointer is not None:
                entry["pointer"] = ref.pointer
            if ref.byte_range is not None:
                entry["byte_range"] = list(ref.byte_range)
            refs.append(_plain(entry))
        out["refs"] = refs
    return out


def encode(doc: EvidenceDoc) -> bytes | None:
    """Spec-029 canonical JSON of ``doc`` (on the capture worker). The bounds are checked
    again first (the items are the application's objects, held by reference); ``None``
    when ``doc`` is now over a bound or over 1 MiB serialised. Raises
    :class:`RecordsMisuseError` when it is now malformed (the worker records it as a
    descriptor-only ``encoding_failed`` object)."""
    if not check_evidence(doc):
        return None
    data = canonical_bytes(document(doc))
    return data if len(data) <= EVIDENCE_MAX_BYTES else None


__all__ = [
    "EVIDENCE_ENVELOPE_KEYS", "EVIDENCE_MAX_REFS", "EVIDENCE_MEDIA_TYPE", "EVIDENCE_ROLE",
    "EVIDENCE_TYPE_RE", "POINTER_RE", "REGISTERED_EVIDENCE_TYPES", "check_evidence",
    "document", "encode",
]  # fmt: skip
