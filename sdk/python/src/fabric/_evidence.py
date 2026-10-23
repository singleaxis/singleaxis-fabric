# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The structured evidence carrier (spec 050 §3.4a): bounded, closed and identity-mapped
before anything is persisted (R7, R8, R9).

:meth:`~fabric._capture_types.EvidenceDoc.build` calls :func:`measure_evidence` on the
application thread: one bounded walk (item count, depth, string lengths and a total-work
bound, :data:`EVIDENCE_MAX_VALUES`), then each item against its type's registered closed
item schema (:data:`EVIDENCE_ITEM_SCHEMAS`). Nothing is serialised there. The capture
worker (``wire/_pipeline.py``) calls :func:`encode`: it takes its own bounded copy of the
document (the items are the application's objects, held by reference, and may have changed
since ``emit``), validates that copy again, maps every ID property by the records input's
identity rule (:class:`EvidenceIds`; omitted without a key) and serialises the copy as
spec-029 canonical JSON. A raw ``RecordBody(role="record.evidence")`` takes the same path
(:func:`encode_raw`). So a clear caller id or a field outside the closed schema never
reaches the spool, the store or the Node (§3.17 privacy canaries).

The envelope constants, :data:`REGISTERED_EVIDENCE_TYPES` and :data:`EVIDENCE_ITEM_SCHEMAS`
are the Python twin of the generated ``E/evidence_types_generated.go`` and of each type's
schema under ``contracts/coverage/v1/evidence/``; ``tests/test_record_evidence.py`` and
``tests/test_reconstruct_project.py`` pin them, so the agent never writes a type the
Node's pre-acknowledgement check refuses.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
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
from ._sequence import V2_TYPES, EmittedId

# --- the twin of E/evidence_types_generated.go and the type schemas (pinned by test) --------
EVIDENCE_MAX_REFS = 64
# The closed top-level keys of the envelope (True: required).
EVIDENCE_ENVELOPE_KEYS: Mapping[str, bool] = {
    "schema_version": True, "evidence_type": True, "items": True, "continuation": False,
    "refs": False,
}  # fmt: skip
# Every registered evidence type (P1 registers only the test type; 053/054 add theirs).
REGISTERED_EVIDENCE_TYPES: frozenset[str] = frozenset({"fabric.test.items/v1"})
# An ID property's clear-mode alternative (R8), admitted only under identity_mode clear.
CLEAR_KEYWORD = "x-fabric-clear"
_TEST_ITEMS_SCHEMA: Mapping[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://singleaxis.ai/contracts/coverage/v1/evidence/fabric.test.items-v1.schema.json",
    "type": "object",
    "additionalProperties": False,
    "required": ["name", "count"],
    "properties": {
        "name": {"type": "string", "pattern": "^[a-z][a-z0-9_.-]{0,63}$"},
        "count": {"type": "integer", "minimum": 0, "maximum": 1000000},
        "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
        "kind": {"enum": ["alpha", "beta", "other"]},
        "ref_index": {"type": "integer", "minimum": 0, "maximum": 63},
        "tags": {
            "type": "array", "maxItems": 8,
            "items": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,31}$"},
        },
        "actor": {
            "type": "string", "pattern": "^act-[0-9a-f]{32}$",
            CLEAR_KEYWORD: {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},
        },
    },
}  # fmt: skip
#: The closed item schema of each registered type (its file under
#: ``contracts/coverage/v1/evidence/``, annotations dropped). ``fabric.reconstruct``
#: validates stored objects against the same dictionaries.
EVIDENCE_ITEM_SCHEMAS: Mapping[str, Mapping[str, Any]] = MappingProxyType({
    "fabric.test.items/v1": _TEST_ITEMS_SCHEMA,
})  # fmt: skip
# ---------------------------------------------------------------------------------------------

#: The total-work bound of one document (R9): every value walked (each item, nested
#: container and scalar, and each ref) counts one, and the walk stops as soon as it is
#: passed (the document is then ``payload_too_large``). 4096 items of 16 values each (the
#: largest item ``fabric.test.items/v1`` admits) fit exactly.
EVIDENCE_MAX_VALUES = 65_536
# The conservative in-flight charge (bytes) of a document held by reference until the
# worker encodes it: a character may expand to a 6-byte JSON escape; a value carries
# punctuation and object overhead. Never more than the 1 MiB the worker can write.
_CHARGE_PER_CHAR, _CHARGE_PER_VALUE, _CHARGE_BASE = 6, 32, 64

EVIDENCE_TYPE_RE = re.compile(r"^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+/v[1-9][0-9]{0,3}$")
POINTER_RE = re.compile(r"^(/([^~/]|~[01]){0,64}){0,16}$")
_INT_MIN, _INT_MAX = -(1 << 63), (1 << 63) - 1
_REF_KEYS = frozenset({"object_id", "role", "pointer", "byte_range"})
_RANGE = 2  # a byte_range is [start, end)


class _OverBound(Exception):  # noqa: N818 - internal control flow, never raised out
    pass


class EvidenceSchemaError(RecordsMisuseError):
    """An item outside its type's closed schema (an extra or free-text property, an ID
    property that is not a string). ``EvidenceDoc.build`` fails open on it (R9): the record
    carries a descriptor-only ``record.evidence`` (``parse_failed``); it raises only under
    ``FABRIC_RECORDS_STRICT=1``."""


def _misuse(what: str) -> RecordsMisuseError:
    return RecordsMisuseError(f"records API misuse: evidence {what}")


def _refused(what: str) -> EvidenceSchemaError:
    return EvidenceSchemaError(f"records API misuse: evidence {what}")


# --- identity (R8) ------------------------------------------------------------------------------


def _omit_ids(prefix: str, value: str) -> str | None:
    return None


@dataclass(frozen=True, slots=True)
class EvidenceIds:
    """How the capture worker emits an evidence ID property (R8). ``map(prefix, value)`` is
    the records input's identity rule: an ``EmittedId`` of its issuer unchanged, else the
    keyed v2 pseudonym; ``None`` (the property is omitted) without a key or in the
    production profile without one; the opaque clear form only in the explicit clear
    mode, where ``clear`` admits the type schema's ``x-fabric-clear`` alternative."""

    map: Callable[[str, str], str | None]
    clear: bool = False


#: Without a records input's rule nothing derived from a caller id is written.
OMIT_IDS = EvidenceIds(_omit_ids)


# --- the bounded walk (application thread at build, worker at encode) ----------------------------


class _Walk:
    """The work of one walk; :class:`_OverBound` past :data:`EVIDENCE_MAX_VALUES` values or
    past 1 MiB of characters (the serialised object could only be larger)."""

    __slots__ = ("chars", "values")

    def __init__(self) -> None:
        self.values = self.chars = 0

    def take(self, chars: int = 0) -> None:
        self.values += 1
        self.chars += chars
        if self.values > EVIDENCE_MAX_VALUES or self.chars > EVIDENCE_MAX_BYTES:
            raise _OverBound

    @property
    def charge(self) -> int:
        estimate = (_CHARGE_BASE + self.chars * _CHARGE_PER_CHAR
                    + self.values * _CHARGE_PER_VALUE)  # fmt: skip
        return min(EVIDENCE_MAX_BYTES, estimate)


def _string(value: str, walk: _Walk) -> str:
    if len(value) > EVIDENCE_MAX_STRING:
        raise _OverBound
    walk.take(len(value))
    # An EmittedId keeps its type until the identity rule has seen it (it passes through).
    return value if isinstance(value, EmittedId) else str.__str__(value)


def _copy(value: Any, depth: int, walk: _Walk) -> Any:
    """A plain copy of ``value``; ``depth`` is the depth of the container holding it (an
    item is depth 1). A nested container past the depth bound is refused before it is
    entered, so a cyclic value stops there."""
    if value is None or isinstance(value, bool):
        walk.take()
        return value
    if isinstance(value, int):
        if not _INT_MIN <= value <= _INT_MAX:
            raise _misuse("int outside int64")
        walk.take()
        return int(value)
    if isinstance(value, str):
        return _string(value, walk)
    if isinstance(value, Mapping):
        return _copy_object(value, depth + 1, walk)
    if isinstance(value, (list, tuple)):
        if depth + 1 > EVIDENCE_MAX_DEPTH or len(value) > EVIDENCE_MAX_ITEMS:
            raise _OverBound
        walk.take()
        return [_copy(element, depth + 1, walk) for element in value]
    raise _misuse("value class (floats, bytes and objects are refused)")


def _copy_object(item: Mapping[Any, Any], depth: int, walk: _Walk) -> dict[str, Any]:
    if depth > EVIDENCE_MAX_DEPTH or len(item) > EVIDENCE_MAX_ITEMS:
        raise _OverBound
    walk.take()
    out: dict[str, Any] = {}
    for key, value in item.items():
        if not isinstance(key, str) or not key:
            raise _misuse("key (non-empty str only)")
        if len(key) > EVIDENCE_MAX_STRING:
            raise _OverBound
        walk.chars += len(key)
        out[str.__str__(key)] = _copy(value, depth, walk)
    return out


def _copy_ref(ref: object, walk: _Walk) -> dict[str, Any]:
    if not isinstance(ref, EvidenceRef) or not isinstance(ref.object_id, str) or (
        not UUID4_RE.fullmatch(ref.object_id)
    ):  # fmt: skip
        raise _misuse("ref (EvidenceRef with a uuid4 object_id)")
    if not isinstance(ref.role, str) or not ref.role:
        raise _misuse("ref role")
    if ref.pointer is not None and (
        not isinstance(ref.pointer, str) or not POINTER_RE.fullmatch(ref.pointer)
    ):  # fmt: skip
        raise _misuse("ref pointer (an RFC 6901 pointer)")
    span = ref.byte_range
    if span is not None:
        if not isinstance(span, tuple) or len(span) != _RANGE:
            raise _misuse("ref byte_range")
        low, high = span
        if type(low) is not int or type(high) is not int or not 0 <= low <= high:
            raise _misuse("ref byte_range")
    entry: dict[str, Any] = {"object_id": str.__str__(ref.object_id),
                             "role": str.__str__(_string(ref.role, walk))}  # fmt: skip
    if ref.pointer is not None:
        entry["pointer"] = str.__str__(_string(ref.pointer, walk))
    if span is not None:
        entry["byte_range"] = [span[0], span[1]]
    return entry


@dataclass(frozen=True, slots=True)
class _Snapshot:
    evidence_type: str
    items: list[dict[str, Any]]
    refs: list[dict[str, Any]]
    continuation: tuple[int, bool] | None
    charge: int


def _snapshot(doc: EvidenceDoc) -> _Snapshot | None:
    """The bounded plain copy of ``doc``; ``None`` over a bound. Raises
    :class:`RecordsMisuseError` for a malformed envelope or value class."""
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
    refs, items = doc.refs, doc.items
    if not isinstance(refs, (tuple, list)) or not isinstance(items, (tuple, list)):
        raise _misuse("items and refs are sequences")
    walk = _Walk()
    try:
        copied_refs = [_copy_ref(ref, walk) for ref in refs[: EVIDENCE_MAX_REFS + 1]]
        if len(refs) > EVIDENCE_MAX_REFS or len(items) > EVIDENCE_MAX_ITEMS:
            return None
        copied: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, Mapping):
                raise _misuse("item (objects only)")
            copied.append(_copy_object(item, 1, walk))
    except _OverBound:
        return None
    return _Snapshot(
        str.__str__(doc.evidence_type), copied, copied_refs,
        None if continuation is None else (continuation.index, continuation.final), walk.charge,
    )  # fmt: skip


# --- the closed item schemas (the keyword subset type schemas use) --------------------------------

Predicate = Callable[[Any], bool]
_ANNOTATIONS = frozenset({"$schema", "$id", "title", "description", "examples", "default"})
_KEYWORDS = frozenset({
    "type", "properties", "required", "additionalProperties", "pattern", "enum", "const",
    "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems", "items",
    CLEAR_KEYWORD,
}) | _ANNOTATIONS  # fmt: skip


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


_TYPES: Mapping[str, Predicate] = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": _is_int,
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}
# keyword -> (lower bound?, what it measures: None when it does not apply to the value)
_SIZED: Mapping[str, tuple[bool, Callable[[Any], int | None]]] = {
    "minimum": (True, lambda v: int(v) if _is_int(v) else None),
    "maximum": (False, lambda v: int(v) if _is_int(v) else None),
    "minLength": (True, lambda v: len(v) if isinstance(v, str) else None),
    "maxLength": (False, lambda v: len(v) if isinstance(v, str) else None),
    "minItems": (True, lambda v: len(v) if isinstance(v, list) else None),
    "maxItems": (False, lambda v: len(v) if isinstance(v, list) else None),
}
_V2_ID_PATTERN = re.compile(r"\^([a-z]+)-\[0-9a-f\]\{32\}\$")


def _regex(pattern: str) -> re.Pattern[str]:
    """ECMA-style search; a trailing ``$`` anchors at the very end (never before a final
    newline, as Python's ``$`` would)."""
    if pattern.endswith("$") and not pattern.endswith("\\$"):
        pattern = pattern[:-1] + r"\Z"
    return re.compile(pattern)


def _same(value: Any, option: Any) -> bool:
    return bool(value == option and type(value) is type(option))


def _sized(keyword: str, limit: int) -> Predicate:
    lower, measure = _SIZED[keyword]

    def ok(value: Any) -> bool:
        size = measure(value)
        return size is None or (size >= limit if lower else size <= limit)

    return ok


def _object(schema: Mapping[str, Any]) -> Predicate:
    properties = {name: _compile(sub) for name, sub in schema.get("properties", {}).items()}
    required = tuple(schema.get("required", ()))
    closed = schema.get("additionalProperties", True) is False

    def ok(value: Any) -> bool:
        if not isinstance(value, dict):
            return True
        if any(name not in value for name in required):
            return False
        if closed and not set(value) <= set(properties):
            return False
        return all(properties[k](x) for k, x in value.items() if k in properties)

    return ok


def _compile(schema: Mapping[str, Any]) -> Predicate:
    """A predicate for ``schema`` (nested properties and array items included; a nested
    clear-mode alternative is never admitted). A keyword outside the subset is a twin
    error, raised at import (pinned by test)."""
    if not set(schema) <= _KEYWORDS:
        raise ValueError("unsupported evidence schema keyword")
    checks: list[Predicate] = []
    if "type" in schema:
        checks.append(_TYPES[schema["type"]])
    if "enum" in schema:
        options = tuple(schema["enum"])
        checks.append(lambda v: any(_same(v, option) for option in options))
    if "const" in schema:
        const = schema["const"]
        checks.append(lambda v: _same(v, const))
    if "pattern" in schema:
        rx = _regex(schema["pattern"])
        checks.append(lambda v: not isinstance(v, str) or rx.search(v) is not None)
    checks.extend(_sized(keyword, schema[keyword]) for keyword in _SIZED if keyword in schema)
    if "items" in schema:
        each = _compile(schema["items"])
        checks.append(lambda v: not isinstance(v, list) or all(each(x) for x in v))
    if {"properties", "required", "additionalProperties"} & set(schema):
        checks.append(_object(schema))
    return lambda v: all(check(v) for check in checks)


@dataclass(frozen=True, slots=True)
class _IdProperty:
    prefix: str | None  # the v2 type its pattern names; None: never derived (omitted)
    own: Predicate
    clear: Predicate


@dataclass(frozen=True, slots=True)
class _ItemSchema:
    required: tuple[str, ...]
    closed: bool
    plain: Mapping[str, Predicate]
    ids: Mapping[str, _IdProperty]


def _item_schema(schema: Mapping[str, Any]) -> _ItemSchema:
    if not set(schema) <= _KEYWORDS or schema.get("type") != "object":
        raise ValueError("an evidence item schema is an object schema")
    plain: dict[str, Predicate] = {}
    ids: dict[str, _IdProperty] = {}
    for name, sub in schema.get("properties", {}).items():
        if CLEAR_KEYWORD in sub:
            own = {key: value for key, value in sub.items() if key != CLEAR_KEYWORD}
            found = _V2_ID_PATTERN.fullmatch(str(own.get("pattern", "")))
            prefix = found.group(1) if found and found.group(1) in V2_TYPES else None
            ids[name] = _IdProperty(prefix, _compile(own), _compile(sub[CLEAR_KEYWORD]))
        else:
            plain[name] = _compile(sub)
    return _ItemSchema(tuple(schema.get("required", ())),
                       schema.get("additionalProperties", True) is False,
                       MappingProxyType(plain), MappingProxyType(ids))  # fmt: skip


_ITEM_SCHEMAS: Mapping[str, _ItemSchema] = MappingProxyType(
    {name: _item_schema(schema) for name, schema in EVIDENCE_ITEM_SCHEMAS.items()}
)


def _apply(item: dict[str, Any], schema: _ItemSchema, ids: EvidenceIds | None) -> dict[str, Any]:
    """``item`` as written: only properties inside its closed schema, each ID property
    mapped by ``ids`` (``None``: at build, where a caller id of any shape is accepted to be
    mapped on the worker). :class:`RecordsMisuseError` (fixed text, never the value) when
    the item is refused."""
    out: dict[str, Any] = {}
    for name, value in item.items():
        check = schema.plain.get(name)
        if check is not None:
            if not check(value):
                raise _refused("item property outside its type schema")
            out[name] = value
            continue
        id_property = schema.ids.get(name)
        if id_property is None:
            if schema.closed:
                raise _refused("item property outside its closed type schema")
            continue  # an open schema's extra property is never written
        if not isinstance(value, str) or not value:
            raise _refused("item id property (a non-empty str)")
        if ids is None:
            out[name] = value
            continue
        prefix = id_property.prefix
        mapped = ids.map(prefix, value) if prefix is not None else None
        if mapped is None:
            continue  # no key: the id is omitted (R8, 049 §2.9 rule 5)
        if not (id_property.own(mapped) or (ids.clear and id_property.clear(mapped))):
            raise _refused("item id property outside its type schema")
        out[name] = str.__str__(mapped)
    if any(name not in out for name in schema.required):
        raise _refused("item without a required property")
    return out


def _validated(snapshot: _Snapshot, ids: EvidenceIds | None) -> list[dict[str, Any]]:
    schema = _ITEM_SCHEMAS.get(snapshot.evidence_type)
    if schema is None:
        raise _refused("type has no registered item schema")
    return [_apply(item, schema, ids) for item in snapshot.items]


# --- the API --------------------------------------------------------------------------------------


def measure_evidence(doc: EvidenceDoc) -> int | None:
    """The in-flight charge of ``doc`` (bytes, at most 1 MiB) when it is within every §3.4a
    bound and each item is inside its type's closed schema; ``None`` when a bound (items,
    refs, depth, string length, total work) is exceeded. Raises
    :class:`RecordsMisuseError` for a malformed document: an unregistered or malformed
    type, a float, bytes, a non-string key, a bad ref or continuation, an item outside its
    closed schema. ID properties are mapped later, on the worker (:func:`encode`)."""
    snapshot = _snapshot(doc)
    if snapshot is None:
        return None
    _validated(snapshot, None)
    return snapshot.charge


def check_evidence(doc: EvidenceDoc) -> bool:
    """``True`` when ``doc`` is within every bound and inside its closed schema (see
    :func:`measure_evidence`, which raises the same misuse); ``False`` over a bound."""
    return measure_evidence(doc) is not None


def encode(doc: EvidenceDoc, ids: EvidenceIds | None = None) -> bytes | None:
    """Spec-029 canonical JSON of ``doc`` (on the capture worker): a bounded copy taken
    first, validated again, its ID properties mapped by ``ids`` (default :data:`OMIT_IDS`).
    ``None`` when it is now over a bound or over 1 MiB serialised. Raises
    :class:`RecordsMisuseError` when it is now malformed or outside its schema (the worker
    then writes a descriptor-only object)."""
    snapshot = _snapshot(doc)
    if snapshot is None:
        return None
    out: dict[str, Any] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION, "evidence_type": snapshot.evidence_type,
        "items": _validated(snapshot, OMIT_IDS if ids is None else ids),
    }  # fmt: skip
    if snapshot.continuation is not None:
        index, final = snapshot.continuation
        out["continuation"] = {"index": index, "final": final}
    if snapshot.refs:
        out["refs"] = snapshot.refs
    data = canonical_bytes(out)
    return data if len(data) <= EVIDENCE_MAX_BYTES else None


def document(doc: EvidenceDoc) -> dict[str, Any]:
    """The ``fabric.record-evidence/v1`` document ``doc`` encodes to without an identity
    rule (ID properties omitted); ``refs`` and ``continuation`` only when present."""
    data = encode(doc)
    if data is None:
        raise _misuse("over a bound")
    loaded: dict[str, Any] = json.loads(data)
    return loaded


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _misuse("duplicate key")
        out[key] = value
    return out


def _refuse_float(_text: str) -> Any:
    raise _misuse("value class (floats are refused)")


def _raw_ref(ref: Any) -> EvidenceRef:
    if not isinstance(ref, dict) or not {"object_id", "role"} <= set(ref) <= _REF_KEYS:
        raise _misuse("ref")
    span = ref.get("byte_range")
    if span is not None and (not isinstance(span, list) or len(span) != _RANGE):
        raise _misuse("ref byte_range")
    return EvidenceRef(ref["object_id"], ref["role"], ref.get("pointer"),
                       None if span is None else (span[0], span[1]))  # fmt: skip


def parse_raw(data: bytes) -> EvidenceDoc:
    """A caller-made ``record.evidence`` body (bytes already within the role's cap) as an
    :class:`EvidenceDoc`, so it takes the same closed-schema and identity path as a built
    one (on the worker). Raises :class:`RecordsMisuseError` unless it is one JSON
    ``fabric.record-evidence/v1`` envelope."""
    try:
        loaded = json.loads(
            data.decode("utf-8"), object_pairs_hook=_no_duplicates,
            parse_float=_refuse_float, parse_constant=_refuse_float,
        )  # fmt: skip
    except RecordsMisuseError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _misuse("body is not JSON") from None
    if not isinstance(loaded, dict):
        raise _misuse("envelope")
    required = {key for key, needed in EVIDENCE_ENVELOPE_KEYS.items() if needed}
    if not required <= set(loaded) <= set(EVIDENCE_ENVELOPE_KEYS):
        raise _misuse("envelope keys")
    if loaded["schema_version"] != EVIDENCE_SCHEMA_VERSION or not isinstance(
        loaded["items"], list
    ):  # fmt: skip
        raise _misuse("envelope")
    refs = loaded.get("refs", [])
    if not isinstance(refs, list):
        raise _misuse("refs")
    cont = loaded.get("continuation")
    continuation = None
    if cont is not None:
        if not isinstance(cont, dict) or set(cont) != {"index", "final"}:
            raise _misuse("continuation")
        continuation = EvidenceContinuation(cont["index"], cont["final"])
    return EvidenceDoc(loaded["evidence_type"], tuple(loaded["items"]),
                       tuple(_raw_ref(ref) for ref in refs[: EVIDENCE_MAX_REFS + 1]),
                       continuation)  # fmt: skip


def encode_raw(data: bytes, ids: EvidenceIds | None = None) -> bytes | None:
    """A caller-made evidence body re-encoded through :func:`encode` (validated, ids
    mapped, canonical); ``None`` over a bound. Raises :class:`RecordsMisuseError`."""
    return encode(parse_raw(data), ids)


__all__ = [
    "CLEAR_KEYWORD", "EVIDENCE_ENVELOPE_KEYS", "EVIDENCE_ITEM_SCHEMAS", "EVIDENCE_MAX_REFS",
    "EVIDENCE_MAX_VALUES", "EVIDENCE_MEDIA_TYPE", "EVIDENCE_ROLE", "EVIDENCE_TYPE_RE", "OMIT_IDS",
    "POINTER_RE", "REGISTERED_EVIDENCE_TYPES", "EvidenceIds", "EvidenceSchemaError",
    "check_evidence", "document", "encode", "encode_raw", "measure_evidence", "parse_raw",
]  # fmt: skip
