# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Evidence-object decoding for the projection (spec 050 §3.4a item 6): a stored
``record.evidence`` object is checked against its registered type schema and mapped to
field wrappers through the registry's field-key -> JSON-pointer map.

Bounded before decoding (R9): the object is refused over 1 MiB, and its bracket nesting is
measured on the raw bytes before any JSON is parsed, so a hostile object never reaches the
parser's recursion. Then, in the order of the Node's pre-acknowledgement check (050 §3.4a
item 4, ``scripts/contracts/p1_reference.evidence_envelope_refusal``): spec-029 canonical
JSON, the closed envelope, a registered ``evidence_type``, and the item, depth, string and
ref bounds. A refused envelope decodes nothing: every field its type registers is
``not_captured(parse_failed)``. An unregistered type is ``unknown_type`` (its fields are not
known, so none is reported).

Each item is then validated against its type's closed item schema by a small validator for
the keyword subset type schemas use (no ``jsonschema`` at runtime); a keyword outside the
subset refuses the item. An ID property's ``x-fabric-clear`` alternative counts only under a
manifest with ``identity_mode: clear`` (R8). An invalid item makes the fields it carries
``not_captured(parse_failed)``; the other fields take the values of the valid items, by the
registry pointer (``*``: every item), as one captured list (an empty list is a captured
value, never ``absent``).

:data:`EVIDENCE_TYPES` is the runtime twin of ``field-registry-v1.json`` ``evidence_types``
and of each type's item schema; ``tests/test_reconstruct_project.py`` pins it to both.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal

from fabric._capture_types import (
    EVIDENCE_MAX_BYTES,
    EVIDENCE_MAX_DEPTH,
    EVIDENCE_MAX_ITEMS,
    EVIDENCE_MAX_STRING,
    EVIDENCE_SCHEMA_VERSION,
    UUID4_RE,
)
from fabric._evidence import EVIDENCE_ENVELOPE_KEYS, EVIDENCE_MAX_REFS, POINTER_RE
from fabric._seal import canonical_bytes

from ._fields_model import FieldValue

DecodeStatus = Literal["ok", "parse_failed", "unknown_type", "not_decoded"]

# The envelope nests at most two levels above an item (object > items[] > item); an item
# nests at most EVIDENCE_MAX_DEPTH levels. Anything deeper is refused before parsing.
_MAX_NESTING = 2 + EVIDENCE_MAX_DEPTH
_REF_KEYS = frozenset({"object_id", "role", "pointer", "byte_range"})
_ROLE_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
_ROLE_MAX = 64
_INT64_MAX = (1 << 63) - 1
CLEAR_KEYWORD = "x-fabric-clear"
_QUOTE, _BACKSLASH = 0x22, 0x5C
_OPEN, _CLOSE = frozenset({0x5B, 0x7B}), frozenset({0x5D, 0x7D})  # [ {  and  ] }
_RANGE = 2  # a byte_range is [start, end)

# --- the twin of field-registry-v1.json evidence_types (pinned by test) ---------------------
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
#: Registered evidence types: the capture points allowed to emit each, its projected fields
#: as ``(layer, key, pointer)`` and its closed item schema.
EVIDENCE_TYPES: Mapping[str, Mapping[str, Any]] = MappingProxyType({
    "fabric.test.items/v1": MappingProxyType({
        "capture_points": ("sdk.records",),
        "fields": (
            ("content", "x-fabric.test_item_names", "/items/*/name"),
            ("content", "x-fabric.test_item_digests", "/items/*/digest"),
            ("decisions_effects", "x-fabric.test_item_counts", "/items/*/count"),
            ("structure", "x-fabric.test_item_actors", "/items/*/actor"),
        ),
        "schema": _TEST_ITEMS_SCHEMA,
    }),
})  # fmt: skip
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvidenceDecode:
    """One decoded evidence object. ``fields`` is keyed ``<layer>.<field key>``; each value's
    ``value`` is the list of the valid items' values at the field's pointer (kept for every
    status; the projection emits it only when ``captured``). ``item_errors`` are the indexes
    of the items the type schema refused."""

    status: DecodeStatus
    evidence_type: str | None = None
    fields: Mapping[str, FieldValue] = field(default_factory=lambda: MappingProxyType({}))
    item_errors: tuple[int, ...] = ()
    continuation: tuple[int, bool] | None = None
    refs: tuple[Mapping[str, Any], ...] = ()
    provenance: str | None = None
    capture_point: str | None = None


class _Refused(Exception):  # noqa: N818 - internal control flow, never raised out
    pass


def _nesting(data: bytes) -> int:
    """The deepest bracket nesting of ``data`` outside JSON strings, without parsing it."""
    depth = deepest = 0
    in_string = escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == _BACKSLASH:
                escaped = True
            elif byte == _QUOTE:
                in_string = False
        elif byte == _QUOTE:
            in_string = True
        elif byte in _OPEN:
            depth += 1
            deepest = max(deepest, depth)
        elif byte in _CLOSE:
            depth -= 1
    return deepest


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _Refused
        out[key] = value
    return out


def _refuse_float(_text: str) -> Any:
    raise _Refused


def _load(data: bytes) -> Any:
    """Spec-029 canonical JSON only: parsed with duplicate keys and floats refused, then
    compared with its own canonical bytes."""
    try:
        document = json.loads(
            data.decode("utf-8"), object_pairs_hook=_no_duplicates,
            parse_float=_refuse_float, parse_constant=_refuse_float,
        )  # fmt: skip
        canonical = canonical_bytes(document)
    except (_Refused, UnicodeDecodeError, ValueError, RecursionError):
        raise _Refused from None
    if canonical != data:
        raise _Refused
    return document


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _ref_ok(ref: Any) -> bool:
    if not isinstance(ref, dict) or not {"object_id", "role"} <= set(ref) <= _REF_KEYS:
        return False
    object_id, role = ref["object_id"], ref["role"]
    if not isinstance(object_id, str) or not UUID4_RE.fullmatch(object_id):
        return False
    if not isinstance(role, str) or len(role) > _ROLE_MAX or not _ROLE_RE.fullmatch(role):
        return False
    pointer = ref.get("pointer")
    if "pointer" in ref and (not isinstance(pointer, str) or not POINTER_RE.fullmatch(pointer)):
        return False
    if "byte_range" not in ref:
        return True
    span = ref["byte_range"]
    return (
        isinstance(span, list) and len(span) == _RANGE and all(_is_int(x) and x >= 0 for x in span)
        and span[0] <= span[1]
    )  # fmt: skip


def _envelope_ok(document: Any) -> bool:  # noqa: PLR0911 - one return per envelope rule
    if not isinstance(document, dict):
        return False
    required = {key for key, needed in EVIDENCE_ENVELOPE_KEYS.items() if needed}
    if not required <= set(document) <= set(EVIDENCE_ENVELOPE_KEYS):
        return False
    if document["schema_version"] != EVIDENCE_SCHEMA_VERSION:
        return False
    if not isinstance(document["evidence_type"], str):
        return False
    items = document["items"]
    if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
        return False
    if "continuation" in document:
        cont = document["continuation"]
        if (
            not isinstance(cont, dict) or set(cont) != {"index", "final"}
            or not _is_int(cont["index"]) or not 0 <= cont["index"] <= _INT64_MAX
            or not isinstance(cont["final"], bool)
        ):  # fmt: skip
            return False
    refs = document.get("refs", [])
    return isinstance(refs, list) and all(_ref_ok(ref) for ref in refs)


def _depth(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + max((_depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_depth(item) for item in value), default=0)
    return 0


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _within_bounds(document: Mapping[str, Any]) -> bool:
    items = document["items"]
    return (
        len(items) <= EVIDENCE_MAX_ITEMS
        and len(document.get("refs", [])) <= EVIDENCE_MAX_REFS
        and all(_depth(item) <= EVIDENCE_MAX_DEPTH for item in items)
        and all(len(text) <= EVIDENCE_MAX_STRING for text in _strings(document))
    )


# --------------------------------------------------------------------------
# The item validator: the closed JSON-schema subset evidence type schemas use
# --------------------------------------------------------------------------

_ANNOTATIONS = frozenset({"$schema", "$id", "title", "description", "examples", "default"})
_KEYWORDS = frozenset({
    "type", "properties", "required", "additionalProperties", "pattern", "enum", "const",
    "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems", "items", "anyOf",
    CLEAR_KEYWORD,
}) | _ANNOTATIONS  # fmt: skip
_TYPES: Mapping[str, Any] = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": _is_int,
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def _pattern_ok(pattern: Any, value: str) -> bool:
    """ECMA-style search; a trailing ``$`` anchors at the very end (never before a final
    newline, as Python's ``$`` would)."""
    if not isinstance(pattern, str):
        raise _Refused
    if pattern.endswith("$") and not pattern.endswith("\\$"):
        pattern = pattern[:-1] + r"\Z"
    try:
        return re.search(pattern, value) is not None
    except re.error:
        raise _Refused from None


def _size(value: Any) -> int | None:
    """What ``minimum``/``maximum`` (an integer) or the length keywords (a string or an
    array) bound; ``None`` for a value they do not apply to."""
    if _is_int(value):
        return int(value)
    if isinstance(value, (str, list)):
        return len(value)
    return None


_LOWER = {"minimum": "integer", "minLength": "string", "minItems": "array"}
_UPPER = {"maximum": "integer", "maxLength": "string", "maxItems": "array"}


def _bounds_ok(schema: Mapping[str, Any], value: Any) -> bool:
    size = _size(value)
    if size is None:
        return True
    kind = "integer" if _is_int(value) else "string" if isinstance(value, str) else "array"
    for keyword, applies in _LOWER.items():
        if applies == kind and keyword in schema and size < schema[keyword]:
            return False
    for keyword, applies in _UPPER.items():
        if applies == kind and keyword in schema and size > schema[keyword]:
            return False
    return True


def _object_ok(schema: Mapping[str, Any], value: dict[str, Any], clear: bool) -> bool:
    properties = schema.get("properties", {})
    if any(name not in value for name in schema.get("required", ())):
        return False
    if schema.get("additionalProperties", True) is False and not set(value) <= set(properties):
        return False
    return all(_valid(properties[name], item, clear)
               for name, item in value.items() if name in properties)  # fmt: skip


def _same(value: Any, option: Any) -> bool:
    return bool(value == option and type(value) is type(option))


def _valid(schema: Any, value: Any, clear: bool) -> bool:  # noqa: PLR0911 - per keyword
    """Whether ``value`` satisfies ``schema``; :class:`_Refused` for a keyword outside the
    subset (the item is then refused: the validator never guesses)."""
    if not isinstance(schema, Mapping) or not set(schema) <= _KEYWORDS:
        raise _Refused
    if clear and CLEAR_KEYWORD in schema:
        own = {key: item for key, item in schema.items() if key != CLEAR_KEYWORD}
        return _valid(own, value, clear) or _valid(schema[CLEAR_KEYWORD], value, clear)
    if "type" in schema and not _TYPES.get(schema["type"], lambda _v: False)(value):
        return False
    if "enum" in schema and not any(_same(value, option) for option in schema["enum"]):
        return False
    if "const" in schema and not _same(value, schema["const"]):
        return False
    if "anyOf" in schema and not any(_valid(option, value, clear) for option in schema["anyOf"]):
        return False
    if isinstance(value, str) and "pattern" in schema and not _pattern_ok(schema["pattern"], value):
        return False
    if not _bounds_ok(schema, value):
        return False
    if isinstance(value, list) and "items" in schema:
        return all(_valid(schema["items"], item, clear) for item in value)
    if isinstance(value, dict):
        return _object_ok(schema, value, clear)
    return True


def item_errors(
    items: Sequence[Any], schema: Mapping[str, Any], *, identity_mode: str = "pseudonymous"
) -> tuple[int, ...]:
    """Indexes of ``items`` the type schema refuses (050 §3.4a item 6, R8)."""
    clear = identity_mode == "clear"
    bad: list[int] = []
    for index, item in enumerate(items):
        try:
            ok = _valid(schema, item, clear)
        except _Refused:
            ok = False
        if not ok:
            bad.append(index)
    return tuple(bad)


def resolve_pointer(document: Any, pointer: str) -> list[Any]:
    """Values at a registry field pointer; ``*`` stands for every element of an array."""
    nodes = [document]
    for raw in pointer.split("/")[1:]:
        part = raw.replace("~1", "/").replace("~0", "~")
        found: list[Any] = []
        for node in nodes:
            if part == "*" and isinstance(node, list):
                found.extend(node)
            elif isinstance(node, dict) and part in node:
                found.append(node[part])
            elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
                found.append(node[int(part)])
        nodes = found
    return nodes


def _failed(evidence_type: str, row: Mapping[str, Any], **kw: Any) -> EvidenceDecode:
    fields = {
        f"{layer}.{key}": FieldValue(key, "not_captured", "parse_failed", [])
        for layer, key, _ in row["fields"]
    }
    return EvidenceDecode("parse_failed", evidence_type, MappingProxyType(fields), **kw)


def _declared_type(data: bytes, evidence_types: Mapping[str, Any]) -> str | None:
    """The registered ``evidence_type`` a non-canonical object names, when it can be read
    at all (its fields are then reported ``parse_failed``); ``None`` otherwise. Only reached
    after the size and nesting bounds."""
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    named = document.get("evidence_type") if isinstance(document, dict) else None
    return named if isinstance(named, str) and named in evidence_types else None


def decode_evidence(  # noqa: PLR0911 - one return per refusal stage
    data: bytes, *, evidence_types: Mapping[str, Any], provenance: str, capture_point: str,
    identity_mode: str = "pseudonymous",
) -> EvidenceDecode:  # fmt: skip
    """Decode one stored evidence object into field values (050 §3.4a item 6). Never raises.

    ``evidence_types`` maps each registered type to its row (``fields`` and ``schema``, as
    :data:`EVIDENCE_TYPES`); without any, nothing can be decoded (``not_decoded``).
    ``provenance`` (from ``fabric.capture.source``) and ``capture_point`` (the record's) are
    carried for the field wrappers; ``identity_mode`` is the record's source manifest's."""
    if not evidence_types:
        return EvidenceDecode("not_decoded")
    carried: dict[str, Any] = {"provenance": provenance, "capture_point": capture_point}
    if len(data) > EVIDENCE_MAX_BYTES or _nesting(data) > _MAX_NESTING:
        return EvidenceDecode("parse_failed", **carried)  # never parsed: bounded first (R9)
    try:
        document = _load(data)
    except _Refused:
        named = _declared_type(data, evidence_types)
        if named is None:
            return EvidenceDecode("parse_failed", **carried)
        return _failed(named, evidence_types[named], **carried)
    if not _envelope_ok(document):
        named = document.get("evidence_type") if isinstance(document, dict) else None
        if isinstance(named, str) and named in evidence_types:
            return _failed(named, evidence_types[named], **carried)
        return EvidenceDecode("parse_failed", **carried)
    evidence_type = document["evidence_type"]
    row = evidence_types.get(evidence_type)
    if row is None:
        return EvidenceDecode("unknown_type", evidence_type, **carried)
    if not _within_bounds(document):
        return _failed(evidence_type, row, **carried)
    items = document["items"]
    bad = item_errors(items, row["schema"], identity_mode=identity_mode)
    valid = {"items": [item for index, item in enumerate(items) if index not in bad]}
    invalid = {"items": [items[index] for index in bad]}
    fields: dict[str, FieldValue] = {}
    for layer, key, pointer in row["fields"]:
        values = resolve_pointer(valid, pointer)
        if resolve_pointer(invalid, pointer):
            fields[f"{layer}.{key}"] = FieldValue(key, "not_captured", "parse_failed", values)
        else:
            fields[f"{layer}.{key}"] = FieldValue(key, "captured", value=values)
    cont = document.get("continuation")
    return EvidenceDecode(
        "ok", evidence_type, MappingProxyType(fields), item_errors=bad,
        continuation=None if cont is None else (cont["index"], cont["final"]),
        refs=tuple(MappingProxyType(ref) for ref in document.get("refs", ())), **carried,
    )  # fmt: skip


__all__ = [
    "CLEAR_KEYWORD", "EVIDENCE_TYPES", "DecodeStatus", "EvidenceDecode", "decode_evidence",
    "item_errors", "resolve_pointer",
]  # fmt: skip
