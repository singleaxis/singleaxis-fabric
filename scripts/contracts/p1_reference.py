# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Reference implementations of the spec 050 (P1) contract rules.

These are the executable definitions the P1 vectors are produced from and
re-checked against (``generate_p0_contracts.py`` writes the vectors,
``validate_coverage_contracts.py`` and ``validate_capture_contracts.py`` recompute
them). The SDK, fabricguard and ``fabric.reconstruct`` implement the same rules
and test against the vectors; this module is never imported by a runtime.

- the canonical record digest and the segment seal digest (050 §3.7, 049 §2.12);
- the span category fabricguard derives (``P/processor.go`` ``activityCategory``,
  050 §3.4 rule N) and the records-class attribute projection (rule A);
- the ``fr3/`` resume-token grammar with the ``fr2/`` legacy parse, and run
  identity rules 1-5 (050 §3.6);
- the ``fabric.record-evidence/v1`` envelope check (050 §3.4a item 4) and the
  Node pre-acknowledgement checks (050 §3.14).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any
from urllib.parse import unquote

INT64_MAX = 9223372036854775807
OPAQUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SEGMENT_RE = re.compile(r"^seg-[0-9a-f]{32}$")
BRANCH_RE = re.compile(r"^br-[0-9a-f]{32}$")
MINTED_RUN_RE = re.compile(r"^r-[0-9a-f]{32}$")
SEGMENT_ENTRY = re.compile(
    r"^(?P<segment_id>seg-[0-9a-f]{32})/(?P<source_id>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})/"
    r"(?P<epoch>[1-9][0-9]{0,18})/(?P<last_sequence>-1|0|[1-9][0-9]{0,18})/"
    r"(?P<manifest_digest>sha256:[0-9a-f]{64})$"
)

# 050 §3.5 (R6): bounds the spool writer checks before writing.
MAX_EXCHANGE_BODIES = (
    260  # 2 sides x (1 primary + 64 parts + 64 part review copies + 1 review copy)
)
MAX_RECORD_BODIES = 8  # bodies + descriptor-only bodies + the evidence object
RECEIVER_OWNED_KEYS = frozenset({"fabric.source.authenticated"})

# 050 §3.4a: the structured evidence carrier.
EVIDENCE_SCHEMA = "fabric.record-evidence/v1"
EVIDENCE_ROLE = "record.evidence"
EVIDENCE_MEDIA_TYPE = "application/vnd.fabric.record-evidence+json"
EVIDENCE_MAX_BYTES = 1 << 20
EVIDENCE_MAX_ITEMS = 4096
EVIDENCE_MAX_DEPTH = 4
EVIDENCE_MAX_STRING = 256
EVIDENCE_MAX_REFS = 64
EVIDENCE_KEYS = frozenset(
    {"schema_version", "evidence_type", "items", "continuation", "refs"}
)
EVIDENCE_REQUIRED = frozenset({"schema_version", "evidence_type", "items"})
EVIDENCE_TYPE_RE = re.compile(
    r"^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+/v[1-9][0-9]{0,3}$"
)
REF_KEYS = frozenset({"object_id", "role", "pointer", "byte_range"})
POINTER_RE = re.compile(r"^(/([^~/]|~[01]){0,64}){0,16}$")


# ------------------------------------------------------------------ canonical JSON
def _no_floats(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("canonical JSON carries no floats")
    if isinstance(value, Mapping):
        for item in value.values():
            _no_floats(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _no_floats(item)


def canonical_json(value: Any) -> str:
    """Spec-029 canonical JSON: sorted keys, ``(",", ":")``, literal UTF-8, no floats."""
    _no_floats(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------ record and seal digests
def record_content(
    kind: str, descriptors: Sequence[Mapping[str, Any]], object_ids: Sequence[str] = ()
) -> list[str | None]:
    """The ``content`` part of a record digest (050 §3.7).

    ``exchange``: the stored digests of the request and response primaries (the
    side object without a ``part_of``/``derived_from`` link), in that order, when
    present. ``record``: the ``stored_sha256`` of each object in
    ``fabric.content.object_ids``, in list order; ``None`` for a descriptor-only
    object.
    """
    if kind == "exchange":
        out: list[str | None] = []
        for role in ("model.exchange.request", "model.exchange.response"):
            for d in descriptors:
                if d["role"] == role and not d.get("links") and "stored_sha256" in d:
                    out.append(d["stored_sha256"])
        return out
    by_id = {d["object_id"]: d for d in descriptors}
    return [by_id[oid].get("stored_sha256") for oid in object_ids]


def record_digest_document(
    *,
    name: str,
    start_ns: int,
    end_ns: int,
    status: str,
    attributes: Mapping[str, Any],
    content: Sequence[str | None],
) -> dict[str, Any]:
    if status not in {"unset", "ok", "error"}:
        raise ValueError("status is unset, ok or error, never a description")
    return {
        "name": name,
        "start_ns": start_ns,
        "end_ns": end_ns,
        "status": status,
        "attributes": {
            k: list(v) if isinstance(v, tuple) else v
            for k, v in attributes.items()
            if k not in RECEIVER_OWNED_KEYS
        },
        "content": list(content),
    }


def record_digest(**parts: Any) -> str:
    """``sha256:`` of the canonical JSON of ``{name, start_ns, end_ns, status, attributes,
    content}`` (049 §2.12 rule 1, 050 §3.7); receiver-owned keys are excluded."""
    return sha256_digest(canonical_bytes(record_digest_document(**parts)))


def loss_entries(loss: Mapping[str, Any]) -> list[list[Any]]:
    """The seal entries of one segment-attributed loss record: ``[p, "loss:<reason>"]`` for
    every position of its range. A segment-attributed range is exact (count equals the
    range size), so no position is guessed (050 §3.3 R3, T8)."""
    first, last = loss["first_sequence"], loss["last_sequence"]
    if loss["count"] != last - first + 1:
        raise ValueError("a segment-attributed loss range is exact")
    return [[p, f"loss:{loss['reason']}"] for p in range(first, last + 1)]


def seal_entries(
    records: Iterable[tuple[int, str]],
    losses: Iterable[Mapping[str, Any]],
    segment_id: str,
) -> list[list[Any]]:
    """Members of one segment's seal: its records' ``(sequence, digest)`` and the positions
    of the loss records naming ``segment_id``; a loss without ``segment_id`` is never a
    member."""
    entries = [[seq, digest] for seq, digest in records]
    for loss in losses:
        if loss.get("segment_id") == segment_id:
            entries += loss_entries(loss)
    return entries


def seal_digest(entries: Iterable[Sequence[Any]]) -> str:
    """``sha256:`` over the canonical JSON of the ``[sequence, entry]`` pairs sorted by
    sequence; an empty segment hashes ``[]`` (050 §3.7)."""
    pairs = sorted(([int(seq), entry] for seq, entry in entries), key=lambda p: p[0])
    if len({p[0] for p in pairs}) != len(pairs):
        raise ValueError("one entry per sequence")
    return sha256_digest(canonical_bytes(pairs))


# ------------------------------------------------------------------ span category (rule N)
_TOOL_KEYS = ("fabric.tool.name", "gen_ai.tool.name", "fabric.tool.result_hash")
_MODEL_KEYS = ("fabric.llm.system", "gen_ai.request.model", "fabric.wire.exchange_id")
_ORDERED = (
    ("fabric.retrieval.source", "fabric.retrieval"),
    ("fabric.memory.kind", "fabric.memory"),
    ("fabric.side_effect.type", "fabric.side_effect"),
    ("fabric.interaction.kind", "fabric.interaction"),
    ("fabric.file.operation", "fabric.file_access"),
    ("fabric.delegation.protocol", "fabric.delegation"),
    ("fabric.checkpoint.checkpoint_id", "fabric.checkpoint"),
    ("fabric.replay.execution_id", "fabric.replay"),
    ("fabric.mcp.server", "fabric.mcp.inventory"),
    ("fabric.skill.name", "fabric.skill"),
    ("fabric.hook.phase", "fabric.hook"),
    ("fabric.coverage.kind", "fabric.coverage"),
    ("fabric.execution.status", "fabric.execution"),
    ("fabric.execution_id", "fabric.execution"),
    ("fabric.decision_id", "fabric.decision"),
)
KNOWN_NAMES = frozenset(
    {
        "fabric.execution", "fabric.decision", "fabric.llm_call", "fabric.model_call",
        "fabric.tool_call", "fabric.retrieval", "fabric.memory", "fabric.side_effect",
        "fabric.interaction", "fabric.file_access", "fabric.delegation", "fabric.error",
        "fabric.retry", "fabric.cancellation", "fabric.deployment_change", "fabric.human_action",
        "fabric.checkpoint", "fabric.replay", "fabric.mcp.inventory", "fabric.skill",
        "fabric.hook", "fabric.coverage",
        "fabric.capture_loss", "fabric.capture_heartbeat", "fabric.capture_manifest",
    }
)  # fmt: skip


def span_category(name_hint: str, attribute_keys: Iterable[str]) -> str:
    """Port of fabricguard's ``activityCategory`` (``P/processor.go``): the exported span
    name of a record, decided by attribute keys first, then by the name itself."""
    keys = set(attribute_keys)
    if "fabric.heartbeat.last_sequence" in keys:
        return "fabric.capture_heartbeat"
    if "fabric.loss.reason" in keys:
        return "fabric.capture_loss"
    if any(k in keys for k in _TOOL_KEYS):
        return "fabric.tool_call"
    if any(k in keys for k in _MODEL_KEYS):
        return "fabric.model_call"
    for key, category in _ORDERED:
        if key in keys:
            return category
    return name_hint if name_hint in KNOWN_NAMES else "fabric.activity"


# ------------------------------------------------------------------ rule A
def condition_holds(
    condition: Mapping[str, Sequence[str]] | None,
    capture_point: str | None,
    point_kinds: Mapping[str, Iterable[str]],
) -> bool:
    """A conditional ``record`` placement (050 §3.4 rule A, F1): ``capture_point_kinds``
    and ``capture_points`` match the id part of ``fabric.capture.point`` (before ``@``)."""
    if not condition:
        return True
    point = (capture_point or "").split("@", 1)[0]
    kinds = set(point_kinds.get(point, ()))
    if "capture_points" in condition and point not in condition["capture_points"]:
        return False
    return "capture_point_kinds" not in condition or bool(
        kinds & set(condition["capture_point_kinds"])
    )


def project_record_attributes(
    attributes: Mapping[str, Any],
    table: Mapping[str, Mapping[str, Any]],
    check_value: Callable[..., bool],
    *,
    labels: str = "pseudonymous",
    identity: str = "pseudonymous",
    conditions: Mapping[str, Mapping[str, Sequence[str]]] | None = None,
    point_kinds: Mapping[str, Iterable[str]] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Rule A (050 §3.4): keep exactly the keys of the records-class table whose value
    passes the key's check; drop (and count) everything else: unknown keys, failing
    values, floats, maps and bytes. A value is never hashed or truncated. ``check_value``
    is the registry check function (``validate_coverage_contracts.check_value``)."""
    kept: dict[str, Any] = {}
    dropped: list[str] = []
    point = attributes.get("fabric.capture.point")
    for key, value in attributes.items():
        check = table.get(key)
        if (
            check is None
            or not condition_holds(
                (conditions or {}).get(key),
                point if isinstance(point, str) else None,
                point_kinds or {},
            )
            or isinstance(value, (float, dict, bytes, bytearray))
            or (
                isinstance(value, list)
                and any(isinstance(v, (float, dict, list, bytes)) for v in value)
            )
            or not check_value(check, value, labels=labels, identity=identity)
        ):
            dropped.append(key)
        else:
            kept[key] = value
    return kept, sorted(dropped)


# ------------------------------------------------------------------ resume tokens
def parse_predecessor(entry: str) -> dict[str, Any] | None:
    match = SEGMENT_ENTRY.fullmatch(entry)
    if (
        match is None
        or int(match["epoch"]) > INT64_MAX
        or int(match["last_sequence"]) > INT64_MAX
    ):
        return None
    return {
        "segment_id": match["segment_id"],
        "source_id": match["source_id"],
        "epoch": int(match["epoch"]),
        "last_sequence": int(match["last_sequence"]),
        "manifest_digest": match["manifest_digest"],
    }


def _entry_and_branch(body: str) -> dict[str, Any] | None:
    branch = None
    head, _, tail = body.rpartition("/")
    if BRANCH_RE.fullmatch(tail):
        body, branch = head, tail
    parsed = parse_predecessor(body)
    if parsed is None:
        return None
    parsed["branch_id"] = branch
    return parsed


def parse_token(token: str) -> dict[str, Any] | None:
    """``fr3/<run correlation id>/<entry>[/br-<32 hex>]`` (050 §3.6), or the legacy
    ``fr2/<entry>[/br-<32 hex>]`` (no correlation id; parsed for one release). The
    correlation id is an opaque id without ``/`` (``r-`` + 32 hex, or a clear run id in
    clear mode). Anything else is ``None`` (the token is dropped)."""
    if token.startswith("fr3/"):
        correlation, sep, rest = token[4:].partition("/")
        if not sep or not OPAQUE_RE.fullmatch(correlation):
            return None
        parsed = _entry_and_branch(rest)
        if parsed is None:
            return None
        return {"version": 3, "correlation_id": correlation, **parsed}
    if token.startswith("fr2/"):
        parsed = _entry_and_branch(token[4:])
        if parsed is None:
            return None
        return {"version": 2, "correlation_id": None, **parsed}
    return None


def format_entry(
    segment_id: str,
    source_id: str,
    epoch: int,
    last_sequence: int,
    manifest_digest: str,
) -> str:
    return f"{segment_id}/{source_id}/{epoch}/{last_sequence}/{manifest_digest}"


def format_token(
    correlation_id: str, entry: str, branch_id: str | None = None
) -> str | None:
    """An ``fr3/`` token, or ``None`` when the correlation id cannot be carried (a clear id
    outside the opaque-id pattern: the token is not issued, ``api_misuse``)."""
    if not OPAQUE_RE.fullmatch(correlation_id) or parse_predecessor(entry) is None:
        return None
    if branch_id is not None and not BRANCH_RE.fullmatch(branch_id):
        return None
    return f"fr3/{correlation_id}/{entry}" + (f"/{branch_id}" if branch_id else "")


def split_carrier(value: str, *, carrier: str) -> list[str]:
    """A join is comma-separated; a W3C ``baggage`` value is percent-decoded first."""
    if carrier == "baggage":
        value = unquote(value, errors="strict")
    return value.split(",")


# ------------------------------------------------------------------ run identity (rules 1-5)
def encode_opaque_id(value: str) -> str:
    if OPAQUE_RE.fullmatch(value):
        return value
    return (
        "h-" + hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:40]
    )


def run_pseudonym(value: str, key: str | None) -> str:
    """``r-`` + 32 hex of HMAC-SHA256(key, value), or SHA-256 without a key (the v1
    function ``run-id-pseudonym-v1.json`` pins)."""
    data = value.encode("utf-8", "surrogatepass")
    raw = (
        hmac.new(key.encode("utf-8"), data, hashlib.sha256)
        if key
        else hashlib.sha256(data)
    )
    return "r-" + raw.hexdigest()[:32]


def map_run_id(
    value: str, *, identity_mode: str, key: str | None, emitted: bool = False
) -> str:
    """The identity rule (050 §3.4, R8): an ``EmittedId`` of this handle passes through;
    pseudonymous mode maps every caller value whatever its shape; clear mode emits it as
    given (``h-`` form when it is not an opaque id)."""
    if emitted:
        return value
    if identity_mode == "clear":
        return encode_opaque_id(value)
    return run_pseudonym(value, key)


def run_identity(
    tokens: Sequence[str],
    run_id: str | None,
    *,
    identity_mode: str = "pseudonymous",
    key: str | None = None,
    run_id_emitted: bool = False,
    minted: str,
) -> dict[str, Any]:
    """Run identity at segment open (050 §3.6): the first rule that applies decides
    ``fabric.run.id`` and ``id_basis``.

    1. valid ``fr3/`` tokens, one correlation id ``c``: ``c`` verbatim (``token``);
    2. differing correlation ids and a clear ``run_id``: the mapped clear id (``caller_join``);
    3. differing correlation ids, no ``run_id``: the lowest by byte order (``token_conflict``);
    4. no valid ``fr3/`` token, a clear ``run_id``: the mapped clear id (``caller``);
    5. no valid token and no run id: the minted correlation id (``minted``).

    Rules 4 and 5 report ``legacy`` when the only valid tokens are ``fr2/`` (no
    correlation id). Malformed tokens are dropped; without a valid token the segment is a
    root (``none``). ``minted`` is the ``r-`` + 32 CSPRNG hex the caller drew.
    """
    if not MINTED_RUN_RE.fullmatch(minted):
        raise ValueError("a minted correlation id is r- + 32 hex")
    parsed = [p for p in (parse_token(t) for t in tokens) if p is not None]
    current = [p for p in parsed if p["version"] == 3]
    correlations = sorted(
        {p["correlation_id"] for p in current}, key=lambda c: c.encode()
    )
    if correlations and len(correlations) == 1:
        out_id, basis = correlations[0], "token"
    elif correlations and run_id is not None:
        out_id = map_run_id(
            run_id, identity_mode=identity_mode, key=key, emitted=run_id_emitted
        )
        basis = "caller_join"
    elif correlations:
        out_id, basis = correlations[0], "token_conflict"
    elif run_id is not None:
        out_id = map_run_id(
            run_id, identity_mode=identity_mode, key=key, emitted=run_id_emitted
        )
        basis = "legacy" if parsed else "caller"
    else:
        out_id, basis = minted, "legacy" if parsed else "minted"
    predecessors: list[str] = []
    branches: list[str] = []
    for p in parsed:
        entry = format_entry(
            p["segment_id"],
            p["source_id"],
            p["epoch"],
            p["last_sequence"],
            p["manifest_digest"],
        )
        if entry not in predecessors:
            predecessors.append(entry)
        if p["branch_id"] and p["branch_id"] not in branches:
            branches.append(p["branch_id"])
    return {
        "run_id": out_id,
        "id_basis": basis,
        "predecessors": predecessors or ["none"],
        "branch_ids": branches,
        "tokens_rejected": len(tokens) - len(parsed),
    }


# ------------------------------------------------------------------ evidence carrier
def _depth(value: Any) -> int:
    if isinstance(value, Mapping):
        return 1 + max((_depth(v) for v in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_depth(v) for v in value), default=0)
    return 0


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for k, v in value.items():
            yield k
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key")
        out[k] = v
    return out


def _envelope_ok(doc: Any) -> bool:
    if not isinstance(doc, dict) or not EVIDENCE_REQUIRED <= set(doc) <= EVIDENCE_KEYS:
        return False
    if doc["schema_version"] != EVIDENCE_SCHEMA or not isinstance(
        doc["evidence_type"], str
    ):
        return False
    if not isinstance(doc["items"], list) or not all(
        isinstance(i, dict) for i in doc["items"]
    ):
        return False
    cont = doc.get("continuation")
    if "continuation" in doc and (
        not isinstance(cont, dict)
        or set(cont) != {"index", "final"}
        or not isinstance(cont["index"], int)
        or isinstance(cont["index"], bool)
        or not 0 <= cont["index"] <= INT64_MAX
        or not isinstance(cont["final"], bool)
    ):
        return False
    refs = doc.get("refs", [])
    if not isinstance(refs, list):
        return False
    for ref in refs:
        if (
            not isinstance(ref, dict)
            or not {"object_id", "role"} <= set(ref) <= REF_KEYS
            or not isinstance(ref["object_id"], str)
            or not UUID4_RE.fullmatch(ref["object_id"])
            or not isinstance(ref["role"], str)
            or (
                "pointer" in ref
                and (
                    not isinstance(ref["pointer"], str)
                    or not POINTER_RE.fullmatch(ref["pointer"])
                )
            )
            or (
                "byte_range" in ref
                and not (
                    isinstance(ref["byte_range"], list)
                    and len(ref["byte_range"]) == 2
                    and all(
                        isinstance(x, int) and not isinstance(x, bool) and x >= 0
                        for x in ref["byte_range"]
                    )
                    and ref["byte_range"][0] <= ref["byte_range"][1]
                )
            )
        ):
            return False
    return True


def evidence_envelope_refusal(raw: bytes, registered: Iterable[str]) -> str | None:
    """The Node's stateless envelope check of a ``record.evidence`` body (050 §3.4a item
    4), in order: canonical JSON (``evidence_not_canonical``), the closed envelope
    (``evidence_envelope``), a registered ``evidence_type`` (``evidence_type_unregistered``),
    then the bounds (``evidence_bounds``: at most 1 MiB, 4096 items, item depth 4, strings
    of 256 characters, 64 refs). ``None``: the envelope passes. Per-type item schemas are
    not checked here (``fabric.reconstruct`` does, :func:`evidence_item_errors`)."""
    if len(raw) > EVIDENCE_MAX_BYTES:
        return "evidence_bounds"
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
        canonical = canonical_bytes(doc)
    except (UnicodeDecodeError, ValueError):
        return "evidence_not_canonical"
    if canonical != raw:
        return "evidence_not_canonical"
    if not _envelope_ok(doc):
        return "evidence_envelope"
    if doc["evidence_type"] not in set(registered):
        return "evidence_type_unregistered"
    if (
        len(doc["items"]) > EVIDENCE_MAX_ITEMS
        or len(doc.get("refs", [])) > EVIDENCE_MAX_REFS
        or any(_depth(item) > EVIDENCE_MAX_DEPTH for item in doc["items"])
        or any(len(s) > EVIDENCE_MAX_STRING for s in _strings(doc))
    ):
        return "evidence_bounds"
    return None


CLEAR_KEYWORD = "x-fabric-clear"


def _clear_mode_schema(schema: Any) -> Any:
    """``schema`` with every property that names an ``x-fabric-clear`` alternative widened
    to ``anyOf: [mapped form, clear form]`` (clear mode only)."""
    if isinstance(schema, Mapping):
        out = {
            k: _clear_mode_schema(v) for k, v in schema.items() if k != CLEAR_KEYWORD
        }
        if CLEAR_KEYWORD in schema:
            return {"anyOf": [out, dict(schema[CLEAR_KEYWORD])]}
        return out
    if isinstance(schema, list):
        return [_clear_mode_schema(v) for v in schema]
    return schema


def evidence_item_errors(
    doc: Mapping[str, Any],
    item_schema: Mapping[str, Any],
    *,
    identity_mode: str = "pseudonymous",
) -> list[int]:
    """Indexes of the items its registered type schema refuses; the fields an invalid item
    carries project ``not_captured(parse_failed)`` (050 §3.4a item 6). An ID property's
    clear-mode alternative (``x-fabric-clear``) counts only when the record's source
    manifest declares ``identity_mode: clear`` (item 2, R8); otherwise only the mapped form
    is valid."""
    from jsonschema import Draft202012Validator, FormatChecker  # noqa: PLC0415

    schema = (
        _clear_mode_schema(item_schema) if identity_mode == "clear" else item_schema
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    return [i for i, item in enumerate(doc["items"]) if not validator.is_valid(item)]


def resolve_pointer(doc: Any, pointer: str) -> list[Any]:
    """Values at a registry field pointer; ``*`` stands for every element of an array."""
    nodes = [doc]
    for part in pointer.split("/")[1:]:
        part = part.replace("~1", "/").replace("~0", "~")
        nxt: list[Any] = []
        for node in nodes:
            if part == "*" and isinstance(node, list):
                nxt += node
            elif isinstance(node, dict) and part in node:
                nxt.append(node[part])
            elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
                nxt.append(node[int(part)])
        nodes = nxt
    return nodes


# ------------------------------------------------------------------ Node pre-acknowledgement
PREVALIDATE_REASONS = (
    "bad_descriptor",
    "digest_mismatch",
    "tenant_not_allowed",
    "source_unbound",
    "evidence_not_canonical",
    "evidence_envelope",
    "evidence_type_unregistered",
    "evidence_bounds",
)


def prevalidate(
    attributes: Mapping[str, Any],
    body: bytes,
    *,
    allowed_tenants: Sequence[str],
    source_binding: Mapping[str, str] | None,
    descriptor_ok: Any,
    registered: Iterable[str],
) -> str | None:
    """The stateless checks ``fabriccontent`` runs before acknowledging a content record
    (050 §3.14), in order; the first failing reason is the HTTP 400's fixed reason and the
    ``fabric_content_prevalidate_refused`` label. ``descriptor_ok(attributes)`` is the
    descriptor rule set (schema, role, protection, links). The store-conflict check needs a
    store read and stays after acknowledgement."""
    if not descriptor_ok(attributes):
        return "bad_descriptor"
    if len(body) != attributes.get("stored_byte_length", 0) or (
        body and sha256_digest(body) != attributes.get("stored_sha256")
    ):
        return "digest_mismatch"
    if attributes["tenant_id"] not in allowed_tenants:
        return "tenant_not_allowed"
    if source_binding is not None and (
        attributes["tenant_id"] != source_binding["tenant_id"]
        or attributes["source_id"] != source_binding["source_id"]
    ):
        return "source_unbound"
    if attributes["role"] == EVIDENCE_ROLE and attributes["status"] == "stored":
        return evidence_envelope_refusal(body, registered)
    return None


def end_run_identity(
    tokens: Sequence[str],
    run_id: str | None,
    *,
    identity_mode: str = "pseudonymous",
    key: str | None = None,
    minted: str,
) -> dict[str, Any]:
    """``end_run`` (050 §3.6): without a valid token it is ``refused_no_token`` and emits
    nothing; with ``run_id=None`` and tokens of different correlation ids it is
    ``refused_conflicting_tokens``; otherwise the zero-width segment takes its run id by
    the run-identity rules (``run_id=None``: the tokens' correlation id)."""
    parsed = [p for p in (parse_token(t) for t in tokens) if p is not None]
    if not parsed:
        return {"status": "refused_no_token"}
    correlations = {p["correlation_id"] for p in parsed if p["version"] == 3}
    if run_id is None and len(correlations) > 1:
        return {"status": "refused_conflicting_tokens"}
    identity = run_identity(
        tokens, run_id, identity_mode=identity_mode, key=key, minted=minted
    )
    return {"status": "ended", **identity}
