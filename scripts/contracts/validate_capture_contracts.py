# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Validate the draft LLM wire-capture contracts (contracts/capture/v1, specs 047 and 048).

JSON Schema handles closed shapes. The semantic checks below reject what a
schema cannot express: a store status that disagrees with the stored body
object ids, loss ranges that cannot hold their count, a scope id on a
heartbeat that is not a run marker, a spool record whose bodies, descriptors
and span disagree, a content log record whose body or representation
disagrees with its descriptor, and a reconstruction verdict (per run or
per scope) stronger than its gaps, checks, scopes, sequence windows and
heartbeats allow. The vector fixtures pin the model-name exposure rule and
the run-id pseudonym that capture, fabricguard and ``fabric.reconstruct``
share (spec 048 §6-§7). The stitch-digest fixture pins the ``fabric.stitch/v1`` per-message projection
that ``fabric.reconstruct`` derives offline from stored bytes; the golden
fixtures pin the exact descriptor bytes and keys a content writer (the
Fabric Node's ``fabriccontent`` exporter or the SDK local store) produces.
Spec 049 P0 adds the run-marker rules (``none`` stands alone among
predecessors, a seal never ends after its source's last position, branch
tokens make the run resumable), checks that heartbeat spans and spool markers
define every run-marker key identically, binds a records-input spool entry to
its source, and closes the generated ``fabric.capture_manifest`` span form.
This validator does not claim any runtime currently emits these documents.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from jsonschema import Draft202012Validator, FormatChecker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from contracts import p1_reference as ref  # noqa: E402

ROOT = Path("contracts/capture/v1")
IDENTITY = ("singleaxis.fabric.capture", "1.3.0")
SCHEMAS = {
    "fabric.llm-exchange/v1": "schema/llm-exchange-v1.schema.json",
    "fabric.loss-record/v1": "schema/loss-record-v1.schema.json",
    "fabric.run-reconstruction/v1": "schema/run-reconstruction-v1.schema.json",
    "fabric.wire-spool-record/v1": "schema/spool-record-v1.schema.json",
    "fabric.content-log-record/v1": "schema/content-log-record-v1.schema.json",
    "fabric.capture-manifest-record/v1": "schema/capture-manifest-record-v1.schema.json",
}
# Spec 049 run-marker keys: identical JSON definitions on fabric.loss-record/v1
# heartbeats and on spool marker records.
_MARKER_KEYS = (
    "segment_id",
    "predecessors",
    "resumable",
    "open_deadline_s",
    "declared_branches",
    "branch_ids",
    "terminal",
    "seal",
    "manifest_id",
    "manifest_digest",
    "manifest_seq",
    "scope_status",
    # spec 050 §4.2 (capture/v1 1.3.0)
    "event_id",
    "id_basis",
    "session_id",
    "user_id",
    "parent_run_id",
    "resumed_from",
    "links",
    "outcome",
    "stop_reason",
    "identity",
)
# Spec 050 §4.2: carried only by the run's root run_start (predecessors ['none']).
_ROOT_ONLY = ("session_id", "user_id", "parent_run_id", "resumed_from", "links")
_INT64_MAX = 9223372036854775807
_EXPECTATIONS = frozenset(
    {"schema", "valid", "invalid", "digests", "golden", "vectors"}
)
_SCOPED_MARKERS = frozenset({"run_start", "run_end", "segment_seal"})
_COMPLETE = "complete_for_declared_scope"
_COMPLETE_OBSERVED = "complete_for_observed_scopes"
_COMPLETE_VERDICTS = frozenset({_COMPLETE, _COMPLETE_OBSERVED})
_RANK = {_COMPLETE: 0, _COMPLETE_OBSERVED: 0, "unverified": 1, "partial": 2}
_ROLE_REF = {
    "model.exchange.request": "fabric.content.request_ref",
    "model.exchange.response": "fabric.content.result_ref",
}


@dataclass(frozen=True)
class CaptureContractError(ValueError):
    """Stable, automation-safe validation failure."""

    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.path}: {self.message}"


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CaptureContractError(
            "capture.document.unreadable", str(path), str(exc)
        ) from exc
    if not isinstance(value, dict):
        raise CaptureContractError(
            "capture.document.not_object", str(path), "expected object"
        )
    return value


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: Any) -> str:
    """Spec-029 canonical JSON: sorted keys, no insignificant whitespace, literal UTF-8."""

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _schema_error(document: Mapping[str, Any], schema: Mapping[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
            document
        ),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        first = errors[0]
        raise CaptureContractError(
            "capture.schema",
            "$" + "".join(f".{part}" for part in first.absolute_path),
            first.message,
        )


def _validate_exchange(document: Mapping[str, Any]) -> None:
    # Spec 049 P0-A: a side without a stored object (content disabled,
    # withheld, omitted) has no body.
    bodies = [document[side] for side in ("request", "response") if side in document]
    # object_id is closed to a uuid4 by the schema: no path, URI or bucket.
    stored = [("object_id" in body) for body in bodies]
    status = document["store_status"]
    if status in {"disabled", "failed"}:
        consistent = not any(stored)
    elif status == "stored":
        consistent = all(stored)
    else:  # partial
        consistent = any(stored) and not all(stored)
    if not consistent:
        raise CaptureContractError(
            "capture.exchange.store_status",
            "$.store_status",
            f"store_status {status!r} disagrees with the stored body object ids",
        )
    if "error_type" in document and document["response_state"] != "error":
        raise CaptureContractError(
            "capture.exchange.error_type",
            "$.error_type",
            "error_type is only recorded for response_state 'error'",
        )


def _validate_loss(document: Mapping[str, Any]) -> None:
    if document["kind"] != "loss":
        if "scope_id" in document and document["heartbeat_kind"] not in _SCOPED_MARKERS:
            raise CaptureContractError(
                "capture.heartbeat.scope",
                "$.scope_id",
                "only run_start / run_end / segment_seal markers carry a scope_id",
            )
        _check_marker(
            document, document["last_sequence"], "$", kind=document["heartbeat_kind"]
        )
        return
    _check_range(document)


def _check_marker(
    marker: Mapping[str, Any], last_sequence: int, path: str, *, kind: str
) -> None:
    """Spec 049 run-marker rules a schema cannot express (sections 2.10, 2.12), and the
    spec 050 §4.2 additions: root-only run fields, id_basis on every P1 run_start."""

    predecessors = marker.get("predecessors", [])
    root_only = [k for k in _ROOT_ONLY if k in marker]
    if root_only and predecessors != ["none"]:
        raise CaptureContractError(
            "capture.marker.root",
            f"{path}.{root_only[0]}",
            "session, user, parent, resumed_from and links ride only on the run's root run_start",
        )
    if kind == "run_start" and "segment_id" in marker and "id_basis" not in marker:
        raise CaptureContractError(
            "capture.marker.id_basis",
            f"{path}.id_basis",
            "a segment's run_start records the run-identity rule that decided its run id",
        )
    if "none" in predecessors and predecessors != ["none"]:
        raise CaptureContractError(
            "capture.marker.predecessors",
            f"{path}.predecessors",
            "'none' marks the run's root and stands alone",
        )
    if len(set(predecessors)) != len(predecessors) or any(
        entry != "none" and int(entry.split("/")[2]) > _INT64_MAX
        for entry in predecessors
    ):
        raise CaptureContractError(
            "capture.marker.predecessors",
            f"{path}.predecessors",
            "entries are distinct and epochs fit 63 bits",
        )
    seal = marker.get("seal")
    if seal is None:
        return
    if seal["last_sequence"] > last_sequence:
        raise CaptureContractError(
            "capture.marker.seal",
            f"{path}.seal.last_sequence",
            "a segment cannot end after the source's last allocated position",
        )
    if seal.get("branch_ids") and marker.get("resumable") is not True:
        raise CaptureContractError(
            "capture.marker.seal",
            f"{path}.seal.branch_ids",
            "issuing branch tokens makes the run resumable (resumable=true on the seal)",
        )


def _check_range(document: Mapping[str, Any]) -> None:
    first, last = document["first_sequence"], document["last_sequence"]
    if last < first or document["count"] > last - first + 1:
        raise CaptureContractError(
            "capture.loss.range",
            "$.count",
            "a loss range needs first <= last and at most last - first + 1 lost exchanges",
        )
    if "segment_id" in document and document["count"] != last - first + 1:
        raise CaptureContractError(
            "capture.loss.segment",
            "$.count",
            "a segment-attributed loss range is exact: it never spans another segment's "
            "positions (spec 050 R3), so the seal is recomputable",
        )


_ROLE_TABLE = Path("contracts/coverage/v1/registry/content-roles-v1.json")
_CAP_BYTES = {"64 KiB": 65536, "256 KiB": 262144, "1 MiB": 1 << 20, "4 MiB": 4 << 20}
# Spec 049 §7.4: max_body_bytes is the deployment's value, never above 63 MiB
# in node mode; the contract bound is that ceiling.
_NODE_MAX_BODY_BYTES = 63 << 20
_POLICY_FIELDS = (
    "privacy_mode",
    "policy_id",
    "policy_version",
    "policy_digest",
    "protection_status",
)
_NO_LENGTH_MODES = frozenset({"omit", "redact", "tokenize", "masked_only"})
_BYTE_MODES = frozenset(
    {"retain_original", "redact", "tokenize", "masked_only", "original_plus_masked"}
)


def _roles() -> dict[str, Mapping[str, Any]]:
    root = Path(__file__).resolve().parents[2]
    table = json.loads((root / _ROLE_TABLE).read_text(encoding="utf-8"))
    return {row["role"]: row for row in table["roles"]}


def _media_allowed(patterns: Sequence[str], media_type: str) -> bool:
    return any(
        p == "*"
        or p == media_type
        or p.endswith("/*")
        and media_type.startswith(p[:-1])
        for p in patterns
    )


def _combination_ok(d: Mapping[str, Any]) -> bool:
    """Status, representation, transformations and digests (spec 048 §3, 049 §4.3, §7.5)."""
    status, representation, transformations = (
        d["status"],
        d["representation"],
        d["transformations"],
    )
    has_stored, has_source, has_source_sha = (
        "stored_byte_length" in d,
        "source_byte_length" in d,
        "source_sha256" in d,
    )
    if status in {"not_captured", "unsupported"}:
        return (
            representation == "unavailable"
            and transformations == []
            and not has_stored
            and "status_reason" in d
        )
    if status == "stored":
        if representation in {"exact", "partial"}:
            return (
                transformations == []
                and d.get("source_sha256") == d["stored_sha256"]
                and d.get("source_byte_length") == d["stored_byte_length"]
                and (
                    representation == "exact" or d["role"] == "model.exchange.response"
                )
            )
        return (
            representation == "split"
            and transformations == ["extract_parts"]
            and has_source_sha
        )
    if status == "truncated":
        return (
            representation == "truncated"
            and transformations == ["truncate"]
            and not has_source_sha
            and has_source
            and d["source_byte_length"] > d["stored_byte_length"]
        )
    if status == "redacted" and not (has_source or has_source_sha):
        kind = {"redacted": "redact", "tokenized": "tokenize"}.get(representation)
        return kind is not None and transformations in ([kind], ["extract_parts", kind])
    return False


def _protection_ok(d: Mapping[str, Any]) -> bool:
    """The policy block against the outcome (spec 049 §7.5, §7.7)."""
    status, reason = d["status"], d.get("status_reason")
    if not any(key in d for key in _POLICY_FIELDS):
        return "transformation_id" not in d and status != "redacted"
    mode, protection = d["privacy_mode"], d["protection_status"]
    has_source, has_source_sha = "source_byte_length" in d, "source_sha256" in d
    retains = mode in {"retain_original", "original_plus_masked"}
    if has_source and mode in _NO_LENGTH_MODES:
        return False
    if status in {"not_captured", "unsupported"}:
        if protection != "withheld":
            return False
        if reason == "protection_failed":
            return mode in _BYTE_MODES and not has_source_sha
        if reason == "privacy_policy":
            # Withheld by the mode itself; under redact or masked_only only a binary
            # part no part transformation applies to (spec 049 §7.5).
            binary_part = d["role"] == "model.exchange.part" and mode in {
                "redact",
                "masked_only",
            }
            return (
                mode in {"metadata_only", "omit"} or binary_part
            ) and not has_source_sha
        return retains or not has_source_sha
    if status in {"stored", "truncated"}:
        return protection == "retained" and retains
    if d["representation"] == "tokenized":
        return mode == "tokenize" and protection == "tokenized"
    if protection != "redacted" or mode not in {
        "redact",
        "masked_only",
        "original_plus_masked",
    }:
        return False
    return mode != "original_plus_masked" or any(
        link["relation"] == "derived_from" for link in d.get("links", [])
    )


def _links_ok(d: Mapping[str, Any]) -> bool:
    links = d.get("links", [])
    part_of = [link for link in links if link["relation"] == "part_of"]
    derived = [link for link in links if link["relation"] == "derived_from"]
    if any(link["object_id"] == d["object_id"] for link in links) or len(derived) > 1:
        return False
    for link in part_of:
        if "byte_range" not in link:
            continue
        start, end = link["byte_range"]
        length = d.get("stored_byte_length", d.get("source_byte_length"))
        if (
            d["status"] == "redacted"
            or start > end
            or (length is not None and end - start != length)
        ):
            return False
    return len(part_of) == (1 if d["role"] == "model.exchange.part" else 0)


def _role_ok(d: Mapping[str, Any]) -> bool:
    row = _roles().get(d["role"])
    if row is None:
        return False
    cap = _CAP_BYTES.get(row["cap"], _NODE_MAX_BODY_BYTES)
    return (
        d["boundary"] in row["boundary"]
        and d["provenance"] in row["provenance"]
        and _media_allowed(row["media_types"], d["media_type"])
        and d.get("stored_byte_length", 0) <= cap
    )


def _check_descriptor(descriptor: Mapping[str, Any], path: str) -> None:
    """The fabriccontent exporter's closed descriptor rules (spec 049 §4.3), mirrored.

    The Node's parser (components/otel-collector-fabric/exporter/
    fabriccontentexporter/record.go) applies the same rules; its tests read
    the content-log-record fixtures of this family.
    """

    checks = (
        ("capture.content.representation", _combination_ok),
        ("capture.content.protection", _protection_ok),
        ("capture.content.links", _links_ok),
        ("capture.content.role", _role_ok),
    )
    for code, check in checks:
        if not check(descriptor):
            raise CaptureContractError(
                code,
                path,
                "descriptor fields disagree with the content-v2 rules of spec 049 §4.3",
            )


def content_descriptor_ok(attributes: Mapping[str, Any]) -> bool:
    """Whether a content-log-record attribute set passes the Node's descriptor rules: the
    closed capture/v1 schema and the content-v2 rules of spec 049 §4.3 (no body check)."""
    root = Path(__file__).resolve().parents[2] / ROOT
    schema = json.loads(
        (root / SCHEMAS["fabric.content-log-record/v1"]).read_text("utf-8")
    )
    document = {
        "schema_version": "fabric.content-log-record/v1",
        "body": {
            "byte_length": 0,
            "sha256": "sha256:" + hashlib.sha256(b"").hexdigest(),
        },
        "attributes": dict(attributes),
    }
    try:
        _schema_error(document, schema)
        _check_descriptor(attributes, "$.attributes")
    except CaptureContractError:
        return False
    return True


def _validate_content(document: Mapping[str, Any]) -> None:
    attributes, body = document["attributes"], document["body"]
    empty = "sha256:" + hashlib.sha256(b"").hexdigest()
    if body["byte_length"] != attributes.get("stored_byte_length", 0) or body[
        "sha256"
    ] != attributes.get("stored_sha256", empty):
        raise CaptureContractError(
            "capture.content.digest",
            "$.body",
            "body length or sha256 differs from the descriptor",
        )
    _check_descriptor(attributes, "$.attributes")


def _spool_inconsistent(path: str, message: str) -> CaptureContractError:
    return CaptureContractError("capture.spool.consistency", path, message)


def _validate_spool(document: Mapping[str, Any]) -> None:
    kind = document["record_kind"]
    if kind == "loss":
        _check_range(document["loss"])
        return
    if kind == "marker":
        _check_marker(
            document["marker"],
            document["marker"]["last_sequence"],
            "$.marker",
            kind=document["marker"]["kind"],
        )
        return
    if kind == "record":
        span, source = document["span"], document["source"]
        attrs = span["attributes"]
        if (attrs["fabric.source_id"], attrs["fabric.source.epoch"]) != (
            source["source_id"],
            source["source_epoch"],
        ):
            raise _spool_inconsistent(
                "$.span.attributes", "span source differs from the record source"
            )
        if span["end_time_unix_nano"] < span["start_time_unix_nano"]:
            raise _spool_inconsistent("$.span", "span ends before it starts")
        _check_record_bodies(document)
        return
    if kind != "exchange":
        return
    span, source = document["span"], document["source"]
    attrs = span["attributes"]
    if (attrs["fabric.source_id"], attrs["fabric.source.epoch"]) != (
        source["source_id"],
        source["source_epoch"],
    ):
        raise _spool_inconsistent(
            "$.span.attributes", "span source differs from the record source"
        )
    if span["end_time_unix_nano"] < span["start_time_unix_nano"]:
        raise _spool_inconsistent("$.span", "span ends before it starts")
    offset, primaries, ids = 0, set(), set()
    descriptors = [body["descriptor"] for body in document["bodies"]]
    for index, body in enumerate(document["bodies"]):
        where = f"$.bodies[{index}]"
        descriptor = body["descriptor"]
        _check_descriptor(descriptor, f"{where}.descriptor")
        expected = {
            "operation_id": attrs["fabric.wire.exchange_id"],
            "run_id": attrs["fabric.run.id"],
            "source_id": attrs["fabric.source_id"],
            "source_epoch": attrs["fabric.source.epoch"],
            "source_sequence": attrs["fabric.source.sequence"],
        }
        # A descriptor-only (not_captured) body occupies no blob bytes.
        if (
            body["offset"] != offset
            or body["length"] != descriptor.get("stored_byte_length", 0)
            or any(descriptor[k] != v for k, v in expected.items())
        ):
            raise _spool_inconsistent(
                where, "bodies must be contiguous and match the span"
            )
        if descriptor["object_id"] in ids:
            raise _spool_inconsistent(where, "object ids are unique within a record")
        ids.add(descriptor["object_id"])
        offset += body["length"]
    by_id = {d["object_id"]: d for d in descriptors}
    for index, descriptor in enumerate(descriptors):
        where = f"$.bodies[{index}]"
        targets = [link["object_id"] for link in descriptor.get("links", [])]
        if any(target not in by_id for target in targets):
            raise _spool_inconsistent(
                where, "a part or review copy links a body of this record"
            )
        role = descriptor["role"]
        # Spec 049 §7.5: only the primary object of a side (no link: the whole
        # side or its split skeleton) is named by the span's ref; parts link
        # part_of, review copies derived_from.
        if role in _ROLE_REF and not targets:
            if (
                role in primaries
                or attrs.get(_ROLE_REF[role]) != descriptor["object_id"]
            ):
                raise _spool_inconsistent(
                    where, "one primary body per side, named by the span's ref"
                )
            primaries.add(role)
    for role, key in _ROLE_REF.items():
        if key in attrs and role not in primaries:
            raise _spool_inconsistent("$.bodies", f"{key} names no spooled body")


def _check_record_bodies(document: Mapping[str, Any]) -> None:
    """Spec 050 §3.5: a record's bodies are its fabric.content.object_ids, in order, each
    bound to the record's attempt, run and source; one evidence object at most; a
    descriptor-only body occupies no blob bytes."""
    attrs = document["span"]["attributes"]
    bodies = document.get("bodies", [])
    ids = [body["descriptor"]["object_id"] for body in bodies]
    if ids != list(attrs.get("fabric.content.object_ids", [])):
        raise _spool_inconsistent(
            "$.bodies", "bodies are the span's fabric.content.object_ids, in order"
        )
    offset = 0
    for index, body in enumerate(bodies):
        where = f"$.bodies[{index}]"
        descriptor = body["descriptor"]
        _check_descriptor(descriptor, f"{where}.descriptor")
        expected = {
            "attempt_id": attrs["fabric.attempt.uid"],
            "source_id": attrs["fabric.source_id"],
            "source_epoch": attrs["fabric.source.epoch"],
            "source_sequence": attrs["fabric.source.sequence"],
        }
        if "fabric.run.id" in attrs:
            expected["run_id"] = attrs["fabric.run.id"]
        if (
            body["offset"] != offset
            or body["length"] != descriptor.get("stored_byte_length", 0)
            or any(descriptor.get(k) != v for k, v in expected.items())
        ):
            raise _spool_inconsistent(
                where,
                "bodies are contiguous and bound to the record's attempt and source",
            )
        offset += body["length"]
    if sum(b["descriptor"]["role"] == ref.EVIDENCE_ROLE for b in bodies) > 1:
        raise _spool_inconsistent("$.bodies", "at most one evidence object per record")


def _ranges_ok(ranges: Sequence[Sequence[int]]) -> bool:
    return all(low <= high for low, high in ranges)


def _validate_sources(document: Mapping[str, Any]) -> dict[tuple[str, int], Any]:
    sources: dict[tuple[str, int], Any] = {}
    for index, source in enumerate(document["sources"]):
        key = (source["source_id"], source["source_epoch"])
        loss = [
            (r["first_sequence"], r["last_sequence"]) for r in source["loss_ranges"]
        ]
        if (
            key in sources
            or not _ranges_ok(source["missing_sequences"])
            or not _ranges_ok(loss)
        ):
            raise CaptureContractError(
                "capture.reconstruction.source",
                f"$.sources[{index}]",
                "sources must be unique with ordered ranges",
            )
        sources[key] = source
    return sources


def _check_run_scopes(run: Mapping[str, Any], path: str) -> None:
    """Scope windows must match a closed scope's markers (spec 048 §6)."""

    scopes: dict[str, Mapping[str, Any]] = {}
    for scope in run.get("scopes", []):
        if scope["scope_id"] in scopes:
            raise CaptureContractError(
                "capture.reconstruction.scope", f"{path}.scopes", "duplicate scope_id"
            )
        scopes[scope["scope_id"]] = scope
    for window in run["declared_scope"]["windows"]:
        if "scope_id" not in window:
            continue
        scope = scopes.get(window["scope_id"])
        proven = "closed_by" in window
        if (
            scope is None
            or (scope["source_id"], scope["source_epoch"])
            != (window["source_id"], window["source_epoch"])
            or (
                proven
                and (
                    scope["state"] != "closed"
                    or scope.get("start_sequence", -2) + 1 != window["first_sequence"]
                    or scope.get("end_sequence") != window["last_sequence"]
                )
            )
        ):
            raise CaptureContractError(
                "capture.reconstruction.scope",
                f"{path}.declared_scope",
                "a scope window names a listed scope; a proven one is its [start + 1, end]",
            )
    if run["verdict"] in _COMPLETE_VERDICTS and any(
        scope["state"] != "closed" for scope in scopes.values()
    ):
        raise CaptureContractError(
            "capture.reconstruction.verdict",
            f"{path}.scopes",
            "a complete run needs every scope closed",
        )


def _validate_scope(
    run: Mapping[str, Any], sources: Mapping[Any, Any], path: str
) -> None:
    windows = run["declared_scope"]["windows"]
    for window in windows:
        key = (window["source_id"], window["source_epoch"])
        if key not in sources or window["last_sequence"] < window["first_sequence"]:
            raise CaptureContractError(
                "capture.reconstruction.scope", f"{path}.declared_scope", "bad window"
            )
    _check_run_scopes(run, path)
    for exchange in run["exchanges"]:
        if not any(
            (w["source_id"], w["source_epoch"])
            == (exchange["source_id"], exchange["source_epoch"])
            and w["first_sequence"] <= exchange["source_sequence"] <= w["last_sequence"]
            and w.get("scope_id", exchange.get("scope_id")) == exchange.get("scope_id")
            for w in windows
        ):
            raise CaptureContractError(
                "capture.reconstruction.scope",
                f"{path}.exchanges",
                "every exchange must lie inside a declared window",
            )
    if run["verdict"] not in _COMPLETE_VERDICTS:
        return
    for window in windows:
        if window.get("closed_by") not in ("run_markers", "final_heartbeat"):
            raise CaptureContractError(
                "capture.reconstruction.verdict",
                f"{path}.declared_scope",
                "a complete run needs every window's end proven (closed_by)",
            )
        source = sources[(window["source_id"], window["source_epoch"])]
        # A scope window's bounds are proven by its markers (spec 048 §6): only
        # sequences inside it matter. Other windows also need their neighbours.
        edge = 0 if "scope_id" in window else 1
        low, high = window["first_sequence"] - edge, window["last_sequence"] + edge
        if window["heartbeat_sequence"] < window["last_sequence"] or any(
            first <= high and last >= low for first, last in source["missing_sequences"]
        ):
            raise CaptureContractError(
                "capture.reconstruction.verdict",
                f"{path}.declared_scope",
                "a complete run needs a covering heartbeat and no missing sequence "
                "inside its windows (or adjacent to a window without a scope)",
            )


def _expected_verdict(
    gaps: Sequence[Mapping[str, Any]], checks: Mapping[str, str]
) -> str:
    """Spec 047 §9.7: partial beats unverified beats complete."""

    effects = {gap["effect"] for gap in gaps}
    if "partial" in effects:
        return "partial"
    if "unverified" in effects or "skipped" in checks.values():
        return "unverified"
    return _COMPLETE


def _validate_reconstruction(document: Mapping[str, Any]) -> None:
    sources = _validate_sources(document)
    for run_index, run in enumerate(document["runs"]):
        path = f"$.runs[{run_index}]"
        checks = set(run["checks"].values())
        expected = _expected_verdict(run["gaps"], run["checks"])
        if expected == _COMPLETE and run.get("scopes"):
            # A scoped run claims only the scopes the record holds (decision H5).
            expected = _COMPLETE_OBSERVED
        if run["verdict"] != expected:
            raise CaptureContractError(
                "capture.reconstruction.verdict",
                f"{path}.verdict",
                f"gaps and checks require verdict {expected!r}",
            )
        if expected in _COMPLETE_VERDICTS and "failed" in checks:
            raise CaptureContractError(
                "capture.reconstruction.verdict",
                f"{path}.checks",
                "a failed check must be explained by a gap",
            )
        counts: dict[str, int] = {}
        for gap in run["gaps"]:
            counts[gap["gap_type"]] = counts.get(gap["gap_type"], 0) + 1
            if gap.get("first_sequence", 0) > gap.get("last_sequence", 0):
                raise CaptureContractError(
                    "capture.reconstruction.gap",
                    f"{path}.gaps",
                    "gap range out of order",
                )
        if counts != run["counts"]["gaps_by_type"]:
            raise CaptureContractError(
                "capture.reconstruction.counts",
                f"{path}.counts.gaps_by_type",
                f"declared {run['counts']['gaps_by_type']}, counted {counts}",
            )
        exchanges = run["exchanges"]
        if run["counts"]["exchanges"] != len(exchanges):
            raise CaptureContractError(
                "capture.reconstruction.counts",
                f"{path}.counts.exchanges",
                "count mismatch",
            )
        known = [exchange["exchange_id"] for exchange in exchanges]
        if len(known) != len(set(known)):
            raise CaptureContractError(
                "capture.reconstruction.order",
                f"{path}.exchanges",
                "duplicate exchange_id",
            )
        threaded = [eid for thread in run["threads"] for eid in thread["exchange_ids"]]
        if sorted(threaded) != sorted(known):
            raise CaptureContractError(
                "capture.reconstruction.threads",
                f"{path}.threads",
                "every exchange belongs to exactly one thread",
            )
        for exchange in exchanges:
            continued = exchange.get("continues_exchange_id")
            if continued is not None and continued not in known:
                raise CaptureContractError(
                    "capture.reconstruction.threads",
                    f"{path}.exchanges",
                    "continues_exchange_id must name an exchange in the run",
                )
        _validate_scope(run, sources, path)
        _check_run_state(run, path)
    _validate_scope_verdicts(document, sources)


_DEADLINE_STATES = frozenset({"open", "unterminated", "deadline_uncertain"})


def _check_run_state(run: Mapping[str, Any], path: str) -> None:
    """Spec 050 §3.12 and §9 delta 5: run states, the info-only run_open gap, segments."""
    state = run.get("run_state")
    open_gaps = [g for g in run["gaps"] if g["gap_type"] == "run_open"]
    if any(g["effect"] != "info" for g in open_gaps) or (open_gaps and state != "open"):
        raise CaptureContractError(
            "capture.reconstruction.run_state",
            f"{path}.gaps",
            "run_open is an info gap of an open run; it never counts in the verdict",
        )
    if state is not None and state != "terminated" and run["verdict"] == _COMPLETE:
        raise CaptureContractError(
            "capture.reconstruction.run_state",
            f"{path}.verdict",
            "a run that is not terminated is at best complete_for_observed_scopes",
        )
    if state in _DEADLINE_STATES and "deadline_at" not in run:
        raise CaptureContractError(
            "capture.reconstruction.run_state",
            f"{path}.deadline_at",
            f"run_state {state} has a deadline",
        )
    segments = run.get("segments", [])
    ids = [segment["segment_id"] for segment in segments]
    if len(set(ids)) != len(ids) or any(
        entry != "none" and ref.parse_predecessor(entry) is None
        for segment in segments
        for entry in segment["predecessors"]
    ):
        raise CaptureContractError(
            "capture.reconstruction.segments",
            f"{path}.segments",
            "segment ids are unique and predecessors are exact entries",
        )
    if run["run_id"] in run.get("run_aliases", []):
        raise CaptureContractError(
            "capture.reconstruction.segments",
            f"{path}.run_aliases",
            "a run is not its own alias",
        )


def _validate_scope_verdicts(
    document: Mapping[str, Any], sources: Mapping[Any, Any]
) -> None:
    """Per-scope verdicts (spec 048 §6, decision H5).

    Every scope a reported run lists has exactly one verdict entry with the
    same listing; its verdict follows from its own gaps and checks; each of
    its gaps is also a gap of its run; a complete scope is closed by its own
    markers with no missing sequence inside its window; and a run is never
    better than its worst scope.
    """

    runs = {run["run_id"]: run for run in document["runs"]}
    listed = {
        (run_id, scope["scope_id"]): scope
        for run_id, run in runs.items()
        for scope in run.get("scopes", [])
    }
    seen: set[tuple[str, str]] = set()
    for index, entry in enumerate(document["scopes"]):
        path = f"$.scopes[{index}]"
        key = (entry["run_id"], entry["scope_id"])
        listing = {
            k: v
            for k, v in entry.items()
            if k not in ("run_id", "verdict", "gaps", "checks")
        }
        if key in seen or listed.get(key) != listing:
            raise CaptureContractError(
                "capture.reconstruction.scope",
                path,
                "a scope verdict names a scope its run lists, once, with the same listing",
            )
        seen.add(key)
        expected = _expected_verdict(entry["gaps"], entry["checks"])
        if entry["verdict"] != expected or (
            expected == _COMPLETE and "failed" in entry["checks"].values()
        ):
            raise CaptureContractError(
                "capture.reconstruction.verdict",
                f"{path}.verdict",
                f"the scope's gaps and checks require verdict {expected!r}",
            )
        run = runs[entry["run_id"]]
        if any(gap not in run["gaps"] for gap in entry["gaps"]):
            raise CaptureContractError(
                "capture.reconstruction.scope",
                f"{path}.gaps",
                "every scope gap is a run gap",
            )
        if _RANK[run["verdict"]] < _RANK[entry["verdict"]]:
            raise CaptureContractError(
                "capture.reconstruction.verdict",
                f"$.runs[{list(runs).index(entry['run_id'])}].verdict",
                "a run is never better than its worst scope",
            )
        if expected != _COMPLETE:
            continue
        source = sources.get((entry["source_id"], entry["source_epoch"]))
        start, end = entry.get("start_sequence"), entry.get("end_sequence")
        if (
            entry["state"] != "closed"
            or source is None
            or start is None
            or end is None
            or source["heartbeat_sequence"] < end
            or any(
                max(first, start + 1) <= min(last, end)
                for first, last in source["missing_sequences"]
            )
        ):
            raise CaptureContractError(
                "capture.reconstruction.verdict",
                path,
                "a complete scope is closed by its markers with no missing sequence inside",
            )
    if set(listed) != seen:
        raise CaptureContractError(
            "capture.reconstruction.scope",
            "$.scopes",
            "every listed scope needs a verdict",
        )


def validate_document(
    document: Mapping[str, Any], schemas: Mapping[str, Mapping[str, Any]]
) -> None:
    """Validate one capture-v1 document by its schema_version."""

    version = document.get("schema_version")
    relative = SCHEMAS.get(version) if isinstance(version, str) else None
    if relative is None:
        raise CaptureContractError(
            "capture.document.kind", "$.schema_version", f"unrecognized {version!r}"
        )
    _schema_error(document, schemas[relative])
    if version == "fabric.llm-exchange/v1":
        _validate_exchange(document)
    elif version == "fabric.loss-record/v1":
        _validate_loss(document)
    elif version == "fabric.wire-spool-record/v1":
        _validate_spool(document)
        marker = document.get("marker", {})
        if marker.get("kind") == "manifest":
            _check_manifest_marker(marker, schemas)
    elif version == "fabric.content-log-record/v1":
        _validate_content(document)
    elif version == "fabric.run-reconstruction/v1":
        _validate_reconstruction(document)
    # fabric.capture-manifest-record/v1 is closed by its generated schema; its
    # semantics are the coverage manifest's (validate_coverage_contracts.py).


def validate_digest_fixture(document: Mapping[str, Any], path: Path) -> None:
    """Pin fabric.stitch/v1 canonical bytes and digests for every case."""

    if (
        document.get("schema_version") != "fabric.stitch-digest-fixture/v1"
        or document.get("projection") != "fabric.stitch/v1"
        or not isinstance(document.get("cases"), list)
        or not document["cases"]
    ):
        raise CaptureContractError(
            "capture.digests.shape", str(path), "bad fixture header"
        )
    by_name: dict[str, str] = {}
    for index, case in enumerate(document["cases"]):
        where = f"{path}#cases[{index}]"
        if not isinstance(case, dict) or not {
            "name",
            "api",
            "side",
            "raw",
            "projected",
            "canonical",
            "sha256",
        } <= set(case):
            raise CaptureContractError(
                "capture.digests.shape", where, "incomplete case"
            )
        if canonical_json(case["projected"]) != case["canonical"]:
            raise CaptureContractError(
                "capture.digests.canonical",
                where,
                "canonical_json(projected) != canonical",
            )
        actual = (
            "sha256:"
            + hashlib.sha256(
                case["canonical"].encode("utf-8", "surrogatepass")
            ).hexdigest()
        )
        if actual != case["sha256"]:
            raise CaptureContractError(
                "capture.digests.sha256", where, "digest mismatch"
            )
        if case["name"] in by_name:
            raise CaptureContractError(
                "capture.digests.shape", where, "duplicate case name"
            )
        by_name[case["name"]] = case["sha256"]
    for index, case in enumerate(document["cases"]):
        twin = case.get("same_digest_as")
        if twin is not None and by_name.get(twin) != case["sha256"]:
            raise CaptureContractError(
                "capture.digests.same_as",
                f"{path}#cases[{index}]",
                f"case must hash equal to {twin!r}",
            )


_MODEL_VECTOR_KEYS = frozenset(
    {"schema_version", "rule", "default_allowlist", "suffix_words", "cases"}
)
_RUN_ID_VECTOR_KEYS = frozenset({"schema_version", "rule", "cases"})


def _model_digest(value: str) -> str:
    return (
        "m-" + hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    )


def _run_pseudonym(run_id: str, key: str | None) -> str:
    data = run_id.encode("utf-8", "surrogatepass")
    if key:
        digest = hmac.new(key.encode("utf-8"), data, hashlib.sha256).hexdigest()
    else:
        digest = hashlib.sha256(data).hexdigest()
    return "r-" + digest[:32]


def validate_vector_fixture(document: Mapping[str, Any], path: Path) -> None:
    """Shared test vectors: closed shape, unique names and self-consistent outputs.

    The vectors are what capture, fabricguard and ``fabric.reconstruct`` test
    against (spec 048 §6-§7); this check pins only what follows from a vector
    itself: the ``m-`` digest of a value that is not allowed, and the ``r-``
    pseudonym of a run id.
    """

    kind = document.get("schema_version")
    if kind == "fabric.model-exposure-vectors/v1":
        shape, fields = (
            _MODEL_VECTOR_KEYS,
            {"name", "value", "allowlist", "allowed", "exposed"},
        )
    elif kind == "fabric.run-id-pseudonym-vectors/v1":
        shape, fields = _RUN_ID_VECTOR_KEYS, {"name", "run_id", "key", "pseudonym"}
    else:
        raise CaptureContractError(
            "capture.vectors.shape", str(path), "unknown vector fixture"
        )
    cases = document.get("cases")
    if set(document) != shape or not isinstance(cases, list) or not cases:
        raise CaptureContractError(
            "capture.vectors.shape", str(path), "bad vector fixture"
        )
    names: set[str] = set()
    for index, case in enumerate(cases):
        where = f"{path}#cases[{index}]"
        if not isinstance(case, dict) or set(case) != fields or case["name"] in names:
            raise CaptureContractError(
                "capture.vectors.shape", where, "bad or duplicate case"
            )
        names.add(case["name"])
        if kind == "fabric.model-exposure-vectors/v1":
            value = case["value"]
            wanted = value if case["allowed"] is True else _model_digest(str(value))
            if not isinstance(value, str) or case["exposed"] != wanted:
                raise CaptureContractError(
                    "capture.vectors.model",
                    where,
                    "exposed value disagrees with allowed",
                )
        elif case["pseudonym"] != _run_pseudonym(case["run_id"], case["key"]):
            raise CaptureContractError(
                "capture.vectors.run_id", where, "pseudonym mismatch"
            )


def _golden_location(
    backend: Mapping[str, Any], tenant: str, object_id: str
) -> tuple[str, str, str]:
    """``(object key, descriptor key, ref)`` of the shared store layout (spec 048 §4)."""

    relative = f"{tenant}/evidence/{object_id}"
    meta = f"{tenant}/evidence/meta/{object_id}.json"
    if backend.get("kind") == "file":
        directory = str(backend.get("directory", ""))
        if not directory.startswith("/") or directory.endswith("/"):
            raise CaptureContractError(
                "capture.golden.layout", "$.backend", "bad directory"
            )
        return relative, meta, f"file://{directory}/{relative}"
    if backend.get("kind") == "s3":
        prefix = str(backend.get("prefix", ""))
        if not prefix.endswith("/") or prefix.startswith("/"):
            raise CaptureContractError(
                "capture.golden.layout", "$.backend", "bad prefix"
            )
        key = prefix + relative
        return key, prefix + meta, f"s3://{backend.get('bucket')}/{key}"
    raise CaptureContractError(
        "capture.golden.layout", "$.backend", "unknown backend kind"
    )


def validate_golden_fixture(
    document: Mapping[str, Any], schemas: Mapping[str, Mapping[str, Any]], path: Path
) -> None:
    """Pin the exact descriptor bytes and keys a content writer produces."""

    if document.get("schema_version") != "fabric.content-descriptor-golden/v1" or set(
        document
    ) != {
        "schema_version",
        "content_log_record",
        "backend",
        "object_key",
        "descriptor_key",
        "ref",
        "descriptor_json",
    }:
        raise CaptureContractError(
            "capture.golden.shape", str(path), "bad golden fixture"
        )
    record = document["content_log_record"]
    validate_document(record, schemas)
    attributes = record["attributes"]
    expected = _golden_location(
        document["backend"], attributes["tenant_id"], attributes["object_id"]
    )
    if expected != (
        document["object_key"],
        document["descriptor_key"],
        document["ref"],
    ):
        raise CaptureContractError(
            "capture.golden.layout", str(path), "store layout differs"
        )
    descriptor = {k: v for k, v in attributes.items() if k != "event_class"}
    descriptor.update(encoding="binary", ref=document["ref"])
    canonical = json.dumps(descriptor, ensure_ascii=False, sort_keys=True) + "\n"
    if canonical != document["descriptor_json"]:
        raise CaptureContractError(
            "capture.golden.descriptor",
            str(path),
            "descriptor_json is not the writer's bytes",
        )


def _artifact(root: Path, relative: object) -> Path:
    if not isinstance(relative, str) or not relative:
        raise CaptureContractError("capture.manifest.path", str(relative), "empty path")
    posix = PurePosixPath(relative)
    if posix.is_absolute() or posix.as_posix() != relative or ".." in posix.parts:
        raise CaptureContractError("capture.manifest.path", relative, "unsafe path")
    path = root.joinpath(*posix.parts)
    cursor = root
    for part in posix.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise CaptureContractError(
                "capture.manifest.path", relative, "symlinked artifact"
            )
    if not path.is_file():
        raise CaptureContractError(
            "capture.manifest.missing", relative, "missing artifact"
        )
    return path


def _pinned_records(root: Path) -> list[dict[str, Any]]:
    manifest = _load(root / "manifest.json")
    if set(manifest) != {"contract", "version", "digest_scope", "artifacts"}:
        raise CaptureContractError(
            "capture.manifest.shape", str(root), "closed manifest fields"
        )
    if (manifest["contract"], manifest["version"]) != IDENTITY or (
        manifest["digest_scope"] != "exact_file_bytes"
    ):
        raise CaptureContractError(
            "capture.manifest.identity", str(root), "wrong identity"
        )
    records = manifest["artifacts"]
    if not isinstance(records, list) or not records:
        raise CaptureContractError(
            "capture.manifest.artifacts", str(root), "empty artifacts"
        )
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "path",
            "sha256",
            "expectation",
            "expected_error",
        }:
            raise CaptureContractError(
                "capture.manifest.record", str(root), "closed fields"
            )
        expectation = record["expectation"]
        error = record["expected_error"]
        if (
            expectation not in _EXPECTATIONS
            or ((expectation == "invalid") != (isinstance(error, str) and bool(error)))
            or (expectation != "invalid" and error is not None)
        ):
            raise CaptureContractError(
                "capture.manifest.record",
                str(record["path"]),
                "bad expectation/error binding",
            )
        relative = record["path"]
        if relative in seen:
            raise CaptureContractError(
                "capture.manifest.path", relative, "duplicate path"
            )
        seen.add(relative)
        if record["sha256"] != _file_sha256(_artifact(root, relative)):
            raise CaptureContractError(
                "capture.manifest.digest",
                relative,
                "SHA-256 does not match exact file bytes",
            )
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*.json")
        if path.name != "manifest.json"
    }
    if actual != seen:
        raise CaptureContractError(
            "capture.manifest.coverage",
            str(root),
            f"unpinned JSON: {sorted(actual ^ seen)}",
        )
    return records


def _check_manifest_marker(
    marker: Mapping[str, Any], schemas: Mapping[str, Mapping[str, Any]]
) -> None:
    """A spooled manifest carries a valid manifest span and no position (spec 049 §2.8)."""

    record = {
        "schema_version": "fabric.capture-manifest-record/v1",
        "name": "fabric.capture_manifest",
        "attributes": marker["manifest"],
    }
    try:
        _schema_error(record, schemas[SCHEMAS["fabric.capture-manifest-record/v1"]])
    except CaptureContractError as exc:
        raise CaptureContractError(
            "capture.marker.manifest", "$.marker.manifest", exc.message
        ) from exc
    if "event_id" in marker and marker["event_id"] != marker["manifest"].get(
        "fabric.event_id"
    ):
        raise CaptureContractError(
            "capture.marker.manifest",
            "$.marker.event_id",
            "a manifest marker's event_id is the manifest's own event_id",
        )
    if (
        marker["last_sequence"]
        != marker["manifest"]["fabric.manifest.after_source_sequence"]
    ):
        raise CaptureContractError(
            "capture.marker.manifest",
            "$.marker.last_sequence",
            "a manifest marker's last_sequence is the manifest's after_source_sequence",
        )


def _check_marker_definitions(schemas: Mapping[str, Mapping[str, Any]]) -> None:
    """Heartbeat spans and spool markers define every run-marker key identically."""

    heartbeat = schemas[SCHEMAS["fabric.loss-record/v1"]]["oneOf"][1]["properties"]
    spool = schemas[SCHEMAS["fabric.wire-spool-record/v1"]]["oneOf"]
    marker = next(
        branch["properties"]["marker"]["properties"]
        for branch in spool
        if branch["properties"]["record_kind"] == {"const": "marker"}
    )
    for key in _MARKER_KEYS:
        if key not in heartbeat or heartbeat.get(key) != marker.get(key):
            raise CaptureContractError(
                "capture.marker.definition",
                key,
                "run-marker key differs between loss-record and spool-record",
            )


def validate_capture_contracts(repo_root: Path) -> list[str]:
    """Validate every pinned capture-v1 artifact and negative fixture."""

    root = (repo_root / ROOT).resolve()
    records = _pinned_records(root)
    schemas: dict[str, Mapping[str, Any]] = {}
    for record in records:
        if record["expectation"] == "schema":
            schema = _load(root / record["path"])
            Draft202012Validator.check_schema(schema)
            schemas[record["path"]] = schema
    missing = set(SCHEMAS.values()) - set(schemas)
    if missing:
        raise CaptureContractError(
            "capture.manifest.schemas", str(root), f"missing {missing}"
        )
    _check_marker_definitions(schemas)
    validated: list[str] = []
    for record in records:
        path = root / record["path"]
        expectation = record["expectation"]
        if expectation == "digests":
            validate_digest_fixture(_load(path), path)
        elif expectation == "golden":
            validate_golden_fixture(_load(path), schemas, path)
        elif expectation == "vectors":
            validate_vector_fixture(_load(path), path)
        elif expectation == "valid":
            validate_document(_load(path), schemas)
        elif expectation == "invalid":
            try:
                validate_document(_load(path), schemas)
            except CaptureContractError as exc:
                if exc.code != record["expected_error"]:
                    raise CaptureContractError(
                        "capture.fixture.wrong_error",
                        record["path"],
                        f"expected {record['expected_error']}, got {exc.code}",
                    ) from exc
            else:
                raise CaptureContractError(
                    "capture.fixture.accepted_invalid",
                    record["path"],
                    "invalid fixture accepted",
                )
        validated.append(f"capture/{record['path']}")
    return validated


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[2]
    )
    args = parser.parse_args(argv)
    try:
        validated = validate_capture_contracts(args.repo_root)
    except CaptureContractError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"validated {len(validated)} pinned capture artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
