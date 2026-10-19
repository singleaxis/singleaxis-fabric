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

ROOT = Path("contracts/capture/v1")
IDENTITY = ("singleaxis.fabric.capture", "1.1.0")
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
)
_INT64_MAX = 9223372036854775807
_EXPECTATIONS = frozenset(
    {"schema", "valid", "invalid", "digests", "golden", "vectors"}
)
_RUN_MARKERS = frozenset({"run_start", "run_end"})
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
    bodies = [document["request"]] + (
        [document["response"]] if "response" in document else []
    )
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
        _check_marker(document, document["last_sequence"], "$")
        return
    _check_range(document)


def _check_marker(marker: Mapping[str, Any], last_sequence: int, path: str) -> None:
    """Spec 049 run-marker rules a schema cannot express (sections 2.10, 2.12)."""

    predecessors = marker.get("predecessors", [])
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


def _check_descriptor(descriptor: Mapping[str, Any], path: str) -> None:
    """Representation, status, transformations and source digest must agree (spec 048 §3)."""

    truncated = descriptor["representation"] == "truncated"
    if truncated:
        consistent = (
            descriptor["status"] == "truncated"
            and descriptor["transformations"] == ["truncate"]
            and "source_sha256" not in descriptor
            and descriptor["source_byte_length"] > descriptor["stored_byte_length"]
        )
    else:
        consistent = (
            descriptor["status"] == "stored"
            and descriptor["transformations"] == []
            and descriptor.get("source_sha256") == descriptor["stored_sha256"]
            and descriptor["source_byte_length"] == descriptor["stored_byte_length"]
        )
    if (
        descriptor["representation"] == "partial"
        and descriptor["role"] != "model.exchange.response"
    ):
        consistent = False
    if not consistent:
        raise CaptureContractError(
            "capture.content.representation",
            path,
            "representation, status, transformations and source fields disagree",
        )


def _validate_content(document: Mapping[str, Any]) -> None:
    attributes, body = document["attributes"], document["body"]
    if (
        body["byte_length"] != attributes["stored_byte_length"]
        or body["sha256"] != attributes["stored_sha256"]
    ):
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
            document["marker"], document["marker"]["last_sequence"], "$.marker"
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
    offset, roles = 0, set()
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
            "stored_byte_length": body["length"],
        }
        if body["offset"] != offset or any(
            descriptor[k] != v for k, v in expected.items()
        ):
            raise _spool_inconsistent(
                where, "bodies must be contiguous and match the span"
            )
        role = descriptor["role"]
        if role in roles or attrs.get(_ROLE_REF[role]) != descriptor["object_id"]:
            raise _spool_inconsistent(
                where, "one body per role, named by the span's ref"
            )
        roles.add(role)
        offset += body["length"]
    for role, key in _ROLE_REF.items():
        if key in attrs and role not in roles:
            raise _spool_inconsistent("$.bodies", f"{key} names no spooled body")


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
    _validate_scope_verdicts(document, sources)


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
