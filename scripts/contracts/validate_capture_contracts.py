# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Validate the draft LLM wire-capture contracts (contracts/capture/v1, spec 042).

JSON Schema handles closed shapes. The semantic checks below reject what a
schema cannot express: a gateway record claiming exact wire bytes, digest
lists that disagree with their counts, inconsistent truncation, cumulative
loss totals that do not add up, and a reconstruction verdict stronger than
its own gaps and checks allow. The stitch-digest fixture pins the
``fabric.stitch/v1`` canonical bytes and SHA-256 every implementation must
reproduce. This validator does not claim any runtime currently emits these
documents.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path("contracts/capture/v1")
IDENTITY = ("singleaxis.fabric.capture", "1.0.0")
SCHEMAS = {
    "fabric.llm-exchange/v1": "schema/llm-exchange-v1.schema.json",
    "fabric.loss-record/v1": "schema/loss-record-v1.schema.json",
    "fabric.run-reconstruction/v1": "schema/run-reconstruction-v1.schema.json",
}
_EXPECTATIONS = frozenset({"schema", "valid", "invalid", "digests"})
_STORED = frozenset({"stored", "truncated"})


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
        raise CaptureContractError("capture.document.unreadable", str(path), str(exc)) from exc
    if not isinstance(value, dict):
        raise CaptureContractError("capture.document.not_object", str(path), "expected object")
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
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        first = errors[0]
        raise CaptureContractError(
            "capture.schema",
            "$" + "".join(f".{part}" for part in first.absolute_path),
            first.message,
        )


def _tenant_bound_ref(ref: str, tenant_id: str) -> bool:
    parsed = urlsplit(ref)
    segments = parsed.path.split("/")
    return (
        parsed.scheme in {"s3", "gs", "file"}
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
        and "%" not in ref
        and tenant_id in segments[:-1]
        and not any(part in {".", ".."} for part in segments)
    )


def _validate_body(body: Mapping[str, Any], fidelity: str, tenant_id: str, path: str) -> None:
    representation = body["representation"]
    if fidelity == "gateway_normalized" and (
        representation in {"exact", "partial", "truncated"} or "source_sha256" in body
    ):
        raise CaptureContractError(
            "capture.exchange.false_exact",
            path,
            "gateway_normalized bodies are canonicalized; they never observed wire bytes",
        )
    if fidelity == "exact_wire" and representation == "canonicalized":
        raise CaptureContractError(
            "capture.exchange.false_exact",
            path,
            "exact_wire bodies store transmitted bytes, never a canonical re-serialization",
        )
    if representation == "exact" and body["status"] == "stored" and (
        body["source_sha256"] != body["stored_sha256"]
        or body["source_byte_length"] != body["stored_byte_length"]
    ):
        raise CaptureContractError(
            "capture.exchange.false_exact", path, "exact source and stored bytes must match"
        )
    if body["status"] == "truncated" and body["source_byte_length"] <= body["stored_byte_length"]:
        raise CaptureContractError(
            "capture.exchange.truncation",
            path,
            "a truncated body must have observed more bytes than it stored",
        )
    if "ref" in body and not _tenant_bound_ref(body["ref"], tenant_id):
        raise CaptureContractError(
            "capture.exchange.ref", f"{path}.ref", "ref must be credential-free and tenant-bound"
        )


def _validate_exchange(document: Mapping[str, Any]) -> None:
    fidelity = document["fidelity"]
    tenant_id = document["tenant_id"]
    bodies: list[Mapping[str, Any]] = []
    for side in ("request", "response"):
        section = document[side]
        if len(section["message_digests"]) != section["message_count"]:
            raise CaptureContractError(
                "capture.exchange.count",
                f"$.{side}.message_digests",
                "message_digests length must equal message_count",
            )
        roles = section.get("message_roles")
        if roles is not None and len(roles) != section["message_count"]:
            raise CaptureContractError(
                "capture.exchange.count",
                f"$.{side}.message_roles",
                "message_roles length must equal message_count",
            )
        if "body" in section:
            _validate_body(section["body"], fidelity, tenant_id, f"$.{side}.body")
            bodies.append(section["body"])
    if fidelity == "gateway_normalized" and document["source"]["component"] != "gateway":
        raise CaptureContractError(
            "capture.exchange.component", "$.source.component", "gateway records need gateway"
        )
    if fidelity == "exact_wire" and document["source"]["component"] != "wire":
        raise CaptureContractError(
            "capture.exchange.component", "$.source.component", "exact_wire records need wire"
        )
    ids = [call["id"] for call in document["response"]["tool_calls"]]
    if len(ids) != len(set(ids)):
        raise CaptureContractError(
            "capture.exchange.tool_calls", "$.response.tool_calls", "tool call ids must be unique"
        )
    truncated = any(body["status"] == "truncated" for body in bodies)
    if truncated != document["capture"]["truncated"]:
        raise CaptureContractError(
            "capture.exchange.truncation",
            "$.capture.truncated",
            "capture.truncated must be true exactly when a body is truncated",
        )
    stored = [body["status"] in _STORED for body in bodies]
    expected = "stored" if all(stored) else ("failed" if not any(stored) else "partial")
    if document["capture"]["store_status"] != expected:
        raise CaptureContractError(
            "capture.exchange.store_status",
            "$.capture.store_status",
            f"store_status must be {expected!r} for the listed body statuses",
        )


def _validate_loss(document: Mapping[str, Any]) -> None:
    cumulative = document["cumulative"]
    if sum(cumulative["by_reason"].values()) != cumulative["total"]:
        raise CaptureContractError(
            "capture.loss.cumulative",
            "$.cumulative",
            "cumulative.total must equal the sum of cumulative.by_reason",
        )
    if document["kind"] == "loss":
        if cumulative["by_reason"].get(document["reason"], 0) < document["count"]:
            raise CaptureContractError(
                "capture.loss.cumulative",
                "$.cumulative.by_reason",
                "cumulative count for the reason cannot be below this record's count",
            )
        if len(document["affected"]) > document["count"]:
            raise CaptureContractError(
                "capture.loss.affected", "$.affected", "more affected entries than lost items"
            )
    own = document["source"]["source_sequence"]
    if document["high_water_sequence"] < own:
        raise CaptureContractError(
            "capture.loss.high_water",
            "$.high_water_sequence",
            "high-water sequence cannot be below the record's own sequence",
        )
    for index, item in enumerate(document["affected"]):
        if item["source_sequence"] >= own:
            raise CaptureContractError(
                "capture.loss.affected",
                f"$.affected[{index}].source_sequence",
                "a loss record can only report sequences allocated before it",
            )


def _validate_reconstruction(document: Mapping[str, Any]) -> None:
    for run_index, run in enumerate(document["runs"]):
        path = f"$.runs[{run_index}]"
        effects = {gap["effect"] for gap in run["gaps"]}
        checks = set(run["checks"].values())
        if "partial" in effects:
            expected = "partial"
        elif "unverified" in effects or "skipped" in checks:
            expected = "unverified"
        else:
            expected = "complete_for_declared_scope"
        if run["verdict"] != expected:
            raise CaptureContractError(
                "capture.reconstruction.verdict",
                f"{path}.verdict",
                f"gaps and checks require verdict {expected!r}",
            )
        if expected == "complete_for_declared_scope" and "failed" in checks:
            raise CaptureContractError(
                "capture.reconstruction.verdict",
                f"{path}.checks",
                "a failed check must be explained by a gap",
            )
        if run["verdict"] == "complete_for_declared_scope" and run["declared_scope"]["bytes"] and (
            run["checks"]["bytes"] != "passed"
        ):
            raise CaptureContractError(
                "capture.reconstruction.verdict",
                f"{path}.checks.bytes",
                "a bytes-scoped complete verdict requires verified bytes",
            )
        counts: dict[str, int] = {}
        for gap in run["gaps"]:
            counts[gap["gap_type"]] = counts.get(gap["gap_type"], 0) + 1
        if counts != run["counts"]["gaps_by_type"]:
            raise CaptureContractError(
                "capture.reconstruction.counts",
                f"{path}.counts.gaps_by_type",
                f"declared {run['counts']['gaps_by_type']}, counted {counts}",
            )
        exchanges = run["exchanges"]
        if run["counts"]["exchanges"] != len(exchanges):
            raise CaptureContractError(
                "capture.reconstruction.counts", f"{path}.counts.exchanges", "count mismatch"
            )
        sequences = [exchange["run_sequence"] for exchange in exchanges]
        if sequences != sorted(set(sequences)):
            raise CaptureContractError(
                "capture.reconstruction.order",
                f"{path}.exchanges",
                "exchanges must be unique and ordered by run_sequence",
            )
        known = {exchange["exchange_id"] for exchange in exchanges}
        threaded = [eid for thread in run["threads"] for eid in thread["exchange_ids"]]
        if sorted(threaded) != sorted(known) or len(threaded) != len(set(threaded)):
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
    else:
        _validate_reconstruction(document)


def validate_digest_fixture(document: Mapping[str, Any], path: Path) -> None:
    """Pin fabric.stitch/v1 canonical bytes and digests for every case."""

    if (
        document.get("schema_version") != "fabric.stitch-digest-fixture/v1"
        or document.get("projection") != "fabric.stitch/v1"
        or not isinstance(document.get("cases"), list)
        or not document["cases"]
    ):
        raise CaptureContractError("capture.digests.shape", str(path), "bad fixture header")
    by_name: dict[str, str] = {}
    for index, case in enumerate(document["cases"]):
        where = f"{path}#cases[{index}]"
        if not isinstance(case, dict) or not {
            "name", "api", "side", "raw", "projected", "canonical", "sha256"
        } <= set(case):
            raise CaptureContractError("capture.digests.shape", where, "incomplete case")
        if canonical_json(case["projected"]) != case["canonical"]:
            raise CaptureContractError(
                "capture.digests.canonical", where, "canonical_json(projected) != canonical"
            )
        actual = "sha256:" + hashlib.sha256(
            case["canonical"].encode("utf-8", "surrogatepass")
        ).hexdigest()
        if actual != case["sha256"]:
            raise CaptureContractError("capture.digests.sha256", where, "digest mismatch")
        if case["name"] in by_name:
            raise CaptureContractError("capture.digests.shape", where, "duplicate case name")
        by_name[case["name"]] = case["sha256"]
    for index, case in enumerate(document["cases"]):
        twin = case.get("same_digest_as")
        if twin is not None and by_name.get(twin) != case["sha256"]:
            raise CaptureContractError(
                "capture.digests.same_as",
                f"{path}#cases[{index}]",
                f"case must hash equal to {twin!r}",
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
            raise CaptureContractError("capture.manifest.path", relative, "symlinked artifact")
    if not path.is_file():
        raise CaptureContractError("capture.manifest.missing", relative, "missing artifact")
    return path


def _pinned_records(root: Path) -> list[dict[str, Any]]:
    manifest = _load(root / "manifest.json")
    if set(manifest) != {"contract", "version", "digest_scope", "artifacts"}:
        raise CaptureContractError("capture.manifest.shape", str(root), "closed manifest fields")
    if (manifest["contract"], manifest["version"]) != IDENTITY or (
        manifest["digest_scope"] != "exact_file_bytes"
    ):
        raise CaptureContractError("capture.manifest.identity", str(root), "wrong identity")
    records = manifest["artifacts"]
    if not isinstance(records, list) or not records:
        raise CaptureContractError("capture.manifest.artifacts", str(root), "empty artifacts")
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "path", "sha256", "expectation", "expected_error"
        }:
            raise CaptureContractError("capture.manifest.record", str(root), "closed fields")
        expectation = record["expectation"]
        error = record["expected_error"]
        if expectation not in _EXPECTATIONS or (
            (expectation == "invalid") != (isinstance(error, str) and bool(error))
        ) or (expectation != "invalid" and error is not None):
            raise CaptureContractError(
                "capture.manifest.record", str(record["path"]), "bad expectation/error binding"
            )
        relative = record["path"]
        if relative in seen:
            raise CaptureContractError("capture.manifest.path", relative, "duplicate path")
        seen.add(relative)
        if record["sha256"] != _file_sha256(_artifact(root, relative)):
            raise CaptureContractError(
                "capture.manifest.digest", relative, "SHA-256 does not match exact file bytes"
            )
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*.json")
        if path.name != "manifest.json"
    }
    if actual != seen:
        raise CaptureContractError(
            "capture.manifest.coverage", str(root), f"unpinned JSON: {sorted(actual ^ seen)}"
        )
    return records


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
        raise CaptureContractError("capture.manifest.schemas", str(root), f"missing {missing}")
    validated: list[str] = []
    for record in records:
        path = root / record["path"]
        expectation = record["expectation"]
        if expectation == "digests":
            validate_digest_fixture(_load(path), path)
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
                    "capture.fixture.accepted_invalid", record["path"], "invalid fixture accepted"
                )
        validated.append(f"capture/{record['path']}")
    return validated


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
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
