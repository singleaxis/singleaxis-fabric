# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Validate Fabric's pinned Capture -> Protect -> Deliver contracts.

JSON Schema closes and versions every document. These checks enforce the
cross-document and sequence invariants that JSON Schema cannot express.
Digests are SHA-256 over exact file bytes; no JSON canonicalization is claimed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from jsonschema import Draft202012Validator, FormatChecker


@dataclass(frozen=True)
class DataPlaneContractError(ValueError):
    """Stable, automation-safe validation failure."""

    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.path}: {self.message}"


CONTRACTS = {
    "activity": {
        "root": Path("contracts/activity/v2"),
        "identity": ("singleaxis.fabric.activity", "2.0.0"),
    },
    "privacy": {
        "root": Path("contracts/privacy/v1"),
        "identity": ("singleaxis.fabric.privacy", "1.0.0"),
    },
    "delivery": {
        "root": Path("contracts/delivery/v1"),
        "identity": ("singleaxis.fabric.delivery", "1.0.0"),
    },
}


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DataPlaneContractError("data-plane.document.unreadable", str(path), str(exc)) from exc
    if not isinstance(value, dict):
        raise DataPlaneContractError(
            "data-plane.document.not_object", str(path), "document must be a JSON object"
        )
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _schema_path(parts: Iterable[object]) -> str:
    rendered = "$"
    for part in parts:
        rendered += f"[{part}]" if isinstance(part, int) else f".{part}"
    return rendered


def _validate_schema(document: Mapping[str, Any], schema: Mapping[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        error = errors[0]
        raise DataPlaneContractError(
            "data-plane.schema.invalid", _schema_path(error.absolute_path), error.message
        )


def validate_activity_sequence(
    document: Mapping[str, Any], schema: Mapping[str, Any]
) -> None:
    """Validate one activity sequence, including causal and source ordering."""

    _validate_schema(document, schema)
    events = document["events"]
    event_ids: set[str] = set()
    for index, event in enumerate(events):
        event_id = event["event_id"]
        if event_id in event_ids:
            raise DataPlaneContractError(
                "activity.event_id.duplicate",
                f"$.events[{index}].event_id",
                "event_id must be unique within a sequence",
            )
        event_ids.add(event_id)

    graph: dict[str, list[str]] = {}
    for index, event in enumerate(events):
        event_id = event["event_id"]
        internal = [
            reference["event_id"]
            for reference in event["correlation"]["causal_references"]
            if reference["scope"] == "sequence"
        ]
        if event_id in internal:
            raise DataPlaneContractError(
                "activity.causality.self_reference",
                f"$.events[{index}].correlation.causal_references",
                "an event cannot causally reference itself",
            )
        graph[event_id] = [reference for reference in internal if reference in event_ids]

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(event_id: str) -> None:
        if event_id in visiting:
            raise DataPlaneContractError(
                "activity.causality.cycle", "$.events", "internal causal references form a cycle"
            )
        if event_id in visited:
            return
        visiting.add(event_id)
        for dependency in graph[event_id]:
            visit(dependency)
        visiting.remove(event_id)
        visited.add(event_id)

    for event_id in graph:
        visit(event_id)

    source_positions: dict[str, int] = {}
    earlier_event_ids: set[str] = set()

    for index, event in enumerate(events):
        event_id = event["event_id"]
        causal_ids = [
            reference["event_id"]
            for reference in event["correlation"]["causal_references"]
            if reference["scope"] == "sequence"
        ]
        unknown = [causal_id for causal_id in causal_ids if causal_id not in earlier_event_ids]
        if unknown:
            raise DataPlaneContractError(
                "activity.causality.not_earlier",
                f"$.events[{index}].correlation.causal_references",
                f"causal references must identify earlier events: {unknown}",
            )

        source_id = event["source"]["source_id"]
        sequence = event["source_sequence"]
        previous = source_positions.get(source_id)
        if previous is not None and sequence <= previous:
            raise DataPlaneContractError(
                "activity.source_sequence.not_increasing",
                f"$.events[{index}].source_sequence",
                f"source sequence {sequence} must be greater than {previous}",
            )
        source_positions[source_id] = sequence
        earlier_event_ids.add(event_id)


def validate_privacy_assertion(
    document: Mapping[str, Any], schema: Mapping[str, Any]
) -> None:
    """Validate one export privacy processor assertion."""

    _validate_schema(document, schema)
    decision = document["decision"]
    if decision["export_allowed"] and decision["prohibited_content_detected"]:
        raise DataPlaneContractError(
            "privacy.prohibited_content.export_allowed",
            "$.decision",
            "an assertion cannot approve export after prohibited content was detected",
        )


def _repo_artifact(repo_root: Path, relative: object) -> Path:
    if not isinstance(relative, str) or not relative:
        raise DataPlaneContractError(
            "data-plane.artifact.invalid_path", str(relative), "artifact path must be non-empty"
        )
    candidate = PurePosixPath(relative)
    if (
        candidate.is_absolute()
        or ".." in candidate.parts
        or "." in candidate.parts
        or not candidate.parts
        or candidate.parts[0] != "contracts"
    ):
        raise DataPlaneContractError(
            "data-plane.artifact.invalid_path",
            relative,
            "artifact must be a normalized repository-relative contracts path",
        )
    resolved = repo_root.joinpath(*candidate.parts)
    if not resolved.is_file() or resolved.is_symlink():
        raise DataPlaneContractError(
            "data-plane.artifact.missing", relative, "pinned regular file does not exist"
        )
    return resolved


def _iso8601(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate_delivery_evidence(
    document: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    repo_root: Path,
    activity_schema: Mapping[str, Any],
    privacy_schema: Mapping[str, Any],
) -> None:
    """Validate delivery progression and its payload/privacy bindings."""

    _validate_schema(document, schema)
    batch = document["batch"]
    payload_record = batch["payload"]
    payload_path = _repo_artifact(repo_root, payload_record["artifact"])
    if _sha256(payload_path) != payload_record["sha256"]:
        raise DataPlaneContractError(
            "delivery.payload.digest_mismatch",
            "$.batch.payload.sha256",
            "payload digest does not match exact artifact bytes",
        )
    payload = _load_json(payload_path)
    validate_activity_sequence(payload, activity_schema)
    payload_event_ids = [event["event_id"] for event in payload["events"]]
    if batch["event_ids"] != payload_event_ids:
        raise DataPlaneContractError(
            "delivery.batch.event_binding",
            "$.batch.event_ids",
            "batch event IDs must exactly match payload event order",
        )

    actual_ranges: dict[str, list[int]] = {}
    for event in payload["events"]:
        actual_ranges.setdefault(event["source"]["source_id"], []).append(event["source_sequence"])
    declared_ranges: dict[str, tuple[int, int]] = {}
    for index, record in enumerate(batch["source_ranges"]):
        if record["first_sequence"] > record["last_sequence"]:
            raise DataPlaneContractError(
                "delivery.batch.source_range_invalid",
                f"$.batch.source_ranges[{index}]",
                "first_sequence must be less than or equal to last_sequence",
            )
        if record["source_id"] in declared_ranges:
            raise DataPlaneContractError(
                "delivery.batch.source_range_duplicate",
                f"$.batch.source_ranges[{index}].source_id",
                "each source may appear in exactly one range",
            )
        declared_ranges[record["source_id"]] = (
            record["first_sequence"],
            record["last_sequence"],
        )
    expected_ranges = {
        source_id: (sequences[0], sequences[-1])
        for source_id, sequences in actual_ranges.items()
    }
    if declared_ranges != expected_ranges:
        raise DataPlaneContractError(
            "delivery.batch.source_range_binding",
            "$.batch.source_ranges",
            "declared source ranges must exactly match the ordered payload",
        )

    privacy_record = batch["privacy_assertion"]
    privacy_path = _repo_artifact(repo_root, privacy_record["artifact"])
    if _sha256(privacy_path) != privacy_record["sha256"]:
        raise DataPlaneContractError(
            "delivery.privacy.digest_mismatch",
            "$.batch.privacy_assertion.sha256",
            "privacy assertion digest does not match exact artifact bytes",
        )
    privacy = _load_json(privacy_path)
    validate_privacy_assertion(privacy, privacy_schema)
    if privacy_record["assertion_id"] != privacy["assertion_id"]:
        raise DataPlaneContractError(
            "delivery.privacy.assertion_binding",
            "$.batch.privacy_assertion.assertion_id",
            "referenced privacy assertion ID does not match the assertion",
        )
    if privacy["batch_id"] != batch["batch_id"]:
        raise DataPlaneContractError(
            "delivery.privacy.batch_binding",
            "$.batch.batch_id",
            "privacy assertion is bound to a different batch",
        )
    if privacy["protected_payload_sha256"] != payload_record["sha256"]:
        raise DataPlaneContractError(
            "delivery.privacy.payload_binding",
            "$.batch.payload.sha256",
            "privacy assertion is bound to a different protected payload digest",
        )
    if privacy["output_event_ids"] != batch["event_ids"]:
        raise DataPlaneContractError(
            "delivery.privacy.event_binding",
            "$.batch.event_ids",
            "privacy assertion output events must exactly match the batch",
        )

    stages = document["stages"]
    canonical_stages = [
        "queued",
        "transmitted",
        "destination.accepted",
        "destination.durably_persisted",
    ]
    stage_names = [stage["stage"] for stage in stages]
    if stage_names != canonical_stages[: len(stage_names)]:
        raise DataPlaneContractError(
            "delivery.stage.sequence",
            "$.stages",
            "delivery stages must be a distinct ordered prefix of the delivery lifecycle",
        )
    stage_ids = [stage["stage_event_id"] for stage in stages]
    if len(stage_ids) != len(set(stage_ids)):
        raise DataPlaneContractError(
            "delivery.stage_event_id.duplicate",
            "$.stages",
            "stage event IDs must be unique",
        )
    times = [_iso8601(stage["recorded_at"]) for stage in stages]
    if times != sorted(times):
        raise DataPlaneContractError(
            "delivery.stage.time_regression",
            "$.stages",
            "delivery stage timestamps must not regress",
        )

    expected_roles = {
        "queued": "fabric_node",
        "transmitted": "fabric_node",
        "destination.accepted": "destination",
        "destination.durably_persisted": "destination",
    }
    for index, stage in enumerate(stages):
        name = stage["stage"]
        if stage["actor"]["role"] != expected_roles[name]:
            raise DataPlaneContractError(
                "delivery.stage.actor_role",
                f"$.stages[{index}].actor.role",
                f"{name} must be asserted by {expected_roles[name]}",
            )
        if name in {"queued", "transmitted"} and (
            "acknowledgement" in stage or "destination_proof" in stage
        ):
            raise DataPlaneContractError(
                "delivery.stage.untrusted_evidence",
                f"$.stages[{index}]",
                "Fabric Node stages cannot carry destination evidence",
            )
        if name == "destination.accepted":
            acknowledgement = stage.get("acknowledgement")
            if (
                not acknowledgement
                or acknowledgement["payload_sha256"] != payload_record["sha256"]
                or acknowledgement["batch_id"] != batch["batch_id"]
                or acknowledgement["issuer_destination_id"] != batch["destination_id"]
                or "destination_proof" in stage
            ):
                raise DataPlaneContractError(
                    "delivery.destination.acknowledgement",
                    f"$.stages[{index}]",
                    "destination acceptance requires an acknowledgement bound to destination, batch, and payload",
                )
            if stage["actor"]["actor_id"] != batch["destination_id"]:
                raise DataPlaneContractError(
                    "delivery.destination.identity",
                    f"$.stages[{index}].actor.actor_id",
                    "delivery acknowledgement must come from the configured destination",
                )
        if name == "destination.durably_persisted":
            proof = stage.get("destination_proof")
            if not proof or "acknowledgement" in stage:
                raise DataPlaneContractError(
                    "delivery.persistence.proof_missing",
                    f"$.stages[{index}]",
                    "durable persistence requires destination-issued proof",
                )
            if (
                stage["actor"]["actor_id"] != batch["destination_id"]
                or proof["issuer_destination_id"] != batch["destination_id"]
            ):
                raise DataPlaneContractError(
                    "delivery.persistence.not_destination_issued",
                    f"$.stages[{index}].destination_proof",
                    "only the configured destination may prove durable persistence",
                )
            if proof["payload_sha256"] != payload_record["sha256"]:
                raise DataPlaneContractError(
                    "delivery.persistence.payload_binding",
                    f"$.stages[{index}].destination_proof.payload_sha256",
                    "persistence proof must bind the batch payload digest",
                )
            if proof["batch_id"] != batch["batch_id"]:
                raise DataPlaneContractError(
                    "delivery.persistence.batch_binding",
                    f"$.stages[{index}].destination_proof.batch_id",
                    "persistence proof must bind the batch ID",
                )
            if _iso8601(proof["issued_at"]) < _iso8601(stage["recorded_at"]):
                raise DataPlaneContractError(
                    "delivery.persistence.proof_time",
                    f"$.stages[{index}].destination_proof.issued_at",
                    "persistence proof cannot predate the persistence stage",
                )


def _contract_artifact(root: Path, relative: object) -> Path:
    if not isinstance(relative, str) or not relative:
        raise DataPlaneContractError(
            "data-plane.manifest.invalid_path", str(relative), "path must be non-empty"
        )
    candidate = PurePosixPath(relative)
    if candidate.is_absolute() or ".." in candidate.parts or "." in candidate.parts:
        raise DataPlaneContractError(
            "data-plane.manifest.invalid_path", relative, "path must be normalized and relative"
        )
    path = root.joinpath(*candidate.parts)
    if not path.is_file() or path.is_symlink():
        raise DataPlaneContractError(
            "data-plane.manifest.missing_artifact", relative, "pinned regular file is missing"
        )
    return path


def _validate_manifest(root: Path, identity: tuple[str, str]) -> list[dict[str, Any]]:
    manifest = _load_json(root / "manifest.json")
    if set(manifest) != {"contract", "version", "digest_scope", "artifacts"}:
        raise DataPlaneContractError(
            "data-plane.manifest.closed", str(root / "manifest.json"), "manifest fields are closed"
        )
    if (manifest["contract"], manifest["version"]) != identity:
        raise DataPlaneContractError(
            "data-plane.manifest.identity", str(root / "manifest.json"), "unexpected contract identity"
        )
    if manifest["digest_scope"] != "exact_file_bytes":
        raise DataPlaneContractError(
            "data-plane.manifest.digest_scope",
            str(root / "manifest.json"),
            "v1/v2 manifests support exact file byte digests only",
        )
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise DataPlaneContractError(
            "data-plane.manifest.artifacts", str(root / "manifest.json"), "artifacts must be non-empty"
        )
    seen: set[str] = set()
    for record in artifacts:
        if not isinstance(record, dict):
            raise DataPlaneContractError(
                "data-plane.manifest.record", str(root / "manifest.json"), "artifact record must be an object"
            )
        expectation = record.get("expectation")
        expected_keys = {"path", "role", "sha256", "expectation"}
        if expectation == "invalid":
            expected_keys.add("expected_error")
        if set(record) != expected_keys or expectation not in {"schema", "valid", "invalid"}:
            raise DataPlaneContractError(
                "data-plane.manifest.record", str(record.get("path")), "artifact record fields are closed"
            )
        relative = record["path"]
        if relative in seen:
            raise DataPlaneContractError(
                "data-plane.manifest.duplicate_path", relative, "artifact path must be unique"
            )
        seen.add(relative)
        path = _contract_artifact(root, relative)
        if record["sha256"] != _sha256(path):
            raise DataPlaneContractError(
                "data-plane.manifest.digest_mismatch", relative, "SHA-256 does not match exact file bytes"
            )
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*.json")
        if path.name != "manifest.json"
    }
    if actual != seen:
        raise DataPlaneContractError(
            "data-plane.manifest.coverage",
            str(root),
            f"unpinned or missing JSON artifacts: {sorted(actual ^ seen)}",
        )
    return artifacts


def validate_data_plane_contracts(repo_root: Path) -> list[str]:
    """Validate all pinned data-plane contracts and negative fixtures."""

    repo_root = repo_root.resolve()
    roots = {name: repo_root / config["root"] for name, config in CONTRACTS.items()}
    records = {
        name: _validate_manifest(roots[name], config["identity"])
        for name, config in CONTRACTS.items()
    }
    schemas: dict[str, dict[str, Any]] = {}
    for name in CONTRACTS:
        schema_records = [record for record in records[name] if record["expectation"] == "schema"]
        if len(schema_records) != 1:
            raise DataPlaneContractError(
                "data-plane.manifest.schema_count", str(roots[name]), "exactly one schema is required"
            )
        schemas[name] = _load_json(roots[name] / schema_records[0]["path"])
        Draft202012Validator.check_schema(schemas[name])

    validators = {
        "activity": lambda doc: validate_activity_sequence(doc, schemas["activity"]),
        "privacy": lambda doc: validate_privacy_assertion(doc, schemas["privacy"]),
        "delivery": lambda doc: validate_delivery_evidence(
            doc,
            schemas["delivery"],
            repo_root=repo_root,
            activity_schema=schemas["activity"],
            privacy_schema=schemas["privacy"],
        ),
    }
    validated: list[str] = []
    for name in CONTRACTS:
        for record in records[name]:
            if record["expectation"] == "schema":
                validated.append(f"{name}/{record['path']}")
                continue
            document = _load_json(roots[name] / record["path"])
            if record["expectation"] == "valid":
                validators[name](document)
            else:
                try:
                    validators[name](document)
                except DataPlaneContractError as exc:
                    if exc.code != record["expected_error"]:
                        raise DataPlaneContractError(
                            "data-plane.fixture.wrong_error",
                            record["path"],
                            f"expected {record['expected_error']}, got {exc.code}",
                        ) from exc
                else:
                    raise DataPlaneContractError(
                        "data-plane.fixture.accepted_invalid",
                        record["path"],
                        "negative fixture unexpectedly validated",
                    )
            validated.append(f"{name}/{record['path']}")
    return validated


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[2]
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        validated = validate_data_plane_contracts(args.repo_root)
    except DataPlaneContractError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"validated {len(validated)} pinned data-plane artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
