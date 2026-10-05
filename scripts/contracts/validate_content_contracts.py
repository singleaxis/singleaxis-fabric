# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Validate Fabric's governed-content contracts (contracts/content/v1).

Same pinning convention as the data-plane contracts: every JSON artifact
under the family root is sha256-pinned in ``manifest.json`` over exact file
bytes. Semantic checks cover what JSON Schema cannot express: manifest
sequence contiguity, descriptor/status consistency, completeness rollups,
byte-fixture digests, and export integrity accounting.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from jsonschema import Draft202012Validator, FormatChecker


@dataclass(frozen=True)
class ContentContractError(ValueError):
    """Stable, automation-safe validation failure."""

    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.path}: {self.message}"


ROOT = Path("contracts/content/v1")
IDENTITY = ("singleaxis.fabric.content", "1.0.0")

_DESCRIPTOR_STATUSES = frozenset({"stored", "pending", "truncated"})
_SCHEMA_BY_VERSION = {
    "fabric.content-object/v1": "schema/content-object-v1.schema.json",
    "fabric.transcript-manifest/v1": "schema/transcript-manifest-v1.schema.json",
    "fabric.transcript-export/v1": "schema/transcript-export-v1.schema.json",
}


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContentContractError(
            "content.document.unreadable", str(path), str(exc)
        ) from exc
    if not isinstance(value, dict):
        raise ContentContractError(
            "content.document.not_object", str(path), "document must be a JSON object"
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
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
            document
        ),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        error = errors[0]
        raise ContentContractError(
            "content.schema.invalid", _schema_path(error.absolute_path), error.message
        )


def canonical_json(value: Any) -> str:
    """Spec-029 canonical JSON: UTF-8, no insignificant whitespace, sorted keys."""

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _canonical_bytes(value: str) -> bytes:
    return value.encode("utf-8", "surrogatepass")


def _select_schema(document: Mapping[str, Any]) -> str:
    version = document.get("schema_version")
    schema_rel = _SCHEMA_BY_VERSION.get(version) if isinstance(version, str) else None
    if schema_rel is None:
        raise ContentContractError(
            "content.document.kind",
            "$.schema_version",
            f"unrecognized schema_version {version!r}",
        )
    return schema_rel


def validate_content_document(
    document: Mapping[str, Any], schemas: Mapping[str, Mapping[str, Any]]
) -> None:
    """Validate one content-object / manifest / export document."""

    schema_rel = _select_schema(document)
    _validate_schema(document, schemas[schema_rel])
    version = document["schema_version"]
    if version == "fabric.transcript-manifest/v1":
        _validate_manifest_semantics(document)
    elif version == "fabric.transcript-export/v1":
        _validate_export_semantics(document)


def _validate_manifest_semantics(document: Mapping[str, Any]) -> None:
    items = document["items"]
    sequences = [item["sequence"] for item in items]
    if sequences != list(range(len(items))):
        raise ContentContractError(
            "content.manifest.sequence",
            "$.items",
            f"item sequences must be contiguous from 0; got {sequences}",
        )
    seen_objects: set[str] = set()
    counts: dict[str, int] = {}
    roles_observed: set[str] = set()
    for index, item in enumerate(items):
        status = item["status"]
        counts[status] = counts.get(status, 0) + 1
        descriptor = item.get("descriptor")
        if status in _DESCRIPTOR_STATUSES:
            if descriptor is None:
                raise ContentContractError(
                    "content.manifest.descriptor",
                    f"$.items[{index}]",
                    f"status {status!r} requires a descriptor",
                )
            if descriptor["status"] != status:
                raise ContentContractError(
                    "content.manifest.descriptor",
                    f"$.items[{index}].descriptor.status",
                    f"descriptor status {descriptor['status']!r} != item status {status!r}",
                )
            if descriptor["role"] != item["role"]:
                raise ContentContractError(
                    "content.manifest.descriptor",
                    f"$.items[{index}].descriptor.role",
                    "descriptor role must match the item role",
                )
            if "ref" not in item:
                raise ContentContractError(
                    "content.manifest.descriptor",
                    f"$.items[{index}].ref",
                    f"status {status!r} requires a resolution ref",
                )
            object_id = descriptor["object_id"]
            if object_id in seen_objects:
                raise ContentContractError(
                    "content.manifest.object_id",
                    f"$.items[{index}].descriptor.object_id",
                    "object_id must be unique within a manifest",
                )
            seen_objects.add(object_id)
            roles_observed.add(item["role"])
        elif descriptor is not None or "ref" in item:
            raise ContentContractError(
                "content.manifest.descriptor",
                f"$.items[{index}]",
                f"status {status!r} must not carry a descriptor or ref",
            )
    declared = document["completeness"]
    if declared != counts:
        raise ContentContractError(
            "content.manifest.completeness",
            "$.completeness",
            f"rollup {declared} does not match item statuses {counts}",
        )
    coverage = document["coverage"]
    observed = set(coverage["roles_observed"])
    if not observed <= roles_observed:
        raise ContentContractError(
            "content.manifest.coverage",
            "$.coverage.roles_observed",
            f"roles_observed must be a subset of stored/pending/truncated item roles: "
            f"{sorted(observed - roles_observed)}",
        )


def _validate_export_semantics(document: Mapping[str, Any]) -> None:
    checked = 0
    for step_index, step in enumerate(document["steps"]):
        for entry_index, entry in enumerate(step["entries"]):
            if entry["status"] == "available":
                checked += 1
                for required in ("ref", "digest", "byte_length", "object_id"):
                    if required not in entry:
                        raise ContentContractError(
                            "content.export.integrity",
                            f"$.steps[{step_index}].entries[{entry_index}]",
                            f"available content requires {required!r}",
                        )
    integrity = document["integrity"]
    if integrity["objects_checked"] != checked:
        raise ContentContractError(
            "content.export.integrity",
            "$.integrity.objects_checked",
            f"declared {integrity['objects_checked']}, counted {checked}",
        )
    if integrity["verified"] and integrity["failures"]:
        raise ContentContractError(
            "content.export.integrity",
            "$.integrity",
            "verified cannot be true while failures are listed",
        )


def validate_bytes_fixture(document: Mapping[str, Any], path: Path) -> None:
    """Validate one shared byte/hash fixture (kind: text | json)."""

    name = document.get("name")
    kind = document.get("kind")
    value = document.get("value")
    digest = document.get("sha256")
    byte_length = document.get("byte_length")
    if (
        not isinstance(name, str)
        or kind not in ("text", "json")
        or not isinstance(value, str)
    ):
        raise ContentContractError(
            "content.bytes.shape", str(path), "fixture requires name, kind, and value"
        )
    if kind == "json":
        source = document.get("input")
        if canonical_json(source) != value:
            raise ContentContractError(
                "content.bytes.canonical",
                str(path),
                "canonical_json(input) must equal value for json fixtures",
            )
    raw = _canonical_bytes(value)
    if byte_length != len(raw):
        raise ContentContractError(
            "content.bytes.digest", str(path), "byte_length does not match UTF-8 bytes"
        )
    if digest != "sha256:" + hashlib.sha256(raw).hexdigest():
        raise ContentContractError(
            "content.bytes.digest", str(path), "sha256 does not match UTF-8 bytes"
        )


def _contract_artifact(root: Path, relative: object) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ContentContractError(
            "content.manifest.invalid_path", str(relative), "path must be non-empty"
        )
    candidate = PurePosixPath(relative)
    if candidate.is_absolute() or ".." in candidate.parts or "." in candidate.parts:
        raise ContentContractError(
            "content.manifest.invalid_path",
            relative,
            "path must be normalized and relative",
        )
    path = root.joinpath(*candidate.parts)
    if not path.is_file() or path.is_symlink():
        raise ContentContractError(
            "content.manifest.missing_artifact",
            relative,
            "pinned regular file is missing",
        )
    return path


def _validate_manifest_pinning(root: Path) -> list[dict[str, Any]]:
    manifest = _load_json(root / "manifest.json")
    if set(manifest) != {"contract", "version", "digest_scope", "artifacts"}:
        raise ContentContractError(
            "content.manifest.closed",
            str(root / "manifest.json"),
            "manifest fields are closed",
        )
    if (manifest["contract"], manifest["version"]) != IDENTITY:
        raise ContentContractError(
            "content.manifest.identity",
            str(root / "manifest.json"),
            "unexpected contract identity",
        )
    if manifest["digest_scope"] != "exact_file_bytes":
        raise ContentContractError(
            "content.manifest.digest_scope",
            str(root / "manifest.json"),
            "v1 manifests support exact file byte digests only",
        )
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise ContentContractError(
            "content.manifest.artifacts",
            str(root / "manifest.json"),
            "artifacts must be non-empty",
        )
    seen: set[str] = set()
    for record in artifacts:
        if not isinstance(record, dict):
            raise ContentContractError(
                "content.manifest.record",
                str(root / "manifest.json"),
                "record must be an object",
            )
        expectation = record.get("expectation")
        expected_keys = {"path", "role", "sha256", "expectation"}
        if expectation == "invalid":
            expected_keys.add("expected_error")
        if set(record) != expected_keys or expectation not in {
            "schema",
            "valid",
            "invalid",
            "fixture",
        }:
            raise ContentContractError(
                "content.manifest.record",
                str(record.get("path")),
                "artifact record fields are closed",
            )
        relative = record["path"]
        if relative in seen:
            raise ContentContractError(
                "content.manifest.duplicate_path",
                relative,
                "artifact path must be unique",
            )
        seen.add(relative)
        path = _contract_artifact(root, relative)
        if record["sha256"] != _sha256(path):
            raise ContentContractError(
                "content.manifest.digest_mismatch",
                relative,
                "SHA-256 does not match exact file bytes",
            )
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*.json")
        if path.name != "manifest.json"
    }
    if actual != seen:
        raise ContentContractError(
            "content.manifest.coverage",
            str(root),
            f"unpinned or missing JSON artifacts: {sorted(actual ^ seen)}",
        )
    return artifacts


def validate_content_contracts(repo_root: Path) -> list[str]:
    """Validate all pinned governed-content artifacts and negative fixtures."""

    root = (repo_root / ROOT).resolve()
    records = _validate_manifest_pinning(root)
    schemas: dict[str, Mapping[str, Any]] = {}
    for record in records:
        if record["expectation"] == "schema":
            schemas[record["path"]] = _load_json(root / record["path"])
            Draft202012Validator.check_schema(schemas[record["path"]])
    for required in _SCHEMA_BY_VERSION.values():
        if required not in schemas:
            raise ContentContractError(
                "content.manifest.schema_count", str(root), f"missing schema {required}"
            )

    validated: list[str] = []
    for record in records:
        path = root / record["path"]
        if record["expectation"] == "schema":
            validated.append(f"content/{record['path']}")
            continue
        document = _load_json(path)
        if record["expectation"] == "fixture":
            validate_bytes_fixture(document, path)
        elif record["expectation"] == "valid":
            validate_content_document(document, schemas)
        else:
            try:
                validate_content_document(document, schemas)
            except ContentContractError as exc:
                if exc.code != record["expected_error"]:
                    raise ContentContractError(
                        "content.fixture.wrong_error",
                        record["path"],
                        f"expected {record['expected_error']}, got {exc.code}",
                    ) from exc
            else:
                raise ContentContractError(
                    "content.fixture.accepted_invalid",
                    record["path"],
                    "negative fixture unexpectedly validated",
                )
        validated.append(f"content/{record['path']}")
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
        validated = validate_content_contracts(args.repo_root)
    except ContentContractError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"validated {len(validated)} pinned content artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
