# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Validate the draft byte-content v2 contract (contracts/content/v2).

Content v2 is the descriptor shape for exact-byte content objects, including
the ``model.exchange.*`` objects written by LLM wire capture (specs 042 and
043). JSON Schema handles closed shapes. These semantic checks reject forged
exactness, status/representation disagreement, unsafe references, and fixture
digest drift.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path("contracts/content/v2")
IDENTITY = ("singleaxis.fabric.content", "2.0.0", "exact_file_bytes")
SCHEMAS = {
    "fabric.content-object/v2": "schema/content-object-v2.schema.json",
}
RESOLVABLE_STATUSES = frozenset({"stored", "truncated", "redacted"})


@dataclass(frozen=True)
class ContentV2ContractError(ValueError):
    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.path}: {self.message}"


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContentV2ContractError("content.unreadable", str(path), str(exc)) from exc
    if not isinstance(value, dict):
        raise ContentV2ContractError(
            "content.not_object", str(path), "expected JSON object"
        )
    return value


def _digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(block)
    return sha.hexdigest()


_REF_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


def _safe_ref(ref: str, tenant_id: str) -> bool:
    parsed = urlsplit(ref)
    segments = parsed.path.split("/")
    return (
        parsed.scheme in {"s3", "gs", "file"}
        and (
            (parsed.scheme == "file" and not parsed.netloc)
            or (
                parsed.scheme in {"s3", "gs"} and bool(_BUCKET.fullmatch(parsed.netloc))
            )
        )
        and len(segments) >= 3
        and segments[0] == ""
        and segments[1:-1].count(tenant_id) == 1
        and all(_REF_SEGMENT.fullmatch(segment) for segment in segments[1:])
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
        and "%" not in ref
        and not any(part in {".", ".."} for part in segments)
    )


def _validate_content(document: Mapping[str, Any]) -> None:
    status = document["status"]
    representation = document["representation"]
    if status == "pending" and any(
        key in document for key in ("stored_sha256", "stored_byte_length")
    ):
        raise ContentV2ContractError(
            "content.pending_bytes",
            "$",
            "pending object cannot claim stored bytes",
        )
    if status == "truncated" and representation != "truncated":
        raise ContentV2ContractError(
            "content.representation",
            "$.representation",
            "truncated status needs truncated representation",
        )
    if status == "redacted" and representation != "redacted":
        raise ContentV2ContractError(
            "content.representation",
            "$.representation",
            "redacted status needs redacted representation",
        )
    if status == "stored" and representation in {
        "truncated",
        "redacted",
        "unavailable",
    }:
        raise ContentV2ContractError(
            "content.representation",
            "$.representation",
            "stored status cannot conceal truncation, redaction or absence",
        )
    if (
        status in {"not_captured", "unsupported", "dropped", "failed"}
        and representation != "unavailable"
    ):
        raise ContentV2ContractError(
            "content.representation",
            "$.representation",
            "uncaptured bytes need unavailable representation",
        )
    if ("source_sha256" in document) != ("source_byte_length" in document):
        raise ContentV2ContractError(
            "content.source_pair",
            "$",
            "source byte length and digest must be present together",
        )
    if ("stored_sha256" in document) != ("stored_byte_length" in document):
        raise ContentV2ContractError(
            "content.stored_pair",
            "$",
            "stored byte length and digest must be present together",
        )
    if representation == "exact" and status in RESOLVABLE_STATUSES:
        if (
            document["source_byte_length"] != document["stored_byte_length"]
            or document["source_sha256"] != document["stored_sha256"]
        ):
            raise ContentV2ContractError(
                "content.false_exact",
                "$",
                "exact source and stored bytes must match",
            )
    if "ref" in document and not _safe_ref(document["ref"], document["tenant_id"]):
        raise ContentV2ContractError(
            "content.ref",
            "$.ref",
            "reference must be credential-free and local to an approved scheme",
        )


def validate_document(
    document: Mapping[str, Any], schemas: Mapping[str, Mapping[str, Any]]
) -> None:
    version = document.get("schema_version")
    selected = SCHEMAS.get(version) if isinstance(version, str) else None
    if selected is None:
        raise ContentV2ContractError(
            "content.unknown_version", "$.schema_version", f"unknown {version!r}"
        )
    schema = schemas[selected]
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
            document
        ),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        first = errors[0]
        raise ContentV2ContractError(
            "content.schema",
            "$" + "".join(f".{part}" for part in first.absolute_path),
            first.message,
        )
    _validate_content(document)


def _validate_binary_fixture(document: Mapping[str, Any], path: Path) -> None:
    if set(document) != {"name", "base64", "byte_length", "sha256"}:
        raise ContentV2ContractError(
            "content.bytes.shape", str(path), "closed byte fixture fields"
        )
    try:
        raw = base64.b64decode(document["base64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ContentV2ContractError(
            "content.bytes.base64", str(path), str(exc)
        ) from exc
    if document["byte_length"] != len(raw) or document["sha256"] != (
        "sha256:" + hashlib.sha256(raw).hexdigest()
    ):
        raise ContentV2ContractError(
            "content.bytes.digest", str(path), "byte digest/length mismatch"
        )


def _validate_example_binding(repo_root: Path) -> None:
    """Bind the pinned valid descriptors to their pinned byte fixtures."""

    root = repo_root / ROOT
    for descriptor_path, bytes_path in (
        ("valid/artifact-after.json", "fixtures/bytes/binary-four-bytes.json"),
        (
            "valid/caller-terminal-chunk.json",
            "fixtures/bytes/binary-terminal-five-bytes.json",
        ),
    ):
        descriptor = _load(root / descriptor_path)
        raw = _load(root / bytes_path)
        if not (
            descriptor["representation"] == "exact"
            and descriptor["source_sha256"]
            == descriptor["stored_sha256"]
            == raw["sha256"]
            and descriptor["source_byte_length"]
            == descriptor["stored_byte_length"]
            == raw["byte_length"]
        ):
            raise ContentV2ContractError(
                "content.fixture.binding",
                descriptor_path,
                "pinned descriptor and byte fixture diverge",
            )


def validate_contracts(repo_root: Path) -> list[str]:
    """Validate every pinned contract artifact and negative fixture."""

    schemas: dict[str, Mapping[str, Any]] = {}
    artifacts: list[tuple[Path, Mapping[str, Any]]] = []
    root = repo_root / ROOT
    manifest = _load(root / "manifest.json")
    if set(manifest) != {"contract", "version", "digest_scope", "artifacts"}:
        raise ContentV2ContractError(
            "content.manifest.shape", str(root), "closed manifest fields"
        )
    if (
        manifest["contract"],
        manifest["version"],
        manifest["digest_scope"],
    ) != IDENTITY:
        raise ContentV2ContractError(
            "content.manifest.identity", str(root), "wrong identity"
        )
    if not isinstance(manifest["artifacts"], list) or not manifest["artifacts"]:
        raise ContentV2ContractError(
            "content.manifest.artifacts",
            str(root),
            "artifacts must be a non-empty list",
        )
    seen: set[str] = set()
    for record in manifest["artifacts"]:
        if not isinstance(record, dict) or set(record) != {
            "path",
            "sha256",
            "expectation",
            "expected_error",
        }:
            raise ContentV2ContractError(
                "content.manifest.record", str(root), "closed artifact fields"
            )
        rel = record["path"]
        if not isinstance(rel, str) or not rel:
            raise ContentV2ContractError(
                "content.manifest.path",
                str(rel),
                "path must be a non-empty string",
            )
        expectation = record["expectation"]
        if (
            expectation not in {"schema", "bytes", "valid", "invalid"}
            or (
                expectation == "invalid"
                and (
                    not isinstance(record["expected_error"], str)
                    or not record["expected_error"]
                )
            )
            or (expectation != "invalid" and record["expected_error"] is not None)
        ):
            raise ContentV2ContractError(
                "content.manifest.record", rel, "invalid expectation/error binding"
            )
        sha256 = record["sha256"]
        if (
            not isinstance(sha256, str)
            or len(sha256) != 64
            or any(character not in "0123456789abcdef" for character in sha256)
        ):
            raise ContentV2ContractError(
                "content.manifest.record", rel, "sha256 must be lowercase hex"
            )
        posix = PurePosixPath(rel)
        if (
            posix.is_absolute()
            or posix.as_posix() != rel
            or "\\" in rel
            or ".." in posix.parts
            or rel in seen
        ):
            raise ContentV2ContractError(
                "content.manifest.path", str(rel), "unsafe/duplicate path"
            )
        seen.add(rel)
        path = root.joinpath(*posix.parts)
        cursor = root
        has_symlink = False
        for part in posix.parts:
            cursor = cursor / part
            has_symlink = has_symlink or cursor.is_symlink()
        if not path.is_file() or has_symlink or _digest(path) != record["sha256"]:
            raise ContentV2ContractError(
                "content.manifest.digest", rel, "missing or modified artifact"
            )
        artifacts.append((path, record))
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*.json")
        if path.name != "manifest.json"
    }
    if actual != seen:
        raise ContentV2ContractError(
            "content.manifest.coverage",
            str(root),
            f"unpinned JSON: {sorted(actual ^ seen)}",
        )
    for path, record in artifacts:
        if record["expectation"] == "schema":
            schema = _load(path)
            Draft202012Validator.check_schema(schema)
            schemas[record["path"]] = schema
    required = set(SCHEMAS.values())
    if not required <= set(schemas):
        raise ContentV2ContractError(
            "content.manifest.schemas",
            "$",
            f"missing schemas: {sorted(required - set(schemas))}",
        )
    validated: list[str] = []
    for path, record in artifacts:
        expectation = record["expectation"]
        if expectation == "schema":
            pass
        elif expectation == "bytes":
            _validate_binary_fixture(_load(path), path)
        elif expectation == "valid":
            validate_document(_load(path), schemas)
        elif expectation == "invalid":
            try:
                validate_document(_load(path), schemas)
            except ContentV2ContractError as exc:
                if exc.code != record["expected_error"]:
                    raise ContentV2ContractError(
                        "content.fixture.wrong_error",
                        str(path),
                        f"expected {record['expected_error']}, got {exc.code}",
                    ) from exc
            else:
                raise ContentV2ContractError(
                    "content.fixture.accepted", str(path), "invalid fixture accepted"
                )
        else:
            raise ContentV2ContractError(
                "content.manifest.expectation", str(path), f"unknown {expectation}"
            )
        validated.append(record["path"])
    _validate_example_binding(repo_root)
    return validated


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[2]
    )
    args = parser.parse_args(argv)
    try:
        paths = validate_contracts(args.repo_root)
    except ContentV2ContractError as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"validated {len(paths)} pinned content-v2 artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
