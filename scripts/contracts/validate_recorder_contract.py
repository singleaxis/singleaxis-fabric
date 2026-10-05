# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Validate the pinned FabricRecorder v1 configuration contract.

The JSON Schema constrains document shape. These checks additionally enforce
the deliberately stricter rules the shipping `fabricctl` recorder package
applies (`tools/fabricctl/internal/recorder`): a document can be schema-valid
yet CLI-invalid. Pinned fixtures lock both sides of that boundary so drift
between the published schema and the release validator surfaces here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

import yaml
from jsonschema import Draft202012Validator

# Bounds mirrored from tools/fabricctl/internal/recorder/recorder.go.
MAX_DOCUMENT_BYTES = 1_048_576

CREDENTIAL_PATTERNS = [
    re.compile(r"(?i)(?:bearer[ :]?)[A-Za-z0-9._~+/-]+"),
    re.compile(r"(?i)(?:sk|pk|api[_-]?key|token|secret)[_-][A-Za-z0-9._~+/-]{8,}"),
    re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
]
OPAQUE_PATTERN = re.compile(r"[A-Za-z0-9_-]{48,}")
HEX_PATTERN = re.compile(r"[A-Fa-f0-9]{40,}")
SEPARATOR_PATTERN = re.compile(r"[/:.]")

PINNED_SUFFIXES = (".json", ".yaml", ".yml")


@dataclass(frozen=True)
class RecorderValidationError(ValueError):
    """One stable, automation-safe recorder contract validation failure."""

    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.path}: {self.message}"


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RecorderValidationError(
            "recorder.document.unreadable", str(path), str(exc)
        ) from exc
    if not isinstance(value, dict):
        raise RecorderValidationError(
            "recorder.document.not_object", str(path), "document must be a JSON object"
        )
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _contract_path(root: Path, relative: object) -> Path:
    if not isinstance(relative, str) or not relative:
        raise RecorderValidationError(
            "recorder.index.invalid_path",
            "manifest.json",
            "artifact path must be a non-empty string",
        )
    candidate = PurePosixPath(relative)
    if candidate.is_absolute() or ".." in candidate.parts or "." in candidate.parts:
        raise RecorderValidationError(
            "recorder.index.invalid_path",
            relative,
            "path must be normalized and contract-relative",
        )
    resolved = root.joinpath(*candidate.parts)
    if not resolved.is_file() or resolved.is_symlink():
        raise RecorderValidationError(
            "recorder.index.missing_artifact",
            relative,
            "pinned regular file does not exist",
        )
    return resolved


def _schema_path(parts: Iterable[object]) -> str:
    rendered = "$"
    for part in parts:
        rendered += f"[{part}]" if isinstance(part, int) else f".{part}"
    return rendered


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys like the CLI decoder."""


def _unique_mapping(
    loader: _StrictLoader, node: yaml.MappingNode, deep: bool = False
) -> dict:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        try:
            duplicate = key in mapping
        except TypeError:
            duplicate = False
        if duplicate:
            raise RecorderValidationError(
                "recorder.document.duplicate_field",
                f"line {key_node.start_mark.line + 1}",
                f"duplicate field {key!r} is rejected by the strict decoder",
            )
        mapping[key] = loader.construct_object(value_node, deep=True)
    return mapping


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping
)


def _load_yaml_payload(payload: bytes, *, source: str) -> dict[str, Any]:
    if not payload or len(payload) > MAX_DOCUMENT_BYTES:
        raise RecorderValidationError(
            "recorder.document.bounds",
            source,
            "configuration must be a non-empty document of at most 1 MiB",
        )
    try:
        documents = list(yaml.load_all(payload, Loader=_StrictLoader))
    except RecorderValidationError:
        raise
    except yaml.YAMLError as exc:
        raise RecorderValidationError(
            "recorder.document.invalid_yaml", source, str(exc)
        ) from exc
    if len(documents) != 1:
        raise RecorderValidationError(
            "recorder.document.multiple",
            source,
            "configuration must contain exactly one YAML document",
        )
    document = documents[0]
    if not isinstance(document, dict):
        raise RecorderValidationError(
            "recorder.document.not_object",
            source,
            "configuration must decode to a single mapping",
        )
    return document


def _looks_sensitive(value: str) -> bool:
    """Mirror recorder.go referenceLooksSensitive credential-shape denial."""

    if not isinstance(value, str):
        return False
    for pattern in CREDENTIAL_PATTERNS:
        if pattern.fullmatch(value):
            return True
    return SEPARATOR_PATTERN.search(value) is None and bool(
        OPAQUE_PATTERN.fullmatch(value) or HEX_PATTERN.fullmatch(value)
    )


def _check_reference(document_path: str, value: Any) -> None:
    if _looks_sensitive(value):
        raise RecorderValidationError(
            "recorder.reference.credential_shape",
            document_path,
            "references and names must not be credential-shaped",
        )


def validate_document(document: Mapping[str, Any], schema: Mapping[str, Any]) -> None:
    """Validate one decoded FabricRecorder document.

    Runs JSON Schema first, then the stricter-than-schema rules the release
    CLI applies: ``spec.identity.recorderId`` must equal ``metadata.name`` and
    no name or reference may be credential-shaped.
    """

    errors = sorted(
        Draft202012Validator(schema).iter_errors(document),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        error = errors[0]
        raise RecorderValidationError(
            "recorder.schema.invalid",
            _schema_path(error.absolute_path),
            error.message,
        )

    metadata = document["metadata"]
    spec = document["spec"]
    identity = spec["identity"]

    _check_reference("$.metadata.name", metadata["name"])
    recorder_id = identity["recorderId"]
    _check_reference("$.spec.identity.recorderId", recorder_id)
    if recorder_id != metadata["name"]:
        raise RecorderValidationError(
            "recorder.identity.recorder_id_mismatch",
            "$.spec.identity.recorderId",
            "spec.identity.recorderId must equal metadata.name",
        )
    _check_reference("$.spec.identity.systemId", identity["systemId"])
    _check_reference("$.spec.identity.deploymentId", identity["deploymentId"])
    _check_reference(
        "$.spec.protect.privacyPolicyRef", spec["protect"]["privacyPolicyRef"]
    )
    _check_reference("$.spec.destination.ref", spec["destination"]["ref"])
    _check_reference("$.spec.installation.ref", spec["installation"]["ref"])


def validate_payload(
    payload: bytes, schema: Mapping[str, Any], *, source: str = "$"
) -> None:
    """Validate raw configuration bytes: bound, single document, then semantics."""

    document = _load_yaml_payload(payload, source=source)
    validate_document(document, schema)


def validate_contract(root: Path) -> list[str]:
    """Verify the pinned manifest, schema, and positive and negative fixtures."""

    root = root.resolve()
    index_path = root / "manifest.json"
    index = _load_json(index_path)
    if (
        index.get("contract") != "singleaxis.fabric.recorder"
        or index.get("version") != "v1"
    ):
        raise RecorderValidationError(
            "recorder.index.identity",
            "manifest.json",
            "unsupported contract identity or version",
        )
    if index.get("digest_scope") != "exact_file_bytes":
        raise RecorderValidationError(
            "recorder.index.digest_scope",
            "manifest.json",
            "manifest must declare digest_scope exact_file_bytes",
        )

    schema_record = index.get("schema")
    if not isinstance(schema_record, dict):
        raise RecorderValidationError(
            "recorder.index.schema", "manifest.json", "schema record is required"
        )
    schema_path = _contract_path(root, schema_record.get("path"))
    if schema_record.get("sha256") != _sha256(schema_path):
        raise RecorderValidationError(
            "recorder.digest.mismatch",
            str(schema_record.get("path")),
            "SHA-256 digest does not match manifest",
        )
    schema = _load_json(schema_path)
    Draft202012Validator.check_schema(schema)

    records = index.get("fixtures")
    if not isinstance(records, list) or not records:
        raise RecorderValidationError(
            "recorder.index.fixtures",
            "manifest.json",
            "non-empty fixtures array is required",
        )
    seen_paths: set[str] = {str(schema_record["path"])}
    validated: list[str] = [str(schema_record["path"])]
    for record in records:
        if not isinstance(record, dict):
            raise RecorderValidationError(
                "recorder.index.fixture",
                "manifest.json",
                "each fixture record must be an object",
            )
        relative = record.get("path")
        path = _contract_path(root, relative)
        if relative in seen_paths:
            raise RecorderValidationError(
                "recorder.index.duplicate_path",
                str(relative),
                "artifact path is listed more than once",
            )
        seen_paths.add(str(relative))
        if record.get("sha256") != _sha256(path):
            raise RecorderValidationError(
                "recorder.digest.mismatch",
                str(relative),
                "SHA-256 digest does not match manifest",
            )
        payload = path.read_bytes()
        expectation = record.get("expectation")
        if expectation == "valid":
            validate_payload(payload, schema, source=str(relative))
        elif expectation == "invalid":
            expected_error = record.get("expected_error")
            if not isinstance(expected_error, str) or not expected_error:
                raise RecorderValidationError(
                    "recorder.index.invalid_fixture",
                    str(relative),
                    "invalid fixture requires expected_error",
                )
            try:
                validate_payload(payload, schema, source=str(relative))
            except RecorderValidationError as exc:
                if exc.code != expected_error:
                    raise RecorderValidationError(
                        "recorder.fixture.wrong_error",
                        str(relative),
                        f"expected {expected_error}, received {exc.code}",
                    ) from exc
            else:
                raise RecorderValidationError(
                    "recorder.fixture.unexpectedly_valid",
                    str(relative),
                    "negative fixture passed validation",
                )
        else:
            raise RecorderValidationError(
                "recorder.index.expectation",
                str(relative),
                "expectation must be valid or invalid",
            )
        validated.append(str(relative))

    present = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and path.suffix in PINNED_SUFFIXES
        and path.name != "manifest.json"
    }
    if present != seen_paths:
        raise RecorderValidationError(
            "recorder.index.coverage",
            "manifest.json",
            f"unpinned={sorted(present - seen_paths)}; "
            f"missing={sorted(seen_paths - present)}",
        )
    return validated


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "contracts" / "recorder" / "v1",
        help="path to contracts/recorder/v1",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        validated = validate_contract(args.root)
    except Exception as exc:
        print(f"recorder contract validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"recorder contract valid: {len(validated)} pinned artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
