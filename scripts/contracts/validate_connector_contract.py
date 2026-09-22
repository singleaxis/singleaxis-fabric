# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Validate the pinned Fabric Connect capability contract.

The JSON Schema constrains document shape.  These checks additionally reject
capability combinations that are syntactically valid but operationally
impossible or misleading (for example, an OTLP receiver claiming it blocks an
agent before a tool executes, or an eBPF probe claiming native decisions).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from jsonschema import Draft202012Validator


@dataclass(frozen=True)
class ContractValidationError(ValueError):
    """One stable, automation-safe contract validation failure."""

    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.path}: {self.message}"


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractValidationError(
            "connect.document.unreadable", str(path), str(exc)
        ) from exc
    if not isinstance(value, dict):
        raise ContractValidationError(
            "connect.document.not_object", str(path), "document must be a JSON object"
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
        raise ContractValidationError(
            "connect.index.invalid_path",
            "manifest.json",
            "artifact path must be a non-empty string",
        )
    candidate = PurePosixPath(relative)
    if candidate.is_absolute() or ".." in candidate.parts or "." in candidate.parts:
        raise ContractValidationError(
            "connect.index.invalid_path",
            relative,
            "path must be normalized and contract-relative",
        )
    resolved = root.joinpath(*candidate.parts)
    if not resolved.is_file() or resolved.is_symlink():
        raise ContractValidationError(
            "connect.index.missing_artifact",
            relative,
            "pinned regular file does not exist",
        )
    return resolved


def _schema_error_path(parts: Iterable[object]) -> str:
    rendered = "$"
    for part in parts:
        rendered += f"[{part}]" if isinstance(part, int) else f".{part}"
    return rendered


def validate_document(document: Mapping[str, Any], schema: Mapping[str, Any]) -> None:
    """Validate one capability document's schema and semantic invariants."""

    errors = sorted(
        Draft202012Validator(schema).iter_errors(document),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        error = errors[0]
        raise ContractValidationError(
            "connect.schema.invalid",
            _schema_error_path(error.absolute_path),
            error.message,
        )

    implementation = document["implementation"]
    kind = implementation["kind"]
    observation = document["observation"]
    surfaces = observation["semantic_surfaces"]
    surface_names = {item["surface"] for item in surfaces}
    control = document["control"]
    agent_actions = control["agent_runtime_actions"]
    telemetry_actions = control["telemetry_pipeline_actions"]
    content = document["content"]
    identity = document["identity"]
    authentication = document["authentication"]
    propagation = document["context_propagation"]["w3c_tracecontext"]
    egress = document["data_egress"]

    if kind == "ebpf_discovery":
        forbidden = {
            "decision_boundary",
            "llm_operation",
            "tool_operation",
            "policy_verdict",
            "guardrail_verdict",
            "authorization_verdict",
            "escalation",
            "evaluation",
        }
        if observation["decision_semantics"] != "none" or surface_names & forbidden:
            raise ContractValidationError(
                "connect.semantic.ebpf_decision_semantics",
                "$.observation",
                "eBPF discovery may declare kernel metadata only, never agent decision semantics",
            )
        if (
            agent_actions
            or telemetry_actions
            or control["interposition"] != "passive_probe"
        ):
            raise ContractValidationError(
                "connect.semantic.ebpf_control",
                "$.control",
                "eBPF discovery must be passive and cannot claim agent or telemetry control",
            )
        # eBPF must never claim raw application content. Hash-only evidence
        # (e.g. command_args_sha256) and network/process metadata are equally
        # content-excluding postures and are permitted.
        if content["raw_content_behavior"] not in {
            "network_metadata_only",
            "hash_only",
            "excluded",
        }:
            raise ContractValidationError(
                "connect.semantic.ebpf_content",
                "$.content.raw_content_behavior",
                "eBPF discovery must not claim application content capture",
            )
        if identity["strength"] not in {"inferred", "none"}:
            raise ContractValidationError(
                "connect.semantic.ebpf_identity",
                "$.identity.strength",
                "kernel discovery cannot claim asserted or authenticated tenant identity",
            )
        if any(propagation.values()):
            raise ContractValidationError(
                "connect.semantic.ebpf_propagation",
                "$.context_propagation.w3c_tracecontext",
                "passive kernel discovery cannot claim W3C context propagation",
            )

    if kind in {"otlp_receiver", "vendor_receiver"} and agent_actions:
        raise ContractValidationError(
            "connect.semantic.runtime_control_kind",
            "$.control.agent_runtime_actions",
            "post-action telemetry receivers cannot claim pre-action agent runtime control",
        )
    if agent_actions and control["interposition"] not in {"in_process", "inline_proxy"}:
        raise ContractValidationError(
            "connect.semantic.runtime_control_position",
            "$.control.interposition",
            "agent runtime control requires in-process or inline-proxy interposition",
        )
    if telemetry_actions and kind not in {
        "gateway_proxy",
        "otlp_receiver",
        "vendor_receiver",
    }:
        raise ContractValidationError(
            "connect.semantic.telemetry_control_kind",
            "$.control.telemetry_pipeline_actions",
            "only gateways and telemetry receivers may claim telemetry pipeline actions",
        )
    if observation["decision_semantics"] == "native":
        if not any(
            item["surface"] == "decision_boundary" and item["source"] == "native_hook"
            for item in surfaces
        ):
            raise ContractValidationError(
                "connect.semantic.native_decision_without_hook",
                "$.observation",
                "native decision semantics require a native decision-boundary hook",
            )
    if (
        content["default_raw_capture"]
        and content["raw_content_behavior"] != "configurable_raw"
    ):
        raise ContractValidationError(
            "connect.semantic.raw_default",
            "$.content",
            "raw capture can default on only when raw capture is explicitly configurable",
        )
    for direction in ("ingress", "egress"):
        default = authentication[f"{direction}_default"]
        supported = authentication[f"{direction}_supported"]
        if default not in supported:
            raise ContractValidationError(
                "connect.semantic.auth_default_unsupported",
                f"$.authentication.{direction}_default",
                f"default method {default!r} is not listed in {direction}_supported",
            )
    if identity["tenant_partitioning"] == "enforced" and identity["strength"] not in {
        "cryptographic",
        "authenticated_mapping",
    }:
        raise ContractValidationError(
            "connect.semantic.unbound_tenant_enforcement",
            "$.identity",
            "enforced tenant partitioning requires cryptographic or authenticated identity mapping",
        )
    if identity["strength"] in {
        "cryptographic",
        "authenticated_mapping",
    } and authentication["ingress_default"] in {
        "none",
        "network_policy_only",
        "in_process_boundary",
    }:
        raise ContractValidationError(
            "connect.semantic.identity_auth_mismatch",
            "$.identity.strength",
            "strong identity requires an authenticated ingress default",
        )
    if egress["network_egress"]:
        if not egress["protocols"] or egress["destinations"] in {"none", "local_only"}:
            raise ContractValidationError(
                "connect.semantic.network_egress_incomplete",
                "$.data_egress",
                "network egress requires a protocol and a network destination class",
            )
        if egress["transport_security"] == "not_applicable":
            raise ContractValidationError(
                "connect.semantic.network_security_missing",
                "$.data_egress.transport_security",
                "network egress must declare how transport security is enforced",
            )
    elif egress["destinations"] not in {"none", "local_only"}:
        raise ContractValidationError(
            "connect.semantic.local_egress_destination",
            "$.data_egress.destinations",
            "a connector without network egress cannot declare a network destination",
        )

    maturity = document["release"]["maturity"]
    for index, evidence in enumerate(document["verification_evidence"]):
        if evidence["type"] == "none" and maturity != "illustrative":
            raise ContractValidationError(
                "connect.semantic.missing_evidence",
                f"$.verification_evidence[{index}]",
                "only illustrative manifests may declare no verification evidence",
            )


def validate_contract(root: Path) -> list[str]:
    """Validate the index, pinned digests, valid manifests, and negative fixtures."""

    root = root.resolve()
    index_path = root / "manifest.json"
    index = _load_json(index_path)
    if (
        index.get("contract") != "singleaxis.fabric.connect-capability"
        or index.get("version") != "1.0.0"
    ):
        raise ContractValidationError(
            "connect.index.identity",
            "manifest.json",
            "unsupported contract identity or version",
        )

    schema_record = index.get("schema")
    if not isinstance(schema_record, dict):
        raise ContractValidationError(
            "connect.index.schema", "manifest.json", "schema record is required"
        )
    schema_path = _contract_path(root, schema_record.get("path"))
    expected_schema_digest = schema_record.get("sha256")
    if expected_schema_digest != _sha256(schema_path):
        raise ContractValidationError(
            "connect.digest.mismatch",
            str(schema_record.get("path")),
            "SHA-256 digest does not match index",
        )
    schema = _load_json(schema_path)
    Draft202012Validator.check_schema(schema)

    records = index.get("artifacts")
    if not isinstance(records, list) or not records:
        raise ContractValidationError(
            "connect.index.artifacts",
            "manifest.json",
            "non-empty artifacts array is required",
        )
    seen_paths: set[str] = set()
    seen_connector_ids: set[str] = set()
    validated: list[str] = []
    for record in records:
        if not isinstance(record, dict):
            raise ContractValidationError(
                "connect.index.artifact",
                "manifest.json",
                "each artifact record must be an object",
            )
        relative = record.get("path")
        path = _contract_path(root, relative)
        if relative in seen_paths:
            raise ContractValidationError(
                "connect.index.duplicate_path",
                str(relative),
                "artifact path is listed more than once",
            )
        seen_paths.add(str(relative))
        if record.get("sha256") != _sha256(path):
            raise ContractValidationError(
                "connect.digest.mismatch",
                str(relative),
                "SHA-256 digest does not match index",
            )
        document = _load_json(path)
        expectation = record.get("expectation")
        if expectation == "valid":
            validate_document(document, schema)
            connector_id = document["connector_id"]
            if connector_id in seen_connector_ids:
                raise ContractValidationError(
                    "connect.index.duplicate_connector",
                    str(relative),
                    f"duplicate connector_id {connector_id!r}",
                )
            seen_connector_ids.add(connector_id)
        elif expectation == "invalid":
            error_code = record.get("error_code")
            if not isinstance(error_code, str) or not error_code:
                raise ContractValidationError(
                    "connect.index.invalid_fixture",
                    str(relative),
                    "invalid fixture requires error_code",
                )
            try:
                validate_document(document, schema)
            except ContractValidationError as exc:
                if exc.code != error_code:
                    raise ContractValidationError(
                        "connect.fixture.wrong_error",
                        str(relative),
                        f"expected {error_code}, received {exc.code}",
                    ) from exc
            else:
                raise ContractValidationError(
                    "connect.fixture.unexpectedly_valid",
                    str(relative),
                    "negative fixture passed validation",
                )
        else:
            raise ContractValidationError(
                "connect.index.expectation",
                str(relative),
                "expectation must be valid or invalid",
            )
        validated.append(str(relative))

    indexed = {"manifest.json", str(schema_record["path"]), *seen_paths}
    present = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*.json")
        if path.is_file() and not path.is_symlink()
    }
    if present != indexed:
        missing = sorted(present - indexed)
        stale = sorted(indexed - present)
        raise ContractValidationError(
            "connect.index.coverage",
            "manifest.json",
            f"unpinned={missing}; missing={stale}",
        )
    return validated


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "contracts" / "connect" / "v1",
        help="path to contracts/connect/v1",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        validated = validate_contract(args.root)
    except Exception as exc:
        # Preserve stable contract errors while also rendering schema setup
        # failures as one-line CI diagnostics.
        print(f"connector contract validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"connector contract valid: {len(validated)} pinned artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
