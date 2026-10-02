# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Validate draft AEEP evidence/v1 and byte-content/v2 contracts.

JSON Schema handles closed shapes. These semantic checks reject false
completeness, forged exactness, unsafe references, and fixture digest drift.
This validator does not claim that any runtime currently emits AEEP.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker


ROOTS = {
    "evidence": Path("contracts/evidence/v1"),
    "content": Path("contracts/content/v2"),
}
SCHEMAS = {
    "agent.evidence.source-capability/v1": (
        "evidence",
        "schema/source-capability-v1.schema.json",
    ),
    "agent.evidence.event/v1": ("evidence", "schema/evidence-event-v1.schema.json"),
    "agent.evidence.run-manifest/v1": (
        "evidence",
        "schema/run-manifest-v1.schema.json",
    ),
    "fabric.content-object/v2": ("content", "schema/content-object-v2.schema.json"),
}
BAD_STATUSES = frozenset(
    {"truncated", "redacted", "not_captured", "unsupported", "dropped", "failed"}
)
RESOLVABLE_STATUSES = frozenset({"stored", "truncated", "redacted"})


@dataclass(frozen=True)
class EvidenceContractError(ValueError):
    code: str
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.path}: {self.message}"


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceContractError("evidence.unreadable", str(path), str(exc)) from exc
    if not isinstance(value, dict):
        raise EvidenceContractError(
            "evidence.not_object", str(path), "expected JSON object"
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


def _validate_verification_ref(
    verification: Mapping[str, Any], tenant_id: str, path: str
) -> None:
    if not _safe_ref(verification["evidence_ref"], tenant_id):
        raise EvidenceContractError(
            "evidence.verification.ref",
            path,
            "verification proof reference must be tenant-bound and credential-free",
        )


def _safe_content_ref(document: Mapping[str, Any]) -> bool:
    ref = document["ref"]
    if not ref.startswith("fabric-local:"):
        return _safe_ref(ref, document["tenant_id"])
    # This adapter scheme is intentionally limited to policy-bound content
    # objects. It is not accepted for external receipts or verification proofs.
    mode = document.get("privacy_mode")
    plane = {
        "retain_original": "original",
        "redact": "derivative",
        "tokenize": "derivative",
    }.get(mode)
    workload = document.get("workload_id")
    if (
        plane is None
        or "policy_digest" not in document
        or not isinstance(workload, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", workload) is None
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", document["tenant_id"])
        is None
    ):
        return False
    expected = f"fabric-local://{document['tenant_id']}/{workload}/{plane}/{document['object_id']}"
    return ref == expected


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _validate_content(document: Mapping[str, Any]) -> None:
    status = document["status"]
    representation = document["representation"]
    if status == "pending" and any(
        key in document for key in ("stored_sha256", "stored_byte_length")
    ):
        raise EvidenceContractError(
            "evidence.content.pending_bytes",
            "$",
            "pending object cannot claim stored bytes",
        )
    if status == "truncated" and representation != "truncated":
        raise EvidenceContractError(
            "evidence.content.representation",
            "$.representation",
            "truncated status needs truncated representation",
        )
    if status == "redacted" and representation not in {"redacted", "tokenized"}:
        raise EvidenceContractError(
            "evidence.content.representation",
            "$.representation",
            "redacted status needs redacted or tokenized representation",
        )
    if status == "stored" and representation in {
        "truncated",
        "redacted",
        "tokenized",
        "unavailable",
    }:
        raise EvidenceContractError(
            "evidence.content.representation",
            "$.representation",
            "stored status cannot conceal truncation, redaction or absence",
        )
    if (
        status in {"not_captured", "unsupported", "dropped", "failed"}
        and representation != "unavailable"
    ):
        raise EvidenceContractError(
            "evidence.content.representation",
            "$.representation",
            "uncaptured bytes need unavailable representation",
        )
    metadata_only = (
        "policy_digest" in document
        and document.get("privacy_mode") == "metadata_only"
        and document.get("protection_status") == "withheld"
        and status in {"not_captured", "dropped"}
        and "source_sha256" not in document
    )
    if ("source_sha256" in document) != (
        "source_byte_length" in document
    ) and not metadata_only:
        raise EvidenceContractError(
            "evidence.content.source_pair",
            "$",
            "source byte length and digest must be present together",
        )
    if "policy_digest" in document:
        _validate_content_protection(document)
    if ("stored_sha256" in document) != ("stored_byte_length" in document):
        raise EvidenceContractError(
            "evidence.content.stored_pair",
            "$",
            "stored byte length and digest must be present together",
        )
    if representation == "exact" and status in RESOLVABLE_STATUSES:
        if (
            document["source_byte_length"] != document["stored_byte_length"]
            or document["source_sha256"] != document["stored_sha256"]
        ):
            raise EvidenceContractError(
                "evidence.content.false_exact",
                "$",
                "exact source and stored bytes must match",
            )
    if "ref" in document and not _safe_content_ref(document):
        raise EvidenceContractError(
            "evidence.content.ref",
            "$.ref",
            "reference must be credential-free and local to an approved scheme",
        )


def _validate_content_protection(document: Mapping[str, Any]) -> None:
    """Keep configured privacy and recorded outcomes consistent, without certifying policy."""
    mode = document["privacy_mode"]
    protection = document["protection_status"]
    status = document["status"]
    expected = {
        "omit": "withheld",
        "metadata_only": "withheld",
        "retain_original": "retained",
        "redact": "redacted",
        "tokenize": "tokenized",
    }
    valid = mode in expected and protection in {
        expected.get(mode),
        "lost",
        "unsupported",
    }
    if protection == "lost":
        valid = valid and status in {"failed", "dropped"}
    elif protection == "unsupported":
        valid = valid and status in {"unsupported", "dropped"}
    elif protection == "withheld":
        valid = valid and status in {"not_captured", "dropped"}
    elif status in {"pending", "stored", "redacted"}:
        representation = "exact" if protection == "retained" else protection
        valid = valid and document["representation"] == representation
        valid = valid and status in {
            "pending",
            "stored" if protection == "retained" else "redacted",
        }
        if mode in {"redact", "tokenize"}:
            valid = valid and document.get("transformations") == [mode]
    else:
        valid = valid and status in {"failed", "dropped"}
    if not valid:
        raise EvidenceContractError(
            "evidence.content.protection",
            "$",
            "deployment privacy mode, protection outcome and content status must agree",
        )


def _validate_event(document: Mapping[str, Any]) -> None:
    if document["provenance"] == "inferred" and (
        "trace_id" in document or "span_id" in document or "run_id" in document
    ):
        raise EvidenceContractError(
            "evidence.event.inferred_identity",
            "$",
            "inferred provenance cannot assert native trace/run identity",
        )
    if "content_ref" in document and not _safe_ref(
        document["content_ref"], document["tenant_id"]
    ):
        raise EvidenceContractError(
            "evidence.event.ref", "$.content_ref", "reference must be credential-free"
        )
    if document["event_name"] in {"agent.evidence.content", "agent.evidence.artifact"}:
        status = document["status"]
        if status in RESOLVABLE_STATUSES and not all(
            key in document
            for key in ("content_object_id", "content_ref", "content_sha256")
        ):
            raise EvidenceContractError(
                "evidence.event.content",
                "$",
                "stored content event requires object ID, ref, and digest",
            )
        if status == "pending" and not all(
            key in document for key in ("content_object_id", "content_ref")
        ):
            raise EvidenceContractError(
                "evidence.event.content",
                "$",
                "pending content event requires object ID and ref",
            )
    if (
        document["status"] in {"not_captured", "unsupported", "dropped", "failed"}
        and "content_object_id" in document
    ):
        raise EvidenceContractError(
            "evidence.event.false_object",
            "$.content_object_id",
            "uncaptured event cannot claim a stored object identity",
        )


def _run_verdict(document: Mapping[str, Any]) -> str:
    scope = document["scope"]
    sources = document["sources"]
    items = document["items"]
    feeds = document["feeds"]
    receipts = document["receipts"]
    if scope["approval_verification"]["method"] != "signature":
        raise EvidenceContractError(
            "evidence.run.scope_approval",
            "$.scope.approval_verification.method",
            "approved scope requires a signature-verification claim",
        )
    _validate_verification_ref(
        scope["approval_verification"],
        document["tenant_id"],
        "$.scope.approval_verification.evidence_ref",
    )
    source_keys: set[tuple[str, int]] = set()
    by_source: dict[str, list[Mapping[str, Any]]] = {}
    partial = False
    unverified = False

    for source in sources:
        key = (source["source_id"], source["epoch"])
        if key in source_keys:
            raise EvidenceContractError(
                "evidence.run.duplicate_source", "$.sources", str(key)
            )
        source_keys.add(key)
        by_source.setdefault(source["source_id"], []).append(source)
        first, high = source["first_sequence"], source["high_water"]
        observed = source["observed_sequences"]
        if (
            high < first
            or observed != sorted(observed)
            or any(seq < first or seq > high for seq in observed)
        ):
            raise EvidenceContractError(
                "evidence.run.sequence",
                "$.sources",
                "invalid source sequence range/order",
            )
        if source["loss_count"] < (
            source["sampled_count"]
            + source["rate_limited_count"]
            + source["overflow_count"]
        ):
            raise EvidenceContractError(
                "evidence.run.loss_counters",
                "$.sources",
                "total known loss cannot be lower than categorized losses",
            )
        if source["start_sequence"] != first or first not in observed:
            raise EvidenceContractError(
                "evidence.run.start",
                "$.sources",
                "source epoch needs an observed start marker at first sequence",
            )
        if source["health"] == "complete" and (
            source["terminal_sequence"] not in observed
            or source["terminal_sequence"] != high
            or _timestamp(source["stopped_at"]) < _timestamp(source["started_at"])
        ):
            raise EvidenceContractError(
                "evidence.run.terminal",
                "$.sources",
                "complete epoch needs an observed terminal marker at high-water",
            )
        if source.get("identity_verification"):
            if source["identity_verification"]["verifier_id"] == source["source_id"]:
                raise EvidenceContractError(
                    "evidence.run.self_verified_source",
                    "$.sources.identity_verification",
                    "a source cannot verify its own workload identity",
                )
            _validate_verification_ref(
                source["identity_verification"],
                document["tenant_id"],
                "$.sources.identity_verification.evidence_ref",
            )
        if observed != list(range(first, high + 1)):
            partial = True
        if source["loss_count"] or source["health"] == "missing":
            partial = True
        if source["health"] == "unknown" or source["unknown_loss"]:
            unverified = True
        if source["sampling_enabled"]:
            partial = True
        if not source["identity_verified"]:
            unverified = True

    if not set(scope["required_source_ids"]) <= set(by_source):
        partial = True

    observed_ids: set[str] = set()
    observed_positions: set[tuple[str, int, int]] = set()
    roles: set[str] = set()
    receipt_ids: set[str] = set()
    durable_content: set[tuple[str, str]] = set()
    durable_events: set[str] = set()
    for receipt in receipts:
        if receipt["receipt_id"] in receipt_ids:
            raise EvidenceContractError(
                "evidence.run.duplicate_receipt", "$.receipts", receipt["receipt_id"]
            )
        receipt_ids.add(receipt["receipt_id"])
        if (
            receipt["tenant_id"] != document["tenant_id"]
            or receipt["run_id"] != document["run_id"]
        ):
            raise EvidenceContractError(
                "evidence.run.receipt_identity",
                "$.receipts",
                "receipt tenant/run must match manifest",
            )
        expected_issuer_type = {
            "source_spooled": "source",
            "node_accepted": "node",
            "destination_accepted": "destination",
            "destination_durable": "destination",
        }[receipt["stage"]]
        if receipt["issuer_type"] != expected_issuer_type:
            raise EvidenceContractError(
                "evidence.run.receipt_stage",
                "$.receipts",
                "receipt stage must be issued by that delivery boundary",
            )
        if receipt.get("verification"):
            if receipt["verification"]["verifier_id"] == receipt["issuer"]:
                raise EvidenceContractError(
                    "evidence.run.self_verified_receipt",
                    "$.receipts.verification",
                    "receipt issuer cannot verify its own durability claim",
                )
            _validate_verification_ref(
                receipt["verification"],
                document["tenant_id"],
                "$.receipts.verification.evidence_ref",
            )
        if receipt["stage"] == "destination_durable" and receipt["verified"]:
            if receipt["subject_type"] == "content_object":
                durable_content.add((receipt["subject_id"], receipt["subject_sha256"]))
            else:
                durable_events.add(receipt["subject_id"])
    for source in sources:
        if source["start_record_id"] not in durable_events:
            unverified = True
        if (
            source["health"] == "complete"
            and source["terminal_record_id"] not in durable_events
        ):
            unverified = True
    object_ids: set[str] = set()
    for item in items:
        record_id = item["record_id"]
        position = (item["source_id"], item["source_epoch"], item["source_sequence"])
        if record_id in observed_ids or position in observed_positions:
            raise EvidenceContractError(
                "evidence.run.duplicate_item",
                "$.items",
                "record ID and source position must be unique",
            )
        observed_ids.add(record_id)
        observed_positions.add(position)
        matching = [
            source
            for source in by_source.get(item["source_id"], [])
            if source["epoch"] == item["source_epoch"]
        ]
        if (
            len(matching) != 1
            or item["source_sequence"] not in matching[0]["observed_sequences"]
        ):
            raise EvidenceContractError(
                "evidence.run.item_source",
                "$.items",
                "item must bind to an observed source sequence",
            )
        roles.add(item["role"])
        if item.get("content_object_id"):
            if item["content_object_id"] in object_ids:
                raise EvidenceContractError(
                    "evidence.run.duplicate_object",
                    "$.items",
                    "one content descriptor cannot represent two distinct items",
                )
            object_ids.add(item["content_object_id"])
        if item["status"] in BAD_STATUSES:
            partial = True
        elif item["status"] == "stored" and item.get("representation") != "exact":
            partial = True
        elif item["status"] != "stored" or not item["verified"]:
            unverified = True
        if item["status"] == "stored" and (
            (item["content_object_id"], item["content_sha256"]) not in durable_content
        ):
            unverified = True
        if record_id not in durable_events:
            unverified = True
        if item["status"] != "stored" and item["verified"]:
            raise EvidenceContractError(
                "evidence.run.false_verification",
                "$.items",
                "only stored bytes may be verified",
            )

    if not set(scope["required_roles"]) <= roles:
        partial = True
    feed_ids: set[str] = set()
    for feed in feeds:
        if feed["feed_id"] in feed_ids:
            raise EvidenceContractError(
                "evidence.run.duplicate_feed", "$.feeds", feed["feed_id"]
            )
        feed_ids.add(feed["feed_id"])
        if feed["issuer"] in by_source:
            raise EvidenceContractError(
                "evidence.run.feed_independence",
                "$.feeds.issuer",
                "independent feed issuer cannot be a capture source",
            )
        if feed.get("verification"):
            if feed["verification"]["verifier_id"] == feed["issuer"]:
                raise EvidenceContractError(
                    "evidence.run.self_verified_feed",
                    "$.feeds.verification",
                    "feed issuer cannot verify its own reconciliation claim",
                )
            _validate_verification_ref(
                feed["verification"],
                document["tenant_id"],
                "$.feeds.verification.evidence_ref",
            )
        if feed["status"] == "matched" and (
            feed["missing_count"] != 0
            or feed["extra_count"] != 0
            or feed["expected_count"] != feed["matched_count"]
            or feed["observed_count"] != feed["matched_count"]
        ):
            raise EvidenceContractError(
                "evidence.run.false_feed_match",
                "$.feeds",
                "matched feed must reconcile all declared counts",
            )
        if feed["status"] == "mismatch":
            partial = True
        elif feed["status"] == "unavailable":
            unverified = True
    if not set(scope["required_feed_ids"]) <= feed_ids:
        unverified = True
    if partial:
        return "partial"
    if unverified:
        return "unverified"
    return "verified_complete_for_declared_scope"


def validate_document(
    document: Mapping[str, Any], schemas: Mapping[str, Mapping[str, Any]]
) -> None:
    version = document.get("schema_version")
    selected = SCHEMAS.get(version) if isinstance(version, str) else None
    if selected is None:
        raise EvidenceContractError(
            "evidence.unknown_version", "$.schema_version", f"unknown {version!r}"
        )
    schema = schemas[f"{selected[0]}/{selected[1]}"]
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
            document
        ),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        first = errors[0]
        raise EvidenceContractError(
            "evidence.schema",
            "$" + "".join(f".{part}" for part in first.absolute_path),
            first.message,
        )
    known_roles = set(
        schemas["content/schema/content-object-v2.schema.json"]["properties"]["role"][
            "enum"
        ]
    )
    if version == "agent.evidence.source-capability/v1":
        if document["observation_level"] == "content" and not document["roles"]:
            raise EvidenceContractError(
                "evidence.capability.roles",
                "$.roles",
                "content capability needs declared roles",
            )
        if not set(document["roles"]) <= known_roles:
            raise EvidenceContractError(
                "evidence.capability.roles", "$.roles", "unknown content role"
            )
        surfaces = document["surfaces"]
        if (
            {surface["boundary"] for surface in surfaces} != set(document["boundaries"])
            or {surface["operation_class"] for surface in surfaces}
            != set(document["operation_classes"])
            or {role for surface in surfaces for role in surface["roles"]}
            != set(document["roles"])
        ):
            raise EvidenceContractError(
                "evidence.capability.surfaces",
                "$.surfaces",
                "surface boundary, operation and role unions must match declarations",
            )
        for surface in surfaces:
            if surface["observation_level"] == "content" and not surface["roles"]:
                raise EvidenceContractError(
                    "evidence.capability.surfaces",
                    "$.surfaces",
                    "content surface needs roles",
                )
            if surface["observation_level"] != "content" and surface["roles"]:
                raise EvidenceContractError(
                    "evidence.capability.surfaces",
                    "$.surfaces",
                    "metadata-only surface cannot claim content roles",
                )
        if any(surface["observation_level"] == "content" for surface in surfaces) != (
            document["observation_level"] == "content"
        ):
            raise EvidenceContractError(
                "evidence.capability.surfaces",
                "$.observation_level",
                "aggregate content level must match surfaces",
            )
    if version == "agent.evidence.event/v1" and "role" in document:
        if document["role"] not in known_roles:
            raise EvidenceContractError(
                "evidence.event.role", "$.role", "unknown content role"
            )
    if version == "agent.evidence.run-manifest/v1":
        declared_roles = set(document["scope"]["required_roles"])
        item_roles = {item["role"] for item in document["items"]}
        if not (declared_roles | item_roles) <= known_roles:
            raise EvidenceContractError(
                "evidence.run.role", "$.scope.required_roles", "unknown content role"
            )
    if version == "fabric.content-object/v2":
        _validate_content(document)
    elif version == "agent.evidence.event/v1":
        _validate_event(document)
    elif version == "agent.evidence.run-manifest/v1":
        verdict = _run_verdict(document)
        if document["verdict"] != verdict:
            raise EvidenceContractError(
                "evidence.run.verdict",
                "$.verdict",
                f"declared {document['verdict']}, computed {verdict}",
            )


def _validate_binary_fixture(document: Mapping[str, Any], path: Path) -> None:
    if set(document) != {"name", "base64", "byte_length", "sha256"}:
        raise EvidenceContractError(
            "evidence.bytes.shape", str(path), "closed byte fixture fields"
        )
    try:
        raw = base64.b64decode(document["base64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise EvidenceContractError(
            "evidence.bytes.base64", str(path), str(exc)
        ) from exc
    if document["byte_length"] != len(raw) or document["sha256"] != (
        "sha256:" + hashlib.sha256(raw).hexdigest()
    ):
        raise EvidenceContractError(
            "evidence.bytes.digest", str(path), "byte digest/length mismatch"
        )


def _validate_example_binding(repo_root: Path) -> None:
    """Bind the pinned end-to-end fixture set, not arbitrary runtime claims."""

    content = _load(repo_root / ROOTS["content"] / "valid/artifact-after.json")
    event = _load(repo_root / ROOTS["evidence"] / "valid/artifact-event.json")
    start = _load(repo_root / ROOTS["evidence"] / "valid/start-event.json")
    terminal = _load(repo_root / ROOTS["evidence"] / "valid/terminal-event.json")
    run = _load(repo_root / ROOTS["evidence"] / "valid/complete-run.json")
    capability_path = repo_root / ROOTS["evidence"] / "valid/sandbox-capability.json"
    capability = _load(capability_path)
    binary = _load(
        repo_root / ROOTS["content"] / "fixtures/bytes/binary-four-bytes.json"
    )
    source = run["sources"][0]
    item = run["items"][0]
    expected = (
        event["tenant_id"] == content["tenant_id"] == run["tenant_id"]
        and event["run_id"] == content["run_id"] == run["run_id"]
        and event["operation_id"] == content["operation_id"]
        and event["record_id"] == item["record_id"]
        and event["content_object_id"]
        == content["object_id"]
        == item["content_object_id"]
        and event["content_ref"] == content["ref"]
        and event["content_sha256"]
        == content["stored_sha256"]
        == item["content_sha256"]
        == binary["sha256"]
        and content["stored_byte_length"] == binary["byte_length"]
        and event["role"] == content["role"] == item["role"]
        and event["status"] == content["status"] == item["status"]
        and content["representation"] == item["representation"]
        and event["boundary"] == content["boundary"] == capability["boundaries"][0]
        and (event["source_id"], event["source_epoch"], event["source_sequence"])
        == (content["source_id"], content["source_epoch"], content["source_sequence"])
        == (item["source_id"], item["source_epoch"], item["source_sequence"])
        and (source["source_id"], source["epoch"])
        == (item["source_id"], item["source_epoch"])
        and source["capability_id"] == capability["connector_id"]
        and source["capability_version"] == capability["version"]
        and source["capability_sha256"] == "sha256:" + _digest(capability_path)
        and item["role"] in capability["roles"]
        and capability["sampling"] == "off"
        and start["record_id"] == source["start_record_id"]
        and start["coverage_phase"] == "start"
        and start["source_sequence"] == source["start_sequence"]
        and start["source_id"] == source["source_id"]
        and start["source_epoch"] == source["epoch"]
        and start["tenant_id"] == run["tenant_id"]
        and start["run_id"] == run["run_id"]
        and terminal["record_id"] == source["terminal_record_id"]
        and terminal["coverage_phase"] == "stop"
        and terminal["source_sequence"] == source["terminal_sequence"]
        and terminal["source_id"] == source["source_id"]
        and terminal["source_epoch"] == source["epoch"]
        and terminal["tenant_id"] == run["tenant_id"]
        and terminal["run_id"] == run["run_id"]
        and {
            (receipt["subject_type"], receipt["subject_id"], receipt["subject_sha256"])
            for receipt in run["receipts"]
        }
        == {
            ("content_object", content["object_id"], content["stored_sha256"]),
            (
                "evidence_event",
                start["record_id"],
                "sha256:"
                + _digest(repo_root / ROOTS["evidence"] / "valid/start-event.json"),
            ),
            (
                "evidence_event",
                event["record_id"],
                "sha256:"
                + _digest(repo_root / ROOTS["evidence"] / "valid/artifact-event.json"),
            ),
            (
                "evidence_event",
                terminal["record_id"],
                "sha256:"
                + _digest(repo_root / ROOTS["evidence"] / "valid/terminal-event.json"),
            ),
        }
    )
    if not expected:
        raise EvidenceContractError(
            "evidence.fixture.binding",
            "$",
            "pinned byte/event/capability/run fixture identities diverge",
        )
    terminal_content = _load(
        repo_root / ROOTS["content"] / "valid/caller-terminal-chunk.json"
    )
    terminal_bytes = _load(
        repo_root / ROOTS["content"] / "fixtures/bytes/binary-terminal-five-bytes.json"
    )
    if not (
        terminal_content["role"] == "terminal.stdout"
        and terminal_content["provenance"] == "caller_reported"
        and terminal_content["representation"] == "exact"
        and terminal_content["source_sha256"]
        == terminal_content["stored_sha256"]
        == terminal_bytes["sha256"]
        and terminal_content["source_byte_length"]
        == terminal_content["stored_byte_length"]
        == terminal_bytes["byte_length"]
    ):
        raise EvidenceContractError(
            "evidence.fixture.binding",
            "$",
            "pinned caller-reported terminal byte fixture diverges",
        )


def validate_contracts(repo_root: Path) -> list[str]:
    """Validate every pinned contract artifact and negative fixture."""

    schemas: dict[str, Mapping[str, Any]] = {}
    artifacts: list[tuple[str, Path, Mapping[str, Any]]] = []
    for family, relative_root in ROOTS.items():
        root = repo_root / relative_root
        manifest = _load(root / "manifest.json")
        if set(manifest) != {"contract", "version", "digest_scope", "artifacts"}:
            raise EvidenceContractError(
                "evidence.manifest.shape", str(root), "closed manifest fields"
            )
        if (manifest["contract"], manifest["version"], manifest["digest_scope"]) != (
            f"singleaxis.fabric.{family}",
            "1.0.0" if family == "evidence" else "2.0.0",
            "exact_file_bytes",
        ):
            raise EvidenceContractError(
                "evidence.manifest.identity", str(root), "wrong identity"
            )
        if not isinstance(manifest["artifacts"], list) or not manifest["artifacts"]:
            raise EvidenceContractError(
                "evidence.manifest.artifacts",
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
                raise EvidenceContractError(
                    "evidence.manifest.record", str(root), "closed artifact fields"
                )
            rel = record["path"]
            if not isinstance(rel, str) or not rel:
                raise EvidenceContractError(
                    "evidence.manifest.path",
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
                raise EvidenceContractError(
                    "evidence.manifest.record", rel, "invalid expectation/error binding"
                )
            sha256 = record["sha256"]
            if (
                not isinstance(sha256, str)
                or len(sha256) != 64
                or any(character not in "0123456789abcdef" for character in sha256)
            ):
                raise EvidenceContractError(
                    "evidence.manifest.record", rel, "sha256 must be lowercase hex"
                )
            posix = PurePosixPath(rel)
            if (
                posix.is_absolute()
                or posix.as_posix() != rel
                or "\\" in rel
                or ".." in posix.parts
                or rel in seen
            ):
                raise EvidenceContractError(
                    "evidence.manifest.path", str(rel), "unsafe/duplicate path"
                )
            seen.add(rel)
            path = root.joinpath(*posix.parts)
            cursor = root
            has_symlink = False
            for part in posix.parts:
                cursor = cursor / part
                has_symlink = has_symlink or cursor.is_symlink()
            if not path.is_file() or has_symlink or _digest(path) != record["sha256"]:
                raise EvidenceContractError(
                    "evidence.manifest.digest", rel, "missing or modified artifact"
                )
            artifacts.append((family, path, record))
        actual = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*.json")
            if path.name != "manifest.json"
        }
        if actual != seen:
            raise EvidenceContractError(
                "evidence.manifest.coverage",
                str(root),
                f"unpinned JSON: {sorted(actual ^ seen)}",
            )
    for family, path, record in artifacts:
        if record["expectation"] == "schema":
            schema = _load(path)
            Draft202012Validator.check_schema(schema)
            schemas[f"{family}/{record['path']}"] = schema
    required = {f"{family}/{rel}" for family, rel in SCHEMAS.values()}
    if not required <= set(schemas):
        raise EvidenceContractError(
            "evidence.manifest.schemas",
            "$",
            f"missing schemas: {sorted(required - set(schemas))}",
        )
    validated: list[str] = []
    for family, path, record in artifacts:
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
            except EvidenceContractError as exc:
                if exc.code != record["expected_error"]:
                    raise EvidenceContractError(
                        "evidence.fixture.wrong_error",
                        str(path),
                        f"expected {record['expected_error']}, got {exc.code}",
                    ) from exc
            else:
                raise EvidenceContractError(
                    "evidence.fixture.accepted", str(path), "invalid fixture accepted"
                )
        else:
            raise EvidenceContractError(
                "evidence.manifest.expectation", str(path), f"unknown {expectation}"
            )
        validated.append(f"{family}/{record['path']}")
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
    except EvidenceContractError as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"validated {len(paths)} pinned evidence/content-v2 artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
