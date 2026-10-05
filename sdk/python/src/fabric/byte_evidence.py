# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Explicit, opt-in content-v2 byte evidence capture.

The default is a bounded process-memory handoff. An explicitly configured
DurableByteSpool adds encrypted protected-byte admission and restartable replay;
passive capture still returns pending, never a durability acknowledgement.
This is not automatic terminal/SSH/database interception. Callers must publish and
reconcile the returned descriptors through their own evidence pipeline.
Only a caller-reported provenance is supportable from this SDK surface.
"""

from __future__ import annotations

import copy
import hashlib
import queue
import re
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

from .byte_spool import ByteSpoolAdmissionError, DurableByteSpool
from .content_store.base import ByteEvidenceStore, check_safe_identifier
from .deployment_policy import ContentProtector, DeploymentPolicy

_ROLES = frozenset(
    {
        "model.request.instructions",
        "model.request.messages",
        "model.request.tool_definitions",
        "model.request.parameters",
        "model.output.messages",
        "tool.definition",
        "tool.call.arguments",
        "tool.call.result",
        "retrieval.query",
        "retrieval.results",
        "memory.write.content",
        "memory.read.content",
        "side_effect.request",
        "side_effect.result",
        "context.file",
        "interaction.payload",
        "terminal.argv",
        "terminal.stdin",
        "terminal.stdout",
        "terminal.stderr",
        "remote.request",
        "remote.result",
        "remote.stream",
        "database.query",
        "database.parameters",
        "database.rows",
        "database.mutation",
        "network.request",
        "network.response",
        "network.stream",
        "sandbox.config",
        "sandbox.output",
        "artifact.before",
        "artifact.after",
        "service.receipt",
    }
)
_BOUNDARIES = frozenset(
    {"caller", "provider_bound", "tool", "terminal", "sandbox", "remote", "host", "service"}
)
_MEDIA_TYPE_RE = re.compile(r"^[a-zA-Z0-9!#$&^_.+-]+/[a-zA-Z0-9!#$&^_.+-]+$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_MEDIA_TYPE_MAX_LENGTH = 128
_OPAQUE_ID_MAX_LENGTH = 128


def _validate_capture_args(
    data: bytes,
    *,
    role: str,
    boundary: str,
    source_id: str,
    source_epoch: int,
    source_sequence: int,
    media_type: str,
    run_id: str | None,
    operation_id: str | None,
    attempt_id: str | None,
    stream_id: str | None,
    chunk_index: int | None,
) -> None:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes; no implicit text conversion")
    if role not in _ROLES:
        raise ValueError("role is not a content-v2 role")
    if boundary not in _BOUNDARIES:
        raise ValueError("boundary is not a content-v2 boundary")
    for name, value in (
        ("source_id", source_id),
        ("run_id", run_id),
        ("operation_id", operation_id),
        ("attempt_id", attempt_id),
        ("stream_id", stream_id),
    ):
        if value is not None and (
            not isinstance(value, str)
            or len(value) > _OPAQUE_ID_MAX_LENGTH
            or not _ID_RE.fullmatch(value)
        ):
            raise ValueError(f"{name} must be a content-v2 opaque identifier")
    if not source_id:
        raise ValueError("source_id is required")
    for counter_name, counter_value in (
        ("source_epoch", source_epoch),
        ("source_sequence", source_sequence),
    ):
        if (
            not isinstance(counter_value, int)
            or isinstance(counter_value, bool)
            or counter_value < 0
        ):
            raise ValueError(f"{counter_name} must be a non-negative integer")
    if chunk_index is not None:
        if stream_id is None:
            raise ValueError("chunk_index requires stream_id")
        if not isinstance(chunk_index, int) or isinstance(chunk_index, bool) or chunk_index < 0:
            raise ValueError("chunk_index must be a non-negative integer")
    if (
        not isinstance(media_type, str)
        or len(media_type) > _MEDIA_TYPE_MAX_LENGTH
        or not _MEDIA_TYPE_RE.fullmatch(media_type)
    ):
        raise ValueError("media_type must be a valid MIME type")


@dataclass(frozen=True, slots=True)
class BytePrivacyPolicy:
    """Customer-approved content handling; transformations run on the writer thread.

    A transform is customer code, not a built-in PII detector. Masked descriptors
    omit the original digest to avoid revealing low-entropy original values.
    Raw queued memory stays inside the customer's approved capture boundary.
    """

    mode: str = "original"
    transform: Callable[[bytes], bytes] | None = None
    transformation_id: str | None = None
    transformation_version: str | None = None

    def __post_init__(self) -> None:
        if self.mode not in {"original", "omit", "masked_only", "original_plus_masked"}:
            raise ValueError("unsupported byte privacy mode")
        masked = self.mode in {"masked_only", "original_plus_masked"}
        if masked and not callable(self.transform):
            raise ValueError("masked modes require a customer transformation")
        for value in (self.transformation_id, self.transformation_version):
            if masked and (
                not isinstance(value, str)
                or len(value) > _OPAQUE_ID_MAX_LENGTH
                or not _ID_RE.fullmatch(value)
            ):
                raise ValueError("masked modes require opaque transformation identity and version")
        if not masked and any(
            value is not None
            for value in (self.transform, self.transformation_id, self.transformation_version)
        ):
            raise ValueError("transformation settings require a masked mode")


def _validate_store_separation(original: ByteEvidenceStore, review: ByteEvidenceStore) -> None:
    probe = "00000000-0000-4000-8000-000000000000"
    original_ref = original.evidence_ref_for(probe)
    review_ref = review.evidence_ref_for(probe)
    if original_ref == review_ref:
        raise ValueError("original and review store namespaces must differ")
    # Distinct refs are insufficient when one configured resolver can read the
    # other's nested namespace. Arbitrary customer stores still need IAM proof.
    for store, other_ref in ((original, review_ref), (review, original_ref)):
        owns_uri = getattr(store, "owns_uri", None)
        if callable(owns_uri) and owns_uri(other_ref):
            raise ValueError("original and review store resolver namespaces must not overlap")


@dataclass(frozen=True, slots=True)
class ByteEvidenceConfig:
    """An explicit role policy and bounded, asynchronous byte destination."""

    store: ByteEvidenceStore
    roles: frozenset[str]
    payload_max_bytes: int = 1024 * 1024
    queue_max_items: int = 64
    max_records: int = 4096
    role_policies: Mapping[str, BytePrivacyPolicy] | None = None
    review_store: ByteEvidenceStore | None = None
    deployment_policy: DeploymentPolicy | None = None
    content_protector: ContentProtector | None = None
    durable_spool: DurableByteSpool | None = None

    def __post_init__(self) -> None:  # noqa: PLR0912
        if not isinstance(self.store, ByteEvidenceStore) or not self.store.tenant_id:
            raise ValueError("byte evidence requires a tenant-scoped byte evidence store")
        check_safe_identifier("tenant_id", self.store.tenant_id)
        if self.durable_spool is not None and (
            not isinstance(self.durable_spool, DurableByteSpool)
            or self.durable_spool.tenant_id != self.store.tenant_id
        ):
            raise ValueError("durable byte spool must match the byte store tenant")
        if not self.roles or not isinstance(self.roles, frozenset) or self.roles - _ROLES:
            raise ValueError("roles must be a non-empty frozenset of content-v2 roles")
        if self.content_protector is not None and self.deployment_policy is None:
            object.__setattr__(self, "deployment_policy", self.content_protector.policy)
        if self.deployment_policy is not None:
            deployment = self.deployment_policy
            if (
                not isinstance(deployment, DeploymentPolicy)
                or deployment.tenant_id != self.store.tenant_id
            ):
                raise ValueError("deployment policy must match byte store tenant")
            if self.role_policies:
                raise ValueError("deployment_policy and role_policies cannot be combined")
            protector = self.content_protector or ContentProtector(
                deployment, payload_max_bytes=self.payload_max_bytes
            )
            if protector.policy.digest != deployment.digest:
                raise ValueError("content protector must match deployment policy")
            object.__setattr__(self, "content_protector", protector)
            if any(deployment.privacy.get(role) in {"redact", "tokenize"} for role in self.roles):
                if (
                    not isinstance(self.review_store, ByteEvidenceStore)
                    or self.review_store.tenant_id != self.store.tenant_id
                ):
                    raise ValueError("deployment derivatives require a same-tenant review store")
                _validate_store_separation(self.store, self.review_store)
        policies = dict(self.role_policies or {})
        if policies.keys() - self.roles or any(
            not isinstance(policy, BytePrivacyPolicy) for policy in policies.values()
        ):
            raise ValueError(
                "role_policies must contain enabled roles and BytePrivacyPolicy values"
            )
        object.__setattr__(self, "role_policies", MappingProxyType(policies))
        if any(policy.mode == "original_plus_masked" for policy in policies.values()):
            if (
                not isinstance(self.review_store, ByteEvidenceStore)
                or self.review_store.tenant_id != self.store.tenant_id
            ):
                raise ValueError(
                    "original_plus_masked requires a separate same-tenant review store"
                )
            _validate_store_separation(self.store, self.review_store)
        for name, value, maximum in (
            ("payload_max_bytes", self.payload_max_bytes, 16 * 1024 * 1024),
            ("queue_max_items", self.queue_max_items, 65536),
            ("max_records", self.max_records, 1000000),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= maximum:
                raise ValueError(f"{name} must be between 1 and {maximum}")


class ByteEvidenceRecorder:
    """Record explicitly observed bytes; never place content on OTLP.

    ``capture`` returns an initial descriptor. ``get`` returns its latest
    settlement. Both the queue and retained record index are bounded;
    overflow is reported as ``dropped``. ``flush`` only confirms local store
    settlement, not downstream receipt or immutable retention.
    """

    def __init__(self, config: ByteEvidenceConfig) -> None:
        self._config = config
        self._queue: queue.Queue[tuple[str, bytes, str | None]] = queue.Queue(
            maxsize=config.queue_max_items
        )
        self._records: dict[str, dict[str, Any]] = {}
        self._condition = threading.Condition()
        self._closed = False
        self._pending = 0
        self._unretained_drops = 0
        self._spool = config.durable_spool
        if self._spool is not None:
            recovered_ids = self._spool.object_ids()
            if len(recovered_ids) > config.max_records:
                raise ValueError("recovered byte spool exceeds recorder index capacity")
            for key in recovered_ids:
                recovered = self._spool.descriptor(key)
                if recovered is not None:
                    self._records[key] = recovered
            self._spool.bind(config.store, config.review_store)
        self._worker = threading.Thread(target=self._run, name="fabric-byte-evidence", daemon=True)
        self._worker.start()

    @property
    def tenant_id(self) -> str:
        """Tenant bound to the configured content store."""
        tenant_id = self._config.store.tenant_id
        if tenant_id is None:
            raise ValueError("byte evidence store lost its tenant binding")
        return tenant_id

    def capture(  # noqa: PLR0912, PLR0915
        self,
        data: bytes,
        *,
        role: str,
        boundary: str,
        source_id: str,
        source_epoch: int,
        source_sequence: int,
        media_type: str = "application/octet-stream",
        run_id: str | None = None,
        operation_id: str | None = None,
        attempt_id: str | None = None,
        stream_id: str | None = None,
        chunk_index: int | None = None,
    ) -> dict[str, Any]:
        """Handoff one exact byte buffer; return a copy of initial status.

        Invalid API arguments raise before any mutation. Resource failures
        and a closed writer become explicit non-stored descriptors.
        """
        _validate_capture_args(
            data,
            role=role,
            boundary=boundary,
            source_id=source_id,
            source_epoch=source_epoch,
            source_sequence=source_sequence,
            media_type=media_type,
            run_id=run_id,
            operation_id=operation_id,
            attempt_id=attempt_id,
            stream_id=stream_id,
            chunk_index=chunk_index,
        )

        object_id = str(uuid.uuid4())
        policy = (self._config.role_policies or {}).get(role, BytePrivacyPolicy())
        enabled = role in self._config.roles and policy.mode != "omit"
        protected = None
        if self._config.content_protector is not None:
            # Protection runs before the handoff. Only permitted bytes enter the queue.
            protected = self._config.content_protector.protect(role if enabled else "", data)
            enabled = enabled and protected.protected_bytes is not None
        # Neither omitted nor masked-only content exposes the original fingerprint.
        digest = (
            "sha256:" + hashlib.sha256(data).hexdigest()
            if protected is None and enabled and policy.mode != "masked_only"
            else None
        )
        descriptor: dict[str, Any] = {
            "schema_version": "fabric.content-object/v2",
            "object_id": object_id,
            "tenant_id": self._config.store.tenant_id,
            "role": role,
            "media_type": media_type,
            "encoding": "binary",
            "representation": "exact" if digest is not None else "unavailable",
            "transformations": [],
            "provenance": "caller_reported",
            "boundary": boundary,
            "source_id": source_id,
            "source_epoch": source_epoch,
            "source_sequence": source_sequence,
            "captured_at": datetime.now(UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "status": "pending",
        }
        if role in (self._config.role_policies or {}):
            descriptor["privacy_mode"] = policy.mode
        if enabled and protected is None:
            descriptor["source_byte_length"] = len(data)
        if enabled and policy.mode == "masked_only":
            descriptor.update(
                representation="redacted",
                transformations=["redact"],
                transformation_id=policy.transformation_id,
                transformation_version=policy.transformation_version,
            )
        if digest is not None:
            descriptor["source_byte_length"] = len(data)
            descriptor["source_sha256"] = digest
        if protected is not None:
            deployment = self._config.deployment_policy
            if deployment is None:  # validated configuration
                raise ValueError("missing deployment policy")
            descriptor.update(
                workload_id=deployment.workload_id,
                policy_digest=deployment.digest,
                policy_id=deployment.policy_id,
                policy_version=deployment.policy_version,
                privacy_mode=protected.mode,
                protection_status=protected.status,
            )
            if "source_byte_length" in protected.metadata:
                descriptor["source_byte_length"] = protected.metadata["source_byte_length"]
            if protected.original_digest is not None:
                descriptor.update(source_sha256=protected.original_digest, representation="exact")
            if protected.status in {"redacted", "tokenized"}:
                descriptor.update(
                    representation=protected.status,
                    transformations=["redact" if protected.status == "redacted" else "tokenize"],
                )
            if protected.protected_bytes is not None:
                data = protected.protected_bytes
        for key, value in (
            ("run_id", run_id),
            ("operation_id", operation_id),
            ("attempt_id", attempt_id),
            ("stream_id", stream_id),
        ):
            if value is not None:
                descriptor[key] = value
        if chunk_index is not None:
            descriptor["chunk_index"] = chunk_index
        with self._condition:
            required_slots = 2 if enabled and policy.mode == "original_plus_masked" else 1
            if len(self._records) + required_slots > self._config.max_records:
                descriptor.update(
                    status="dropped",
                    representation="unavailable",
                    status_reason="record_index_full",
                )
                self._unretained_drops += 1
                return copy.deepcopy(descriptor)
            if not enabled and protected is not None:
                descriptor.update(
                    status={"lost": "failed", "unsupported": "unsupported"}.get(
                        protected.status, "not_captured"
                    ),
                    representation="unavailable",
                    status_reason=protected.metadata["reason"],
                )
            elif not enabled:
                descriptor.update(
                    status="not_captured",
                    representation="unavailable",
                    status_reason="privacy_omitted"
                    if policy.mode == "omit"
                    else "outside_capture_policy",
                )
            elif len(data) > self._config.payload_max_bytes:
                descriptor.update(
                    status="dropped",
                    representation="unavailable",
                    status_reason="payload_too_large",
                )
            elif self._closed:
                descriptor.update(
                    status="failed", representation="unavailable", status_reason="recorder_closed"
                )
            else:
                try:
                    self._enqueue(descriptor, data, policy)
                except Exception:
                    # Prospective refs may authenticate a short-lived capability.
                    # Failure before admission must remain a passive evidence gap,
                    # with no stale ref or customer exception text retained.
                    descriptor.pop("ref", None)
                    descriptor.update(
                        status="failed",
                        representation="unavailable",
                        status_reason="store_reference_failed",
                    )
            self._records[object_id] = descriptor
            return copy.deepcopy(descriptor)

    def _enqueue(self, descriptor: dict[str, Any], data: bytes, policy: BytePrivacyPolicy) -> None:
        object_id = descriptor["object_id"]
        store = self._config.store
        if self._config.deployment_policy is not None and descriptor.get("protection_status") in {
            "redacted",
            "tokenized",
        }:
            store = self._config.review_store or store
        descriptor["ref"] = store.evidence_ref_for(object_id)
        derivative_id = None
        if policy.mode == "original_plus_masked":
            derivative_id = str(uuid.uuid4())
            review_store = self._config.review_store
            if review_store is None:  # Configuration was validated before worker startup.
                raise ValueError("missing review store")
            derivative = {
                **descriptor,
                "object_id": derivative_id,
                "ref": review_store.evidence_ref_for(derivative_id),
                "representation": "redacted",
                "transformations": ["redact"],
                "transformation_id": policy.transformation_id,
                "transformation_version": policy.transformation_version,
                "links": [{"relation": "derived_from", "object_id": object_id}],
            }
            derivative.pop("source_sha256", None)
            self._records[derivative_id] = derivative
        try:
            self._queue.put_nowait((object_id, data, derivative_id))
        except queue.Full:
            descriptor.pop("ref")
            descriptor.update(
                status="dropped", representation="unavailable", status_reason="queue_full"
            )
            if derivative_id is not None:
                self._fail_record(derivative_id, "queue_full", status="dropped")
        else:
            self._pending += 1

    def derivatives(self, object_id: str) -> list[dict[str, Any]]:
        """Return linked review objects separately from the original descriptor."""
        with self._condition:
            return [
                self.get(record["object_id"]) or copy.deepcopy(record)
                for record in self._records.values()
                if {"relation": "derived_from", "object_id": object_id} in record.get("links", [])
            ]

    def get(self, object_id: str) -> dict[str, Any] | None:
        """Read the latest local settlement without exposing stored bytes."""
        if self._spool is not None:
            recovered = self._spool.descriptor(object_id)
            if recovered is not None:
                return recovered
        with self._condition:
            descriptor = self._records.get(object_id)
            return copy.deepcopy(descriptor) if descriptor is not None else None

    def drain_settled(self) -> list[dict[str, Any]]:
        """Remove terminal records for publication by the caller."""
        with self._condition:
            if self._spool is not None:
                for key in self._spool.object_ids():
                    recovered = self._spool.descriptor(key)
                    if recovered is not None and key in self._records:
                        self._records[key] = recovered
            settled = [key for key, value in self._records.items() if value["status"] != "pending"]
            return [copy.deepcopy(self._records.pop(key)) for key in settled]

    @property
    def unretained_drops(self) -> int:
        """Number of overflow descriptors returned but absent from ``get``."""
        with self._condition:
            return self._unretained_drops

    def flush(self, timeout_s: float = 10.0) -> bool:
        """Wait for the local byte store to settle all accepted writes."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        with self._condition:
            while self._pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            if self._spool is None:
                return True
        return self._spool.flush(max(0.0, deadline - time.monotonic()))

    def wait_durable(self, timeout_s: float = 10.0) -> bool:
        """Wait for protected local admission, independent of destination outage.

        False means timeout, absent durable configuration, or known admission
        loss. True does not prove all physical source events were captured.
        """
        if self._spool is None:
            return False
        deadline = time.monotonic() + max(0.0, timeout_s)
        with self._condition:
            while self._pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            if self._unretained_drops or any(
                row["status"] in {"failed", "dropped"} for row in self._records.values()
            ):
                return False
            required = [key for key, row in self._records.items() if row["status"] == "pending"]
        return self._spool.all_durable(required, max(0.0, deadline - time.monotonic()))

    def delivery_state(self, object_id: str) -> dict[str, Any]:
        """Separate passive pending, fsynced durable, delivered and loss states.

        Delivered is the configured store's acknowledgement, not an independent
        Node/destination receipt or an immutable-retention claim.
        """
        if self._spool is not None:
            state = self._spool.state(object_id)
            if state["state"] != "unknown":
                return state
        with self._condition:
            row = self._records.get(object_id)
            if row is None:
                return {"state": "unknown", "durable": False}
            state_name = {
                "pending": "pending",
                "stored": "delivered",
                "redacted": "delivered",
                "failed": "lost",
                "dropped": "lost",
            }.get(row["status"], "not_captured")
            return {"state": state_name, "durable": False, "reason": row.get("status_reason")}

    def spool_health(self) -> dict[str, Any]:
        """Read bounded replay health without revealing content or exception text."""
        return self._spool.health() if self._spool is not None else {"enabled": False}

    def close(self, timeout_s: float = 10.0) -> bool:
        deadline = time.monotonic() + max(0.0, timeout_s)
        with self._condition:
            self._closed = True
        complete = self.flush(max(0.0, deadline - time.monotonic()))
        self._worker.join(max(0.0, deadline - time.monotonic()))
        if self._spool is not None:
            stopped = self._spool.close(max(0.0, deadline - time.monotonic()))
            return complete and stopped and not self._worker.is_alive()
        return complete

    def _run(self) -> None:
        while True:
            try:
                object_id, data, derivative_id = self._queue.get(timeout=0.1)
            except queue.Empty:
                with self._condition:
                    if self._closed and self._pending == 0:
                        return
                continue
            try:
                self._process(object_id, data, derivative_id)
            except Exception as exc:
                # Do not log bytes, URIs, or exception text (which may include sensitive paths).
                with self._condition:
                    for record_id in (object_id, derivative_id):
                        if (
                            record_id is not None
                            and self._records.get(record_id, {}).get("status") == "pending"
                        ):
                            self._fail_record(
                                record_id,
                                exc.reason
                                if isinstance(exc, ByteSpoolAdmissionError)
                                else "store_write_failed",
                            )
            finally:
                with self._condition:
                    self._pending -= 1
                    self._condition.notify_all()
                self._queue.task_done()

    def _process(self, object_id: str, data: bytes, derivative_id: str | None) -> None:
        with self._condition:
            role = self._records[object_id]["role"]
        if self._config.deployment_policy is not None:
            mode = self._config.deployment_policy.privacy.get(role, "omit")
            store = (
                self._config.review_store if mode in {"redact", "tokenize"} else self._config.store
            )
            if store is None:
                raise ValueError("missing deployment content store")
            self._write_record(object_id, data, store)
            return
        policy = (self._config.role_policies or {}).get(role, BytePrivacyPolicy())
        transformed = None
        if policy.transform is not None:
            try:
                transformed = policy.transform(data)
                if not isinstance(transformed, bytes):
                    raise TypeError("transform must return bytes")
                if len(transformed) > self._config.payload_max_bytes:
                    raise ValueError("transformed payload too large")
            except Exception:
                with self._condition:
                    self._fail_record(object_id, "privacy_transform_failed")
                    if derivative_id is not None:
                        self._fail_record(derivative_id, "privacy_transform_failed")
                return
        payload = transformed if policy.mode == "masked_only" else data
        if payload is None:
            raise ValueError("missing transformed content")
        self._write_record(object_id, payload, self._config.store)
        if derivative_id is not None:
            if transformed is None or self._config.review_store is None:
                raise ValueError("missing transformed content or review store")
            self._write_record(derivative_id, transformed, self._config.review_store)

    def _fail_record(self, object_id: str, reason: str, *, status: str = "failed") -> None:
        descriptor = self._records[object_id]
        for key in ("ref", "stored_byte_length", "stored_sha256"):
            descriptor.pop(key, None)
        descriptor.update(status=status, status_reason=reason, representation="unavailable")

    def _write_record(self, object_id: str, data: bytes, store: ByteEvidenceStore) -> None:
        with self._condition:
            descriptor = self._records[object_id]
            stored = {
                **descriptor,
                "status": "redacted"
                if descriptor["representation"] in {"redacted", "tokenized"}
                else "stored",
                "stored_byte_length": len(data),
                "stored_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
            }
        if self._spool is not None:
            self._spool.admit(
                stored, data, route="review" if store is self._config.review_store else "original"
            )
            return
        result = store.put_bytes_object(stored, data)
        if (
            result.uri != stored["ref"]
            or result.content_hash != stored["stored_sha256"].split(":", 1)[1]
        ):
            raise ValueError("byte store returned a mismatched content reference")
        with self._condition:
            self._records[object_id] = stored
