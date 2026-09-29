# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Explicit, opt-in content-v2 byte evidence capture.

This is a bounded *process-memory* handoff, not a durable audit channel or
automatic terminal/SSH/database interception. Callers must publish and
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

from .content_store.base import ByteEvidenceStore, check_safe_identifier

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
        if value is not None and (not isinstance(value, str) or not _ID_RE.fullmatch(value)):
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

    def __post_init__(self) -> None:
        if not isinstance(self.store, ByteEvidenceStore) or not self.store.tenant_id:
            raise ValueError("byte evidence requires a tenant-scoped byte evidence store")
        check_safe_identifier("tenant_id", self.store.tenant_id)
        if not self.roles or not isinstance(self.roles, frozenset) or self.roles - _ROLES:
            raise ValueError("roles must be a non-empty frozenset of content-v2 roles")
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
            probe = "00000000-0000-4000-8000-000000000000"
            original_ref = self.store.evidence_ref_for(probe)
            review_ref = self.review_store.evidence_ref_for(probe)
            if original_ref == review_ref:
                raise ValueError("original and review stores must have distinct namespaces")
            # Bundled resolvers expose owns_uri. Reject overlap there as well;
            # IAM separation for arbitrary customer stores needs deployment proof.
            for store, other_ref in ((self.store, review_ref), (self.review_store, original_ref)):
                owns_uri = getattr(store, "owns_uri", None)
                if callable(owns_uri) and owns_uri(other_ref):
                    raise ValueError(
                        "original and review store resolver namespaces must not overlap"
                    )
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
        self._worker = threading.Thread(target=self._run, name="fabric-byte-evidence", daemon=True)
        self._worker.start()

    @property
    def tenant_id(self) -> str:
        """Tenant bound to the configured content store."""
        tenant_id = self._config.store.tenant_id
        if tenant_id is None:
            raise ValueError("byte evidence store lost its tenant binding")
        return tenant_id

    def capture(
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
        # Neither omitted nor masked-only content exposes the original fingerprint.
        digest = (
            "sha256:" + hashlib.sha256(data).hexdigest()
            if enabled and policy.mode != "masked_only"
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
        if enabled:
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
            if not enabled:
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
                self._enqueue(descriptor, data, policy)
            self._records[object_id] = descriptor
            return copy.deepcopy(descriptor)

    def _enqueue(self, descriptor: dict[str, Any], data: bytes, policy: BytePrivacyPolicy) -> None:
        object_id = descriptor["object_id"]
        descriptor["ref"] = self._config.store.evidence_ref_for(object_id)
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
                copy.deepcopy(record)
                for record in self._records.values()
                if {"relation": "derived_from", "object_id": object_id} in record.get("links", [])
            ]

    def get(self, object_id: str) -> dict[str, Any] | None:
        """Read the latest local settlement without exposing stored bytes."""
        with self._condition:
            descriptor = self._records.get(object_id)
            return copy.deepcopy(descriptor) if descriptor is not None else None

    def drain_settled(self) -> list[dict[str, Any]]:
        """Remove terminal records for publication by the caller."""
        with self._condition:
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
            return True

    def close(self, timeout_s: float = 10.0) -> bool:
        with self._condition:
            self._closed = True
        complete = self.flush(timeout_s)
        self._worker.join(timeout=0 if not complete else min(timeout_s, 1.0))
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
            except Exception:
                # Do not log bytes, URIs, or exception text (which may include sensitive paths).
                with self._condition:
                    for record_id in (object_id, derivative_id):
                        if (
                            record_id is not None
                            and self._records.get(record_id, {}).get("status") == "pending"
                        ):
                            self._fail_record(record_id, "store_write_failed")
            finally:
                with self._condition:
                    self._pending -= 1
                    self._condition.notify_all()
                self._queue.task_done()

    def _process(self, object_id: str, data: bytes, derivative_id: str | None) -> None:
        with self._condition:
            role = self._records[object_id]["role"]
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
                "status": "redacted" if descriptor["representation"] == "redacted" else "stored",
                "stored_byte_length": len(data),
                "stored_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
            }
        result = store.put_bytes_object(stored, data)
        if (
            result.uri != stored["ref"]
            or result.content_hash != stored["stored_sha256"].split(":", 1)[1]
        ):
            raise ValueError("byte store returned a mismatched content reference")
        with self._condition:
            self._records[object_id] = stored
