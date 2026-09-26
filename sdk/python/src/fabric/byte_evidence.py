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
from dataclasses import dataclass
from datetime import UTC, datetime
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
class ByteEvidenceConfig:
    """An explicit role policy and bounded, asynchronous byte destination."""

    store: ByteEvidenceStore
    roles: frozenset[str]
    payload_max_bytes: int = 1024 * 1024
    queue_max_items: int = 64
    max_records: int = 4096

    def __post_init__(self) -> None:
        if not isinstance(self.store, ByteEvidenceStore) or not self.store.tenant_id:
            raise ValueError("byte evidence requires a tenant-scoped byte evidence store")
        check_safe_identifier("tenant_id", self.store.tenant_id)
        if not self.roles or not isinstance(self.roles, frozenset) or self.roles - _ROLES:
            raise ValueError("roles must be a non-empty frozenset of content-v2 roles")
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
        self._queue: queue.Queue[tuple[str, bytes]] = queue.Queue(maxsize=config.queue_max_items)
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
        return self._config.store.tenant_id

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
        # An excluded role must not even produce a content fingerprint.
        digest = (
            "sha256:" + hashlib.sha256(data).hexdigest() if role in self._config.roles else None
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
            if role not in self._config.roles:
                descriptor.update(
                    status="not_captured",
                    representation="unavailable",
                    status_reason="outside_capture_policy",
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
            elif len(self._records) >= self._config.max_records:
                descriptor.update(
                    status="dropped",
                    representation="unavailable",
                    status_reason="record_index_full",
                )
                self._unretained_drops += 1
                return copy.deepcopy(descriptor)
            else:
                descriptor["ref"] = self._config.store.evidence_ref_for(object_id)
                try:
                    self._queue.put_nowait((object_id, data))
                except queue.Full:
                    descriptor.pop("ref")
                    descriptor.update(
                        status="dropped", representation="unavailable", status_reason="queue_full"
                    )
                else:
                    self._pending += 1
            self._records[object_id] = descriptor
            return copy.deepcopy(descriptor)

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
                object_id, data = self._queue.get(timeout=0.1)
            except queue.Empty:
                with self._condition:
                    if self._closed and self._pending == 0:
                        return
                continue
            try:
                with self._condition:
                    descriptor = self._records[object_id]
                    stored = {
                        **descriptor,
                        "status": "stored",
                        "stored_byte_length": len(data),
                        "stored_sha256": descriptor["source_sha256"],
                    }
                result = self._config.store.put_bytes_object(stored, data)
                if (
                    result.uri != stored["ref"]
                    or result.content_hash != stored["source_sha256"].split(":", 1)[1]
                ):
                    raise ValueError("byte store returned a mismatched content reference")
                with self._condition:
                    self._records[object_id] = stored
            except Exception:
                # Do not log bytes, URIs, or exception text (which may include sensitive paths).
                with self._condition:
                    failed = self._records[object_id]
                    failed.pop("ref", None)
                    failed.update(
                        status="failed",
                        status_reason="store_write_failed",
                        representation="unavailable",
                    )
            finally:
                with self._condition:
                    self._pending -= 1
                    self._condition.notify_all()
                self._queue.task_done()
