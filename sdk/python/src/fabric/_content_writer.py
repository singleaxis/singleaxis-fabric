# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Passive asynchronous content writer (spec 032).

Moves object-store I/O off the agent's execution path. Three durability
modes:

- ``inline``: write on the caller's thread (legacy ``content_store=``
  semantics; no loss window but store latency is on the agent path).
- ``process``: bounded in-process queue + background worker. Process
  death loses queued, unwritten objects — the documented loss window.
- ``spooled``: fsync'd spool entry on enqueue, then the worker uploads.
  Only a crash before the spool fsync returns can lose content.

A nonblocking enqueue is NOT a durable acknowledgment; ``flush`` /
``close`` and the manifest's per-item statuses are how a consumer learns
what actually landed.
"""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import os
import queue
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ._content import ContentDescriptor, ContentStatus

if TYPE_CHECKING:
    from .content_store.base import GovernedStore

_LOG = logging.getLogger("fabric.content_writer")

_DURABILITY_MODES = frozenset({"inline", "process", "spooled"})
_QUEUE_MAX_CAP = 65536
_PAYLOAD_MAX_CAP = 16 * 1024 * 1024
_ENQUEUE_TIMEOUT_CAP_MS = 100


@dataclass(frozen=True, slots=True)
class ContentCaptureConfig:
    """Explicit governed-content activation (spec 028).

    Requires all three of: a governed ``store``, a capture policy
    (``roles`` — ``"all"`` or an explicit set of spec-028 role names),
    and a ``durability`` mode. ``spooled`` additionally requires
    ``spool_dir``. Anything missing fails closed at construction.
    """

    store: GovernedStore
    roles: frozenset[str] | str
    durability: str = "process"
    queue_max_items: int = 1024
    payload_max_bytes: int = 1024 * 1024
    enqueue_timeout_ms: int = 0
    spool_dir: str | None = None
    spool_max_bytes: int = 1024 * 1024 * 1024
    retry_max_attempts: int = 5
    retry_max_elapsed_s: float = 300.0
    worker_flush_interval_ms: int = 250
    shutdown_flush_timeout_s: float = 10.0

    def __post_init__(self) -> None:
        if self.store is None:
            raise ValueError("ContentCaptureConfig: store is required")
        if self.roles is None or self.roles == frozenset():
            raise ValueError("ContentCaptureConfig: roles are required")
        if self.durability not in _DURABILITY_MODES:
            raise ValueError(
                f"ContentCaptureConfig: durability must be one of "
                f"{sorted(_DURABILITY_MODES)}, got {self.durability!r}"
            )
        if self.durability == "spooled" and not self.spool_dir:
            raise ValueError("ContentCaptureConfig: spooled durability requires spool_dir")
        for name, value, cap in (
            ("queue_max_items", self.queue_max_items, _QUEUE_MAX_CAP),
            ("payload_max_bytes", self.payload_max_bytes, _PAYLOAD_MAX_CAP),
            ("enqueue_timeout_ms", self.enqueue_timeout_ms, _ENQUEUE_TIMEOUT_CAP_MS),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"ContentCaptureConfig: {name} must be a non-negative int")
            if value > cap:
                raise ValueError(f"ContentCaptureConfig: {name} exceeds hard cap {cap}")

    def resolved_roles(self, all_roles: frozenset[str]) -> frozenset[str]:
        if self.roles == "all":
            return all_roles
        unknown = set(self.roles) - set(all_roles)
        if unknown:
            raise ValueError(
                f"ContentCaptureConfig: unknown roles {sorted(unknown)}; "
                f"supported: {sorted(all_roles)}"
            )
        return frozenset(self.roles)


@dataclass(frozen=True, slots=True)
class FlushResult:
    """Outcome of :meth:`ContentWriter.flush` — exact accounting."""

    stored: int
    pending: int
    dropped: int
    failed: int


@dataclass(slots=True)
class _Task:
    descriptor: ContentDescriptor
    content: str
    attempts: int = 0
    first_enqueued: float = field(default_factory=time.monotonic)


class ContentWriter:
    """Bounded, passive delivery of content objects to a GovernedStore.

    ``submit`` returns the object status — ``pending`` when the write was
    accepted for later delivery, ``stored`` (inline), ``dropped`` at a
    resource bound, or ``failed`` when the store itself rejected the item.
    It never raises into the agent path.
    """

    def __init__(self, config: ContentCaptureConfig) -> None:
        self._config = config
        self._store = config.store
        self._queue: queue.Queue[_Task] = queue.Queue(maxsize=config.queue_max_items)
        self._pending: dict[str, _Task] = {}
        self._pending_lock = threading.Lock()
        self._closed = False
        self._stats = {
            "enqueued": 0,
            "stored": 0,
            "dropped": 0,
            "failed": 0,
            "spooled": 0,
            "recovered": 0,
        }
        self._settled_callbacks: list[Callable[[ContentDescriptor, str], None]] = []
        self._worker: threading.Thread | None = None
        self._wake = threading.Event()
        self._spool_dir: Path | None = None
        if config.durability == "spooled":
            self._spool_dir = Path(config.spool_dir or "")
            self._spool_dir.mkdir(parents=True, exist_ok=True)
            self._recover_spool()
        if config.durability in ("process", "spooled"):
            self._worker = threading.Thread(
                target=self._run, name="fabric-content-writer", daemon=True
            )
            self._worker.start()

    # -- submission -------------------------------------------------------

    def on_settled(self, callback: Callable[[ContentDescriptor, str], None]) -> None:
        """Register a hook fired when a pending item reaches stored/failed."""
        self._settled_callbacks.append(callback)

    def submit(self, descriptor: ContentDescriptor, content: str) -> str:
        """Enqueue a content object for delivery; returns its item status.

        Caller path ends here: serialization + hashing already happened at
        capture time, so a later source mutation cannot change the record.
        Never raises — failures map to ``dropped``/``failed`` statuses.
        """
        if self._closed:
            _LOG.warning("fabric.content_writer: submit after close; marking failed")
            return ContentStatus.FAILED
        task = _Task(descriptor=descriptor, content=content)
        if self._config.durability == "inline":
            return self._submit_inline(task)
        if self._config.durability == "spooled" and (self._queue.full() or not self._spool(task)):
            self._stats["dropped"] += 1
            return ContentStatus.DROPPED
        try:
            if self._config.enqueue_timeout_ms:
                self._queue.put(task, timeout=self._config.enqueue_timeout_ms / 1000.0)
            else:
                self._queue.put_nowait(task)
        except queue.Full:
            if self._config.durability == "spooled":
                with contextlib.suppress(OSError):
                    self._spool_path(descriptor.object_id).unlink(missing_ok=True)
            self._stats["dropped"] += 1
            _LOG.warning(
                "fabric.content_writer: queue full (%d); dropping object %s role %s",
                self._config.queue_max_items,
                descriptor.object_id,
                descriptor.role,
            )
            return ContentStatus.DROPPED
        with self._pending_lock:
            self._pending[descriptor.object_id] = task
        self._stats["enqueued"] += 1
        self._wake.set()
        return ContentStatus.PENDING

    def _submit_inline(self, task: _Task) -> str:
        try:
            return self._deliver(task)
        except _RetryLaterError:
            # Inline callers get no retry queue; a failed first attempt is
            # terminal for this item — reported, never raised.
            self._stats["failed"] += 1
            self._settle(task, ContentStatus.FAILED)
            return ContentStatus.FAILED

    # -- spool --------------------------------------------------------------

    def _spool_root(self) -> Path:
        if self._spool_dir is None:
            raise RuntimeError("spool requested without a spool_dir")
        return self._spool_dir

    def _spool_path(self, object_id: str) -> Path:
        return self._spool_root() / f"{object_id}.json"

    def _spool(self, task: _Task) -> bool:
        """fsync a spool entry for ``task``. False when the spool bound hit."""
        spool_dir = self._spool_root()
        entry = json.dumps(
            {
                "descriptor": task.descriptor.to_json(),
                "content_b64": base64.b64encode(
                    task.content.encode("utf-8", "surrogatepass")
                ).decode("ascii"),
            }
        ).encode("utf-8")
        if self._spool_usage() + len(entry) > self._config.spool_max_bytes:
            _LOG.warning(
                "fabric.content_writer: spool full; dropping %s",
                task.descriptor.object_id,
            )
            return False
        path = self._spool_path(task.descriptor.object_id)
        try:
            fd, tmp = tempfile.mkstemp(dir=str(spool_dir), prefix=".spool-", suffix=".tmp")
            with os.fdopen(fd, "wb") as stream:
                stream.write(entry)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, path)
            dir_fd = os.open(str(spool_dir), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
            self._stats["spooled"] += 1
            return True
        except OSError:
            _LOG.warning("fabric.content_writer: spool write failed", exc_info=True)
            return False

    def _spool_usage(self) -> int:
        total = 0
        for path in self._spool_root().glob("*.json"):
            try:
                total += path.stat().st_size
            except OSError:
                continue
        return total

    def _recover_spool(self) -> None:
        """Re-enqueue spool entries surviving a previous process crash."""
        for path in sorted(self._spool_root().glob("*.json")):
            try:
                entry = json.loads(path.read_text(encoding="utf-8"))
                descriptor = _descriptor_from_json(entry["descriptor"])
                content = base64.b64decode(entry["content_b64"]).decode("utf-8", "surrogatepass")
            except (OSError, KeyError, ValueError):
                _LOG.warning("fabric.content_writer: unreadable spool entry %s", path)
                continue
            task = _Task(descriptor=descriptor, content=content)
            try:
                self._queue.put_nowait(task)
            except queue.Full:
                self._stats["dropped"] += 1
                continue
            with self._pending_lock:
                self._pending[descriptor.object_id] = task
            self._stats["recovered"] += 1

    # -- delivery -----------------------------------------------------------

    def _deliver(self, task: _Task) -> str:
        task.attempts += 1
        try:
            self._store.put_object(task.descriptor.to_json(), task.content)
        except Exception:
            if (
                task.attempts < self._config.retry_max_attempts
                and time.monotonic() - task.first_enqueued < self._config.retry_max_elapsed_s
            ):
                raise _RetryLaterError from None
            self._stats["failed"] += 1
            _LOG.warning(
                "fabric.content_writer: delivery failed permanently for %s role %s",
                task.descriptor.object_id,
                task.descriptor.role,
                exc_info=True,
            )
            self._settle(task, ContentStatus.FAILED)
            return ContentStatus.FAILED
        self._stats["stored"] += 1
        self._settle(task, ContentStatus.STORED)
        if self._spool_dir is not None:
            try:
                self._spool_path(task.descriptor.object_id).unlink(missing_ok=True)
            except OSError:
                _LOG.warning("fabric.content_writer: spool cleanup failed", exc_info=True)
        return ContentStatus.STORED

    def _settle(self, task: _Task, status: str) -> None:
        with self._pending_lock:
            self._pending.pop(task.descriptor.object_id, None)
        for callback in self._settled_callbacks:
            try:
                callback(task.descriptor, status)
            except Exception:
                _LOG.warning("fabric.content_writer: settled callback failed", exc_info=True)

    def _run(self) -> None:
        """Worker loop: drain the queue, retry with bounded backoff."""
        delay = self._config.worker_flush_interval_ms / 1000.0
        retry_backlog: list[_Task] = []
        while True:
            self._wake.wait(timeout=delay)
            self._wake.clear()
            deadline_retry = retry_backlog
            retry_backlog = []
            for task in deadline_retry:
                try:
                    self._deliver(task)
                except _RetryLaterError:
                    retry_backlog.append(task)
            while True:
                try:
                    task = self._queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    self._deliver(task)
                except _RetryLaterError:
                    retry_backlog.append(task)
            if self._closed and self._queue.empty() and not retry_backlog:
                return

    # -- lifecycle ------------------------------------------------------------

    def flush(self, timeout_s: float | None = None) -> FlushResult:
        """Block until queue + spool drain or ``timeout_s`` expires.

        Opt-in awaitable for tests and graceful shutdown. Returns exact
        per-status counts — a ``pending`` remainder is an honest gap, not
        a silent loss.
        """
        deadline = None if timeout_s is None else time.monotonic() + timeout_s
        while True:
            with self._pending_lock:
                remaining = len(self._pending)
            if remaining == 0 and self._queue.empty():
                break
            if deadline is not None and time.monotonic() >= deadline:
                break
            self._wake.set()
            time.sleep(0.01)
        with self._pending_lock:
            pending = len(self._pending)
        return FlushResult(
            stored=self._stats["stored"],
            pending=pending,
            dropped=self._stats["dropped"],
            failed=self._stats["failed"],
        )

    def close(self) -> None:
        """Flush within the configured shutdown bound, then stop the worker.

        Idempotent. A remainder after the bound stays ``pending`` — the
        manifest's completeness rollup reports it; we never claim
        delivered content we did not deliver.
        """
        if self._closed:
            return
        self.flush(timeout_s=self._config.shutdown_flush_timeout_s)
        self._closed = True
        self._wake.set()
        if self._worker is not None:
            self._worker.join(timeout=5.0)
        close = getattr(self._store, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                _LOG.warning("fabric.content_writer: store close failed", exc_info=True)

    def stats(self) -> dict[str, int]:
        with self._pending_lock:
            pending = len(self._pending)
        return {
            **self._stats,
            "pending": pending,
            "queue_depth": self._queue.qsize(),
        }


def _descriptor_from_json(doc: Mapping[str, Any]) -> ContentDescriptor:
    return ContentDescriptor(
        object_id=doc["object_id"],
        tenant_id=doc["tenant_id"],
        role=doc["role"],
        media_type=doc["media_type"],
        byte_length=doc["byte_length"],
        digest=doc["digest"],
        captured_at=doc["captured_at"],
        representation=doc["representation"],
        source=doc["source"],
        status=doc["status"],
        bindings=doc.get("bindings", {}),
        original_byte_length=doc.get("original_byte_length"),
        status_reason=doc.get("status_reason"),
    )


class _RetryLaterError(Exception):
    """Internal control flow: delivery failed but retries remain."""
