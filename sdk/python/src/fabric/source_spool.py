# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Crash-recoverable, metadata-only source journal for the synthetic slice.

Submission is bounded and nonblocking. A return from ``append`` is never a
durability receipt; only ``status(record_id) == 'spooled'`` means the event
file and directory were fsynced locally. The unspooled crash window remains.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import queue
import re
import stat
import threading
import time
import uuid
from pathlib import Path
from typing import Any

_EVENT_KEYS = frozenset(
    {
        "record_id",
        "tenant_id",
        "run_id",
        "source_id",
        "source_epoch",
        "source_sequence",
        "operation_id",
        "attempt_id",
        "boundary",
        "role",
        "object_id",
        "status",
        "status_reason",
        "observed_at",
        "outcome",
    }
)
_OUTCOME_KEYS = frozenset(
    {
        "http_status",
        "returncode",
        "signal_number",
        "timed_out",
        "artifact_path_sha256",
        "artifact_phase",
        "artifact_present",
        "artifact_size",
        "object_id",
    }
)
_REQUIRED_EVENT_KEYS = frozenset(
    {
        "record_id",
        "tenant_id",
        "run_id",
        "source_id",
        "source_epoch",
        "source_sequence",
        "operation_id",
        "attempt_id",
        "boundary",
        "role",
        "status",
        "observed_at",
    }
)
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_FILE_MODE = 0o600
_DIRECTORY_MODE = 0o700


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_atomic(path: Path, data: bytes) -> None:
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    except BaseException:
        # Leave any incomplete temporary entry for fail-closed investigation.
        raise


def _secure_regular(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != _FILE_MODE:
        raise ValueError("source journal entry must be a real mode-0600 file")
    if info.st_uid != os.geteuid():
        raise ValueError("source journal entry owner mismatch")


def _read_secure(path: Path, max_bytes: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != _FILE_MODE
            or info.st_uid != os.geteuid()
        ):
            raise ValueError("source journal entry changed or is unsafe")
        if info.st_size < 0 or info.st_size > max_bytes:
            raise ValueError("source journal entry exceeds configured capacity")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ValueError("source journal entry grew beyond configured capacity")
            return data
    finally:
        os.close(fd)


class SyntheticSourceSpool:
    """One tenant/run owner with restart epochs and immutable event records."""

    def __init__(
        self,
        root: str,
        *,
        tenant_id: str,
        run_id: str,
        max_bytes: int = 16 * 1024 * 1024,
        queue_max_items: int = 64,
    ) -> None:
        path = Path(root)
        if not path.is_absolute() or path.is_symlink():
            raise ValueError("source spool root must be an absolute real directory")
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != _DIRECTORY_MODE:
            raise ValueError("source spool root must be a mode-0700 directory")
        if info.st_uid != os.geteuid():
            raise ValueError("source spool root owner mismatch")
        if not tenant_id or not run_id or max_bytes <= 0 or queue_max_items <= 0:
            raise ValueError("source spool identity and positive bounds are required")
        self.root = path.resolve(strict=True)
        self.tenant_id = tenant_id
        self.run_id = run_id
        self.max_bytes = max_bytes
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=queue_max_items)
        self._condition = threading.Condition()
        self._pending = 0
        self._closed = False
        self._statuses: dict[str, str] = {}
        self._recovered: list[dict[str, Any]] = []
        self._recovered_gaps: list[dict[str, Any]] = []
        self._used = 0
        self._lock_fd = os.open(
            self.root / ".lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), _FILE_MODE
        )
        try:
            _secure_regular(self.root / ".lock")
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._recovered, self._used = self._recover()
            self._recovered_gaps = self._find_recovered_gaps(self._recovered)
            self.epoch = self._open_epoch()
        except BaseException:
            os.close(self._lock_fd)
            raise
        self._worker = threading.Thread(target=self._run, name="fabric-source-spool", daemon=True)
        self._worker.start()

    def _recover(self) -> tuple[list[dict[str, Any]], int]:
        events: list[dict[str, Any]] = []
        used = 0
        seen_ids: set[str] = set()
        seen_positions: set[tuple[str, int, int]] = set()
        for path in sorted(self.root.iterdir()):
            if path.name in {".lock", "state.json"}:
                continue
            if not path.name.startswith("event-") or not path.name.endswith(".json"):
                raise ValueError("unexpected or incomplete source spool entry")
            _secure_regular(path)
            remaining = self.max_bytes - used
            body = json.loads(_read_secure(path, remaining))
            if not isinstance(body, dict) or set(body) != {"event", "sha256"}:
                raise ValueError("invalid source spool event wrapper")
            event = body["event"]
            if not isinstance(event, dict):
                raise ValueError("invalid source spool event")
            self._validate_event(event)
            digest = "sha256:" + hashlib.sha256(_canonical(event)).hexdigest()
            if body["sha256"] != digest:
                raise ValueError("source spool event checksum mismatch")
            if path.name != f"event-{event['record_id']}.json":
                raise ValueError("source spool filename and record ID disagree")
            position = (event["source_id"], event["source_epoch"], event["source_sequence"])
            if event["record_id"] in seen_ids or position in seen_positions:
                raise ValueError("duplicate source spool record or source position")
            seen_ids.add(event["record_id"])
            seen_positions.add(position)
            used += path.stat().st_size
            if used > self.max_bytes:
                raise ValueError("recovered source spool exceeds configured capacity")
            events.append(event)
        events.sort(
            key=lambda event: (event["source_epoch"], event["source_id"], event["source_sequence"])
        )
        return events, used

    @staticmethod
    def _find_recovered_gaps(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        positions: dict[tuple[int, str], set[int]] = {}
        for event in events:
            positions.setdefault((event["source_epoch"], event["source_id"]), set()).add(
                event["source_sequence"]
            )
        gaps: list[dict[str, Any]] = []
        for (epoch, source), observed in sorted(positions.items()):
            ranges: list[dict[str, int]] = []
            previous = -1
            for sequence in sorted(observed):
                if sequence > previous + 1:
                    ranges.append({"start": previous + 1, "end": sequence - 1})
                previous = sequence
            if ranges:
                gaps.append({"source_epoch": epoch, "source_id": source, "missing_ranges": ranges})
        return gaps

    def _open_epoch(self) -> int:
        state_path = self.root / "state.json"
        if state_path.exists() or state_path.is_symlink():
            _secure_regular(state_path)
            state = json.loads(_read_secure(state_path, 4096))
            if (
                not isinstance(state, dict)
                or set(state) != {"tenant_id", "run_id", "epoch"}
                or state["tenant_id"] != self.tenant_id
                or state["run_id"] != self.run_id
                or not isinstance(state["epoch"], int)
                or isinstance(state["epoch"], bool)
                or state["epoch"] < 0
            ):
                raise ValueError("source spool state identity or epoch invalid")
            if any(event["source_epoch"] > state["epoch"] for event in self._recovered):
                raise ValueError("source spool event epoch exceeds persisted state")
            epoch = state["epoch"] + 1
        else:
            if self._recovered:
                raise ValueError("source spool events exist without epoch state")
            epoch = 0
        _write_atomic(
            state_path,
            _canonical({"tenant_id": self.tenant_id, "run_id": self.run_id, "epoch": epoch}),
        )
        return epoch

    def _validate_event(self, event: dict[str, Any]) -> None:
        if set(event) - _EVENT_KEYS or not set(event) >= _REQUIRED_EVENT_KEYS:
            raise ValueError("source spool event has missing or forbidden fields")
        if event["tenant_id"] != self.tenant_id or event["run_id"] != self.run_id:
            raise ValueError("source spool event identity mismatch")
        for key in (
            "record_id",
            "source_id",
            "operation_id",
            "attempt_id",
            "boundary",
            "role",
            "status",
            "observed_at",
        ):
            if not isinstance(event[key], str) or not event[key]:
                raise ValueError("source spool event string identity invalid")
        if not _SAFE_ID.fullmatch(event["record_id"]):
            raise ValueError("source spool record ID is unsafe")
        for key in ("source_epoch", "source_sequence"):
            value = event[key]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError("source spool event position invalid")
        if "outcome" in event:
            outcome = event["outcome"]
            if (
                event["role"] != "operation.outcome"
                or not isinstance(outcome, dict)
                or set(outcome) - _OUTCOME_KEYS
            ):
                raise ValueError("source spool outcome has forbidden fields")

    def append(self, event: dict[str, Any]) -> str:
        """Submit metadata without disk I/O; return pending/dropped/failed."""
        self._validate_event(event)
        if event["source_epoch"] != self.epoch:
            raise ValueError("source spool event epoch mismatch")
        record_id = event["record_id"]
        with self._condition:
            if record_id in self._statuses:
                raise ValueError("source spool duplicate record ID")
            if self._closed:
                self._statuses[record_id] = "failed"
                return "failed"
            try:
                self._queue.put_nowait(copy.deepcopy(event))
            except queue.Full:
                self._statuses[record_id] = "dropped"
                return "dropped"
            self._statuses[record_id] = "pending"
            self._pending += 1
            return "pending"

    def _write_event(self, event: dict[str, Any]) -> int:
        body = _canonical(
            {
                "event": event,
                "sha256": "sha256:" + hashlib.sha256(_canonical(event)).hexdigest(),
            }
        )
        with self._condition:
            if len(body) > self.max_bytes - self._used:
                raise OverflowError("source spool capacity exhausted")
        target = self.root / f"event-{event['record_id']}.json"
        if target.exists() or target.is_symlink():
            raise ValueError("source spool event file already exists")
        _write_atomic(target, body)
        return len(body)

    def _run(self) -> None:
        while True:
            try:
                event = self._queue.get(timeout=0.1)
            except queue.Empty:
                with self._condition:
                    if self._closed and self._pending == 0:
                        return
                continue
            try:
                used = self._write_event(event)
                status = "spooled"
            except OverflowError:
                used = 0
                status = "dropped"
            except Exception:
                used = 0
                status = "failed"
            with self._condition:
                self._used += used
                self._statuses[event["record_id"]] = status
                self._pending -= 1
                self._condition.notify_all()
            self._queue.task_done()

    def status(self, record_id: str) -> str | None:
        with self._condition:
            return self._statuses.get(record_id)

    def flush(self, timeout_s: float = 10.0) -> bool:
        deadline = time.monotonic() + max(timeout_s, 0)
        with self._condition:
            while self._pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def recovered(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._recovered)

    def recovered_gaps(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._recovered_gaps)

    def close(self, timeout_s: float = 10.0) -> bool:
        with self._condition:
            self._closed = True
        settled = self.flush(timeout_s)
        if not settled:
            return False
        self._worker.join(timeout=1.0)
        if self._worker.is_alive():
            return False
        fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
        os.close(self._lock_fd)
        return True
