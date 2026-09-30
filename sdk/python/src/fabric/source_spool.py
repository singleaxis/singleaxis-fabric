# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Crash-recoverable, metadata-only source journal for the synthetic slice.

Submission is bounded and nonblocking. A return from ``append`` is never a
durability receipt; only ``status(record_id) == 'spooled'`` means the event
file and directory were fsynced locally. The unspooled crash window remains.
"""

from __future__ import annotations

import contextlib
import copy
import fcntl
import hashlib
import json
import math
import os
import queue
import re
import stat
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .byte_evidence import _BOUNDARIES, _ROLES

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
        "call_id",
        "parent_call_id",
        "agent_id",
        "kind",
        "streaming",
        "stream_id",
        "chunk_index",
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
        "result_status",
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
_SEAL_SCHEMA = "fabric.source-epoch-seal/v1"
_MAX_SEAL_BYTES = 64 * 1024
_MAX_SEAL_TIMEOUT_S = 3600
_STATUSES = frozenset(
    {
        "recorded",
        "pending",
        "stored",
        "redacted",
        "not_captured",
        "truncated",
        "unsupported",
        "dropped",
        "failed",
    }
)


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


def _secure_regular(path: Path, *, directory_fd: int | None = None) -> None:
    info = (
        path.lstat()
        if directory_fd is None
        else os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
    )
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != _FILE_MODE
        or info.st_nlink != 1
    ):
        raise ValueError("source journal entry must be a real mode-0600 file")
    if info.st_uid != os.geteuid():
        raise ValueError("source journal entry owner mismatch")


def _read_secure(path: Path, max_bytes: int, *, directory_fd: int | None = None) -> bytes:
    fd = os.open(
        path if directory_fd is None else path.name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK,
        dir_fd=directory_fd,
    )
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != _FILE_MODE
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
        ):
            raise ValueError("source journal entry changed or is unsafe")
        if info.st_size < 0 or info.st_size > max_bytes:
            raise ValueError("source journal entry exceeds configured capacity")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ValueError("source journal entry grew beyond configured capacity")
            after = os.fstat(fd)
            if len(data) != info.st_size or (
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
                info.st_nlink,
            ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink):
                raise ValueError("source journal entry changed while reading")
            return data
    finally:
        os.close(fd)


def _events_digest(events: list[dict[str, Any]]) -> str:
    """Hash unambiguous length-framed canonical records in source order."""
    digest = hashlib.sha256()
    for event in sorted(events, key=lambda row: (row["source_id"], row["source_sequence"])):
        body = _canonical(event)
        digest.update(len(body).to_bytes(8, "big"))
        digest.update(body)
    return "sha256:" + digest.hexdigest()


class SyntheticSourceSpool:
    """One tenant/run owner with restart epochs and immutable event records."""

    def __init__(  # noqa: PLR0915 - validate owner, recover epochs and acquire lock atomically
        self,
        root: str,
        *,
        tenant_id: str,
        run_id: str,
        max_bytes: int = 16 * 1024 * 1024,
        queue_max_items: int = 64,
        max_records: int = 4096,
    ) -> None:
        path = Path(root)
        if not path.is_absolute() or path.is_symlink():
            raise ValueError("source spool root must be an absolute real directory")
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != _DIRECTORY_MODE:
            raise ValueError("source spool root must be a mode-0700 directory")
        if info.st_uid != os.geteuid():
            raise ValueError("source spool root owner mismatch")
        if (
            not _SAFE_ID.fullmatch(tenant_id)
            or not _SAFE_ID.fullmatch(run_id)
            or max_bytes <= 0
            or queue_max_items <= 0
            or max_records <= 0
        ):
            raise ValueError("source spool identity and positive bounds are required")
        self.root = path.resolve(strict=True)
        self.tenant_id = tenant_id
        self.run_id = run_id
        self.max_bytes = max_bytes
        self.max_records = max_records
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=queue_max_items)
        self._condition = threading.Condition()
        self._pending = 0
        self._closed = False
        self._seal_attempted = False
        self._current_seal: dict[str, Any] | None = None
        self._statuses: dict[str, str] = {}
        self._admitted_digests: dict[str, str] = {}
        self._recovered: list[dict[str, Any]] = []
        self._recovered_seals: list[dict[str, Any]] = []
        self._seal_intents: set[int] = set()
        self._unsealed_epoch_ranges: list[dict[str, int]] = []
        self._recovered_gaps: list[dict[str, Any]] = []
        self._used = 0
        self._unretained_drops = 0
        self._positions: set[tuple[str, int, int]] = set()
        self._lock_fd = os.open(
            self.root / ".lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), _FILE_MODE
        )
        try:
            _secure_regular(self.root / ".lock")
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._recovered, self._recovered_seals, self._seal_intents, self._used = self._recover()
            self._recovered_gaps = self._find_recovered_gaps(self._recovered)
            self._statuses = {event["record_id"]: "spooled" for event in self._recovered}
            self._positions = {
                (event["source_id"], event["source_epoch"], event["source_sequence"])
                for event in self._recovered
            }
            self.epoch = self._open_epoch()
            sealed_epochs = {seal["source_epoch"] for seal in self._recovered_seals}
            start = 0
            for sealed_epoch in sorted(sealed_epochs):
                if sealed_epoch > start:
                    self._unsealed_epoch_ranges.append({"start": start, "end": sealed_epoch - 1})
                start = sealed_epoch + 1
            if start < self.epoch:
                self._unsealed_epoch_ranges.append({"start": start, "end": self.epoch - 1})
        except BaseException:
            os.close(self._lock_fd)
            raise
        self._worker = threading.Thread(target=self._run, name="fabric-source-spool", daemon=True)
        self._worker.start()

    def _recover(  # noqa: PLR0912, PLR0915 - closed journal entry formats require distinct checks
        self,
        *,
        directory_fd: int | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[int], int]:
        events: list[dict[str, Any]] = []
        seals: list[dict[str, Any]] = []
        intents: set[int] = set()
        used = 0
        seen_ids: set[str] = set()
        seen_positions: set[tuple[str, int, int]] = set()
        paths = (
            sorted(self.root.iterdir())
            if directory_fd is None
            else [self.root / name for name in sorted(os.listdir(directory_fd))]
        )
        for path in paths:
            if path.name in {".lock", "state.json"}:
                continue
            if path.name.startswith("intent-") and path.name.endswith(".json"):
                _secure_regular(path, directory_fd=directory_fd)
                raw_intent = _read_secure(
                    path, min(4096, self.max_bytes - used), directory_fd=directory_fd
                )
                intent = json.loads(raw_intent)
                if (
                    not isinstance(intent, dict)
                    or set(intent) != {"schema_version", "tenant_id", "run_id", "source_epoch"}
                    or intent["schema_version"] != _SEAL_SCHEMA
                    or intent["tenant_id"] != self.tenant_id
                    or intent["run_id"] != self.run_id
                    or not isinstance(intent["source_epoch"], int)
                    or isinstance(intent["source_epoch"], bool)
                    or intent["source_epoch"] < 0
                    or path.name != f"intent-{intent['source_epoch']}.json"
                    or _canonical(intent) != raw_intent
                    or intent["source_epoch"] in intents
                ):
                    raise ValueError("source spool seal intent invalid")
                intents.add(intent["source_epoch"])
                used += len(raw_intent)
                continue
            if path.name.startswith("seal-") and path.name.endswith(".json"):
                _secure_regular(path, directory_fd=directory_fd)
                remaining = min(_MAX_SEAL_BYTES, self.max_bytes - used)
                raw_seal = _read_secure(path, remaining, directory_fd=directory_fd)
                seal = json.loads(raw_seal)
                self._validate_seal_shape(seal)
                if _canonical(seal) != raw_seal:
                    raise ValueError("source spool seal encoding invalid")
                if path.name != f"seal-{seal['source_epoch']}.json":
                    raise ValueError("source spool seal filename and epoch disagree")
                if any(previous["source_epoch"] == seal["source_epoch"] for previous in seals):
                    raise ValueError("duplicate source spool epoch seal")
                used += len(raw_seal)
                seals.append(seal)
                continue
            if not path.name.startswith("event-") or not path.name.endswith(".json"):
                raise ValueError("unexpected or incomplete source spool entry")
            _secure_regular(path, directory_fd=directory_fd)
            remaining = self.max_bytes - used
            raw_event = _read_secure(path, remaining, directory_fd=directory_fd)
            body = json.loads(raw_event)
            if not isinstance(body, dict) or set(body) != {"event", "sha256"}:
                raise ValueError("invalid source spool event wrapper")
            event = body["event"]
            if not isinstance(event, dict):
                raise ValueError("invalid source spool event")
            self._validate_event(event)
            digest = "sha256:" + hashlib.sha256(_canonical(event)).hexdigest()
            if body["sha256"] != digest:
                raise ValueError("source spool event checksum mismatch")
            if _canonical(body) != raw_event:
                raise ValueError("source spool event encoding invalid")
            if path.name != f"event-{event['record_id']}.json":
                raise ValueError("source spool filename and record ID disagree")
            position = (event["source_id"], event["source_epoch"], event["source_sequence"])
            if event["record_id"] in seen_ids or position in seen_positions:
                raise ValueError("duplicate source spool record or source position")
            seen_ids.add(event["record_id"])
            seen_positions.add(position)
            used += len(raw_event)
            if used > self.max_bytes:
                raise ValueError("recovered source spool exceeds configured capacity")
            events.append(event)
            if len(events) > self.max_records:
                raise ValueError("recovered source spool exceeds record capacity")
        events.sort(
            key=lambda event: (event["source_epoch"], event["source_id"], event["source_sequence"])
        )
        for seal in seals:
            self._verify_seal_events(
                seal, [event for event in events if event["source_epoch"] == seal["source_epoch"]]
            )
        # An intent is fsynced before the seal. If a later seal write fails
        # after rename but before directory fsync, its presence bars credit.
        seals = [seal for seal in seals if seal["source_epoch"] not in intents]
        seals.sort(key=lambda seal: seal["source_epoch"])
        return events, seals, intents, used

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

    def _validate_high_water(self, high_water: Any) -> dict[str, int]:
        if not isinstance(high_water, dict) or not high_water or len(high_water) > self.max_records:
            raise ValueError("source spool seal source map invalid")
        count = 0
        for source, high in high_water.items():
            if (
                not isinstance(source, str)
                or _SAFE_ID.fullmatch(source) is None
                or not isinstance(high, int)
                or isinstance(high, bool)
                or high < -1
                or high >= self.max_records
            ):
                raise ValueError("source spool seal source position invalid")
            count += high + 1
            if count > self.max_records:
                raise ValueError("source spool seal record capacity exceeded")
        return high_water

    def _validate_seal_shape(self, seal: Any) -> None:
        if not isinstance(seal, dict) or set(seal) != {
            "schema_version",
            "tenant_id",
            "run_id",
            "source_epoch",
            "source_high_water",
            "record_count",
            "events_sha256",
        }:
            raise ValueError("source spool seal schema invalid")
        if (
            seal["schema_version"] != _SEAL_SCHEMA
            or seal["tenant_id"] != self.tenant_id
            or seal["run_id"] != self.run_id
            or not isinstance(seal["source_epoch"], int)
            or isinstance(seal["source_epoch"], bool)
            or seal["source_epoch"] < 0
            or not isinstance(seal["record_count"], int)
            or isinstance(seal["record_count"], bool)
            or seal["record_count"] < 0
            or seal["record_count"] > self.max_records
            or not isinstance(seal["events_sha256"], str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", seal["events_sha256"]) is None
        ):
            raise ValueError("source spool seal identity or digest invalid")
        self._validate_high_water(seal["source_high_water"])

    def _verify_seal_events(self, seal: dict[str, Any], events: list[dict[str, Any]]) -> None:
        expected = seal["source_high_water"]
        if len(events) != seal["record_count"]:
            raise ValueError("source spool seal record count mismatch")
        actual: dict[str, set[int]] = {}
        for event in events:
            if event["source_epoch"] != seal["source_epoch"]:
                raise ValueError("source spool seal epoch mismatch")
            actual.setdefault(event["source_id"], set()).add(event["source_sequence"])
        for source, high in expected.items():
            observed = actual.pop(source, set())
            if len(observed) != high + 1 or (
                observed and (min(observed) != 0 or max(observed) != high)
            ):
                raise ValueError("source spool seal sequence mismatch")
        if actual:
            raise ValueError("source spool seal contains undeclared source")
        if _events_digest(events) != seal["events_sha256"]:
            raise ValueError("source spool seal event digest mismatch")

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
            if (
                any(event["source_epoch"] > state["epoch"] for event in self._recovered)
                or any(seal["source_epoch"] > state["epoch"] for seal in self._recovered_seals)
                or any(epoch > state["epoch"] for epoch in self._seal_intents)
            ):
                raise ValueError("source spool event epoch exceeds persisted state")
            epoch = state["epoch"] + 1
        else:
            if self._recovered or self._recovered_seals or self._seal_intents:
                raise ValueError("source spool events exist without epoch state")
            epoch = 0
        _write_atomic(
            state_path,
            _canonical({"tenant_id": self.tenant_id, "run_id": self.run_id, "epoch": epoch}),
        )
        return epoch

    def _validate_event(self, event: dict[str, Any]) -> None:  # noqa: PLR0912 - closed field validators
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
        for key in (
            "source_id",
            "operation_id",
            "attempt_id",
            "object_id",
            "call_id",
            "agent_id",
            "stream_id",
        ):
            if key in event and (
                not isinstance(event[key], str) or not _SAFE_ID.fullmatch(event[key])
            ):
                raise ValueError("source spool identity is unsafe")
        if event.get("parent_call_id") is not None and (
            not isinstance(event["parent_call_id"], str)
            or not _SAFE_ID.fullmatch(event["parent_call_id"])
        ):
            raise ValueError("source spool parent identity is unsafe")
        if (
            event["boundary"] not in _BOUNDARIES
            or event["role"] not in _ROLES | {"operation.start", "operation.outcome"}
            or event["status"] not in _STATUSES
        ):
            raise ValueError("source spool boundary/role/status invalid")
        if "kind" in event and event["kind"] not in {"model", "tool", "database", "agent"}:
            raise ValueError("source spool call kind invalid")
        if "streaming" in event and not isinstance(event["streaming"], bool):
            raise ValueError("source spool streaming flag invalid")
        if "chunk_index" in event and (
            "stream_id" not in event
            or not isinstance(event["chunk_index"], int)
            or isinstance(event["chunk_index"], bool)
            or event["chunk_index"] < 0
        ):
            raise ValueError("source spool chunk position invalid")
        if "status_reason" in event and (
            not isinstance(event["status_reason"], str)
            or not _SAFE_ID.fullmatch(event["status_reason"])
        ):
            raise ValueError("source spool status reason invalid")
        if not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", event["observed_at"]
        ):
            raise ValueError("source spool observation time invalid")
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
            for key, value in outcome.items():
                valid = (
                    isinstance(value, bool)
                    if key in {"timed_out", "artifact_present"}
                    else isinstance(value, int) and not isinstance(value, bool)
                    if key in {"http_status", "returncode", "artifact_size"}
                    else value is None or (isinstance(value, int) and not isinstance(value, bool))
                    if key == "signal_number"
                    else isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
                    if key == "artifact_path_sha256"
                    else value in {"before", "after"}
                    if key == "artifact_phase"
                    else value in {"ok", "error", "cancelled", "deferred"}
                    if key == "result_status"
                    else isinstance(value, str) and _SAFE_ID.fullmatch(value) is not None
                )
                if not valid:
                    raise ValueError("source spool outcome value invalid")

    def append(self, event: dict[str, Any]) -> str:
        """Submit metadata without disk I/O; return pending/dropped/failed."""
        self._validate_event(event)
        if event["source_epoch"] != self.epoch:
            raise ValueError("source spool event epoch mismatch")
        record_id = event["record_id"]
        position = (event["source_id"], event["source_epoch"], event["source_sequence"])
        admitted = copy.deepcopy(event)
        admitted_digest = "sha256:" + hashlib.sha256(_canonical(admitted)).hexdigest()
        with self._condition:
            if record_id in self._statuses or position in self._positions:
                raise ValueError("source spool duplicate record ID or position")
            if len(self._statuses) >= self.max_records:
                self._unretained_drops += 1
                return "dropped"
            self._positions.add(position)
            if self._closed:
                self._statuses[record_id] = "failed"
                self._current_seal = None
                return "failed"
            try:
                self._queue.put_nowait(admitted)
            except queue.Full:
                self._statuses[record_id] = "dropped"
                return "dropped"
            self._statuses[record_id] = "pending"
            self._admitted_digests[record_id] = admitted_digest
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

    def recovered_seals(self) -> list[dict[str, Any]]:
        """Verified disk metadata for prior epochs, without source attestation."""
        return copy.deepcopy(self._recovered_seals)

    def unsealed_epoch_ranges(self) -> list[dict[str, int]]:
        """Compact inclusive prior epoch ranges with no terminal metadata seal."""
        return copy.deepcopy(self._unsealed_epoch_ranges)

    def current_seal(self) -> dict[str, Any] | None:
        return copy.deepcopy(self._current_seal)

    def readback_sealed_epoch(self, epoch: int) -> dict[str, Any]:
        """Fresh offline disk readback; cached seals are not durability evidence.

        This does not advance an epoch, flush a writer or mutate the journal.
        Failures expose no paths, bytes or underlying filesystem errors.
        """
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
            raise ValueError("invalid source readback epoch")
        directory_fd = None
        try:
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
            directory_fd = os.open(self.root.anchor, flags)
            for component in self.root.parts[1:]:
                child_fd = os.open(component, flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = child_fd
            info = os.fstat(directory_fd)
            if (
                not stat.S_ISDIR(info.st_mode)
                or stat.S_IMODE(info.st_mode) != _DIRECTORY_MODE
                or info.st_uid != os.geteuid()
            ):
                raise ValueError("unsafe source root")
            events, seals, intents, _used = self._recover(directory_fd=directory_fd)
            seal = next((item for item in seals if item["source_epoch"] == epoch), None)
            if epoch in intents or seal is None:
                raise ValueError("source epoch unavailable")
            records = [item for item in events if item["source_epoch"] == epoch]
            return copy.deepcopy({"seal": seal, "records": records})
        except (OSError, ValueError, TypeError, OverflowError, RecursionError):
            raise ValueError("source readback unavailable or invalid") from None
        finally:
            if directory_fd is not None:
                os.close(directory_fd)

    def seal_epoch(  # noqa: PLR0911, PLR0912 - each failure returns a fixed public reason
        self, expected_high_water: dict[str, int], timeout_s: float = 10.0
    ) -> dict[str, Any]:
        """Offline metadata consistency check; never a complete-run receipt."""
        with self._condition:
            if self._seal_attempted or self._closed:
                return {"status": "refused", "reason": "already_finalized"}
            self._seal_attempted = True
            self._closed = True
        if (
            isinstance(timeout_s, bool)
            or not isinstance(timeout_s, (int, float))
            or not math.isfinite(timeout_s)
            or timeout_s < 0
            or timeout_s > _MAX_SEAL_TIMEOUT_S
        ):
            return {"status": "refused", "reason": "invalid_timeout"}
        try:
            self._validate_high_water(expected_high_water)
        except (TypeError, ValueError):
            return {"status": "refused", "reason": "invalid_high_water"}
        if not self.flush(timeout_s):
            return {"status": "refused", "reason": "unsettled_writes"}
        with self._condition:
            if (
                self._pending
                or self._unretained_drops
                or any(status != "spooled" for status in self._statuses.values())
            ):
                return {"status": "refused", "reason": "source_loss"}
            admitted = dict(self._admitted_digests)
            used = self._used
        try:
            events, _prior_seals, _prior_intents, disk_used = self._recover()
            current = [event for event in events if event["source_epoch"] == self.epoch]
            if disk_used != used:
                return {"status": "refused", "reason": "disk_mismatch"}
            if {event["record_id"] for event in current} != set(admitted):
                return {"status": "refused", "reason": "admission_mismatch"}
            for event in current:
                digest = "sha256:" + hashlib.sha256(_canonical(event)).hexdigest()
                if digest != admitted[event["record_id"]]:
                    return {"status": "refused", "reason": "admission_mismatch"}
            seal = {
                "schema_version": _SEAL_SCHEMA,
                "tenant_id": self.tenant_id,
                "run_id": self.run_id,
                "source_epoch": self.epoch,
                "source_high_water": copy.deepcopy(expected_high_water),
                "record_count": len(current),
                "events_sha256": _events_digest(current),
            }
            self._validate_seal_shape(seal)
            self._verify_seal_events(seal, current)
            body = _canonical(seal)
            if len(body) > _MAX_SEAL_BYTES:
                return {"status": "refused", "reason": "seal_too_large"}
            target = self.root / f"seal-{self.epoch}.json"
            intent_path = self.root / f"intent-{self.epoch}.json"
            if target.exists() or target.is_symlink():
                return {"status": "refused", "reason": "seal_already_exists"}
            if intent_path.exists() or intent_path.is_symlink():
                return {"status": "refused", "reason": "seal_already_exists"}
            intent = _canonical(
                {
                    "schema_version": _SEAL_SCHEMA,
                    "tenant_id": self.tenant_id,
                    "run_id": self.run_id,
                    "source_epoch": self.epoch,
                }
            )
            if len(body) + len(intent) > self.max_bytes - used:
                return {"status": "refused", "reason": "capacity_exhausted"}
            _write_atomic(intent_path, intent)
            _write_atomic(target, body)
            intent_path.unlink()
            try:
                _sync_directory(self.root)
            except OSError:
                # The seal itself has already been fsynced. A failed final
                # intent removal still refuses this attempt. Restore the
                # pre-synced intent where possible so recovery cannot credit
                # an ambiguous finalization as completed.
                with contextlib.suppress(OSError):
                    _write_atomic(intent_path, intent)
                raise
        except (OSError, ValueError, OverflowError, json.JSONDecodeError):
            return {"status": "refused", "reason": "seal_io_or_integrity_failure"}
        with self._condition:
            self._used += len(body)
            lost = self._unretained_drops or any(
                status != "spooled" for status in self._statuses.values()
            )
            if not lost:
                self._current_seal = seal
        if lost:
            # Preserve a detected loss across restart, not just in memory.
            # Do not hold the admission lock during filesystem operations.
            with contextlib.suppress(OSError):
                _write_atomic(intent_path, intent)
            return {"status": "refused", "reason": "source_loss"}
        return {"status": "sealed", "reason": "ok", "seal": copy.deepcopy(seal)}

    def health(self) -> dict[str, Any]:
        """Local stage counts, never a downstream or complete-source receipt."""
        with self._condition:
            statuses = list(self._statuses.values())
            return {
                "epoch": self.epoch,
                "pending": self._pending,
                "spooled": statuses.count("spooled"),
                "failed": statuses.count("failed"),
                "dropped": statuses.count("dropped") + self._unretained_drops,
                "unretained_drops": self._unretained_drops,
                "used_bytes": self._used,
                "closed": self._closed,
                "pre_fsync_loss_unknown": True,
            }

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
