# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Opt-in adapters for the bounded, synthetic evidence slice (spec 040).

These adapters do not install global hooks or claim universal observation.
An optional metadata-only source spool persists settled events off the action
path; its pre-spool crash window and absent destination proof remain gaps.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import threading
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, cast
from urllib.parse import urlsplit

from fabric.byte_evidence import ByteEvidenceRecorder
from fabric.source_spool import SyntheticSourceSpool

_MAX_CHUNK_BYTES = 64 * 1024
_TERMINATE_GRACE_SECONDS = 2
_DRAIN_GRACE_SECONDS = 3
_OUTCOME_FIELDS = frozenset(
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
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _opaque_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def _signal_process_group(process: subprocess.Popen[bytes], number: int) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, number)


class SyntheticCaptureSession:
    """Bounded local event index around an existing nonblocking byte writer.

    It does *not* authenticate a source or produce a complete-run manifest.
    Optional source spooling persists an epoch and settled metadata events,
    but cannot eliminate the pre-spool crash window.
    """

    def __init__(
        self,
        recorder: ByteEvidenceRecorder,
        *,
        tenant_id: str,
        run_id: str,
        source_spool: SyntheticSourceSpool | None = None,
    ) -> None:
        if recorder.tenant_id != tenant_id:
            raise ValueError("recorder store tenant does not match session tenant")
        if source_spool is not None and (
            source_spool.tenant_id != tenant_id or source_spool.run_id != run_id
        ):
            raise ValueError("source spool tenant/run does not match session")
        self.recorder = recorder
        self.source_spool = source_spool
        self.tenant_id = tenant_id
        self.run_id = run_id
        self.source_epoch = source_spool.epoch if source_spool is not None else 0
        self._lock = threading.Lock()
        self._next: dict[str, int] = {}
        self._events: list[dict[str, Any]] = []
        self._operations: list[dict[str, Any]] = []

    def _sequence(self, source_id: str) -> int:
        with self._lock:
            number = self._next.get(source_id, 0)
            self._next[source_id] = number + 1
            return number

    def _journal(self, event: dict[str, Any]) -> None:
        if self.source_spool is None:
            return
        try:
            self.source_spool.append(event)
        except Exception:
            # A journal error changes evidence health, never the action.
            event["source_spool_submission_failed"] = True

    def capture(
        self,
        data: bytes,
        *,
        source_id: str,
        boundary: str,
        role: str,
        operation_id: str,
        attempt_id: str,
        media_type: str = "application/octet-stream",
        stream_id: str | None = None,
        chunk_index: int | None = None,
    ) -> dict[str, Any]:
        sequence = self._sequence(source_id)
        record_id = _opaque_id("evt")
        try:
            descriptor = self.recorder.capture(
                data,
                role=role,
                boundary=boundary,
                source_id=source_id,
                source_epoch=self.source_epoch,
                source_sequence=sequence,
                media_type=media_type,
                run_id=self.run_id,
                operation_id=operation_id,
                attempt_id=attempt_id,
                stream_id=stream_id,
                chunk_index=chunk_index,
            )
        except Exception:
            # Recording faults must not change the provider or subprocess.
            descriptor = {
                "object_id": _opaque_id("failed"),
                "status": "failed",
                "status_reason": "recorder_exception",
            }
        event = {
            "record_id": record_id,
            "tenant_id": self.tenant_id,
            "run_id": self.run_id,
            "source_id": source_id,
            "source_epoch": self.source_epoch,
            "source_sequence": sequence,
            "operation_id": operation_id,
            "attempt_id": attempt_id,
            "boundary": boundary,
            "role": role,
            "object_id": descriptor["object_id"],
            "status": descriptor["status"],
            "observed_at": _now(),
        }
        with self._lock:
            self._events.append(event)
        self._journal(event)
        return descriptor

    def gap(
        self,
        *,
        source_id: str,
        boundary: str,
        role: str,
        operation_id: str,
        attempt_id: str,
        status: str,
        reason: str,
    ) -> None:
        if status not in {"truncated", "unsupported", "dropped", "failed", "not_captured"}:
            raise ValueError("gap status must be an incomplete evidence state")
        with self._lock:
            event = {
                "record_id": _opaque_id("evt"),
                "tenant_id": self.tenant_id,
                "run_id": self.run_id,
                "source_id": source_id,
                "source_epoch": self.source_epoch,
                "source_sequence": self._next.setdefault(source_id, 0),
                "operation_id": operation_id,
                "attempt_id": attempt_id,
                "boundary": boundary,
                "role": role,
                "status": status,
                "status_reason": reason,
                "observed_at": _now(),
            }
            self._events.append(event)
            self._next[source_id] += 1

        self._journal(event)

    def outcome(self, *, source_id: str, **fields: Any) -> None:
        values = {
            key: value
            for key, value in fields.items()
            if key not in {"operation_id", "attempt_id", "boundary"}
        }
        valid = not set(values) - _OUTCOME_FIELDS and all(
            (
                isinstance(value, bool)
                if key in {"timed_out", "artifact_present"}
                else isinstance(value, int) and not isinstance(value, bool)
                if key in {"http_status", "returncode", "artifact_size"}
                else value is None or isinstance(value, int)
                if key == "signal_number"
                else isinstance(value, str) and _HEX_SHA256.fullmatch(value) is not None
                if key == "artifact_path_sha256"
                else value in {"before", "after"}
                if key == "artifact_phase"
                else isinstance(value, str)
                and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value) is not None
            )
            for key, value in values.items()
        )
        if not valid:
            self.gap(
                source_id=source_id,
                boundary=fields["boundary"],
                role="operation.outcome",
                operation_id=fields["operation_id"],
                attempt_id=fields["attempt_id"],
                status="unsupported",
                reason="outcome_field_not_allowed",
            )
            return
        sequence = self._sequence(source_id)
        observed_at = _now()
        event = {
            "record_id": _opaque_id("evt"),
            "tenant_id": self.tenant_id,
            "run_id": self.run_id,
            "source_id": source_id,
            "source_epoch": self.source_epoch,
            "source_sequence": sequence,
            "operation_id": fields["operation_id"],
            "attempt_id": fields["attempt_id"],
            "boundary": fields["boundary"],
            "role": "operation.outcome",
            "status": "recorded",
            "observed_at": observed_at,
            "outcome": values,
        }
        with self._lock:
            self._operations.append({**event, **fields})
        self._journal(event)

    def snapshot(self, *, settle_timeout_s: float = 10.0) -> dict[str, Any]:
        settled = self.recorder.flush(settle_timeout_s)
        spool_settled = (
            self.source_spool.flush(settle_timeout_s) if self.source_spool is not None else False
        )
        with self._lock:
            events = [dict(event) for event in self._events]
            operations = [dict(item) for item in self._operations]
            high_water = {source: sequence - 1 for source, sequence in self._next.items()}
        for event in events:
            if "object_id" not in event:
                continue
            descriptor = self.recorder.get(event["object_id"])
            if descriptor is None:
                event["status"] = "failed"
                event["status_reason"] = "descriptor_not_retained"
            else:
                event["status"] = descriptor["status"]
                event["descriptor"] = descriptor
        if self.source_spool is not None:
            for item in [*events, *operations]:
                item["source_spool_status"] = self.source_spool.status(item["record_id"])
        return {
            "schema_version": "fabric.synthetic-capture/v1",
            "tenant_id": self.tenant_id,
            "run_id": self.run_id,
            "source_epoch": self.source_epoch,
            "source_epoch_persisted": self.source_spool is not None,
            "source_identity_authenticated": False,
            "source_high_water": high_water,
            "writer_settled": settled,
            "source_spool_settled": spool_settled,
            "source_spool_recovered_gaps": (
                self.source_spool.recovered_gaps() if self.source_spool is not None else []
            ),
            "pre_spool_crash_window_unverified": True,
            "unretained_drops": self.recorder.unretained_drops,
            "events": events,
            "operations": operations,
        }


class ControlledHTTPModelAdapter:
    """Observe exact HTTP body bytes passed to one controlled loopback endpoint."""

    def __init__(self, session: SyntheticCaptureSession, endpoint: str) -> None:
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("synthetic provider endpoint must be credential-free loopback HTTP")
        self.session = session
        self.host = parsed.hostname
        self.port = parsed.port or 80
        self.path = parsed.path or "/"

    def post(
        self,
        body: bytes,
        *,
        operation_id: str,
        attempt_id: str,
        timeout_s: float = 10.0,
    ) -> tuple[int, bytes]:
        if not isinstance(body, bytes):
            raise TypeError("model request body must be bytes")
        context_bytes = json.dumps(
            {
                "method": "POST",
                "scheme": "http",
                "host": self.host,
                "port": self.port,
                "path": self.path,
                "content_type": "application/octet-stream",
                "content_length": len(body),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.session.capture(
            context_bytes,
            source_id="provider-http-1",
            boundary="provider_bound",
            role="interaction.payload",
            operation_id=operation_id,
            attempt_id=attempt_id,
            media_type="application/json",
        )
        self.session.capture(
            body,
            source_id="provider-http-1",
            boundary="provider_bound",
            role="model.request.messages",
            operation_id=operation_id,
            attempt_id=attempt_id,
        )
        connection = http.client.HTTPConnection(self.host, self.port, timeout=timeout_s)
        try:
            connection.request(
                "POST", self.path, body=body, headers={"Content-Type": "application/octet-stream"}
            )
            response = connection.getresponse()
            response_body = response.read()
            self.session.capture(
                response_body,
                source_id="provider-http-1",
                boundary="provider_bound",
                role="model.output.messages",
                operation_id=operation_id,
                attempt_id=attempt_id,
            )
            self.session.outcome(
                source_id="provider-http-1",
                operation_id=operation_id,
                attempt_id=attempt_id,
                boundary="provider_bound",
                http_status=response.status,
            )
            return response.status, response_body
        except Exception:
            self.session.gap(
                source_id="provider-http-1",
                boundary="provider_bound",
                role="model.output.messages",
                operation_id=operation_id,
                attempt_id=attempt_id,
                status="failed",
                reason="provider_transport_failed",
            )
            raise
        finally:
            connection.close()


@dataclass(frozen=True, slots=True)
class TerminalResult:
    returncode: int
    signal_number: int | None
    stdout: bytes
    stderr: bytes
    observed_stream_order: tuple[tuple[str, int], ...]
    timed_out: bool


class BoundedTerminalAdapter:
    """No-shell subprocess observation with bounded *capture* volume.

    The returned stdout/stderr are the process's actual bytes. Capture may
    truncate while the subprocess continues; no output is silently omitted
    from the evidence status. This first slice is scoped to synthetic output
    sizes and is not a general-purpose unbounded terminal proxy.
    """

    def __init__(
        self,
        session: SyntheticCaptureSession,
        *,
        allowed_cwd_root: str,
        chunk_bytes: int = 4096,
        max_capture_output_bytes: int = 8 * 1024 * 1024,
        max_stdin_bytes: int = 64 * 1024,
    ) -> None:
        if (
            not 0 < chunk_bytes <= _MAX_CHUNK_BYTES
            or max_capture_output_bytes <= 0
            or max_stdin_bytes <= 0
        ):
            raise ValueError("terminal bounds must be positive")
        self.session = session
        self.allowed_cwd_root = Path(allowed_cwd_root).resolve(strict=True)
        if not self.allowed_cwd_root.is_dir():
            raise ValueError("terminal cwd root must be a directory")
        self.chunk_bytes = chunk_bytes
        self.max_capture_output_bytes = max_capture_output_bytes
        self.max_stdin_bytes = max_stdin_bytes

    def run(  # noqa: PLR0912, PLR0915 - stream multiplexing keeps one observed order
        self,
        argv: list[str],
        *,
        cwd: str,
        stdin: bytes,
        operation_id: str,
        attempt_id: str,
        approved_env: dict[str, str] | None = None,
        timeout_s: float = 60.0,
        cancel: threading.Event | None = None,
    ) -> TerminalResult:
        if not argv or not all(isinstance(item, str) and "\x00" not in item for item in argv):
            raise ValueError("argv must be a non-empty list of NUL-free strings")
        if not isinstance(stdin, bytes):
            raise TypeError("stdin must be exact bytes")
        if len(stdin) > self.max_stdin_bytes:
            raise ValueError("stdin exceeds declared subprocess input bound")
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        resolved_cwd = Path(cwd).resolve(strict=True)
        if not resolved_cwd.is_dir() or not resolved_cwd.is_relative_to(self.allowed_cwd_root):
            raise ValueError("terminal cwd must be inside the approved root")
        approved_env = approved_env or {}
        if any(
            not key.startswith("SYNTHETIC_") or "\x00" in key or "\x00" in value
            for key, value in approved_env.items()
        ):
            raise ValueError("only SYNTHETIC_ environment keys are approved")
        argv_bytes = b"\x00".join(os.fsencode(item) for item in argv) + b"\x00"
        context_bytes = json.dumps(
            {"cwd": str(resolved_cwd), "approved_env": approved_env},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        for role, data, media_type in (
            ("terminal.argv", argv_bytes, "application/octet-stream"),
            ("interaction.payload", context_bytes, "application/json"),
        ):
            self.session.capture(
                data,
                source_id="terminal-1",
                boundary="terminal",
                role=role,
                operation_id=operation_id,
                attempt_id=attempt_id,
                media_type=media_type,
            )
        env = {**os.environ, **approved_env}
        try:
            process = subprocess.Popen(  # noqa: S603 - explicit no-shell synthetic scope
                argv,
                cwd=resolved_cwd,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=True,
            )
        except OSError:
            self.session.gap(
                source_id="terminal-1",
                boundary="terminal",
                role="terminal.stdout",
                operation_id=operation_id,
                attempt_id=attempt_id,
                status="failed",
                reason="subprocess_start_failed",
            )
            raise
        if process.stdin is None or process.stdout is None or process.stderr is None:
            process.kill()
            process.wait()
            raise RuntimeError("subprocess pipes unavailable")
        for stream in (process.stdin, process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        if stdin:
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            process.stdin.close()
            self.session.capture(
                b"",
                source_id="terminal-1",
                boundary="terminal",
                role="terminal.stdin",
                operation_id=operation_id,
                attempt_id=attempt_id,
                stream_id=f"{operation_id}-stdin",
                chunk_index=0,
            )
        stdin_offset = 0
        chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
        indices = {"stdin": 0, "stdout": 0, "stderr": 0}
        observed_order: list[tuple[str, int]] = []
        captured_output = 0
        truncated: set[str] = set()
        deadline = time.monotonic() + timeout_s
        timed_out = False
        termination_started_at: float | None = None
        while selector.get_map():
            if not timed_out and (time.monotonic() >= deadline or (cancel and cancel.is_set())):
                timed_out = True
                termination_started_at = time.monotonic()
                _signal_process_group(process, signal.SIGTERM)
            for key, _ in selector.select(timeout=0.05):
                selected_stream = key.fileobj
                if isinstance(selected_stream, int):
                    raise RuntimeError("selector returned an unexpected file descriptor")
                selected_stream = cast(BinaryIO, selected_stream)
                name = key.data
                if name == "stdin":
                    try:
                        written = os.write(
                            selected_stream.fileno(),
                            stdin[stdin_offset : stdin_offset + self.chunk_bytes],
                        )
                    except BrokenPipeError:
                        written = 0
                    if written:
                        piece = stdin[stdin_offset : stdin_offset + written]
                        self.session.capture(
                            piece,
                            source_id="terminal-1",
                            boundary="terminal",
                            role="terminal.stdin",
                            operation_id=operation_id,
                            attempt_id=attempt_id,
                            stream_id=f"{operation_id}-stdin",
                            chunk_index=indices["stdin"],
                        )
                        observed_order.append(("stdin", indices["stdin"]))
                        indices["stdin"] += 1
                        stdin_offset += written
                    if not written or stdin_offset == len(stdin):
                        selector.unregister(selected_stream)
                        selected_stream.close()
                    continue
                try:
                    piece = os.read(selected_stream.fileno(), self.chunk_bytes)
                except BlockingIOError:
                    continue
                if not piece:
                    selector.unregister(selected_stream)
                    selected_stream.close()
                    continue
                chunks[name].append(piece)
                if captured_output + len(piece) <= self.max_capture_output_bytes:
                    self.session.capture(
                        piece,
                        source_id="terminal-1",
                        boundary="terminal",
                        role=f"terminal.{name}",
                        operation_id=operation_id,
                        attempt_id=attempt_id,
                        stream_id=f"{operation_id}-{name}",
                        chunk_index=indices[name],
                    )
                    observed_order.append((name, indices[name]))
                    indices[name] += 1
                    captured_output += len(piece)
                elif name not in truncated:
                    truncated.add(name)
                    self.session.gap(
                        source_id="terminal-1",
                        boundary="terminal",
                        role=f"terminal.{name}",
                        operation_id=operation_id,
                        attempt_id=attempt_id,
                        status="truncated",
                        reason="output_capture_limit",
                    )
            if timed_out and termination_started_at is not None:
                elapsed = time.monotonic() - termination_started_at
                if elapsed > _TERMINATE_GRACE_SECONDS:
                    _signal_process_group(process, signal.SIGKILL)
                if elapsed > _DRAIN_GRACE_SECONDS and selector.get_map():
                    for key in list(selector.get_map().values()):
                        selected = key.fileobj
                        selector.unregister(selected)
                        if not isinstance(selected, int):
                            cast(BinaryIO, selected).close()
                    for role in ("terminal.stdout", "terminal.stderr"):
                        self.session.gap(
                            source_id="terminal-1",
                            boundary="terminal",
                            role=role,
                            operation_id=operation_id,
                            attempt_id=attempt_id,
                            status="failed",
                            reason="stream_drain_timeout",
                        )
        selector.close()
        returncode = process.wait()
        for name in ("stdout", "stderr"):
            if indices[name] == 0 and name not in truncated:
                self.session.capture(
                    b"",
                    source_id="terminal-1",
                    boundary="terminal",
                    role=f"terminal.{name}",
                    operation_id=operation_id,
                    attempt_id=attempt_id,
                    stream_id=f"{operation_id}-{name}",
                    chunk_index=0,
                )
                observed_order.append((name, 0))
        if stdin_offset < len(stdin):
            self.session.gap(
                source_id="terminal-1",
                boundary="terminal",
                role="terminal.stdin",
                operation_id=operation_id,
                attempt_id=attempt_id,
                status="truncated",
                reason="child_closed_stdin",
            )
        self.session.outcome(
            source_id="terminal-1",
            operation_id=operation_id,
            attempt_id=attempt_id,
            boundary="terminal",
            returncode=returncode,
            signal_number=-returncode if returncode < 0 else None,
            timed_out=timed_out,
        )
        return TerminalResult(
            returncode=returncode,
            signal_number=-returncode if returncode < 0 else None,
            stdout=b"".join(chunks["stdout"]),
            stderr=b"".join(chunks["stderr"]),
            observed_stream_order=tuple(observed_order),
            timed_out=timed_out,
        )


class AllowlistedArtifactObserver:
    """Capture exact before/after bytes for named regular files only."""

    def __init__(
        self,
        session: SyntheticCaptureSession,
        *,
        root: str,
        relative_paths: list[str],
        max_bytes: int = 1024 * 1024,
    ) -> None:
        self.session = session
        root_path = Path(root)
        if root_path.is_symlink():
            raise ValueError("artifact root must not be a symlink")
        self.root = root_path.resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("artifact root must be a real directory")
        if not relative_paths or max_bytes <= 0:
            raise ValueError("artifact paths and positive max_bytes are required")
        self.paths = [self._path(name) for name in relative_paths]
        self.max_bytes = max_bytes

    def _path(self, name: str) -> Path:
        relative = PurePosixPath(name)
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise ValueError("artifact path must be a safe relative path")
        candidate = self.root.joinpath(*relative.parts)
        cursor = self.root
        for part in relative.parts:
            cursor /= part
            if cursor.is_symlink():
                raise ValueError("symlinked artifact path is not supported")
        if not candidate.resolve().is_relative_to(self.root):
            raise ValueError("artifact path escapes root")
        return candidate

    def observe(self, *, phase: str, operation_id: str, attempt_id: str) -> dict[str, bool]:
        if phase not in {"before", "after"}:
            raise ValueError("artifact phase must be before or after")
        existence: dict[str, bool] = {}
        for path in self.paths:
            relative = str(path.relative_to(self.root))
            # Re-check after the subprocess: it may have replaced a path with
            # a symlink. Never follow one into an unapproved location.
            if any(
                parent.is_symlink()
                for parent in (path, *path.parents)
                if parent != self.root and parent.is_relative_to(self.root)
            ) or not path.resolve().is_relative_to(self.root):
                existence[relative] = False
                self.session.gap(
                    source_id="artifact-1",
                    boundary="tool",
                    role=f"artifact.{phase}",
                    operation_id=operation_id,
                    attempt_id=attempt_id,
                    status="unsupported",
                    reason="symlink_or_escape",
                )
                continue
            if not path.exists():
                existence[relative] = False
                self.session.outcome(
                    source_id="artifact-1",
                    operation_id=operation_id,
                    attempt_id=attempt_id,
                    boundary="tool",
                    artifact_path_sha256=hashlib.sha256(relative.encode()).hexdigest(),
                    artifact_phase=phase,
                    artifact_present=False,
                )
                if phase == "after":
                    self.session.gap(
                        source_id="artifact-1",
                        boundary="tool",
                        role="artifact.after",
                        operation_id=operation_id,
                        attempt_id=attempt_id,
                        status="not_captured",
                        reason="expected_artifact_absent",
                    )
                continue
            if not path.is_file():
                existence[relative] = False
                self.session.gap(
                    source_id="artifact-1",
                    boundary="tool",
                    role=f"artifact.{phase}",
                    operation_id=operation_id,
                    attempt_id=attempt_id,
                    status="unsupported",
                    reason="not_regular_file",
                )
                continue
            existence[relative] = True
            try:
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode):
                        raise ValueError("not_regular_file")
                    if info.st_size > self.max_bytes:
                        raise ValueError("artifact_capture_limit")
                    data = os.read(fd, self.max_bytes + 1)
                    if len(data) > self.max_bytes or os.fstat(fd).st_size != len(data):
                        raise ValueError("artifact_changed_or_oversize")
                finally:
                    os.close(fd)
            except ValueError as exc:
                reason = str(exc)
                self.session.gap(
                    source_id="artifact-1",
                    boundary="tool",
                    role=f"artifact.{phase}",
                    operation_id=operation_id,
                    attempt_id=attempt_id,
                    status="truncated" if reason == "artifact_capture_limit" else "unsupported",
                    reason=reason,
                )
                continue
            except OSError:
                self.session.gap(
                    source_id="artifact-1",
                    boundary="tool",
                    role=f"artifact.{phase}",
                    operation_id=operation_id,
                    attempt_id=attempt_id,
                    status="failed",
                    reason="artifact_read_failed",
                )
                continue
            descriptor = self.session.capture(
                data,
                source_id="artifact-1",
                boundary="tool",
                role=f"artifact.{phase}",
                operation_id=operation_id,
                attempt_id=attempt_id,
            )
            self.session.outcome(
                source_id="artifact-1",
                operation_id=operation_id,
                attempt_id=attempt_id,
                boundary="tool",
                artifact_path_sha256=hashlib.sha256(relative.encode()).hexdigest(),
                artifact_phase=phase,
                artifact_present=True,
                artifact_size=len(data),
                object_id=descriptor["object_id"],
            )
        return existence
