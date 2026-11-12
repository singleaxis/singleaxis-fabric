# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""What ``fabric run`` leaves in ``.fabric/state`` (spec 058 §5.5 step 4), so ``verify``
and ``show`` default to the last run (F16) and ``doctor`` reads its status file.

- ``runs/<started_ns>-<label>.json``: one record per ``fabric run``: the label, the start
  time, the command name (never its arguments), the project, the runtime, whether capture
  was turned on and the findings that say why not. Local output, mode 0600.
- ``runs/<started_ns>-<label>.status.json``: the agent's ``FABRIC_WIRE_STATUS_FILE``.
- ``canaries.json``: the labels of the canary runs ``fabric verify`` recorded, so they are
  never taken for the user's runs.
- ``interpreters.json``: per interpreter path and modification time, what it answered
  about its SDK (the 150 ms budget of §5.5 needs this cache).

Everything in ``.fabric/state`` sits in the project directory, which may be a checkout of
somebody else's repository: every value read back is checked for type and shape, and
nothing read from it is ever executed or used as a path outside ``.fabric/state``."""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets as _random
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

RUN_SCHEMA = "fabric.cli-run/v1"
RUNS_DIR = "runs"
CANARIES_FILE = "canaries.json"
INTERPRETERS_FILE = "interpreters.json"
MAX_RUNS = 200  # records kept; older ones (and their status files) are removed
MAX_CANARIES = 100
MAX_INTERPRETERS = 32
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_RECORD_RE = re.compile(r"^(?P<ns>[0-9]{1,20})-(?P<label>[A-Za-z0-9][A-Za-z0-9._-]{0,63})\.json$")
_RUNTIMES = ("python", "node", "other")


def new_label(now: datetime | None = None) -> str:
    """A fresh run label: ``run-YYYYMMDD-HHMMSS-xxxx`` (UTC; four random hex digits)."""
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%d-%H%M%S")
    return f"run-{stamp}-{_random.token_hex(2)}"


def _iso(ns: int) -> str:
    return (
        datetime.fromtimestamp(ns / 1e9, UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


@dataclass
class RunRecord:
    """One ``fabric run``."""

    label: str
    started_ns: int
    command: str
    runtime: str = "other"
    capture: str = "off"  # on | off
    project: str | None = None
    interpreter: str | None = None
    sensor: str = "off"  # scoped | not_scoped | off
    findings: list[dict[str, str]] = field(default_factory=list)  # {"id", "detail"?}
    path: Path | None = None  # where the record is (not stored)

    @property
    def stem(self) -> str:
        return f"{self.started_ns}-{self.label}"

    @property
    def started_at(self) -> str:
        return _iso(self.started_ns)

    def status_file(self, runs_dir: Path) -> Path:
        return runs_dir / f"{self.stem}.status.json"

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": RUN_SCHEMA,
            "label": self.label,
            "started_ns": self.started_ns,
            "started_at": self.started_at,
            "command": self.command,
            "runtime": self.runtime,
            "capture": self.capture,
            "project": self.project,
            "interpreter": self.interpreter,
            "sensor": self.sensor,
            "findings": self.findings,
        }


def runs_dir(state_dir: Path) -> Path:
    """``.fabric/state/runs`` (under the project's ``.fabric``)."""
    return state_dir / "state" / RUNS_DIR


def _write_private(path: Path, text: str) -> None:
    """Write ``text`` atomically, mode 0600, never through a symlink."""
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{_random.token_hex(4)}.tmp")
    fd = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(temporary, path)


def ensure_runs_dir(state_dir: Path) -> Path:
    """Create ``.fabric/state/runs`` (0700). A symlink anywhere on the way is refused
    (``OSError``): the project directory may be somebody else's checkout."""
    directory = state_dir
    for part in ("state", RUNS_DIR):
        if directory.is_symlink():
            raise OSError(f"{directory} is a symlink")
        directory.mkdir(mode=0o700, exist_ok=True)
        directory = directory / part
    if directory.is_symlink():
        raise OSError(f"{directory} is a symlink")
    directory.mkdir(mode=0o700, exist_ok=True)
    return directory


def save(record: RunRecord, state_dir: Path) -> Path:
    """Write the run record (``OSError`` when it cannot be) and prune old records."""
    directory = ensure_runs_dir(state_dir)
    path = directory / f"{record.stem}.json"
    _write_private(path, json.dumps(record.to_json(), indent=2, sort_keys=True) + "\n")
    with contextlib.suppress(OSError):
        _prune(directory)
    return path


def _prune(directory: Path) -> None:
    records = sorted(
        (m for p in directory.iterdir() if (m := _RECORD_RE.match(p.name))),
        key=lambda m: int(m["ns"]),
    )
    for match in records[:-MAX_RUNS] if len(records) > MAX_RUNS else []:
        stem = match.string[: -len(".json")]
        for name in (f"{stem}.json", f"{stem}.status.json"):
            with contextlib.suppress(OSError):
                (directory / name).unlink()


def _text(value: Any, limit: int = 4096) -> str | None:
    return value if isinstance(value, str) and len(value) <= limit else None


def _parse(path: Path) -> RunRecord | None:
    match = _RECORD_RE.match(path.name)
    if match is None or path.is_symlink():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(data, dict) or data.get("schema") != RUN_SCHEMA:
        return None
    if data.get("label") != match["label"] or data.get("started_ns") != int(match["ns"]):
        return None
    findings = [
        {k: str(v)[:2048] for k, v in item.items() if k in ("id", "detail") and isinstance(v, str)}
        for item in data.get("findings") or []
        if isinstance(item, dict)
        and isinstance(item.get("id"), str)
        and re.fullmatch(r"F[CWERN]-[0-9]{3}", item["id"])
    ]
    return RunRecord(
        label=match["label"],
        started_ns=int(match["ns"]),
        command=_text(data.get("command"), 255) or "?",
        runtime=str(data["runtime"]) if data.get("runtime") in _RUNTIMES else "other",
        capture="on" if data.get("capture") == "on" else "off",
        project=_text(data.get("project"), 63),
        interpreter=_text(data.get("interpreter")),
        sensor=str(data["sensor"]) if data.get("sensor") in ("scoped", "not_scoped") else "off",
        findings=findings,
        path=path,
    )


def load_runs(state_dir: Path) -> list[RunRecord]:
    """Every readable run record, newest first."""
    directory = runs_dir(state_dir)
    try:
        paths = list(directory.iterdir()) if not directory.is_symlink() else []
    except OSError:
        return []
    runs = [record for path in paths if (record := _parse(path)) is not None]
    return sorted(runs, key=lambda r: r.started_ns, reverse=True)


def find_run(state_dir: Path, label: str | None) -> tuple[RunRecord | None, RunRecord | None]:
    """The run named ``label`` (its newest record), or the last run when ``label`` is
    ``None``; and the run recorded right after it (its window ends there)."""
    runs = load_runs(state_dir)
    for index, record in enumerate(runs):
        if label is None or record.label == label:
            return record, (runs[index - 1] if index > 0 else None)
    return None, None


def read_status(record: RunRecord, state_dir: Path) -> dict[str, Any] | None:
    """The agent's status file of ``record`` (written by the SDK), or ``None``."""
    path = record.status_file(runs_dir(state_dir))
    if path.is_symlink():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8")[: 1 << 20])
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


# ---------------------------------------------------------------- canaries


def load_canaries(state_dir: Path) -> list[str]:
    path = state_dir / "state" / CANARIES_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return []
    labels = data.get("labels") if isinstance(data, dict) else None
    return [x for x in labels or [] if isinstance(x, str) and LABEL_RE.fullmatch(x)]


def add_canary(state_dir: Path, label: str) -> None:
    """Remember a canary label (best effort: a canary not remembered is still excluded by
    ``fabric verify`` itself, which knows its own label)."""
    labels = [*load_canaries(state_dir), label][-MAX_CANARIES:]
    with contextlib.suppress(OSError):
        directory = state_dir / "state"
        if directory.is_symlink():
            return
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write_private(directory / CANARIES_FILE, json.dumps({"labels": labels}) + "\n")


# ---------------------------------------------------------------- interpreter cache


def _interpreter_key(interpreter: Path) -> tuple[str, int] | None:
    try:
        real = interpreter.resolve()
        return str(real), real.stat().st_mtime_ns
    except OSError:
        return None


def cached_probe(state_dir: Path | None, interpreter: Path) -> dict[str, Any] | None:
    """The cached answer of ``interpreter`` (same path and modification time), or ``None``."""
    key = _interpreter_key(interpreter)
    if state_dir is None or key is None:
        return None
    path = state_dir / "state" / INTERPRETERS_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None
    entry = data.get(key[0]) if isinstance(data, dict) else None
    if not isinstance(entry, dict) or entry.get("mtime_ns") != key[1]:
        return None
    answer = entry.get("answer")
    return answer if isinstance(answer, dict) else None


def store_probe(state_dir: Path | None, interpreter: Path, answer: dict[str, Any]) -> None:
    """Cache an interpreter's answer (best effort; at most 32 interpreters)."""
    key = _interpreter_key(interpreter)
    if state_dir is None or key is None:
        return
    with contextlib.suppress(OSError, ValueError, RecursionError):
        directory = state_dir / "state"
        if directory.is_symlink() or state_dir.is_symlink():
            return
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = directory / INTERPRETERS_FILE
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError):
            data = {}
        data = data if isinstance(data, dict) else {}
        data[key[0]] = {"mtime_ns": key[1], "answer": answer, "at": int(time.time())}
        if len(data) > MAX_INTERPRETERS:
            for name in sorted(
                data, key=lambda k: data[k].get("at", 0) if isinstance(data[k], dict) else 0
            )[: len(data) - MAX_INTERPRETERS]:
                del data[name]
        _write_private(path, json.dumps(data, sort_keys=True) + "\n")
