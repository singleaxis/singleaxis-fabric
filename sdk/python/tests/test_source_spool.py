# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Synthetic metadata source spool: restart, loss and fail-closed recovery."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from fabric.source_spool import SyntheticSourceSpool


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "source-spool"
    root.mkdir(mode=0o700)
    return root


def _event(record_id: str, epoch: int, sequence: int) -> dict[str, Any]:
    return {
        "record_id": record_id,
        "tenant_id": "synthetic-tenant",
        "run_id": "run-1",
        "source_id": "terminal-1",
        "source_epoch": epoch,
        "source_sequence": sequence,
        "operation_id": "tool-1",
        "attempt_id": "try-1",
        "boundary": "terminal",
        "role": "terminal.stdout",
        "status": "pending",
        "observed_at": "2026-09-26T00:00:00Z",
    }


def _open(
    root: Path, *, max_bytes: int = 16 * 1024 * 1024, queue_max_items: int = 64
) -> SyntheticSourceSpool:
    return SyntheticSourceSpool(
        str(root),
        tenant_id="synthetic-tenant",
        run_id="run-1",
        max_bytes=max_bytes,
        queue_max_items=queue_max_items,
    )


def _append(spool: SyntheticSourceSpool, event: dict[str, Any], expected: str = "pending") -> None:
    actual = spool.append(event)
    assert actual == expected


def _flush(spool: SyntheticSourceSpool) -> None:
    settled = spool.flush()
    assert settled


def _close(spool: SyntheticSourceSpool) -> None:
    closed = spool.close()
    assert closed


def test_source_spool_fsync_recovery_and_new_epoch(tmp_path: Path) -> None:
    root = _root(tmp_path)
    first = _open(root)
    assert first.epoch == 0
    event = _event("evt-one", first.epoch, 0)
    _append(first, event)
    _flush(first)
    assert first.status("evt-one") == "spooled"
    _close(first)
    second = _open(root)
    assert second.epoch == 1
    assert second.recovered() == [event]
    _append(second, _event("evt-two", second.epoch, 0))
    _flush(second)
    _close(second)
    third = _open(root)
    assert [item["record_id"] for item in third.recovered()] == ["evt-one", "evt-two"]
    _close(third)


def test_source_spool_recovery_exposes_missing_sequence_range(tmp_path: Path) -> None:
    root = _root(tmp_path)
    first = _open(root)
    _append(first, _event("evt-second", first.epoch, 1))
    _flush(first)
    _close(first)
    recovered = _open(root)
    assert recovered.recovered_gaps() == [
        {
            "source_epoch": 0,
            "source_id": "terminal-1",
            "missing_ranges": [{"start": 0, "end": 0}],
        }
    ]
    _close(recovered)


def test_crash_before_async_fsync_is_not_recoverable_without_external_truth(tmp_path: Path) -> None:
    root = _root(tmp_path)
    script = (
        "import json,os,sys,time; "
        "from fabric.source_spool import SyntheticSourceSpool; "
        "spool=SyntheticSourceSpool(sys.argv[1],tenant_id='synthetic-tenant',run_id='run-1'); "
        "spool._write_event=lambda event: time.sleep(30); "
        "spool.append(json.loads(sys.argv[2])); os._exit(0)"
    )
    result = subprocess.run(  # noqa: S603 - fixed synthetic fixture command
        [sys.executable, "-c", script, str(root), json.dumps(_event("evt-lost", 0, 0))],
        check=False,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 0
    recovered = _open(root)
    assert recovered.epoch == 1
    assert recovered.recovered() == []
    assert recovered.recovered_gaps() == []
    # The independent fixture knew evt-lost was submitted, while the source
    # journal could not prove it. This is why its pre-spool window forbids a
    # complete-run verdict even after a clean-looking restart.
    _close(recovered)


def test_source_spool_overflow_is_explicit_and_nonblocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    spool = _open(root, queue_max_items=1)
    gate = threading.Event()
    entered = threading.Event()
    real_write = spool._write_event

    def blocked(event: dict[str, Any]) -> int:
        entered.set()
        gate.wait(timeout=3)
        return real_write(event)

    monkeypatch.setattr(spool, "_write_event", blocked)
    _append(spool, _event("evt-one", spool.epoch, 0))
    entered_set = entered.wait(timeout=2)
    assert entered_set
    _append(spool, _event("evt-two", spool.epoch, 1))
    _append(spool, _event("evt-three", spool.epoch, 2), "dropped")
    gate.set()
    _flush(spool)
    assert spool.status("evt-one") == "spooled"
    assert spool.status("evt-two") == "spooled"
    assert spool.status("evt-three") == "dropped"
    _close(spool)


def test_source_spool_quota_write_failure_and_privacy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    spool = _open(root, max_bytes=1)
    _append(spool, _event("evt-overflow", spool.epoch, 0))
    _flush(spool)
    assert spool.status("evt-overflow") == "dropped"
    _close(spool)
    failed = _open(root)
    monkeypatch.setattr(
        failed, "_write_event", lambda _event: (_ for _ in ()).throw(OSError("secret-canary"))
    )
    _append(failed, _event("evt-failed", failed.epoch, 0))
    _flush(failed)
    assert failed.status("evt-failed") == "failed"
    _close(failed)
    assert b"secret-canary" not in b"".join(
        path.read_bytes() for path in root.iterdir() if path.is_file()
    )


def test_source_spool_rejects_concurrent_owner_corruption_and_unsafe_entries(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    first = _open(root)
    with pytest.raises(BlockingIOError):
        _open(root)
    _append(first, _event("evt-one", first.epoch, 0))
    _flush(first)
    _close(first)
    event_file = root / "event-evt-one.json"
    data = json.loads(event_file.read_text())
    data["event"]["role"] = "terminal.stderr"
    event_file.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="checksum"):
        _open(root)
    event_file.unlink()
    (root / ".incomplete.tmp").write_bytes(b"partial")
    with pytest.raises(ValueError, match="incomplete"):
        _open(root)


def test_source_spool_rejects_unsafe_root_and_identity(tmp_path: Path) -> None:
    root = _root(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(root)
    with pytest.raises(ValueError, match="real directory"):
        _open(alias)
    first = _open(root)
    _close(first)
    with pytest.raises(ValueError, match="identity"):
        SyntheticSourceSpool(str(root), tenant_id="other", run_id="run-1")
    os.chmod(root, 0o500)
    try:
        with pytest.raises(ValueError, match="0700"):
            _open(root)
    finally:
        os.chmod(root, 0o700)


def test_source_spool_rejects_duplicate_positions_and_bounds_status_index(tmp_path: Path) -> None:
    root = _root(tmp_path)
    spool = SyntheticSourceSpool(
        str(root), tenant_id="synthetic-tenant", run_id="run-1", max_records=1
    )
    try:
        _append(spool, _event("first", spool.epoch, 0))
        with pytest.raises(ValueError, match="duplicate"):
            spool.append(_event("different-id", spool.epoch, 0))
        _append(spool, _event("second", spool.epoch, 1), "dropped")
        _flush(spool)
        assert spool.health()["unretained_drops"] == 1
        assert spool.status("second") is None
    finally:
        _close(spool)


@pytest.mark.parametrize(
    "change",
    [
        {"role": "PRIVATE text"},
        {"status": "PRIVATE text"},
        {"kind": "PRIVATE text"},
        {"call_id": "PRIVATE text"},
        {"parent_call_id": "PRIVATE text"},
        {"streaming": "yes"},
        {"chunk_index": 1},
        {"status_reason": "PRIVATE text"},
        {"observed_at": "PRIVATE text"},
        {"role": "operation.outcome", "outcome": {"result_status": "PRIVATE text"}},
        {"role": "operation.outcome", "outcome": {"http_status": "PRIVATE text"}},
    ],
)
def test_source_spool_closed_metadata_rejects_unstructured_content(
    tmp_path: Path, change: Any
) -> None:
    spool = _open(_root(tmp_path))
    try:
        event = {**_event("event", spool.epoch, 0), **change}
        with pytest.raises(ValueError):
            spool.append(event)
        assert list(spool.root.glob("event-*.json")) == []
    finally:
        _close(spool)
