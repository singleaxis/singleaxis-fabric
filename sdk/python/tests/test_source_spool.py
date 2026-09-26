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


def test_source_spool_fsync_recovery_and_new_epoch(tmp_path: Path) -> None:
    root = _root(tmp_path)
    first = _open(root)
    assert first.epoch == 0
    event = _event("evt-one", first.epoch, 0)
    assert first.append(event) == "pending"
    assert first.flush()
    assert first.status("evt-one") == "spooled"
    assert first.close()
    second = _open(root)
    assert second.epoch == 1
    assert second.recovered() == [event]
    assert second.append(_event("evt-two", second.epoch, 0)) == "pending"
    assert second.flush() and second.close()
    third = _open(root)
    assert [item["record_id"] for item in third.recovered()] == ["evt-one", "evt-two"]
    assert third.close()


def test_source_spool_recovery_exposes_missing_sequence_range(tmp_path: Path) -> None:
    root = _root(tmp_path)
    first = _open(root)
    assert first.append(_event("evt-second", first.epoch, 1)) == "pending"
    assert first.flush() and first.close()
    recovered = _open(root)
    assert recovered.recovered_gaps() == [
        {
            "source_epoch": 0,
            "source_id": "terminal-1",
            "missing_ranges": [{"start": 0, "end": 0}],
        }
    ]
    assert recovered.close()


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
    assert recovered.close()


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
    assert spool.append(_event("evt-one", spool.epoch, 0)) == "pending"
    assert entered.wait(timeout=2)
    assert spool.append(_event("evt-two", spool.epoch, 1)) == "pending"
    assert spool.append(_event("evt-three", spool.epoch, 2)) == "dropped"
    gate.set()
    assert spool.flush()
    assert spool.status("evt-one") == "spooled"
    assert spool.status("evt-two") == "spooled"
    assert spool.status("evt-three") == "dropped"
    assert spool.close()


def test_source_spool_quota_write_failure_and_privacy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    spool = _open(root, max_bytes=1)
    assert spool.append(_event("evt-overflow", spool.epoch, 0)) == "pending"
    assert spool.flush()
    assert spool.status("evt-overflow") == "dropped"
    assert spool.close()
    failed = _open(root)
    monkeypatch.setattr(
        failed, "_write_event", lambda _event: (_ for _ in ()).throw(OSError("secret-canary"))
    )
    assert failed.append(_event("evt-failed", failed.epoch, 0)) == "pending"
    assert failed.flush()
    assert failed.status("evt-failed") == "failed"
    assert failed.close()
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
    first.append(_event("evt-one", first.epoch, 0))
    assert first.flush() and first.close()
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
    assert first.close()
    with pytest.raises(ValueError, match="identity"):
        SyntheticSourceSpool(str(root), tenant_id="other", run_id="run-1")
    os.chmod(root, 0o777)  # noqa: S103 - deliberately exercise unsafe permissions
    with pytest.raises(ValueError, match="0700"):
        _open(root)
