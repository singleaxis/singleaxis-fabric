# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Synthetic metadata source spool: restart, loss and fail-closed recovery."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

import fabric.source_spool as source_spool_module
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


def test_seal_empty_epoch_and_recovery_of_unsealed_empty_epoch(tmp_path: Path) -> None:
    root = _root(tmp_path)
    first = _open(root)
    assert first.seal_epoch({"terminal-1": -1})["status"] == "sealed"
    assert first.seal_epoch({"terminal-1": -1}) == {
        "status": "refused",
        "reason": "already_finalized",
    }
    assert first.append(_event("late", first.epoch, 0)) == "failed"
    assert first.current_seal() is None
    _close(first)
    second = _open(root)
    assert second.recovered_seals()[0]["source_high_water"] == {"terminal-1": -1}
    assert second.unsealed_epoch_ranges() == []
    _close(second)
    third = _open(root)
    assert third.unsealed_epoch_ranges() == [{"start": 1, "end": 1}]
    _close(third)


def test_multisource_seal_survives_restart_and_accounts_for_capacity(tmp_path: Path) -> None:
    root = _root(tmp_path)
    first = _open(root)
    for source, sequence in [("model", 0), ("terminal-1", 0), ("terminal-1", 1)]:
        event = _event(f"{source}-{sequence}", first.epoch, sequence)
        event["source_id"] = source
        _append(first, event)
    _flush(first)
    seal = first.seal_epoch({"model": 0, "terminal-1": 1})
    assert seal["status"] == "sealed"
    assert seal["seal"]["record_count"] == 3
    seal_path = root / "seal-0.json"
    assert seal_path.stat().st_mode & 0o777 == 0o600
    assert (
        first.health()["used_bytes"]
        == sum(path.stat().st_size for path in root.glob("event-*.json")) + seal_path.stat().st_size
    )
    _close(first)
    second = _open(root)
    assert second.recovered_seals() == [seal["seal"]]
    assert second.unsealed_epoch_ranges() == []
    _close(second)


@pytest.mark.parametrize(
    "alteration", ["delete_tail", "extra", "rehash", "seal_tenant", "seal_mode"]
)
def test_recovered_seal_fails_closed_on_disk_mismatch(tmp_path: Path, alteration: str) -> None:
    root = _root(tmp_path)
    first = _open(root)
    _append(first, _event("first", 0, 0))
    _append(first, _event("second", 0, 1))
    _flush(first)
    assert first.seal_epoch({"terminal-1": 1})["status"] == "sealed"
    _close(first)
    if alteration == "delete_tail":
        (root / "event-second.json").unlink()
    elif alteration == "extra":
        extra = _event("extra", 0, 2)
        body = {
            "event": extra,
            "sha256": "sha256:"
            + hashlib.sha256(
                json.dumps(extra, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        }
        (root / "event-extra.json").write_text(
            json.dumps(body, sort_keys=True, separators=(",", ":"))
        )
        os.chmod(root / "event-extra.json", 0o600)
    elif alteration == "rehash":
        path = root / "event-first.json"
        body = json.loads(path.read_text())
        body["event"]["role"] = "terminal.stderr"
        body["sha256"] = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(body["event"], sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        )
        path.write_text(json.dumps(body, sort_keys=True, separators=(",", ":")))
    elif alteration == "seal_tenant":
        path = root / "seal-0.json"
        seal = json.loads(path.read_text())
        seal["tenant_id"] = "other-tenant"
        path.write_text(json.dumps(seal, sort_keys=True, separators=(",", ":")))
    else:
        os.chmod(root / "seal-0.json", 0o644)
    with pytest.raises(ValueError):
        _open(root)


def test_seal_detects_admission_time_substitution_and_declared_range(tmp_path: Path) -> None:
    root = _root(tmp_path)
    first = _open(root)
    _append(first, _event("first", 0, 0))
    _flush(first)
    path = root / "event-first.json"
    body = json.loads(path.read_text())
    body["event"]["role"] = "terminal.stderr"
    body["sha256"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(body["event"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    path.write_text(json.dumps(body, sort_keys=True, separators=(",", ":")))
    assert first.seal_epoch({"terminal-1": 0}) == {
        "status": "refused",
        "reason": "admission_mismatch",
    }
    _close(first)
    second = _open(root)
    assert second.unsealed_epoch_ranges() == [{"start": 0, "end": 0}]
    assert second.seal_epoch({"terminal-1": -1})["status"] == "sealed"
    _close(second)


@pytest.mark.parametrize(
    "high_water",
    [
        {},
        {"terminal-1": True},
        {"terminal-1": 4096},
        {"terminal-1": -2},
        {"not safe": 0},
    ],
)
def test_seal_rejects_invalid_high_water(tmp_path: Path, high_water: dict[str, int]) -> None:
    spool = _open(_root(tmp_path))
    assert spool.seal_epoch(high_water) == {"status": "refused", "reason": "invalid_high_water"}
    _close(spool)


def test_seal_requires_contiguous_positions_and_no_loss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    first = _open(root)
    _append(first, _event("second", 0, 1))
    _flush(first)
    assert first.seal_epoch({"terminal-1": 1}) == {
        "status": "refused",
        "reason": "seal_io_or_integrity_failure",
    }
    _close(first)
    second = _open(root)
    monkeypatch.setattr(second, "_write_event", lambda _event: (_ for _ in ()).throw(OSError()))
    _append(second, _event("failed", 1, 0))
    _flush(second)
    assert second.seal_epoch({"terminal-1": 0}) == {"status": "refused", "reason": "source_loss"}
    _close(second)


@pytest.mark.parametrize("failed_sync", [1, 2, 3])
def test_seal_fsync_failure_never_recovers_as_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_sync: int
) -> None:
    root = _root(tmp_path)
    spool = _open(root)
    _append(spool, _event("first", 0, 0))
    _flush(spool)
    actual_sync = source_spool_module._sync_directory
    calls = 0

    def fail_one_sync(path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == failed_sync:
            raise OSError("secret-canary")
        actual_sync(path)

    monkeypatch.setattr(source_spool_module, "_sync_directory", fail_one_sync)
    assert spool.seal_epoch({"terminal-1": 0}) == {
        "status": "refused",
        "reason": "seal_io_or_integrity_failure",
    }
    _close(spool)
    monkeypatch.undo()
    # A failure during the first intent fsync may leave an incomplete temp;
    # fail-closed startup is permitted. Later failures retain the intent.
    try:
        recovered = _open(root)
    except ValueError:
        return
    assert recovered.recovered_seals() == []
    assert recovered.unsealed_epoch_ranges() == [{"start": 0, "end": 0}]
    _close(recovered)


def test_seal_capacity_includes_intent_and_seal(tmp_path: Path) -> None:
    root = _root(tmp_path)
    spool = _open(root, max_bytes=600)
    _append(spool, _event("first", 0, 0))
    _flush(spool)
    assert spool.status("first") == "spooled"
    assert spool.seal_epoch({"terminal-1": 0}) == {
        "status": "refused",
        "reason": "capacity_exhausted",
    }
    _close(spool)


def test_process_crash_after_intent_before_seal_is_unsealed(tmp_path: Path) -> None:
    root = _root(tmp_path)
    script = (
        "import os,sys; import fabric.source_spool as m; "
        "from fabric.source_spool import SyntheticSourceSpool; "
        "s=SyntheticSourceSpool(sys.argv[1],tenant_id='synthetic-tenant',run_id='run-1'); "
        "real=m._write_atomic; "
        "m._write_atomic=lambda p,b: os._exit(0) if p.name.startswith('seal-') else real(p,b); "
        "s.seal_epoch({'terminal-1':-1}); os._exit(2)"
    )
    result = subprocess.run(  # noqa: S603 - fixed synthetic fixture command
        [sys.executable, "-c", script, str(root)],
        check=False,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 0
    recovered = _open(root)
    assert recovered.recovered_seals() == []
    assert recovered.unsealed_epoch_ranges() == [{"start": 0, "end": 0}]
    _close(recovered)


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), -1, True, "1"])
def test_seal_rejects_invalid_timeout(tmp_path: Path, timeout: Any) -> None:
    spool = _open(_root(tmp_path))
    assert spool.seal_epoch({"terminal-1": -1}, timeout_s=timeout) == {
        "status": "refused",
        "reason": "invalid_timeout",
    }
    _close(spool)


def test_late_append_during_seal_prevents_in_memory_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spool = _open(_root(tmp_path))
    original = source_spool_module._write_atomic

    def append_after_seal_write(path: Path, data: bytes) -> None:
        original(path, data)
        if path.name == f"seal-{spool.epoch}.json":
            assert spool.append(_event("late", spool.epoch, 0)) == "failed"

    monkeypatch.setattr(source_spool_module, "_write_atomic", append_after_seal_write)
    assert spool.seal_epoch({"terminal-1": -1}) == {"status": "refused", "reason": "source_loss"}
    assert spool.current_seal() is None
    _close(spool)
    monkeypatch.undo()
    reopened = _open(spool.root)
    try:
        assert reopened.recovered_seals() == []
        assert reopened.unsealed_epoch_ranges() == [{"start": 0, "end": 0}]
    finally:
        _close(reopened)
