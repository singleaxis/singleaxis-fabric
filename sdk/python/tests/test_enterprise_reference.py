# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The public reference command must exercise actual separate-process recovery."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest


def _runner() -> Any:
    path = Path(__file__).resolve().parents[3] / "examples/enterprise-reference/run.py"
    specification = importlib.util.spec_from_file_location("enterprise_reference_runner", path)
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def test_reference_real_process_recovery_and_exact_readback(tmp_path: Path) -> None:
    runner = _runner()
    report = runner.run(tmp_path / "reference", iterations=3)
    assert report["verdict"] == "LOCAL_REFERENCE_CHECKS_PASS"
    assert report["production_verdict"] == "NO_GO"
    assert set(report["checks"].values()) == {True}
    assert report["expected_content_objects"] == 6
    assert report["expected_metadata_records"] == 12
    assert report["byte_delivery"]["lost"] == 0
    assert report["metadata_after_restart"]["node_accepted"] == 12
    assert report["metadata_after_restart"]["destination_durable"] is False
    assert report["node"]["actual_otlp_collector"] is False
    assert report["destination"]["cloud_attestation"] is False
    assert report["final_boundary"]["after_deliberate_bypass"]["status"] == "unverified"
    assert json.loads((tmp_path / "reference/report.json").read_text()) == report


@pytest.mark.parametrize("iterations", [0, 101, True])
def test_reference_rejects_unbounded_workload(tmp_path: Path, iterations: Any) -> None:
    with pytest.raises(ValueError, match="iterations"):
        _runner().run(tmp_path / "invalid", iterations=iterations)
    assert not (tmp_path / "invalid").exists()


@pytest.mark.parametrize("corrupt", [False, True])
def test_reference_never_blesses_shrunken_recovery_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, corrupt: bool
) -> None:
    from fabric.byte_spool import DurableByteSpool  # noqa: PLC0415

    runner = _runner()
    real_close = DurableByteSpool.close
    injected = False

    def close_then_lose(self: Any, timeout_s: float = 10) -> bool:
        nonlocal injected
        stopped = real_close(self, timeout_s)
        if not injected and stopped:
            files = list((tmp_path / "reference" / "byte-spool").glob("*.spool"))
            if files:
                injected = True
                if corrupt:
                    files[0].write_bytes(b"corrupted")
                else:
                    files[0].unlink()
        return stopped

    monkeypatch.setattr(DurableByteSpool, "close", close_then_lose)
    with pytest.raises((RuntimeError, ValueError)):
        runner.run(tmp_path / "reference", iterations=1)
    assert injected
    assert not (tmp_path / "reference/report.json").exists()


def test_reference_requires_successful_distributed_campaign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace  # noqa: PLC0415

    runner = _runner()
    actual = runner._module

    def load(name: str, path: Path) -> Any:
        if name == "reference_closure_campaign":
            return SimpleNamespace(run_closure_campaign=lambda _output: {"status": "failed"})
        return actual(name, path)

    monkeypatch.setattr(runner, "_module", load)
    with pytest.raises(RuntimeError, match="closure campaign failed"):
        runner.run(tmp_path / "reference", iterations=1)
    assert not (tmp_path / "reference/report.json").exists()
