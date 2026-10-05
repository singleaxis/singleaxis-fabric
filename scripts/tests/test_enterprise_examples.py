# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Real offline examples, their closed inputs, and honest fixture-only claims."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(relative: str) -> Any:
    spec = importlib.util.spec_from_file_location("enterprise_example", ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("scenario", ["clean", "gaps"])
def test_orchestration_real_effects_and_exact_http_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scenario: str
) -> None:
    module = _load("examples/enterprise-orchestration/run.py")
    child = tmp_path / "work"
    child.mkdir()
    monkeypatch.chdir(child)
    report = module.run(Path("../evidence"), scenario=scenario)
    assert all(report["effect_readback"].values())
    reconciliation = report["http_reconciliation"]
    assert reconciliation["captured_attempts"] == 3
    assert reconciliation["physical_attempts"] == (4 if scenario == "gaps" else 3)
    assert reconciliation["fixture_http_routes_reconciled"] is (scenario == "clean")
    assert report["deliberate_bypass_detected"] is (scenario == "gaps")
    assert report["partial_stream_detected"] is (scenario == "gaps")
    assert reconciliation["unmatched_captured_attempts"] == []
    assert report["production_verdict"] == "NO_GO"
    assert report["full_route_coverage_complete"] is False
    assert report["external_model_provider"] == "not_invoked"
    assert report["passive_denied_storage"]["event_statuses"] == ["failed", "failed"]
    calls = report["source_snapshot"]["calls"]
    parent = next(row for row in calls if row["operation_id"] == "orchestrator")
    worker_calls = [row for row in calls if row["operation_id"].endswith("-operation")]
    assert len(worker_calls) == 3
    assert all(row["parent_call_id"] == parent["call_id"] for row in worker_calls)
    assert report["source_recovery"]["status"] == (
        "recovered_unqualified" if scenario == "gaps" else "not_run"
    )
    assert module.CANARY not in (tmp_path / "evidence/report.json").read_bytes()


def test_starter_policy_runs_directly_without_storage_root(tmp_path: Path) -> None:
    module = _load("examples/enterprise-orchestration/run.py")
    report = module.run(
        tmp_path / "evidence",
        ROOT / "examples/enterprise/policy.local.json",
        scenario="clean",
    )
    assert report["http_reconciliation"]["fixture_http_routes_reconciled"] is True
    assert report["storage"]["encryption"] == "AES-256-GCM"
    assert report["source_seal"]["status"] == "refused"


def test_clean_all_original_policy_can_seal_metadata_without_production_claim(
    tmp_path: Path,
) -> None:
    module = _load("examples/enterprise-orchestration/run.py")
    policy = json.loads((ROOT / "examples/enterprise/policy.local.json").read_text())
    policy["privacy"] = {
        role: "retain_original"
        for role in (
            "model.request.messages",
            "model.output.messages",
            "tool.call.arguments",
            "tool.call.result",
            "terminal.stdout",
            "terminal.stderr",
            "artifact.after",
            "database.rows",
            "memory.write.content",
            "memory.read.content",
        )
    }
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy))
    report = module.run(tmp_path / "evidence", policy_path, scenario="clean")
    assert report["source_seal"]["status"] == "sealed"
    assert report["full_route_coverage_complete"] is False
    assert report["production_verdict"] == "NO_GO"


def test_local_runner_accepts_parent_relative_new_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load("scripts/qualification/run_enterprise_local.py")
    child = tmp_path / "work"
    child.mkdir()
    monkeypatch.chdir(child)
    report = module.run(Path("../evidence"))
    assert set(report["local_checks"].values()) == {"PASS"}
    assert all(
        int(row["trace_id"], 16) and int(row["span_id"], 16)
        for row in report["source_snapshot"]["calls"]
    )


@pytest.mark.parametrize(
    "payload",
    [
        b'{"workers":["file","database","process"],"join_background":false}',
        b'{"workers":["file","database","process"],"join_background":1}',
        b'{"workers":["shell"],"join_background":true}',
        b'{"workers":["file","database","process"],"join_background":true,"command":"x"}',
        b'{"workers":[],"workers":["file","database","process"],"join_background":true}',
        b"[]",
    ],
)
def test_untrusted_plan_cannot_change_worker_contract(payload: bytes) -> None:
    module = _load("examples/enterprise-orchestration/run.py")
    with pytest.raises(ValueError):
        module.validated_plan(payload)


def test_reconciliation_cannot_substitute_wrong_route_with_equal_counts() -> None:
    module = _load("examples/enterprise-orchestration/run.py")
    result = module.reconcile_http_attempts(
        [{"route": "/bypass", "attempt": 1, "status": 200}],
        [{"operation_id": "model-plan", "attempt_id": "try-1", "status": "ok"}],
    )
    assert result["physical_attempts"] == result["captured_attempts"] == 1
    assert result["fixture_http_routes_reconciled"] is False
    assert result["missing_physical_attempts"][0]["route"] == "/bypass"
    assert result["unmatched_captured_attempts"][0]["route"] == "/model"


@pytest.mark.parametrize(
    "path",
    [
        "examples/enterprise-orchestration/run.py",
        "scripts/qualification/run_enterprise_local.py",
    ],
)
def test_examples_preserve_existing_output(path: str, tmp_path: Path) -> None:
    module = _load(path)
    output = tmp_path / "evidence"
    output.mkdir()
    sentinel = output / "previous-result"
    sentinel.write_bytes(b"keep")
    with pytest.raises(FileExistsError):
        module.run(output)
    assert sentinel.read_bytes() == b"keep"


def test_duplicate_policy_key_is_rejected(tmp_path: Path) -> None:
    module = _load("examples/enterprise-orchestration/run.py")
    path = tmp_path / "policy.json"
    path.write_text('{"storage":{},"storage":{}}')
    with pytest.raises(ValueError, match="duplicate JSON key"):
        module.run(tmp_path / "evidence", path)


def test_optimized_orchestration_refuses_false_qualification(tmp_path: Path) -> None:
    output = tmp_path / "not-created"
    result = subprocess.run(
        [
            sys.executable,
            "-O",
            str(ROOT / "examples/enterprise-orchestration/run.py"),
            "--scenario",
            "clean",
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode != 0
    assert "optimized Python is unsupported" in result.stderr
    assert "LOCAL_CHECKS_PASS" not in result.stdout
    assert not output.exists()
