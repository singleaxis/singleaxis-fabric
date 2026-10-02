# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Run user quickstart entrypoints against real local capture/storage paths."""

from __future__ import annotations

import importlib.util
import json
import secrets
import threading
from pathlib import Path
from typing import Any

import pytest

from fabric.content_store.local import LocalFilesystemContentStore
from fabric.deployment_policy import DeploymentPolicy
from fabric.enterprise import PolicyCaptureSession
from fabric.governed_store import GovernedLocalContentStore, LocalCapabilityAuthority


def load(relative: str) -> Any:
    path = Path(__file__).resolve().parents[3] / relative
    spec = importlib.util.spec_from_file_location("enterprise_fixture", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_configured_actual_capture_lifecycle(tmp_path: Path) -> None:
    module = load("scripts/qualification/run_enterprise_local.py")
    report = module.run(tmp_path / "evidence")
    assert set(report["local_checks"].values()) == {"PASS"}
    assert report["production_verdict"] == "NO_GO"
    assert report["external_control_coverage"] == "unverified"
    assert report["persistence_states"]["not_captured"] > 0
    assert report["deletion"]["state"] == "deleted"
    assert report["storage"]["encryption"] == "AES-256-GCM"


def test_real_multi_agent_orchestration_detects_gaps(tmp_path: Path) -> None:
    module = load("examples/enterprise-orchestration/run.py")
    report = module.run(tmp_path / "orchestration")
    assert report["deliberate_bypass_detected"] is True
    assert report["full_route_coverage_complete"] is False
    assert all(report["effect_readback"].values())
    assert report["retry_outcomes"] == ["error", "ok"]
    assert report["source_recovery"]["new_epoch"] == 1
    assert report["source_recovery"]["original_history_verified"] is False
    assert report["passive_denied_storage"]["event_statuses"] == ["failed", "failed"]


def test_session_rejects_unbound_legacy_store_before_capture(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[3]
    policy = DeploymentPolicy.from_dict(
        json.loads((root / "examples/enterprise/policy.local.json").read_text())
    )
    store = LocalFilesystemContentStore(str(tmp_path / "unbound"), tenant_id=policy.tenant_id)
    with pytest.raises(ValueError, match="policy mismatch"):
        PolicyCaptureSession(
            policy=policy, store=store, run_id="run", source_id="source", agent_id="agent"
        )
    assert not list(tmp_path.rglob("*.json"))


@pytest.mark.parametrize("blocked", [False, True])
def test_session_close_reports_settlement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, blocked: bool
) -> None:
    root = Path(__file__).resolve().parents[3]
    configuration = json.loads((root / "examples/enterprise/policy.local.json").read_text())
    configuration["privacy"] = {
        "tool.call.arguments": "retain_original",
        "tool.call.result": "retain_original",
    }
    policy = DeploymentPolicy.from_dict(configuration)
    authority = LocalCapabilityAuthority(secrets.token_bytes(32))
    capability = authority.issue(
        policy=policy, subject_id="close-test", permissions={"write_original"}
    )
    store = GovernedLocalContentStore(
        tmp_path / "store",
        plane="original",
        policy=policy,
        authority=authority,
        capability=capability,
        encryption_key=secrets.token_bytes(32),
    )
    session = PolicyCaptureSession(
        policy=policy, store=store, run_id="run", source_id="source", agent_id="agent"
    )
    entered = threading.Event()
    release = threading.Event()
    process = session.writer._process

    def delayed_process(object_id: str, data: bytes, derivative_id: str | None) -> None:
        entered.set()
        release.wait(timeout=5.0)
        process(object_id, data, derivative_id)

    try:
        if blocked:
            monkeypatch.setattr(session.writer, "_process", delayed_process)
        assert session.calls.call(b"input", lambda _: b"result") == b"result"
        if blocked:
            assert entered.wait(timeout=2.0)
            assert session.close(timeout_s=0.0) is False
            assert session.report()["persistence_states"]["pending"] > 0
            release.set()
        assert session.close() is True
        assert "pending" not in session.report()["persistence_states"]
    finally:
        release.set()
        session.close()
        store.close()
