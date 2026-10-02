# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Executable application-onboarding example, not production qualification."""

from __future__ import annotations

import importlib.util
import json
import secrets
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples/enterprise-reference/integrate.py"
POLICY = EXAMPLE.with_name("policy.integration.json")


def load():
    spec = importlib.util.spec_from_file_location(
        "enterprise_integration_example", EXAMPLE
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_exact_integration_and_doctor_commands_pass_locally(tmp_path: Path) -> None:
    output = tmp_path / "demo"
    result = subprocess.run(
        [sys.executable, str(EXAMPLE), "--output", str(output)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["local_integration_passed"] is True
    report = json.loads((output / "integration-report.json").read_text())
    assert report["response_preserved"] and report["background_parent_linked"]
    assert report["http_boundary"]["receiver_count"] == report["call_count"] == 2
    assert report["byte_delivery"]["delivered"] == 4
    assert report["journal_health"]["spooled"] == 8
    assert report["production_qualified"] is False
    assert report["destination_delivery"] == "not_configured"
    assert report["key_custody"] == "ephemeral_demo_only_not_restart_recoverable"
    assert report["shutdown_settled"]
    for path in output.rglob("*"):
        if path.is_file():
            assert b"synthetic-model-input" not in path.read_bytes()
            assert b"synthetic-tool-input" not in path.read_bytes()
    doctor = subprocess.run(
        [
            sys.executable,
            "-m",
            "fabric.enterprise_preflight",
            "--policy",
            str(POLICY),
            "--scope",
            str(output / "scope.json"),
            "--snapshot",
            str(output / "snapshot.json"),
            "--run-canary",
            "--filesystem-root",
            str(output),
            "--output",
            str(output / "preflight.json"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert doctor.returncode == 0, doctor.stderr
    preflight = json.loads((output / "preflight.json").read_text())
    assert preflight["verdict"] == "LOCAL_READY"
    assert preflight["production_verdict"] == "NO_GO"


def test_shared_dispatch_preserves_result_and_exception_and_counts_unsupported(
    tmp_path: Path,
) -> None:
    from fabric.deployment_policy import DeploymentPolicy

    module = load()
    capture = module.initialize_capture(
        tmp_path / "application",
        policy=DeploymentPolicy.from_dict(json.loads(POLICY.read_text())),
        authority_key=secrets.token_bytes(32),
        storage_key=secrets.token_bytes(32),
        spool_key=secrets.token_bytes(32),
    )
    sentinel = object()
    original = RuntimeError("PRIVATE_ERROR_NOT_METADATA")

    def failure(_payload):
        raise original

    try:
        assert (
            capture.dispatch(
                b"input",
                lambda _: sentinel,
                kind="tool",
                operation_id="result",
                attempt_id="result-1",
            )
            is sentinel
        )
        with pytest.raises(RuntimeError) as caught:
            capture.dispatch(
                b"input",
                failure,
                kind="model",
                operation_id="failure",
                attempt_id="failure-1",
            )
        assert caught.value is original
        snapshot = capture.session.calls.snapshot()
        assert {row["status"] for row in snapshot["calls"]} == {"ok", "error"}
        assert any(row["status"] == "unsupported" for row in snapshot["events"])
        assert "PRIVATE_ERROR_NOT_METADATA" not in json.dumps(snapshot)
    finally:
        assert capture.close()
    assert capture.close()


def test_lifecycle_does_not_close_store_beneath_unsettled_worker() -> None:
    module = load()
    stopped = [False]
    journal_calls = []
    store_calls = []
    capture = module.AppCapture(
        session=SimpleNamespace(close=lambda **_: stopped[0]),
        journal=SimpleNamespace(
            close=lambda **_: journal_calls.append("close") or True
        ),
        store=SimpleNamespace(close=lambda: store_calls.append("close")),
    )
    assert capture.close() is False
    assert store_calls == []
    stopped[0] = True
    assert capture.close() is True
    assert capture.close() is True
    assert journal_calls == store_calls == ["close"]


def test_transform_requirements_are_not_silently_replaced_by_original_capture(
    tmp_path: Path,
) -> None:
    from fabric.deployment_policy import DeploymentPolicy

    module = load()
    value = json.loads(POLICY.read_text())
    value["privacy"]["model.request.messages"] = "redact"
    with pytest.raises(ValueError, match="customization"):
        module.initialize_capture(
            tmp_path / "rejected",
            policy=DeploymentPolicy.from_dict(value),
            authority_key=secrets.token_bytes(32),
            storage_key=secrets.token_bytes(32),
            spool_key=secrets.token_bytes(32),
        )
    assert not (tmp_path / "rejected").exists()
