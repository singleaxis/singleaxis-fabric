"""Regression assertions on real subprocess runs, never synthetic span counts."""

import json
from pathlib import Path
import subprocess
import sys
import pytest

HERE = Path(__file__).parent


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("none", 0),
        ("otel-explicit", 6),
        ("fabric-explicit", 6),
        ("fabric-auto", 4),
        ("openinference-auto", 4),
    ],
)
def test_actual_instrumentation_scope(tmp_path, mode, expected):
    subprocess.run(
        [
            sys.executable,
            str(HERE / "run.py"),
            "--worker",
            "--mode",
            mode,
            "--work",
            str(tmp_path),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    result = json.loads((tmp_path / "result.json").read_text())
    truth = json.loads((tmp_path / "truth.json").read_text())
    assert len(truth) == 7
    assert {t["witness"] for t in truth} == {
        "HTTP server",
        "filesystem readback",
        "child stdout and exit",
    }
    assert result["captured_local_records"] == expected
    assert result["exported_spans"] == expected
    assert result["error_records"] == int(mode != "none")
    assert not result["unwrapped_action_captured"]
    if mode in {"otel-explicit", "fabric-explicit"}:
        assert result["independent_inventory_unmatched_action_ids"] == [
            ["bypass", "one"]
        ]
        assert not result["raw_canary_in_export"]


@pytest.mark.parametrize(
    "mode", ["otel-explicit", "fabric-explicit", "fabric-auto", "openinference-auto"]
)
def test_actual_export_failure_visible_in_witness(tmp_path, mode):
    subprocess.run(
        [
            sys.executable,
            str(HERE / "run.py"),
            "--worker",
            "--mode",
            mode,
            "--fault",
            "export-first-failure",
            "--work",
            str(tmp_path),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    result = json.loads((tmp_path / "result.json").read_text())
    assert result["failed_export_spans"] == 1
    assert result["captured_local_records"] - result["exported_spans"] == 1


@pytest.mark.parametrize(
    "mode", ["otel-explicit", "fabric-explicit", "fabric-auto", "openinference-auto"]
)
def test_abrupt_process_exit_before_batch_flush(tmp_path, mode):
    proc = subprocess.run(
        [
            sys.executable,
            str(HERE / "run.py"),
            "--worker",
            "--mode",
            mode,
            "--fault",
            "crash-before-flush",
            "--work",
            str(tmp_path),
        ],
        capture_output=True,
        timeout=30,
    )
    assert proc.returncode == 23
    assert len(json.loads((tmp_path / "truth.json").read_text())) == 7
    assert not (tmp_path / "exported.jsonl").exists()


@pytest.mark.parametrize(
    "mode,route",
    [
        ("fabric-auto", "--managed-provider"),
        ("openinference-auto", "--redact-exceptions"),
    ],
)
def test_actual_protected_routes(tmp_path, mode, route):
    subprocess.run(
        [
            sys.executable,
            str(HERE / "run.py"),
            "--worker",
            "--mode",
            mode,
            route,
            "--work",
            str(tmp_path),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    result = json.loads((tmp_path / "result.json").read_text())
    assert result["captured_local_records"] == 4
    assert result["exported_spans"] == 4
    assert not result["raw_canary_in_export"]
    assert sum(s["status"]["status_code"] == "ERROR" for s in result["spans"]) == 1
