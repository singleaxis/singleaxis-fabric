"""Offline checks for the conservative subscription-backed stage reconciler."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).resolve().parents[1] / "qualification" / "run_sol_local_stage.py"
)
SPEC = importlib.util.spec_from_file_location("run_sol_local_stage", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
stage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage)


def _event(command: str, index: int) -> dict:
    return {
        "type": "item.completed",
        "item": {
            "id": f"item_{index}",
            "type": "command_execution",
            "command": command,
            "aggregated_output": "ok\n",
            "exit_code": 0,
        },
    }


@pytest.fixture
def observed_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, dict]:
    workspace, _db_path, _canary = stage.fixture(tmp_path)
    before = stage.inventory(workspace)
    report = b'{"incident_id":"INC-42","action":"human_review"}'
    stage.write_private(workspace / "report.json", report)
    stage.write_private(
        workspace / "artifact.bin", b"\x00" + hashlib.sha256(report).digest()
    )
    routes = ["/telemetry/INC-42", "/db/INC-42", "/ticket/INC-42"]
    entries = []
    for index, route in enumerate(routes, 1):
        request = (
            b'{"incident_id":"INC-42","action":"human_review"}' if index == 3 else b""
        )
        response = b'{"ok":true}'
        request_name = f"request-{index:04d}.bin"
        response_name = f"response-{index:04d}.bin"
        stage.write_private(tmp_path / request_name, request)
        stage.write_private(tmp_path / response_name, response)
        entries.append(
            {
                "sequence": index,
                "method": "POST" if index == 3 else "GET",
                "route": route,
                "status": 200,
                "request": {
                    "path": request_name,
                    **stage.file_record(tmp_path / request_name),
                },
                "response": {
                    "path": response_name,
                    **stage.file_record(tmp_path / response_name),
                },
            }
        )
    stage.write_private(
        tmp_path / "service-journal.jsonl",
        ("\n".join(json.dumps(entry) for entry in entries) + "\n").encode(),
    )
    commands = [
        "python3 calculate.py case.json",
        "git status --short",
        *(f"curl http://127.0.0.1:1234{route}" for route in routes),
    ]
    events = [_event(command, index) for index, command in enumerate(commands)]
    events.append({"type": "turn.completed", "usage": {}})
    stage.write_private(
        tmp_path / "codex.jsonl",
        ("\n".join(json.dumps(event) for event in events) + "\n").encode(),
    )
    stage.write_private(tmp_path / "codex.stderr", b"")
    original_run_checked = stage.run_checked

    def checked(argv: list[str], cwd: Path) -> bytes:
        if argv == ["codex", "--version"]:
            return b"codex-cli synthetic-fixture\n"
        return original_run_checked(argv, cwd)

    monkeypatch.setattr(stage, "run_checked", checked)
    return tmp_path, workspace, before


def test_complete_fixture_never_claims_verified(
    observed_run: tuple[Path, Path, dict],
) -> None:
    root, workspace, before = observed_run
    result = stage.reconcile(root, workspace, before, 0, False, False)
    assert result["verdict"] == "unverified"
    assert not result["production_go"]
    assert result["mismatches"] == []


def test_direct_bypass_and_corrupt_byte_lower_verdict(
    observed_run: tuple[Path, Path, dict],
) -> None:
    root, workspace, before = observed_run
    journal = root / "service-journal.jsonl"
    entries = [json.loads(line) for line in journal.read_text().splitlines()]
    bypass = dict(entries[0], sequence=4)
    journal.write_text(journal.read_text() + json.dumps(bypass) + "\n")
    result = stage.reconcile(root, workspace, before, 0, False, True)
    assert result["verdict"] == "partial"
    assert any(
        item.get("route") == "/telemetry/INC-42" for item in result["mismatches"]
    )
    (root / entries[1]["response"]["path"]).write_bytes(b"corrupt")
    result = stage.reconcile(root, workspace, before, 0, False, True)
    assert any(
        item.get("boundary") == "service_byte_object" for item in result["mismatches"]
    )
