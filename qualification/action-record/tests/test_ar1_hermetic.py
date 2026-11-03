# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""AR-1 in hermetic mode (spec 056 §6.2), plus unit checks of the harness pieces.

Run from the repository root with the SDK's interpreter::

    sdk/python/.venv/bin/python -m pytest qualification/action-record/tests -q

The end-to-end test uses the built Node (``components/otel-collector-fabric/dist`` or
``FABRIC_NODE_DIST``) when there is one, else sends the agent's telemetry straight to
the sink; ``AR1_REQUIRE_NODE=1`` makes a missing Node a failure.
"""

from __future__ import annotations

import ast
import json
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from ar1 import expect, replay  # noqa: E402
from ar1.fixture_model import T1, T2, T3A, T3B, T4, Script  # noqa: E402
from ar1.harness import Harness, Options  # noqa: E402


def test_the_agent_imports_nothing_from_fabric() -> None:
    """The agent under test is plain: capture is switched on only from outside."""
    tree = ast.parse((HERE / "ar1" / "agent.py").read_text())
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported |= {
        str(node.module).split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert "fabric" not in imported and "ar1" not in imported
    assert "openai" in imported


def test_the_script_answers_only_the_expected_results() -> None:
    script = Script("/data", "http://[::1]:1/x")
    assert script.turn([]) is not None and script.turn([T1]) is not None
    assert script.turn([T1, T2, T3A, T3B, T4]) is not None
    assert script.turn([T2]) is None and script.turn([T1, T2, T3B, T3A]) is None
    assert "&&" in script.step1 and "|" in script.step3a and "|" in script.step3b


def test_the_replay_binds_each_tree_to_its_effect() -> None:
    effects = [
        replay.Effect("u1", 501, 500, 1_000_000_000, "ls /d && sha256sum /d/a.txt", 1_002_000_000),
        replay.Effect("u2", 502, 500, 2_000_000_000, "sh -c curl -fsS ... | head -c 65536"),
        replay.Effect("u3", 503, 500, 3_000_000_000, "something else"),
    ]
    bound = replay.bind(
        effects,
        [900_000_000, 1_900_000_000],
        peers={"model": ("127.0.0.1", 8000), "fixture_host": ("::1", 9000)},
        visits={"fixture_http": [2_010_000_000], "fixture_ping": [2_500_000_000]},
        agent_ppid=1,
    )
    assert bound.steps == {"u1": "1", "u2": "2"} and bound.unmatched == ["u3"]
    assert set(bound.anchors) == {"u1", "u2"} and len(bound.lineage["u2"]) == 3
    records = [r for s in bound.export["resourceLogs"][0]["scopeLogs"] for r in s["logRecords"]]
    attrs = [{a["key"]: next(iter(a["value"].values())) for a in r["attributes"]} for r in records]
    anchors = [a for a in attrs if a["log.record.uid"] in bound.anchors.values()]
    assert {(a["process.pid"], a["process.parent_pid"]) for a in anchors} == {
        ("501", "500"),
        ("502", "500"),
    }
    # Step 1 models dash: the last command of the list is exec'd in place, a second exec of
    # the anchor process (same pid and parent pid), kept before the effect's observed exit.
    pairs = zip(attrs, records, strict=True)
    by_uid = {a["log.record.uid"]: (a, int(r["timeUnixNano"])) for a, r in pairs}
    in_place = [by_uid[u] for u in bound.lineage["u1"] if by_uid[u][0]["process.pid"] == "501"]
    assert [(a["process.parent_pid"], a["process.executable.name"]) for a, _ in in_place] == [
        ("500", "sha256sum")
    ]
    assert in_place[0][1] < 1_002_000_000 and len(bound.lineage["u1"]) == 2
    connects = [a for a in attrs if a["audit.syscall"] == "connect"]
    assert len(connects) == 2 + 1 + 1  # two model calls, curl, the ping
    assert all("process.start_ns" not in a for a in attrs)  # the local profile has none
    times = [int(r["timeUnixNano"]) for r in records]
    assert times == sorted(times)


def test_manifest_reason_reads_the_capture_points() -> None:
    rows = [
        {
            "name": "fabric.capture_manifest",
            "attributes": {
                "fabric.manifest.capture_points": [
                    "exec.subprocess@0.8.0:H:disabled:0:0:hook_disabled",
                    "wire.py.httpx@0.8.0:W:active:0:0:-",
                ]
            },
        }
    ]
    assert expect.manifest_reason(rows, "exec.subprocess") == {"disabled:hook_disabled"}


def test_ar1_hermetic(tmp_path: Path) -> None:
    """Every variant of AR-1 with the host chain replayed; see README.md."""
    node = "required" if os.environ.get("AR1_REQUIRE_NODE") == "1" else "auto"
    result = Harness(Options(mode="hermetic", out=tmp_path, node=node, log=lambda _: None)).run()
    failures = {
        name: [c for c in v["checks"] if not c["passed"]]
        for name, v in result["variants"].items()
        if not v["passed"]
    }
    assert result["passed"], json.dumps(failures, indent=1)[:6000]
    assert set(result["variants"]) == {"base", "a", "b", "c", "d", "e", "canaries"}


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
