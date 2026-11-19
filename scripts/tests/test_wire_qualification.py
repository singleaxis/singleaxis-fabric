# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 055 §3.1, §9.4: the TypeScript wire qualification table and its audit script.

The table (``sdk/typescript/wire-qualification.json``) is validated with the coverage
family; here: the audit script's channel list is the schema's, its ``--check`` comparison
accepts a matching row and names the fix for a missing or differing one, the CI job audits
exactly the builds the spec names (Node 22, 24.0.0, the lowest Node 24 build publishing
both body channels and the newest audited 24.x), and no gate or active claim is made
before its unit. An ``active`` tuple (unit 055-t6) carries the SHA-256 of its committed
``ts-wire-passivity`` report, which passed every gate on exactly that build, and the CI
passivity job runs on exactly the active tuples."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TABLE = REPO_ROOT / "sdk" / "typescript" / "wire-qualification.json"
SCRIPT = REPO_ROOT / "scripts" / "typescript" / "audit-undici-channels.mjs"
SCHEMA = REPO_ROOT / "contracts/coverage/v1/schema/wire-qualification-v1.schema.json"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "recorder-ci.yml"
RESULTS = REPO_ROOT / "qualification" / "node-wire" / "results"
PASSIVITY_GATES = {
    "calibration",
    "hook_cost",
    "gate_self_test",
    "event_loop",
    "forbidden_work",
    "behaviour_identity",
    "memory_bound",
}
# Gates added after the committed reports were measured: a report may predate them
# (large_shapes: unit 055-t8; unit 055-t17 commits the claim's reports with every gate).
LATER_PASSIVITY_GATES = {"large_shapes"}


def _table() -> dict[str, Any]:
    table: dict[str, Any] = json.loads(TABLE.read_text(encoding="utf-8"))
    return table


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


def _node(expression: str) -> Any:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    program = (
        f"import * as audit from {json.dumps(SCRIPT.as_uri())};\n"
        f"process.stdout.write(JSON.stringify({expression}));"
    )
    done = subprocess.run(
        [node, "--input-type=module", "-e", program],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def _ci_versions() -> list[str]:
    text = WORKFLOW.read_text(encoding="utf-8")
    job = text[text.index("  ts-wire-audit:") :]
    job = job[: job.index("\n  fabric-node:")]
    match = re.search(r"node-version: \[([^\]]*)\]", job)
    assert match is not None
    assert "--check sdk/typescript/wire-qualification.json" in job
    return [v.strip().strip('"') for v in match.group(1).split(",")]


def test_audit_channels_are_the_schema_channels() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert _node("audit.CHANNELS") == schema["$defs"]["channel"]["enum"]
    assert _node("audit.AUDIT_SCHEMA") == "fabric.undici-channel-audit/v1"


def test_check_accepts_a_matching_row_and_names_the_fix_otherwise() -> None:
    row = next(a for a in _table()["audits"] if a["result"] == "both_body_channels")
    table = json.dumps(_table())
    assert _node(f"audit.compare({table}, {json.dumps(row)})") == []
    newer = dict(row, node="24.99.0")
    missing = _node(f"audit.compare({table}, {json.dumps(newer)})")
    assert len(missing) == 1 and "has no audit row" in missing[0]
    assert "Fix: add this row" in missing[0] and '"node":"24.99.0"' in missing[0]
    lost = dict(row, published=[], result="missing_body_channels")
    differing = _node(f"audit.compare({table}, {json.dumps(lost)})")
    assert any("published" in p for p in differing)
    assert any("result" in p and "Fix:" in p for p in differing)


def test_ci_audits_the_builds_the_spec_names() -> None:
    table = _table()
    linux = {
        a["node"]: a for a in table["audits"] if a["platform"] == "linux-x64-glibc"
    }
    versions = _ci_versions()
    assert all(v in linux for v in versions), "every CI build has a linux-x64-glibc row"
    by_major = {v: _version(v) for v in versions}
    node22 = [v for v, parts in by_major.items() if parts[0] == 22]
    assert len(node22) == 1 and linux[node22[0]]["result"] == "missing_body_channels"
    assert linux["24.0.0"]["result"] == "missing_body_channels"
    both = sorted(
        (v for v, a in linux.items() if a["result"] == "both_body_channels"),
        key=_version,
    )
    assert both, "no audited build publishes both body channels (spec 055 §10.3)"
    minimum, newest = both[0], both[-1]
    assert minimum in versions and newest in versions
    assert newest == max(linux, key=_version), "the newest audited build is Node 24"
    # Every Node 24 build below the candidate minimum that was audited lacks the channels.
    for version, row in linux.items():
        if _version(version) < _version(minimum):
            assert row["result"] == "missing_body_channels", version


def test_table_makes_no_claim_before_its_units() -> None:
    """Unit 055-t1 writes audited tuples; 055-t6 makes an undici tuple active with its
    passivity report; core-HTTP tuples arrive with 055-t21 and the gates flip in 055-t17
    and 055-t22."""
    table = _table()
    assert table["gates"] == {
        "TS-1U": "not_passed",
        "TS-1D": "not_passed",
        "TS-1H": "not_passed",
    }
    assert {t["claim"] for t in table["tuples"]} <= {"audited", "active"}
    assert {t["point"] for t in table["tuples"]} == {"wire.ts.undici"}
    audited = {
        (a["node"], a["platform"])
        for a in table["audits"]
        if a["result"] == "both_body_channels"
    }
    assert {(t["node"], t["platform"]) for t in table["tuples"]} == audited


def _report_path(tuple_: dict[str, Any]) -> Path:
    return RESULTS / f"passivity-{tuple_['node']}-{tuple_['platform']}.json"


def _active() -> list[dict[str, Any]]:
    return [t for t in _table()["tuples"] if t["claim"] == "active"]


def test_every_active_tuple_has_its_passed_report_committed() -> None:
    for tuple_ in _active():
        path = _report_path(tuple_)
        assert path.is_file(), f"{path.name}: commit the CI report of this tuple"
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert tuple_["report_sha256"] == f"sha256:{digest}", path.name
        report = json.loads(path.read_text(encoding="utf-8"))
        assert report["schema"] == "fabric.node-wire-passivity-report/v1"
        assert report["quick"] is False and report["result"] == "passed"
        assert report["voided_runs"] in (0, 1)
        assert (
            PASSIVITY_GATES
            <= set(report["gates"])
            <= PASSIVITY_GATES | LATER_PASSIVITY_GATES
        )
        assert all(report["gates"].values()), path.name
        assert report["tuple"] == {
            "point": tuple_["point"],
            "node": tuple_["node"],
            "undici": tuple_["undici"],
            "undici_origin": tuple_["undici_origin"],
            "platform": tuple_["platform"],
        }
        assert report["hook_cost"]["trials"] >= 30
        assert report["self_test_hook"]["gate_failed_on_stall"] is True
        assert report["self_test_event_loop"]["gate_failed_on_stall"] is True
    committed = {p.name for p in RESULTS.glob("passivity-*.json")}
    assert committed == {_report_path(t).name for t in _active()}


def test_the_passivity_job_runs_on_exactly_the_active_tuples() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    job = text[text.index("  ts-wire-passivity:") :]
    job = job[: job.index("\n  typescript-native:")]
    rows = re.findall(
        r'node-version: "([^"]+)", platform: ([a-z0-9-]+), runner: ([a-z0-9.-]+)', job
    )
    runners = {
        "linux-x64-glibc": "ubuntu-24.04",
        "linux-arm64-glibc": "ubuntu-24.04-arm",
    }
    assert rows, "the ts-wire-passivity matrix lists its tuples"
    for _node, platform, runner in rows:
        assert runners.get(platform) == runner, platform
    assert "qualification/node-wire/passivity/run.mjs" in job
    assert {(n, p) for n, p, _ in rows} == {
        (t["node"], t["platform"]) for t in _active()
    }
