# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for exact-SHA workflow evidence verification."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from release import verify_workflow_runs as verifier  # noqa: E402


SHA = "0123456789abcdef0123456789abcdef01234567"


def _run(
    *,
    sha: str = SHA,
    status: str = "completed",
    conclusion: str = "success",
    run_id: int = 42,
) -> dict[str, object]:
    return {
        "id": run_id,
        "html_url": f"https://github.com/singleaxis/singleaxis-fabric/actions/runs/{run_id}",
        "head_sha": sha,
        "event": "push",
        "status": status,
        "conclusion": conclusion,
    }


def test_selects_latest_success_for_exact_sha() -> None:
    evidence = verifier.select_successful_run(
        "ci.yml",
        SHA,
        {"workflow_runs": [_run(run_id=41), _run(run_id=43), _run(run_id=42)]},
    )
    assert evidence.run_id == 43
    assert evidence.head_sha == SHA


@pytest.mark.parametrize(
    "payload",
    [
        {"workflow_runs": []},
        {"workflow_runs": [_run(sha="f" * 40)]},
        {"workflow_runs": [_run(status="in_progress", conclusion="success")]},
        {"workflow_runs": [_run(conclusion="failure")]},
        {},
    ],
)
def test_missing_or_non_success_evidence_fails_closed(
    payload: dict[str, object],
) -> None:
    with pytest.raises(verifier.EvidenceError):
        verifier.select_successful_run("ci.yml", SHA, payload)


def test_policy_requires_unique_workflow_files(tmp_path: Path) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps({"required_workflows": ["ci.yml", "ci.yml"]}), encoding="utf-8"
    )
    with pytest.raises(verifier.EvidenceError, match="duplicates"):
        verifier.load_required_workflows(policy)


def test_release_requires_production_profile_on_exact_sha() -> None:
    policy = Path(__file__).resolve().parents[1] / "release" / "release-policy.json"
    required = verifier.load_required_workflows(policy)
    assert "e2e.yml" in required
    assert "e2e-production-profile.yml" in required


def test_verify_queries_every_required_workflow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queried: list[str] = []

    def fake_query(repository: str, workflow: str, sha: str) -> dict[str, object]:
        assert repository == "singleaxis/singleaxis-fabric"
        assert sha == SHA
        queried.append(workflow)
        return {"workflow_runs": [_run()]}

    monkeypatch.setattr(verifier, "query_workflow", fake_query)
    records = verifier.verify_required_workflows(
        "singleaxis/singleaxis-fabric", SHA, ("ci.yml", "security.yml")
    )
    assert [record.workflow for record in records] == ["ci.yml", "security.yml"]
    assert queried == ["ci.yml", "security.yml"]


def test_short_sha_is_rejected_before_query() -> None:
    with pytest.raises(verifier.EvidenceError, match="40-character"):
        verifier.verify_required_workflows(
            "singleaxis/singleaxis-fabric", "abc123", ("ci.yml",)
        )


def test_semgrep_findings_fail_the_security_workflow() -> None:
    import shlex
    import yaml

    workflow = (
        Path(__file__).resolve().parents[2] / ".github/workflows/recorder-security.yml"
    )
    config = yaml.safe_load(workflow.read_text())
    commands = [
        step["run"] for step in config["jobs"]["semgrep"]["steps"] if "run" in step
    ]
    assert len(commands) == 1
    arguments = shlex.split(commands[0])
    assert arguments[:2] == ["semgrep", "scan"]
    assert "--error" in arguments
    assert "--sarif" in arguments
    assert "--exclude" not in arguments
    assert "--exclude-rule" not in arguments
