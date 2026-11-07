# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed verification of required GitHub workflow runs on an exact SHA."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class WorkflowEvidence:
    workflow: str
    run_id: int
    run_url: str
    head_sha: str
    event: str
    status: str
    conclusion: str


class EvidenceError(ValueError):
    """Required release evidence is absent, stale, or unsuccessful."""


def load_required_workflows(policy_path: Path) -> tuple[str, ...]:
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    workflows = policy.get("required_workflows")
    if not isinstance(workflows, list) or not workflows:
        raise EvidenceError("release policy has no required_workflows")
    if not all(isinstance(item, str) and item.endswith(".yml") for item in workflows):
        raise EvidenceError(
            "required_workflows must be a non-empty list of .yml filenames"
        )
    if len(set(workflows)) != len(workflows):
        raise EvidenceError("required_workflows contains duplicates")
    return tuple(workflows)


def select_successful_run(
    workflow: str, sha: str, payload: dict[str, Any]
) -> WorkflowEvidence:
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list):
        raise EvidenceError(f"{workflow}: GitHub response has no workflow_runs list")

    candidates: list[dict[str, Any]] = []
    for run in runs:
        if not isinstance(run, dict) or run.get("head_sha") != sha:
            continue
        if run.get("status") == "completed" and run.get("conclusion") == "success":
            candidates.append(run)

    if not candidates:
        raise EvidenceError(
            f"{workflow}: no completed/success run exists for exact SHA {sha}"
        )

    # API order is not a trust primitive. Select deterministically by run id.
    selected = max(candidates, key=lambda run: int(run.get("id", 0)))
    run_id = selected.get("id")
    run_url = selected.get("html_url")
    event = selected.get("event")
    if not isinstance(run_id, int) or run_id <= 0:
        raise EvidenceError(f"{workflow}: successful run has no valid id")
    if not isinstance(run_url, str) or not run_url.startswith("https://github.com/"):
        raise EvidenceError(f"{workflow}: successful run has no canonical GitHub URL")
    if not isinstance(event, str) or not event:
        raise EvidenceError(f"{workflow}: successful run has no trigger event")

    return WorkflowEvidence(
        workflow=workflow,
        run_id=run_id,
        run_url=run_url,
        head_sha=sha,
        event=event,
        status="completed",
        conclusion="success",
    )


def query_workflow(repository: str, workflow: str, sha: str) -> dict[str, Any]:
    endpoint = (
        f"repos/{repository}/actions/workflows/{workflow}/runs"
        f"?head_sha={sha}&per_page=50"
    )
    result = subprocess.run(
        ["gh", "api", endpoint],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or "gh api returned no diagnostic"
        raise EvidenceError(f"{workflow}: unable to query GitHub evidence: {detail}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"{workflow}: GitHub returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise EvidenceError(f"{workflow}: GitHub returned a non-object response")
    return payload


def verify_required_workflows(
    repository: str, sha: str, workflows: Sequence[str]
) -> list[WorkflowEvidence]:
    if len(sha) != 40 or any(char not in "0123456789abcdef" for char in sha.lower()):
        raise EvidenceError("--sha must be a full 40-character Git commit SHA")
    if repository.count("/") != 1:
        raise EvidenceError("--repository must use OWNER/REPOSITORY form")

    return [
        select_successful_run(workflow, sha, query_workflow(repository, workflow, sha))
        for workflow in workflows
    ]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        workflows = load_required_workflows(args.policy)
        evidence = verify_required_workflows(args.repository, args.sha, workflows)
    except (EvidenceError, OSError, json.JSONDecodeError) as exc:
        print(f"release evidence verification failed: {exc}", file=sys.stderr)
        return 1

    document = {
        "schema_version": "fabric.release-workflow-evidence/v1",
        "repository": args.repository,
        "commit_sha": args.sha,
        "required_workflows": [item.__dict__ for item in evidence],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"verified {len(evidence)} required workflows on exact SHA {args.sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
