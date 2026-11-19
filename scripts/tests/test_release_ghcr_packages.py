# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The GHCR package allowlist (release-policy.json ``ghcr_packages``).

Legacy images stayed on GHCR after their sources were removed. The release policy now
lists every package a release publishes, and ``check_ghcr_packages.py`` refuses a
workflow that publishes anything else, or that publishes in a way it cannot name.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from release import check_ghcr_packages as ghcr  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
POLICY = json.loads(
    (ROOT / "scripts/release/release-policy.json").read_text(encoding="utf-8")
)
RELEASE = ".github/workflows/release.yml"


def test_the_release_publishes_exactly_the_allowlist() -> None:
    assert POLICY["ghcr_packages"] == [
        "fabric-otelcol",
        "fabric-host-emitter",
        "fabric-cli",
        "charts/fabric",
    ]
    assert ghcr.check(ROOT, POLICY) == [
        "charts/fabric",
        "fabric-cli",
        "fabric-host-emitter",
        "fabric-otelcol",
    ]
    assert set(ghcr.published(ROOT)) == set(POLICY["ghcr_packages"])
    assert ghcr.main(["--policy", str(ROOT / "scripts/release/release-policy.json"),
                      "--repo-root", str(ROOT)]) == 0  # fmt: skip


def test_the_release_qualification_runs_the_check() -> None:
    workflow = yaml.safe_load((ROOT / RELEASE).read_text(encoding="utf-8"))
    runs = [
        str(step.get("run", ""))
        for step in workflow["jobs"]["qualify-release"]["steps"]
    ]
    assert any("scripts/release/check_ghcr_packages.py" in run for run in runs)


def test_the_verification_guide_names_every_package() -> None:
    guide = (ROOT / "docs/verify-release.md").read_text(encoding="utf-8")
    for name in POLICY["ghcr_packages"]:
        assert f"ghcr.io/<owner>/{name}" in guide


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A copy of the workflows and the chart the check reads."""
    shutil.copytree(ROOT / ".github/workflows", tmp_path / ".github/workflows")
    (tmp_path / "charts/fabric").mkdir(parents=True)
    shutil.copy(
        ROOT / "charts/fabric/Chart.yaml", tmp_path / "charts/fabric/Chart.yaml"
    )
    return tmp_path


def _edit(repo: Path, change: Any) -> None:
    path = repo / RELEASE
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    change(workflow)
    path.write_text(yaml.safe_dump(workflow, sort_keys=False), encoding="utf-8")


def test_a_legacy_image_in_the_matrix_is_refused(repo: Path) -> None:
    _edit(repo, lambda w: w["jobs"]["publish-image"]["strategy"]["matrix"]["include"].append(
        {"component": "redteam-runner", "image": "fabric-redteam-runner", "context": "x"}))  # fmt: skip
    with pytest.raises(ghcr.PackageError, match="fabric-redteam-runner"):
        ghcr.check(repo, POLICY)


def test_an_unlisted_chart_is_refused(repo: Path) -> None:
    chart = repo / "charts/fabric/Chart.yaml"
    chart.write_text(
        chart.read_text().replace("name: fabric\n", "name: fabric-legacy\n", 1)
    )
    with pytest.raises(ghcr.PackageError):
        ghcr.check(repo, POLICY)


def test_an_unrecognized_push_is_refused(repo: Path) -> None:
    def sidecar(workflow: dict[str, Any]) -> None:
        workflow["jobs"]["publish-sidecar"] = {
            "runs-on": "ubuntu-latest",
            "steps": [{"run": "docker push ghcr.io/acme/fabric-presidio-sidecar:1"}],
        }

    _edit(repo, sidecar)
    with pytest.raises(ghcr.PackageError, match="cannot name"):
        ghcr.check(repo, POLICY)


def test_a_package_writer_that_publishes_nothing_recognized_is_refused(
    repo: Path,
) -> None:
    def writer(workflow: dict[str, Any]) -> None:
        workflow["jobs"]["publish-other"] = {
            "runs-on": "ubuntu-latest",
            "permissions": {"packages": "write"},
            "steps": [{"run": "./publish.sh"}],
        }

    _edit(repo, writer)
    with pytest.raises(ghcr.PackageError, match="packages: write"):
        ghcr.check(repo, POLICY)


def test_an_unnamed_image_push_is_refused(repo: Path) -> None:
    _edit(
        repo,
        lambda w: w["jobs"]["publish-image"]["env"].update(IMAGE_NAME="acme/other"),
    )
    with pytest.raises(ghcr.PackageError, match="IMAGE_NAME"):
        ghcr.check(repo, POLICY)


def test_an_allowlisted_package_no_workflow_publishes_is_refused(repo: Path) -> None:
    policy = {**POLICY, "ghcr_packages": [*POLICY["ghcr_packages"], "fabric-relay"]}
    with pytest.raises(ghcr.PackageError, match="fabric-relay"):
        ghcr.check(repo, policy)


def test_every_release_image_must_be_allowlisted() -> None:
    policy = {**POLICY, "ghcr_packages": ["fabric-otelcol", "charts/fabric"]}
    with pytest.raises(ghcr.PackageError, match="fabric-host-emitter"):
        ghcr.allowlist(policy)
