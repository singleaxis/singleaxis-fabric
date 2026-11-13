# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 §11.1: the ``fabric-cli`` image is a release image with the same
qualification as the others, and its content check refuses what the policy forbids.

The check itself (``scripts/release/check_cli_image.py``) runs against the built image in
the ``fabric-cli-image`` CI job; these tests pin its rules and the release wiring."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "release"))

from check_cli_image import ImageError, check_config, check_inventory  # noqa: E402
from check_image_metadata import load_policy, main as check_metadata  # noqa: E402

POLICY = load_policy(ROOT / "scripts" / "release" / "release-policy.json")


def _inventory() -> dict[str, Any]:
    wheel = POLICY["python_distribution"]
    return {
        "version": "0.12.1",
        "files": sorted({*wheel["required_wheel_paths"], "fabric/cli/__init__.py"}),
        "console_scripts": dict(wheel["required_console_scripts"]),
        "extras": ["cli", "otlp", "s3"],
        "commands": list(POLICY["cli_image"]["commands"]),
        "distributions": [["singleaxis-fabric", "Customer-controlled capture"],
                          ["httpx", "The next generation HTTP client."]],
    }  # fmt: skip


def _config() -> dict[str, Any]:
    want = POLICY["image_metadata"]["fabric-cli"]
    return {
        "User": "65532:65532",
        "Entrypoint": ["fabric"],
        "Labels": {
            "org.opencontainers.image.title": want["title"],
            "org.opencontainers.image.description": want["description"],
            "org.opencontainers.image.source": "https://github.com/singleaxis/singleaxis-fabric",
        },
    }


def test_a_conforming_image_passes() -> None:
    check_inventory(POLICY, _inventory())
    check_config(POLICY, _config())


def test_the_commands_are_the_i1_allowlist() -> None:
    assert POLICY["cli_image"]["commands"] == [
        "plan", "init", "up", "down", "run", "verify", "doctor", "show", "version", "help",
    ]  # fmt: skip
    inventory = _inventory()
    inventory["commands"].append("snapshot")
    with pytest.raises(ImageError, match="I1 allowlist"):
        check_inventory(POLICY, inventory)


@pytest.mark.parametrize("path", ["fabric/judge.py", "fabric/guardrail_adapters/x.py"])
def test_a_forbidden_module_is_refused(path: str) -> None:
    inventory = _inventory()
    inventory["files"].append(path)
    with pytest.raises(ImageError, match="forbids"):
        check_inventory(POLICY, inventory)


def test_a_distribution_naming_a_forbidden_capability_is_refused() -> None:
    inventory = _inventory()
    inventory["distributions"].append(["llm-guardrails", "x"])
    with pytest.raises(ImageError, match="outside the recorder"):
        check_inventory(POLICY, inventory)


def test_missing_extras_and_scripts_are_refused() -> None:
    inventory = _inventory()
    inventory["extras"] = ["otlp"]
    with pytest.raises(ImageError, match="extras"):
        check_inventory(POLICY, inventory)
    inventory = _inventory()
    inventory["console_scripts"].pop("singleaxis-fabric")
    with pytest.raises(ImageError, match="console scripts"):
        check_inventory(POLICY, inventory)


@pytest.mark.parametrize("user", ["", "0", "root", "0:0"])
def test_a_root_image_is_refused(user: str) -> None:
    config = _config()
    config["User"] = user
    with pytest.raises(ImageError, match="non-root"):
        check_config(POLICY, config)


def test_labels_are_the_policys() -> None:
    config = _config()
    config["Labels"]["org.opencontainers.image.description"] = "evaluates agents"
    with pytest.raises(ImageError):
        check_config(POLICY, config)
    dockerfile = ROOT / "components" / "fabric-cli" / "Dockerfile"
    policy = ROOT / "scripts" / "release" / "release-policy.json"
    assert check_metadata(["--policy", str(policy), "--image", "fabric-cli",
                           "--dockerfile", str(dockerfile)]) == 0  # fmt: skip


def test_the_release_workflow_publishes_signs_and_qualifies_the_image() -> None:
    release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    matrix = release["jobs"]["publish-image"]["strategy"]["matrix"]["include"]
    assert {"component": "fabric-cli", "image": "fabric-cli", "context": "."} in matrix
    qualify = json.dumps(release["jobs"]["qualify-release"]["steps"])
    assert (
        "--image fabric-cli" in qualify
        and "components/fabric-cli/Dockerfile" in qualify
    )


def test_ci_builds_and_checks_the_image() -> None:
    ci = yaml.safe_load((ROOT / ".github/workflows/recorder-ci.yml").read_text())
    steps = json.dumps(ci["jobs"]["fabric-cli-image"]["steps"])
    assert "components/fabric-cli/Dockerfile" in steps
    assert "scripts/release/check_cli_image.py" in steps
    assert "trivy" in steps


def test_the_image_installs_only_locked_packages() -> None:
    dockerfile = (ROOT / "components/fabric-cli/Dockerfile").read_text()
    for line in dockerfile.splitlines():
        if line.lstrip().startswith("FROM "):
            assert "@sha256:" in line, line
        if "pip install" in line and "/tmp/dist/" not in line:
            assert "--require-hashes" in line, line
    ignore = (ROOT / "components/fabric-cli/Dockerfile.dockerignore").read_text()
    assert ignore.splitlines()[2] == "*", "the build context must start from nothing"
    assert copy.deepcopy(POLICY["ghcr_packages"]).count("fabric-cli") == 1
