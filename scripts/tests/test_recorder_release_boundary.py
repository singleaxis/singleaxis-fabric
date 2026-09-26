# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Release-boundary tests for the recorder-first OSS artifact set."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

# Canonical legacy component names (single source of truth for every
# release-boundary scan) live in a fixture so additional boundary tests
# can consume the same list without drifting.
_BOUNDARY_FIXTURE = json.loads(
    (ROOT / "scripts/tests/fixtures/forbidden_components.json").read_text(
        encoding="utf-8"
    )
)
FORBIDDEN_COMPONENTS: tuple[str, ...] = tuple(_BOUNDARY_FIXTURE["forbidden_components"])
FORBIDDEN_CHART_NAMES: tuple[str, ...] = FORBIDDEN_COMPONENTS + tuple(
    _BOUNDARY_FIXTURE["forbidden_chart_names"]
)

REQUIRED_WORKFLOWS: tuple[str, ...] = (
    "recorder-ci.yml",
    "recorder-security.yml",
    "recorder-license.yml",
    "codeql.yml",
    "e2e.yml",
)


def test_release_policy_is_recorder_only() -> None:
    policy = json.loads(
        (ROOT / "scripts/release/release-policy.json").read_text(encoding="utf-8")
    )
    assert policy["helm"] == {
        "first_party_app_charts": ["otel-collector"],
        "third_party_app_charts": [],
    }
    assert policy["images"] == ["fabric-otelcol", "fabric-host-emitter"]
    assert policy["python_distribution"]["required_console_scripts"] == {}
    forbidden = set(policy["python_distribution"]["forbidden_wheel_paths"])
    assert {
        "fabric/guardrails.py",
        "fabric/judge.py",
        "fabric/policy.py",
        "fabric/presidio.py",
        "fabric/tool_auth.py",
    }.issubset(forbidden)
    assert set(policy["contracts"]["public_families"]) == {
        "activity",
        "connect",
        "content",
        "delivery",
        "privacy",
        "recorder",
    }
    assert policy["contracts"]["public_versions"] == {
        "activity": ["v2"],
        "connect": ["v1"],
        "content": ["v1"],
        "delivery": ["v1"],
        "privacy": ["v1"],
        "recorder": ["v1"],
    }
    assert policy["required_workflows"] == [
        "recorder-ci.yml",
        "recorder-security.yml",
        "codeql.yml",
        "recorder-license.yml",
        "e2e.yml",
    ]


def test_required_workflows_qualify_the_recorder_on_main() -> None:
    for workflow_name in REQUIRED_WORKFLOWS:
        workflow = (ROOT / ".github/workflows" / workflow_name).read_text(
            encoding="utf-8"
        )
        assert "push:\n    branches: [main]" in workflow
        for forbidden in FORBIDDEN_COMPONENTS:
            assert forbidden not in workflow, (
                f"{workflow_name} references legacy component {forbidden!r}"
            )
    assert not (ROOT / ".github/workflows/ci.yml").exists()
    assert not (ROOT / ".github/workflows/license.yml").exists()
    assert not (ROOT / ".github/workflows/security.yml").exists()


def test_release_workflow_does_not_publish_legacy_runtime_artifacts() -> None:
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    for forbidden in (
        "publish-sidecar-images",
        "component: fabric-relay",
        "path: .\n          format: spdx-json",
        "git archive --format=tar.gz",
        *FORBIDDEN_COMPONENTS,
    ):
        assert forbidden not in workflow
    assert "component: otel-collector-fabric" in workflow
    assert "component: host-emitter" in workflow
    assert "sbom: true" in workflow
    assert "provenance: true" in workflow


def test_fabric_node_binary_manifest_contains_no_legacy_processors() -> None:
    manifest = (ROOT / "components/otel-collector-fabric/ocb-config.yaml").read_text(
        encoding="utf-8"
    )
    assert "fabricguardprocessor" in manifest
    for forbidden in (
        "fabricpolicyprocessor",
        "fabricredactprocessor",
        "fabricsamplerprocessor",
    ):
        assert forbidden not in manifest


def test_fabric_node_image_boots_through_the_gate() -> None:
    """The image entrypoint must be fabric-gate, which refuses configs the
    recorder cannot protect (non-traces/logs pipelines, unsafe bearer-token
    files) before exec'ing otelcol-fabric. The gate source ships in the
    component so the Dockerfile COPY cannot silently drop it."""
    dockerfile = (ROOT / "components/otel-collector-fabric/Dockerfile").read_text(
        encoding="utf-8"
    )
    assert 'ENTRYPOINT ["/fabric-gate"]' in dockerfile
    assert "dist/fabric-gate" in dockerfile
    gate_dir = ROOT / "components/otel-collector-fabric/gate"
    assert (gate_dir / "go.mod").is_file()
    assert (gate_dir / "main.go").is_file()


def test_umbrella_declares_only_collector_dependency() -> None:
    chart_text = (ROOT / "charts/fabric/Chart.yaml").read_text(encoding="utf-8")
    dependency_text = chart_text.split("\ndependencies:\n", maxsplit=1)[1]
    assert re.findall(r"(?m)^  - name: ([^\s]+)", dependency_text) == ["otel-collector"]
    for forbidden in FORBIDDEN_CHART_NAMES:
        assert forbidden not in chart_text
