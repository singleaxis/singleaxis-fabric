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
    # Spec 058 §11.1: the operator CLI image (its content check: test_cli_image_check.py).
    assert policy["images"] == ["fabric-otelcol", "fabric-host-emitter", "fabric-cli"]
    # Spec 058 §5.1 (I1, OQ-1): the operator CLI and its alias, exactly; nothing else.
    assert policy["python_distribution"]["required_console_scripts"] == {
        "fabric": "fabric.cli:main",
        "singleaxis-fabric": "fabric.cli:main",
    }
    forbidden = set(policy["python_distribution"]["forbidden_wheel_paths"])
    assert {
        "fabric/_coverage_canary.py",
        "fabric/_instrumentation_registry.py",
        "fabric/adapters/crewai.py",
        "fabric/auto_instrument.py",
        "fabric/capture_capabilities.py",
        "fabric/capture_identity.py",
        "fabric/capture_readback.py",
        "fabric/control_protocol.py",
        "fabric/coverage_manifest.py",
        "fabric/deployment_state.py",
        "fabric/distributed_closure.py",
        "fabric/enterprise.py",
        "fabric/enterprise_preflight.py",
        "fabric/guardrails.py",
        "fabric/judge.py",
        "fabric/policy.py",
        "fabric/presidio.py",
        "fabric/reference_receipts.py",
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
        "e2e-production-profile.yml",
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


def test_redaction_service_example_is_not_a_release_artifact() -> None:
    """The reference redaction service (examples/redaction-service) is an example a
    customer runs, never part of the wheel, sdist, npm package or a release image."""
    import tomllib

    assert (ROOT / "examples/redaction-service/redaction_service.py").is_file()
    pyproject = tomllib.loads(
        (ROOT / "sdk/python/pyproject.toml").read_text(encoding="utf-8")
    )
    targets = pyproject["tool"]["hatch"]["build"]["targets"]
    assert targets["wheel"]["packages"] == ["src/fabric"]
    assert set(targets["sdist"]["include"]) == {"/src", "/README.md", "/LICENSE"}
    package = json.loads(
        (ROOT / "sdk/typescript/package.json").read_text(encoding="utf-8")
    )
    # bin/: the npm launcher (spec 058 §1.4), `fabric run` and `fabric doctor` only.
    assert set(package["files"]) <= {"bin", "dist", "README.md", "LICENSE"}
    assert package["bin"] == {"fabric": "bin/fabric.mjs"}
    scanned = [
        *(ROOT / ".github/workflows").glob("release*.yml"),
        *(ROOT / "scripts/release").rglob("*"),
        *(ROOT / "components").rglob("Dockerfile*"),
        *(ROOT / "deploy").rglob("Dockerfile*"),
    ]
    for path in scanned:
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            assert "redaction-service" not in text, path
            assert "redaction_service" not in text, path


# Spec 056 M2 (WP6-10): the production profile adds no runtime dependency, no
# privileged chart workload, no shipped test command and no evaluation component.

_PROVIDER_SDKS = ("openai", "anthropic", "e2b", "e2b-code-interpreter", "modal", "daytona",
                  "boto3", "mcp", "langchain", "litellm")  # fmt: skip


def _requirement_name(requirement: str) -> str:
    return re.split(r"[\s<>=!~;\[(]", requirement.strip(), maxsplit=1)[0].lower()


def test_default_wheel_installs_no_provider_sdk() -> None:
    """The SDK observes provider SDKs the application already uses (the remote sandbox
    hook included); installing Fabric never installs one. They stay in extras."""
    import tomllib

    project = tomllib.loads(
        (ROOT / "sdk/python/pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    installed = {_requirement_name(r) for r in project["dependencies"]}
    assert not installed & set(_PROVIDER_SDKS), installed
    extras = project.get("optional-dependencies", {})
    assert {_requirement_name(r) for r in extras.get("hooks-sandbox-e2b", ())} == {
        "e2b",
        "e2b-code-interpreter",
    }


def test_chart_packages_no_privileged_workload() -> None:
    """OD-10: the chart adds only the host ingress groups; the privileged eBPF sensor
    stays a customer-deployed example under deploy/kubernetes."""
    templates = [
        p
        for p in (ROOT / "charts").rglob("*")
        if p.is_file() and "templates" in p.parts
    ]
    assert templates
    for path in templates:
        text = path.read_text(encoding="utf-8", errors="replace")
        for forbidden in ("privileged: true", "hostPID: true", "hostNetwork: true",
                          "SYS_ADMIN", "CAP_BPF", "/sys/fs/cgroup", "/sys/kernel"):  # fmt: skip
            assert forbidden not in text, (path, forbidden)
    example = (ROOT / "deploy/kubernetes/host-emitter-daemonset.yaml").read_text(
        encoding="utf-8"
    )
    assert "privileged: true" in example or "CAP_BPF" in example or "BPF" in example


def test_no_image_or_release_builds_the_replay_command() -> None:
    """hostrecords-replay (spec 056 §7.3.3 (m)) is built only by tests and CI: no
    Dockerfile, release workflow, release script or Make target names it."""
    scanned = [
        *(ROOT / ".github/workflows").glob("release*.yml"),
        *(ROOT / "scripts/release").rglob("*"),
        *(ROOT / "components").rglob("Dockerfile*"),
        *(ROOT / "deploy").rglob("Dockerfile*"),
        *(ROOT / "components").rglob("Makefile"),
        *(ROOT / "components").rglob(".goreleaser*"),
        ROOT / "components/otel-collector-fabric/ocb-config.yaml",
    ]
    for path in scanned:
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            assert "hostrecords-replay" not in text, path
            assert "cmd/hostrecords-replay" not in text, path
    assert (
        ROOT / "components/otel-collector-fabric/hostrecords/cmd/hostrecords-replay"
    ).is_dir()


# One deny-list for every boundary scan: the release policy's, which the image metadata
# check (scripts/release/check_image_metadata.py) and release qualification also use.
_POLICY_TERMS = json.loads(
    (ROOT / "scripts/release/release-policy.json").read_text(encoding="utf-8")
)["forbidden_capability_terms"]["patterns"]
_EVALUATION = re.compile("(?i)(" + "|".join(f"(?:{p})" for p in _POLICY_TERMS) + ")")


def test_no_artifact_gains_an_evaluator_policy_or_enforcement_component() -> None:
    """AGENTS.md: the Node binary, its images and the wheel carry capture, protection and
    delivery only. Policy here means the capture policy (what to keep), never a decision
    about the agent."""
    manifest = (ROOT / "components/otel-collector-fabric/ocb-config.yaml").read_text(
        encoding="utf-8"
    )
    modules = re.findall(r"(?m)^\s*- gomod: (\S+)", manifest)
    assert modules
    for module in modules:
        assert not _EVALUATION.search(module), module
        assert "policyprocessor" not in module and "enforce" not in module, module
    package = ROOT / "sdk/python/src/fabric"
    for path in package.rglob("*.py"):
        assert not _EVALUATION.search(str(path.relative_to(package))), path
    for dockerfile in (ROOT / "components").rglob("Dockerfile*"):
        lines = dockerfile.read_text(encoding="utf-8", errors="replace").splitlines()
        instructions = [line for line in lines if not line.lstrip().startswith("#")]
        assert not _EVALUATION.search("\n".join(instructions)), dockerfile


# Spec 057 B7 and B9 (WP7-3): the security-context records add no control artifact, and no
# release artifact ships a mapping profile or a classification list.

SPEC_057_MODULES = (
    "_rec_check.py", "_rec_controls.py", "_rec_extension.py", "_rec_grant.py", "_rec_run.py",
    "_records_api.py", "_security_policy.py", "records/__init__.py", "records/_handles.py",
    "records/_vocab.py", "records/_walker.py", "reconstruct/_controls.py",
    "reconstruct/_security.py", "reconstruct/_derive.py", "reconstruct/dialects/__init__.py",
    "reconstruct/dialects/offered_grant.py", "reconstruct/dialects/safety_map.py",
    "reconstruct/dialects/tool_result.py", "reconstruct/dialects/jsonrpc2.py",
    "reconstruct/dialects/mcp.py", "reconstruct/_mcp_read.py", "hooks/_mcp.py",
)  # fmt: skip
# Where the mapping-profile schema and its example, the capture policy's security_context
# section and the classification vocabularies live: never a published contract family.
_SECURITY_CONTEXT_FAMILIES = ("capture", "coverage", "deployment-policy")
_LIST_KEYS = ("control_hosts", "control_addresses", "hook_programs", "watched_paths",
              "tool_result_markers")  # fmt: skip


def test_spec_057_modules_and_package_metadata_carry_no_capability_term() -> None:
    import tomllib

    package = ROOT / "sdk/python/src/fabric"
    for relative in SPEC_057_MODULES:
        assert (package / relative).is_file(), relative
        assert not _EVALUATION.search(relative), relative
    project = tomllib.loads(
        (ROOT / "sdk/python/pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    fields = [project["description"], *project.get("keywords", ()),
              *project.get("classifiers", ())]  # fmt: skip
    npm = json.loads((ROOT / "sdk/typescript/package.json").read_text(encoding="utf-8"))
    fields += [npm["description"], *npm.get("keywords", ())]
    for value in fields:
        assert not _EVALUATION.search(value), value


def test_no_release_artifact_ships_a_mapping_profile_or_classification_list() -> None:
    """B9: classification is customer configuration and mapping profiles are the
    customer's. The contract families holding the profile schema and its example fixture
    are not published; no chart, Node build file or image ships a profile or a filled
    list. (The wheel and sdist are checked by ``qualify_recorder_wheel.py`` in CI.)"""
    policy = json.loads(
        (ROOT / "scripts/release/release-policy.json").read_text(encoding="utf-8")
    )
    for family in _SECURITY_CONTEXT_FAMILIES:
        assert family not in policy["contracts"]["public_families"], family
    assert (
        ROOT / "contracts/capture/v1/schema/otlp-mapping-profile-v1.schema.json"
    ).is_file()
    shipped = [
        *(p for p in (ROOT / "charts").rglob("*") if p.is_file()),
        *(ROOT / "components").rglob("Dockerfile*"),
        ROOT / "components/otel-collector-fabric/ocb-config.yaml",
        *(ROOT / "components/otel-collector-fabric").glob("*.yaml"),
        *(ROOT / "scripts/release").rglob("*"),
        *(ROOT / ".github/workflows").glob("release*.yml"),
    ]
    keys = "|".join(_LIST_KEYS)
    filled = re.compile(rf'"?({keys})"?\s*:\s*(\[\s*[{{"]|\n\s+-)')
    for path in shipped:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        assert "otlp-mapping-profile" not in text, path
        assert not filled.search(text), path
        if path.name.startswith("Dockerfile"):
            for line in text.splitlines():
                if line.lstrip().upper().startswith(("COPY", "ADD")):
                    assert "contracts/capture" not in line and "fixtures" not in line, (
                        path
                    )
