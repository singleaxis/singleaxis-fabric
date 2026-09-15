# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures/release_identity_cases.json"
VERIFIER_PATH = Path(__file__).parents[1] / "verify_release_identity.py"
VERIFIER_SPEC = importlib.util.spec_from_file_location(
    "fabric_release_identity", VERIFIER_PATH
)
assert VERIFIER_SPEC is not None and VERIFIER_SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(VERIFIER_SPEC)
sys.modules[VERIFIER_SPEC.name] = VERIFIER
VERIFIER_SPEC.loader.exec_module(VERIFIER)

EXPECTED_RUNTIME_MODULES = VERIFIER.EXPECTED_RUNTIME_MODULES
verify = VERIFIER.verify

FABRIC_CHARTS = {
    "fabric-relay": "0.1.0",
    "nemo-sidecar": "0.3.0",
    "otel-collector": "0.4.0",
    "presidio-sidecar": "0.2.0",
    "redteam-runner": "0.2.0",
    "update-agent": "0.2.0",
}


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _materialize(root: Path, case_name: str) -> None:
    cases = json.loads(FIXTURES.read_text(encoding="utf-8"))
    case = cases[case_name]
    release = "0.7.0"
    chart_versions = {
        **FABRIC_CHARTS,
        "otel-collector": case["otel_chart_version"],
        "nemo-sidecar": case["nemo_chart_version"],
        "langfuse": "0.2.0",
    }
    dependencies = "\n".join(
        f'  - name: {name}\n    version: {version}\n    repository: ""'
        for name, version in chart_versions.items()
    )
    _write(
        root,
        "charts/fabric/Chart.yaml",
        f"apiVersion: v2\nname: fabric\nversion: {release}\n"
        f'appVersion: "{release}"\ndependencies:\n{dependencies}\n',
    )
    requirement_records = [
        {"name": name, "version": version, "repository": ""}
        for name, version in chart_versions.items()
    ]
    lock_records = [dict(record) for record in requirement_records]
    lock_digest = VERIFIER._helm_lock_digest(requirement_records, lock_records)
    lock_dependencies = "\n".join(
        f'- name: {name}\n  repository: ""\n  version: {version}'
        for name, version in chart_versions.items()
    )
    _write(
        root,
        "charts/fabric/Chart.lock",
        f"dependencies:\n{lock_dependencies}\ndigest: {lock_digest}\n"
        'generated: "2026-08-25T00:00:00Z"\n',
    )
    for name, chart_version in chart_versions.items():
        if name == "langfuse":
            app_version = "2.93.0"
        elif name == "fabric-relay":
            app_version = case["relay_version"]
        else:
            app_version = case["runtime_version"]
        _write(
            root,
            f"charts/fabric/charts/{name}/Chart.yaml",
            f"apiVersion: v2\nname: {name}\nversion: {chart_version}\n"
            f'appVersion: "{app_version}"\n',
        )

    _write(root, "VERSION", f"{release}\n")
    _write(
        root,
        "charts/fabric/values.yaml",
        f'global:\n  fabric:\n    version: "{release}"\n',
    )
    for relative in EXPECTED_RUNTIME_MODULES:
        _write(root, relative, f'__version__ = "{case["runtime_version"]}"\n')
    _write(
        root,
        "components/otel-collector-fabric/ocb-config.yaml",
        f"dist:\n  version: {case['collector_version']}\n",
    )
    _write(
        root,
        "components/fabric-relay/ocb-config.yaml",
        f"dist:\n  version: {case['relay_version']}\n",
    )
    _write(
        root,
        "sdk/python/pyproject.toml",
        '[tool.hatch.version]\npath = "src/fabric/_version.py"\n',
    )
    _write(
        root,
        "sdk/python/src/fabric/_version.py",
        f'__version__ = "{case["python_fallback"]}"\n',
    )
    package = {"name": "@singleaxis/fabric", "version": case["typescript_version"]}
    lock = {
        "name": "@singleaxis/fabric",
        "version": case["typescript_version"],
        "packages": {"": {"version": case["typescript_version"]}},
    }
    _write(root, "sdk/typescript/package.json", json.dumps(package))
    _write(root, "sdk/typescript/package-lock.json", json.dumps(lock))
    _write(root, "sdk/python/src/fabric/_attributes.py", 'SCHEMA_VERSION = "1.0"\n')
    _write(
        root,
        "sdk/typescript/src/attributes.ts",
        'export const SCHEMA_VERSION = "1.0";\n',
    )

    if case["workflow"] == "legacy":
        workflow = (
            "run: |\n"
            '  V="${GITHUB_REF_NAME#v}"\n'
            '  sed -i -E "s/^version:.*/version: ${V}/" charts/fabric/Chart.yaml\n'
        )
    else:
        workflow = (
            "run: python scripts/verify_release_identity.py --expected v0.7.0\n"
            "env:\n  VERSION: ${{ needs.verify-tag.outputs.version }}\n"
            "matrix:\n  component: otel-collector-fabric\n"
            "file: components/${{ matrix.component }}/Dockerfile\n"
            "package-fabricctl:\n"
            'run: GOOS="${goos}" go build\n'
            "checksum: fabricctl-SHA256SUMS\n"
            "needs: [package-fabricctl,]\n"
            "name: fabricctl-release\n"
            "path: dist\n"
        )
    _write(root, ".github/workflows/release.yml", workflow)
    _write(
        root,
        ".github/workflows/recorder-ci.yml",
        "filters:\n  - charts/fabric/Chart.lock\n"
        "run: python -m pytest scripts/tests -q\n"
        "run: python scripts/verify_release_identity.py --json\n"
        "file: components/otel-collector-fabric/Dockerfile\n"
        "tags: fabric-otelcol:pr\n"
        "image-ref: fabric-otelcol:pr\n"
        "output: trivy-fabric-otelcol.sarif\n",
    )


def test_reproduces_pre_contract_version_mismatches(tmp_path: Path) -> None:
    _materialize(tmp_path, "mismatched")

    result = verify(tmp_path, "v0.7.0")

    assert not result.ok
    message = "\n".join(result.errors)
    assert (
        "components/otel-collector-fabric/ocb-config.yaml:dist.version='0.2.0'"
        in message
    )
    assert "sdk/typescript:package='0.2.0'" in message
    assert "predates required migration floor '0.4.0'" in message
    assert "still derives versions ad hoc" in message
    assert "mutates version declarations" in message


def test_accepts_corrected_coordinated_declarations(tmp_path: Path) -> None:
    _materialize(tmp_path, "corrected")

    result = verify(tmp_path, "0.7.0")

    assert result.ok, result.errors
    assert result.release_version == "0.7.0"
    assert result.schema_versions == {"python": "1.0", "typescript": "1.0"}
    assert (
        result.compatibility_rules["helm_chart_packages"]["rule"]
        == "independent-semver"
    )


def test_cli_emits_machine_readable_evidence(tmp_path: Path) -> None:
    _materialize(tmp_path, "corrected")
    completed = subprocess.run(
        [
            sys.executable,
            str(VERIFIER_PATH),
            "--root",
            str(tmp_path),
            "--expected",
            "v0.7.0",
            "--json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    report = json.loads(completed.stdout)
    assert report["status"] == "ok"
    assert report["release_version"] == "0.7.0"
    assert report["source_commit"] is None


def test_expected_tag_must_match_version(tmp_path: Path) -> None:
    _materialize(tmp_path, "corrected")

    result = verify(tmp_path, "v0.8.0")

    assert not result.ok
    assert "expected tag/version '0.8.0'" in "\n".join(result.errors)


def test_chart_lock_is_required(tmp_path: Path) -> None:
    _materialize(tmp_path, "corrected")
    (tmp_path / "charts/fabric/Chart.lock").unlink()

    result = verify(tmp_path, "v0.7.0")

    assert not result.ok
    assert "missing required release declaration" in "\n".join(result.errors)


def test_chart_lock_dependency_versions_must_match(tmp_path: Path) -> None:
    _materialize(tmp_path, "corrected")
    lock = tmp_path / "charts/fabric/Chart.lock"
    lock.write_text(
        lock.read_text(encoding="utf-8").replace(
            '- name: otel-collector\n  repository: ""\n  version: 0.4.0',
            '- name: otel-collector\n  repository: ""\n  version: 0.3.0',
        ),
        encoding="utf-8",
    )

    result = verify(tmp_path, "v0.7.0")

    message = "\n".join(result.errors)
    assert not result.ok
    assert "Chart.lock dependencies do not exactly match Chart.yaml" in message
    assert "expected Helm dependency digest" in message


def test_chart_lock_digest_must_not_be_stale(tmp_path: Path) -> None:
    _materialize(tmp_path, "corrected")
    lock = tmp_path / "charts/fabric/Chart.lock"
    lock.write_text(
        lock.read_text(encoding="utf-8").replace(
            "digest: sha256:",
            "digest: sha256:deadbeef",
            1,
        ),
        encoding="utf-8",
    )

    result = verify(tmp_path, "v0.7.0")

    assert not result.ok
    assert "expected Helm dependency digest" in "\n".join(result.errors)


def test_release_workflows_must_cover_fabric_node_and_fabricctl(tmp_path: Path) -> None:
    _materialize(tmp_path, "corrected")
    release = tmp_path / ".github/workflows/release.yml"
    release.write_text(
        release.read_text(encoding="utf-8").replace("package-fabricctl:", ""),
        encoding="utf-8",
    )
    ci = tmp_path / ".github/workflows/recorder-ci.yml"
    ci.write_text(
        ci.read_text(encoding="utf-8").replace("image-ref: fabric-otelcol:pr\n", ""),
        encoding="utf-8",
    )

    result = verify(tmp_path, "v0.7.0")

    message = "\n".join(result.errors)
    assert not result.ok
    assert "release workflow lacks fabricctl cross-platform packaging" in message
    assert "CI lacks Fabric Node PR image scan" in message
