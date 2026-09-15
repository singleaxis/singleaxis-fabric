#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Verify that every shipped Fabric artifact identifies one release.

``VERSION`` is the authoritative release identity. Ecosystem package versions
that have a different meaning (Helm chart package versions and Langfuse's
upstream app version) are governed by the explicit compatibility rules below.
The JSON report is intended for CI evidence and release automation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)

# Machine-readable policy: consumers can distinguish a Fabric runtime release
# from a Helm packaging revision or a wrapped upstream application's version.
COMPATIBILITY_RULES: dict[str, Any] = {
    "policy_version": 1,
    "coordinated_runtime": {
        "rule": "exact",
        "source": "VERSION",
        "members": [
            "fabric-owned Helm appVersion values",
            "Fabric Python runtime modules",
            "OpenTelemetry Collector Builder dist.version values",
            "Python SDK source version",
            "TypeScript SDK package version",
        ],
    },
    "helm_chart_packages": {
        "rule": "independent-semver",
        "dependency_rule": "umbrella dependency version must equal subchart version",
        "lock_rule": "Chart.lock dependencies and Helm SHA-256 digest must match Chart.yaml",
        "migration_floors": {
            # This is the first recorder-only Fabric Node chart package.
            "otel-collector": "0.4.0",
        },
    },
}

FABRIC_CHARTS = {"otel-collector"}
EXPECTED_RUNTIME_MODULES: set[str] = set()
EXPECTED_OCB_MANIFESTS = {
    "components/otel-collector-fabric/ocb-config.yaml",
}


@dataclass(frozen=True)
class Artifact:
    name: str
    version: str
    policy: str


@dataclass
class Verification:
    release_version: str
    expected_version: str | None
    source_commit: str | None
    schema_versions: dict[str, str]
    compatibility_rules: dict[str, Any]
    artifacts: list[Artifact]
    errors: list[str]

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_json(self) -> dict[str, Any]:
        return {
            "status": "ok" if self.ok else "error",
            "release_version": self.release_version,
            "expected_version": self.expected_version,
            "source_commit": self.source_commit,
            "schema_versions": self.schema_versions,
            "compatibility_rules": self.compatibility_rules,
            "artifacts": [asdict(artifact) for artifact in self.artifacts],
            "errors": self.errors,
        }


def _read(path: Path, errors: list[str]) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        errors.append(f"missing required release declaration: {path}")
        return ""


def _match_version(text: str, pattern: str, label: str, errors: list[str]) -> str:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        errors.append(f"cannot read {label}")
        return ""
    return match.group(1)


def _require_semver(version: str, label: str, errors: list[str]) -> None:
    if version and not SEMVER_RE.fullmatch(version):
        errors.append(f"{label} is not SemVer: {version!r}")


def _require_equal(
    version: str,
    expected: str,
    label: str,
    artifacts: list[Artifact],
    errors: list[str],
) -> None:
    artifacts.append(Artifact(label, version, "coordinated-runtime/exact"))
    if version and version != expected:
        errors.append(f"{label}={version!r}; expected coordinated release {expected!r}")


def _semver_core(version: str) -> tuple[int, int, int]:
    match = SEMVER_RE.fullmatch(version)
    if not match:
        return (0, 0, 0)
    return tuple(int(match.group(index)) for index in range(1, 4))


def _chart_fields(path: Path, errors: list[str]) -> tuple[str, str, str]:
    text = _read(path, errors)
    name = _match_version(text, r"^name:\s*[\"']?([^\s\"']+)", f"{path}:name", errors)
    version = _match_version(
        text, r"^version:\s*[\"']?([^\s\"']+)", f"{path}:version", errors
    )
    app_version = _match_version(
        text, r"^appVersion:\s*[\"']?([^\s\"']+)", f"{path}:appVersion", errors
    )
    return name, version, app_version


def _yaml_scalar(value: str) -> str:
    return value.strip().strip("\"'")


def _umbrella_dependency_records(text: str, errors: list[str]) -> list[dict[str, Any]]:
    """Parse the Helm dependency fields that participate in HashReq.

    Field insertion order mirrors Helm's ``chart.Dependency`` Go struct JSON
    order. HashReq marshals ``[requirements, lock]`` and SHA-256 hashes the
    compact JSON, which is the digest stored in Chart.lock.
    """
    if "dependencies:\n" not in text:
        errors.append("charts/fabric/Chart.yaml has no dependencies section")
        return []
    lines = text.split("dependencies:\n", 1)[1].splitlines()
    raw_records: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    list_field: str | None = None
    for line in lines:
        if line and not line.startswith(" "):
            break
        name_match = re.match(r"^  - name:\s*(.*)", line)
        if name_match:
            current = {"name": _yaml_scalar(name_match.group(1))}
            raw_records.append(current)
            list_field = None
            continue
        if current is None:
            continue
        scalar_match = re.match(
            r"^    (version|repository|condition|alias|enabled):\s*(.*)", line
        )
        if scalar_match:
            key, value = scalar_match.groups()
            parsed: Any = _yaml_scalar(value)
            if key == "enabled":
                parsed = parsed.lower() == "true"
            current[key] = parsed
            list_field = None
            continue
        list_start = re.match(r"^    (tags|import-values):\s*$", line)
        if list_start:
            list_field = list_start.group(1)
            current[list_field] = []
            continue
        list_value = re.match(r"^      -\s*(.*)", line)
        if list_value and list_field:
            current[list_field].append(_yaml_scalar(list_value.group(1)))

    fields = (
        "name",
        "version",
        "repository",
        "condition",
        "tags",
        "enabled",
        "import-values",
        "alias",
    )
    records: list[dict[str, Any]] = []
    for raw in raw_records:
        raw.setdefault("repository", "")
        # Helm's JSON tags omit empty optional fields, but repository is not
        # optional and therefore participates even when it is an empty string.
        records.append(
            {
                field: raw[field]
                for field in fields
                if field in raw
                and (field == "repository" or raw[field] not in ("", False, [], None))
            }
        )
    return records


def _lock_dependency_records(text: str, errors: list[str]) -> list[dict[str, Any]]:
    if "dependencies:\n" not in text:
        errors.append("charts/fabric/Chart.lock has no dependencies section")
        return []
    records: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in text.split("dependencies:\n", 1)[1].splitlines():
        name_match = re.match(r"^- name:\s*(.*)", line)
        if name_match:
            current = {"name": _yaml_scalar(name_match.group(1))}
            records.append(current)
            continue
        if current is None:
            continue
        scalar_match = re.match(r"^  (version|repository):\s*(.*)", line)
        if scalar_match:
            key, value = scalar_match.groups()
            # Preserve Helm's Go-struct field order, not YAML source order.
            current[key] = _yaml_scalar(value)
    ordered: list[dict[str, Any]] = []
    for raw in records:
        raw.setdefault("repository", "")
        ordered.append(
            {
                field: raw[field]
                for field in ("name", "version", "repository")
                if field in raw and (field == "repository" or raw[field] != "")
            }
        )
    return ordered


def _helm_lock_digest(
    requirements: list[dict[str, Any]], locked: list[dict[str, Any]]
) -> str:
    # Equivalent to Helm resolver.HashReq: json.Marshal([2][]Dependency)
    # followed by SHA-256. Compact separators reproduce Go encoding/json.
    payload = json.dumps(
        [requirements, locked], ensure_ascii=False, separators=(",", ":")
    )
    return f"sha256:{hashlib.sha256(payload.encode('utf-8')).hexdigest()}"


def _source_commit(root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip() or None


def verify(root: Path, expected: str | None = None) -> Verification:
    root = root.resolve()
    errors: list[str] = []
    artifacts: list[Artifact] = []
    release_version = _read(root / "VERSION", errors).strip()
    _require_semver(release_version, "VERSION", errors)
    if expected:
        expected = expected.removeprefix("v")
        _require_semver(expected, "--expected", errors)
        if release_version and release_version != expected:
            errors.append(
                f"VERSION={release_version!r}; expected tag/version {expected!r}"
            )

    umbrella_path = root / "charts/fabric/Chart.yaml"
    umbrella_text = _read(umbrella_path, errors)
    umbrella_name, umbrella_version, umbrella_app = _chart_fields(umbrella_path, errors)
    if umbrella_name and umbrella_name != "fabric":
        errors.append(f"umbrella chart is named {umbrella_name!r}, expected 'fabric'")
    _require_equal(
        umbrella_version, release_version, "helm/fabric:version", artifacts, errors
    )
    _require_equal(
        umbrella_app, release_version, "helm/fabric:appVersion", artifacts, errors
    )
    requirement_records = _umbrella_dependency_records(umbrella_text, errors)
    dependencies = {
        str(record.get("name", "")): str(record.get("version", ""))
        for record in requirement_records
    }

    lock_path = root / "charts/fabric/Chart.lock"
    lock_text = _read(lock_path, errors)
    lock_records = _lock_dependency_records(lock_text, errors) if lock_text else []
    locked_dependencies = {
        str(record.get("name", "")): str(record.get("version", ""))
        for record in lock_records
    }
    if locked_dependencies != dependencies:
        errors.append(
            "charts/fabric/Chart.lock dependencies do not exactly match Chart.yaml: "
            f"locked={locked_dependencies}, required={dependencies}"
        )
    recorded_digest = _match_version(
        lock_text,
        r"^digest:\s*([^\s]+)",
        "charts/fabric/Chart.lock digest",
        errors,
    )
    computed_digest = _helm_lock_digest(requirement_records, lock_records)
    artifacts.append(
        Artifact("helm/fabric:Chart.lock", recorded_digest, "helm-lock/sha256")
    )
    if recorded_digest and recorded_digest != computed_digest:
        errors.append(
            f"charts/fabric/Chart.lock digest={recorded_digest!r}; "
            f"expected Helm dependency digest {computed_digest!r}"
        )

    chart_root = root / "charts/fabric/charts"
    # Only declared umbrella dependencies are release artifacts. Historical or
    # experimental chart source may remain below charts/ during migration, but
    # it must not silently enter the coordinated release inventory.
    chart_paths = [chart_root / name / "Chart.yaml" for name in sorted(dependencies)]
    chart_names: set[str] = set()
    for chart_path in chart_paths:
        name, chart_version, app_version = _chart_fields(chart_path, errors)
        if not name:
            continue
        chart_names.add(name)
        _require_semver(chart_version, f"helm/{name}:version", errors)
        artifacts.append(
            Artifact(f"helm/{name}:version", chart_version, "helm-package/independent")
        )
        dependency_version = dependencies.get(name)
        if dependency_version != chart_version:
            errors.append(
                f"umbrella dependency {name!r}={dependency_version!r}; "
                f"subchart version is {chart_version!r}"
            )
        if name in FABRIC_CHARTS:
            _require_equal(
                app_version,
                release_version,
                f"helm/{name}:appVersion",
                artifacts,
                errors,
            )
        else:
            _require_semver(app_version, f"helm/{name}:appVersion", errors)
            artifacts.append(
                Artifact(
                    f"helm/{name}:appVersion", app_version, "upstream-app/independent"
                )
            )

        floor = COMPATIBILITY_RULES["helm_chart_packages"]["migration_floors"].get(name)
        if floor and _semver_core(chart_version) < _semver_core(floor):
            errors.append(
                f"helm/{name}:version={chart_version!r} predates required migration floor {floor!r}"
            )

    missing_charts = FABRIC_CHARTS - chart_names
    for name in sorted(missing_charts):
        errors.append(f"missing required Fabric subchart: {name}")

    for relative in sorted(EXPECTED_RUNTIME_MODULES):
        text = _read(root / relative, errors)
        version = _match_version(
            text, r'^__version__\s*=\s*["\']([^"\']+)', relative, errors
        )
        _require_equal(version, release_version, relative, artifacts, errors)

    for relative in sorted(EXPECTED_OCB_MANIFESTS):
        text = _read(root / relative, errors)
        version = _match_version(
            text, r"^  version:\s*([^\s]+)", f"{relative}:dist.version", errors
        )
        _require_equal(
            version, release_version, f"{relative}:dist.version", artifacts, errors
        )

    python_project = _read(root / "sdk/python/pyproject.toml", errors)
    python_version_path = _match_version(
        python_project,
        r'^path\s*=\s*["\']([^"\']+)',
        "sdk/python Hatch version path",
        errors,
    )
    if python_version_path != "src/fabric/_version.py":
        errors.append(
            "sdk/python Hatch version path must be 'src/fabric/_version.py'; "
            f"found {python_version_path!r}"
        )
    python_runtime = _read(root / "sdk/python/src/fabric/_version.py", errors)
    python_source_version = _match_version(
        python_runtime,
        r'^__version__\s*=\s*["\']([^"\']+)',
        "sdk/python source version",
        errors,
    )
    _require_equal(
        python_source_version,
        release_version,
        "sdk/python:source_version",
        artifacts,
        errors,
    )

    package_text = _read(root / "sdk/typescript/package.json", errors)
    lock_text = _read(root / "sdk/typescript/package-lock.json", errors)
    try:
        package = json.loads(package_text)
        package_lock = json.loads(lock_text)
    except json.JSONDecodeError as exc:
        errors.append(f"invalid TypeScript package metadata: {exc}")
    else:
        package_version = str(package.get("version", ""))
        lock_version = str(package_lock.get("version", ""))
        lock_root_version = str(
            package_lock.get("packages", {}).get("", {}).get("version", "")
        )
        _require_equal(
            package_version,
            release_version,
            "sdk/typescript:package",
            artifacts,
            errors,
        )
        _require_equal(
            lock_version,
            release_version,
            "sdk/typescript:package-lock",
            artifacts,
            errors,
        )
        _require_equal(
            lock_root_version,
            release_version,
            "sdk/typescript:package-lock-root",
            artifacts,
            errors,
        )

    values_text = _read(root / "charts/fabric/values.yaml", errors)
    global_version = _match_version(
        values_text,
        r"^    version:\s*[\"']?([^\s\"']+)",
        "charts/fabric/values.yaml global.fabric.version",
        errors,
    )
    _require_equal(
        global_version, release_version, "helm/global.fabric.version", artifacts, errors
    )

    schema_versions: dict[str, str] = {}
    for name, relative, pattern in (
        (
            "python",
            "sdk/python/src/fabric/_attributes.py",
            r'^SCHEMA_VERSION\s*=\s*["\']([^"\']+)',
        ),
        (
            "typescript",
            "sdk/typescript/src/attributes.ts",
            r'^export const SCHEMA_VERSION\s*=\s*["\']([^"\']+)',
        ),
    ):
        text = _read(root / relative, errors)
        schema_versions[name] = _match_version(
            text, pattern, f"{name} schema version", errors
        )
    if len(set(schema_versions.values())) > 1:
        errors.append(f"SDK schema versions disagree: {schema_versions}")

    workflow = _read(root / ".github/workflows/release.yml", errors)
    if "python scripts/verify_release_identity.py" not in workflow:
        errors.append("release workflow does not run the release-identity verifier")
    if "${GITHUB_REF_NAME#v}" in workflow:
        errors.append(
            "release workflow still derives versions ad hoc from GITHUB_REF_NAME"
        )
    if re.search(r"sed\s+-i[^\n]*(?:version|appVersion)", workflow):
        errors.append(
            "release workflow mutates version declarations instead of verifying source"
        )
    if "needs.verify-tag.outputs.version" not in workflow:
        errors.append(
            "release workflow does not consume the verified release version output"
        )
    release_artifact_markers = {
        "Fabric Node image publication": (
            "component: otel-collector-fabric",
            "components/${{ matrix.component }}/Dockerfile",
        ),
        "fabricctl cross-platform packaging": (
            "package-fabricctl:",
            'GOOS="${goos}"',
            "fabricctl-SHA256SUMS",
            "name: fabricctl-release",
        ),
        "fabricctl GitHub release attachment": (
            "package-fabricctl,",
            "name: fabricctl-release",
            "path: dist",
        ),
    }
    for capability, markers in release_artifact_markers.items():
        missing = [marker for marker in markers if marker not in workflow]
        if missing:
            errors.append(
                f"release workflow lacks {capability}; missing markers: {missing}"
            )

    ci_workflow = _read(root / ".github/workflows/recorder-ci.yml", errors)
    ci_coverage_markers = {
        "recorder release-boundary tests": (
            "scripts/tests",
            "scripts/verify_release_identity.py --json",
        ),
        "Fabric Node PR image build": (
            "file: components/otel-collector-fabric/Dockerfile",
            "tags: fabric-otelcol:pr",
        ),
        "Fabric Node PR image scan": (
            "image-ref: fabric-otelcol:pr",
            "trivy-fabric-otelcol.sarif",
        ),
    }
    for capability, markers in ci_coverage_markers.items():
        missing = [marker for marker in markers if marker not in ci_workflow]
        if missing:
            errors.append(f"CI lacks {capability}; missing markers: {missing}")

    return Verification(
        release_version=release_version,
        expected_version=expected,
        source_commit=_source_commit(root),
        schema_versions=schema_versions,
        compatibility_rules=COMPATIBILITY_RULES,
        artifacts=artifacts,
        errors=errors,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument(
        "--expected", help="Expected version or release tag (for example v0.7.0)"
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit the evidence report as JSON"
    )
    args = parser.parse_args(argv)

    result = verify(args.root, args.expected)
    if args.json:
        print(json.dumps(result.to_json(), indent=2, sort_keys=True))
    elif result.ok:
        commit = result.source_commit or "unavailable"
        schemas = ", ".join(
            f"{key}={value}" for key, value in result.schema_versions.items()
        )
        print(f"release identity verified: {result.release_version}")
        print(f"source commit: {commit}")
        print(f"schema versions: {schemas}")
        print(f"verified declarations: {len(result.artifacts)}")
    else:
        print("release identity verification failed:", file=sys.stderr)
        for error in result.errors:
            print(f"- {error}", file=sys.stderr)
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
