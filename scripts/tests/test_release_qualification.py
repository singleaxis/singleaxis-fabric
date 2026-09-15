# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for deterministic release artifact qualification."""

from __future__ import annotations

import io
import json
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from release import qualify_release as qualify  # noqa: E402


def _policy(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    policy: dict[str, object] = {
        "schema_version": "fabric.release-policy/v1",
        "required_workflows": ["ci.yml"],
        "python_distribution": {
            "name": "singleaxis-fabric",
            "required_wheel_paths": [
                "fabric/__init__.py",
                "fabric/_version.py",
                "fabric/py.typed",
            ],
            "allowed_wheel_package_roots": ["fabric"],
            "required_console_scripts": {"fabricctl": "fabric.cli:main"},
            "required_sdist_paths": [
                "pyproject.toml",
                "README.md",
                "LICENSE",
                "src/fabric/__init__.py",
                "src/fabric/_version.py",
                "src/fabric/py.typed",
            ],
            "allowed_sdist_top_level": [
                "src",
                "pyproject.toml",
                "README.md",
                "LICENSE",
                "PKG-INFO",
            ],
        },
        "helm": {
            "first_party_app_charts": ["collector"],
            "third_party_app_charts": ["vendor"],
        },
        "images": ["fabric-collector"],
    }
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    return path, policy


def _chart(tmp_path: Path) -> Path:
    root = tmp_path / "chart"
    (root / "charts" / "collector").mkdir(parents=True)
    (root / "charts" / "vendor").mkdir(parents=True)
    (root / "Chart.yaml").write_text(
        'apiVersion: v2\nname: fabric\nversion: 0.1.0\nappVersion: "0.1.0"\n',
        encoding="utf-8",
    )
    (root / "charts" / "collector" / "Chart.yaml").write_text(
        'apiVersion: v2\nname: collector\nversion: 0.3.0\nappVersion: "0.1.0"\n',
        encoding="utf-8",
    )
    (root / "charts" / "vendor" / "Chart.yaml").write_text(
        'apiVersion: v2\nname: vendor\nversion: 1.0.0\nappVersion: "9.8.7"\n',
        encoding="utf-8",
    )
    (root / "values.yaml").write_text(
        'global:\n  fabric:\n    version: "0.1.0"\n', encoding="utf-8"
    )
    return root


def _metadata(version: str) -> bytes:
    return (
        "Metadata-Version: 2.4\n"
        "Name: singleaxis-fabric\n"
        f"Version: {version}\n"
        "Requires-Python: >=3.11\n\n"
    ).encode()


def _dist(tmp_path: Path, version: str = "1.2.3") -> Path:
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = dist / f"singleaxis_fabric-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("fabric/__init__.py", "")
        archive.writestr("fabric/_version.py", "")
        archive.writestr("fabric/py.typed", "")
        archive.writestr(
            f"singleaxis_fabric-{version}.dist-info/METADATA", _metadata(version)
        )
        archive.writestr(
            f"singleaxis_fabric-{version}.dist-info/entry_points.txt",
            "[console_scripts]\nfabricctl = fabric.cli:main\n",
        )
        archive.writestr(f"singleaxis_fabric-{version}.dist-info/RECORD", "")

    root = f"singleaxis_fabric-{version}"
    sdist = dist / f"singleaxis_fabric-{version}.tar.gz"
    files = {
        "PKG-INFO": _metadata(version),
        "pyproject.toml": b"[build-system]\n",
        "README.md": b"# SDK\n",
        "LICENSE": b"Apache-2.0\n",
        "src/fabric/__init__.py": b"",
        "src/fabric/_version.py": b"",
        "src/fabric/py.typed": b"",
    }
    with tarfile.open(sdist, "w:gz") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return dist


@pytest.mark.parametrize(
    ("tag", "semver", "python_version"),
    [
        ("v1.2.3", "1.2.3", "1.2.3"),
        ("v1.2.3-rc.2", "1.2.3-rc.2", "1.2.3rc2"),
        ("1.2.3-beta", "1.2.3-beta", "1.2.3b0"),
    ],
)
def test_release_versions(tag: str, semver: str, python_version: str) -> None:
    assert qualify.release_versions(tag) == (semver, python_version)


@pytest.mark.parametrize("tag", ["v1.2", "v01.2.3", "release-1.2.3", "v1.2.3-dev.1"])
def test_release_versions_reject_ambiguous_tags(tag: str) -> None:
    with pytest.raises(qualify.QualificationError):
        qualify.release_versions(tag)


def test_stamp_and_verify_chart_preserves_vendor_version(tmp_path: Path) -> None:
    _, policy = _policy(tmp_path)
    chart = _chart(tmp_path)
    qualify.stamp_chart(chart, policy, "1.2.3")
    qualify.verify_chart(chart, policy, "1.2.3")
    assert (
        qualify._yaml_scalar(chart / "charts/vendor/Chart.yaml", "appVersion")
        == "9.8.7"
    )


def test_python_artifacts_are_inspected_and_hashed(tmp_path: Path) -> None:
    _, policy = _policy(tmp_path)
    records = qualify.qualify_python_dist(
        _dist(tmp_path), policy, "1.2.3", smoke_install=False
    )
    assert {record["version"] for record in records} == {"1.2.3"}
    assert all(len(record["sha256"]) == 64 for record in records)


def test_packaged_chart_is_version_bound_and_hashed(tmp_path: Path) -> None:
    package = tmp_path / "fabric-1.2.3.tgz"
    content = b'apiVersion: v2\nname: fabric\nversion: 1.2.3\nappVersion: "1.2.3"\n'
    with tarfile.open(package, "w:gz") as archive:
        info = tarfile.TarInfo("fabric/Chart.yaml")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    record = qualify.inspect_chart_package(package, "1.2.3")
    assert record["filename"] == package.name
    assert len(record["sha256"]) == 64


def test_wheel_missing_typed_marker_fails_closed(tmp_path: Path) -> None:
    _, policy = _policy(tmp_path)
    dist = _dist(tmp_path)
    wheel = next(dist.glob("*.whl"))
    rewritten = tmp_path / "bad.whl"
    with zipfile.ZipFile(wheel) as source, zipfile.ZipFile(rewritten, "w") as target:
        for name in source.namelist():
            if name != "fabric/py.typed":
                target.writestr(name, source.read(name))
    with pytest.raises(qualify.QualificationError, match="fabric/py.typed"):
        qualify.inspect_wheel(rewritten, policy, "1.2.3")


def test_wheel_missing_fabricctl_entry_point_fails_closed(tmp_path: Path) -> None:
    _, policy = _policy(tmp_path)
    dist = _dist(tmp_path)
    wheel = next(dist.glob("*.whl"))
    rewritten = tmp_path / "bad-entrypoint.whl"
    with zipfile.ZipFile(wheel) as source, zipfile.ZipFile(rewritten, "w") as target:
        for name in source.namelist():
            if not name.endswith("entry_points.txt"):
                target.writestr(name, source.read(name))
    with pytest.raises(qualify.QualificationError, match="entry_points.txt"):
        qualify.inspect_wheel(rewritten, policy, "1.2.3")


def test_wheel_rejects_unexpected_top_level_content(tmp_path: Path) -> None:
    _, policy = _policy(tmp_path)
    dist = _dist(tmp_path)
    wheel = next(dist.glob("*.whl"))
    rewritten = tmp_path / "bloated.whl"
    with zipfile.ZipFile(wheel) as source, zipfile.ZipFile(rewritten, "w") as target:
        for name in source.namelist():
            target.writestr(name, source.read(name))
        target.writestr("tests/test_private_contract.py", "")
    with pytest.raises(qualify.QualificationError, match="unexpected wheel content"):
        qualify.inspect_wheel(rewritten, policy, "1.2.3")


def test_wheel_rejects_forbidden_capability_path(tmp_path: Path) -> None:
    _, policy = _policy(tmp_path)
    python_policy = policy["python_distribution"]
    assert isinstance(python_policy, dict)
    python_policy["forbidden_wheel_paths"] = ["fabric/judge.py"]
    dist = _dist(tmp_path)
    wheel = next(dist.glob("*.whl"))
    rewritten = tmp_path / "capability.whl"
    with zipfile.ZipFile(wheel) as source, zipfile.ZipFile(rewritten, "w") as target:
        for name in source.namelist():
            target.writestr(name, source.read(name))
        target.writestr("fabric/judge.py", "")
    with pytest.raises(qualify.QualificationError, match="forbidden capability"):
        qualify.inspect_wheel(rewritten, policy, "1.2.3")


def test_wheel_rejects_unexpected_console_script(tmp_path: Path) -> None:
    _, policy = _policy(tmp_path)
    python_policy = policy["python_distribution"]
    assert isinstance(python_policy, dict)
    python_policy["required_console_scripts"] = {}
    with pytest.raises(qualify.QualificationError, match="unexpected console scripts"):
        qualify.inspect_wheel(next(_dist(tmp_path).glob("*.whl")), policy, "1.2.3")


def test_sdist_rejects_path_traversal(tmp_path: Path) -> None:
    _, policy = _policy(tmp_path)
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(bad, "w:gz") as archive:
        content = b"bad"
        info = tarfile.TarInfo("package/../escape")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    with pytest.raises(qualify.QualificationError, match="unsafe archive member"):
        qualify.inspect_sdist(bad, policy, "1.2.3")


def test_sdist_rejects_tests_and_duplicate_conformance_goldens(tmp_path: Path) -> None:
    _, policy = _policy(tmp_path)
    dist = _dist(tmp_path)
    source = next(dist.glob("*.tar.gz"))
    rewritten = tmp_path / "bloated.tar.gz"
    with (
        tarfile.open(source, "r:gz") as source_archive,
        tarfile.open(rewritten, "w:gz") as target,
    ):
        for member in source_archive.getmembers():
            extracted = source_archive.extractfile(member)
            target.addfile(member, extracted)
        content = b"{}\n"
        info = tarfile.TarInfo("singleaxis_fabric-1.2.3/tests/conformance/golden.json")
        info.size = len(content)
        target.addfile(info, io.BytesIO(content))
    with pytest.raises(qualify.QualificationError, match="unexpected sdist content"):
        qualify.inspect_sdist(rewritten, policy, "1.2.3")


def test_sdist_rejects_forbidden_capability_path(tmp_path: Path) -> None:
    _, policy = _policy(tmp_path)
    python_policy = policy["python_distribution"]
    assert isinstance(python_policy, dict)
    python_policy["forbidden_sdist_paths"] = ["src/fabric/policy.py"]
    source = next(_dist(tmp_path).glob("*.tar.gz"))
    rewritten = tmp_path / "capability.tar.gz"
    with (
        tarfile.open(source, "r:gz") as source_archive,
        tarfile.open(rewritten, "w:gz") as target,
    ):
        for member in source_archive.getmembers():
            extracted = source_archive.extractfile(member)
            target.addfile(member, extracted)
        content = b""
        info = tarfile.TarInfo("singleaxis_fabric-1.2.3/src/fabric/policy.py")
        info.size = len(content)
        target.addfile(info, io.BytesIO(content))
    with pytest.raises(qualify.QualificationError, match="forbidden capability"):
        qualify.inspect_sdist(rewritten, policy, "1.2.3")


def test_workflow_evidence_is_bound_to_sha_and_policy(tmp_path: Path) -> None:
    policy_path, policy = _policy(tmp_path)
    evidence = tmp_path / "evidence.json"
    sha = "a" * 40
    evidence.write_text(
        json.dumps(
            {
                "commit_sha": sha,
                "required_workflows": [{"workflow": "ci.yml"}],
            }
        ),
        encoding="utf-8",
    )
    assert qualify._verify_workflow_evidence(evidence, sha, policy)
    with pytest.raises(qualify.QualificationError, match="commit SHA"):
        qualify._verify_workflow_evidence(evidence, "b" * 40, policy)
    assert policy_path.is_file()
