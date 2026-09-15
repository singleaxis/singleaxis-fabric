# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Deterministically qualify Fabric release versions and Python artifacts."""

from __future__ import annotations

import argparse
import configparser
import email.parser
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

SEMVER_RE = re.compile(
    r"^v?(?P<base>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))"
    r"(?P<pre>-(?:alpha|beta|rc)(?:\.(?:0|[1-9]\d*))?)?$"
)
FIELD_RE = re.compile(r"^(?P<key>[A-Za-z][A-Za-z0-9]*):\s*(?P<value>.+?)\s*$")


class QualificationError(ValueError):
    """An artifact cannot be proven to meet the release policy."""


def release_versions(tag: str) -> tuple[str, str]:
    """Return the Helm/SemVer and Python/PEP 440 versions for a release tag."""
    match = SEMVER_RE.fullmatch(tag)
    if match is None:
        raise QualificationError(
            "release tag must be vMAJOR.MINOR.PATCH with optional -alpha.N, -beta.N, or -rc.N"
        )
    semver = match.group("base") + (match.group("pre") or "")
    prerelease = match.group("pre")
    if prerelease is None:
        return semver, semver
    label, _, number = prerelease[1:].partition(".")
    pep_label = {"alpha": "a", "beta": "b", "rc": "rc"}[label]
    return semver, f"{match.group('base')}{pep_label}{number or '0'}"


def _yaml_scalar(path: Path, field: str) -> str:
    matches: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = FIELD_RE.fullmatch(line)
        if match is not None and match.group("key") == field:
            matches.append(match.group("value").strip("\"'"))
    if len(matches) != 1:
        raise QualificationError(
            f"{path}: expected exactly one top-level {field} field"
        )
    return matches[0]


def _replace_top_level_field(
    path: Path, field: str, value: str, *, quote: bool
) -> None:
    replacement = f'{field}: "{value}"' if quote else f"{field}: {value}"
    lines = path.read_text(encoding="utf-8").splitlines()
    hits = 0
    for index, line in enumerate(lines):
        match = FIELD_RE.fullmatch(line)
        if match is not None and match.group("key") == field:
            lines[index] = replacement
            hits += 1
    if hits != 1:
        raise QualificationError(
            f"{path}: expected exactly one top-level {field} field"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _load_policy(path: Path) -> dict[str, Any]:
    policy = json.loads(path.read_text(encoding="utf-8"))
    if policy.get("schema_version") != "fabric.release-policy/v1":
        raise QualificationError("unsupported or missing release policy schema_version")
    return policy


def stamp_chart(chart_dir: Path, policy: dict[str, Any], version: str) -> None:
    _replace_top_level_field(chart_dir / "Chart.yaml", "version", version, quote=False)
    _replace_top_level_field(
        chart_dir / "Chart.yaml", "appVersion", version, quote=True
    )
    for name in policy["helm"]["first_party_app_charts"]:
        _replace_top_level_field(
            chart_dir / "charts" / name / "Chart.yaml",
            "appVersion",
            version,
            quote=True,
        )

    values = chart_dir / "values.yaml"
    text = values.read_text(encoding="utf-8")
    pattern = re.compile(r"(?m)^(global:\n\s{2}fabric:\n\s{4}version:)\s*[^\n]+$")
    text, count = pattern.subn(rf'\1 "{version}"', text)
    if count != 1:
        raise QualificationError(f"{values}: expected one global.fabric.version field")
    values.write_text(text, encoding="utf-8")


def verify_chart(chart_dir: Path, policy: dict[str, Any], version: str) -> None:
    root = chart_dir / "Chart.yaml"
    if _yaml_scalar(root, "version") != version:
        raise QualificationError(f"{root}: chart version does not match {version}")
    if _yaml_scalar(root, "appVersion") != version:
        raise QualificationError(f"{root}: appVersion does not match {version}")
    for name in policy["helm"]["first_party_app_charts"]:
        path = chart_dir / "charts" / name / "Chart.yaml"
        if _yaml_scalar(path, "appVersion") != version:
            raise QualificationError(f"{path}: appVersion does not match {version}")
    for name in policy["helm"]["third_party_app_charts"]:
        path = chart_dir / "charts" / name / "Chart.yaml"
        if not path.is_file():
            raise QualificationError(f"required third-party chart is missing: {path}")


def inspect_chart_package(path: Path, expected_version: str) -> dict[str, Any]:
    """Inspect the exact Helm archive that will be published."""
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        names = _safe_members((member.name for member in members), path)
        if any(member.issym() or member.islnk() for member in members):
            raise QualificationError(
                f"{path}: links are not permitted in the Helm package"
            )
        chart_metadata = "fabric/Chart.yaml"
        if chart_metadata not in names:
            raise QualificationError(f"{path}: missing {chart_metadata}")
        extracted = archive.extractfile(chart_metadata)
        if extracted is None:
            raise QualificationError(f"{path}: {chart_metadata} is not a regular file")
        metadata = extracted.read().decode("utf-8")
    version_matches = re.findall(r"(?m)^version:\s*['\"]?([^'\"\s]+)", metadata)
    app_matches = re.findall(r"(?m)^appVersion:\s*['\"]?([^'\"\s]+)", metadata)
    if version_matches != [expected_version] or app_matches != [expected_version]:
        raise QualificationError(
            f"{path}: packaged chart version/appVersion do not both match {expected_version}"
        )
    return {
        "filename": path.name,
        "sha256": _sha256(path),
        "version": expected_version,
        "member_count": len(names),
    }


def _safe_members(names: Iterable[str], artifact: Path) -> tuple[str, ...]:
    members = tuple(names)
    if len(members) != len(set(members)):
        raise QualificationError(f"{artifact}: duplicate archive member")
    for name in members:
        member = PurePosixPath(name)
        if member.is_absolute() or ".." in member.parts or "" in member.parts:
            raise QualificationError(f"{artifact}: unsafe archive member {name!r}")
        if name.endswith((".pyc", ".pyo")) or "__pycache__" in member.parts:
            raise QualificationError(
                f"{artifact}: compiled Python artifact must not ship: {name}"
            )
    return members


def _metadata_fields(raw: bytes, artifact: Path) -> tuple[str, str, str]:
    message = email.parser.BytesParser().parsebytes(raw)
    name = message.get("Name")
    version = message.get("Version")
    requires_python = message.get("Requires-Python")
    if not all(
        isinstance(value, str) and value for value in (name, version, requires_python)
    ):
        raise QualificationError(
            f"{artifact}: package metadata lacks Name, Version, or Requires-Python"
        )
    return name, version, requires_python


def inspect_wheel(
    path: Path, policy: dict[str, Any], expected_version: str
) -> dict[str, Any]:
    with zipfile.ZipFile(path) as archive:
        names = _safe_members(archive.namelist(), path)
        metadata_paths = [
            name for name in names if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_paths) != 1:
            raise QualificationError(f"{path}: expected exactly one dist-info/METADATA")
        dist_info = metadata_paths[0].split("/", maxsplit=1)[0]
        allowed_roots = set(
            policy["python_distribution"]["allowed_wheel_package_roots"]
        ) | {dist_info}
        unexpected = sorted(
            name for name in names if PurePosixPath(name).parts[0] not in allowed_roots
        )
        if unexpected:
            raise QualificationError(
                f"{path}: unexpected wheel content: {', '.join(unexpected)}"
            )
        forbidden_paths = set(
            policy["python_distribution"].get("forbidden_wheel_paths", [])
        )
        forbidden_prefixes = tuple(
            policy["python_distribution"].get("forbidden_wheel_prefixes", [])
        )
        forbidden = sorted(
            member
            for member in names
            if member in forbidden_paths or member.startswith(forbidden_prefixes)
        )
        if forbidden:
            raise QualificationError(
                f"{path}: wheel contains forbidden capability paths: "
                f"{', '.join(forbidden)}"
            )
        name, version, requires_python = _metadata_fields(
            archive.read(metadata_paths[0]), path
        )
        parser = configparser.ConfigParser(interpolation=None)
        required_scripts = policy["python_distribution"]["required_console_scripts"]
        entry_point_paths = [
            member for member in names if member == f"{dist_info}/entry_points.txt"
        ]
        if len(entry_point_paths) > 1 or (required_scripts and not entry_point_paths):
            raise QualificationError(
                f"{path}: expected one dist-info/entry_points.txt when scripts are required"
            )
        if entry_point_paths:
            try:
                parser.read_string(archive.read(entry_point_paths[0]).decode("utf-8"))
            except (UnicodeDecodeError, configparser.Error) as exc:
                raise QualificationError(f"{path}: invalid entry_points.txt") from exc
    expected_name = policy["python_distribution"]["name"]
    if name != expected_name or version != expected_version:
        raise QualificationError(
            f"{path}: metadata is {name} {version}; expected {expected_name} {expected_version}"
        )
    required = policy["python_distribution"]["required_wheel_paths"]
    missing = sorted(set(required) - set(names))
    if missing:
        raise QualificationError(
            f"{path}: missing required wheel paths: {', '.join(missing)}"
        )
    observed_scripts = (
        dict(parser.items("console_scripts"))
        if parser.has_section("console_scripts")
        else {}
    )
    missing_scripts = {
        script: target
        for script, target in required_scripts.items()
        if observed_scripts.get(script) != target
    }
    if missing_scripts:
        expected = ", ".join(
            f"{script}={target}" for script, target in sorted(missing_scripts.items())
        )
        raise QualificationError(
            f"{path}: missing required console scripts: {expected}"
        )
    unexpected_scripts = {
        script: target
        for script, target in observed_scripts.items()
        if required_scripts.get(script) != target
    }
    if unexpected_scripts:
        observed = ", ".join(
            f"{script}={target}"
            for script, target in sorted(unexpected_scripts.items())
        )
        raise QualificationError(f"{path}: unexpected console scripts: {observed}")
    return {
        "filename": path.name,
        "sha256": _sha256(path),
        "name": name,
        "version": version,
        "requires_python": requires_python,
        "member_count": len(names),
    }


def inspect_sdist(
    path: Path, policy: dict[str, Any], expected_version: str
) -> dict[str, Any]:
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        names = _safe_members((member.name for member in members), path)
        if any(member.issym() or member.islnk() for member in members):
            raise QualificationError(
                f"{path}: links are not permitted in the source distribution"
            )
        roots = {PurePosixPath(name).parts[0] for name in names}
        if len(roots) != 1:
            raise QualificationError(
                f"{path}: source distribution must have one root directory"
            )
        root = next(iter(roots))
        allowed_top_level = set(
            policy["python_distribution"]["allowed_sdist_top_level"]
        )
        unexpected = []
        for member_name in names:
            parts = PurePosixPath(member_name).parts
            if len(parts) == 1:
                continue
            if parts[1] not in allowed_top_level:
                unexpected.append(member_name)
        if unexpected:
            raise QualificationError(
                f"{path}: unexpected sdist content: {', '.join(sorted(unexpected))}"
            )
        forbidden_paths = set(
            policy["python_distribution"].get("forbidden_sdist_paths", [])
        )
        forbidden_prefixes = tuple(
            policy["python_distribution"].get("forbidden_sdist_prefixes", [])
        )
        forbidden = []
        for member_name in names:
            parts = PurePosixPath(member_name).parts
            if len(parts) < 2:
                continue
            relative = PurePosixPath(*parts[1:]).as_posix()
            if relative in forbidden_paths or relative.startswith(forbidden_prefixes):
                forbidden.append(member_name)
        if forbidden:
            raise QualificationError(
                f"{path}: source distribution contains forbidden capability paths: "
                f"{', '.join(sorted(forbidden))}"
            )
        pkg_info = f"{root}/PKG-INFO"
        try:
            extracted = archive.extractfile(pkg_info)
        except KeyError as exc:
            raise QualificationError(f"{path}: missing PKG-INFO") from exc
        if extracted is None:
            raise QualificationError(f"{path}: PKG-INFO is not a regular file")
        name, version, requires_python = _metadata_fields(extracted.read(), path)
    expected_name = policy["python_distribution"]["name"]
    if name != expected_name or version != expected_version:
        raise QualificationError(
            f"{path}: metadata is {name} {version}; expected {expected_name} {expected_version}"
        )
    required = {
        f"{root}/{item}"
        for item in policy["python_distribution"]["required_sdist_paths"]
    }
    missing = sorted(required - set(names))
    if missing:
        raise QualificationError(
            f"{path}: missing required sdist paths: {', '.join(missing)}"
        )
    return {
        "filename": path.name,
        "sha256": _sha256(path),
        "name": name,
        "version": version,
        "requires_python": requires_python,
        "member_count": len(names),
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def smoke_install_wheel(
    path: Path,
    expected_version: str,
    required_scripts: dict[str, str],
) -> None:
    with tempfile.TemporaryDirectory(prefix="fabric-release-smoke-") as directory:
        environment = Path(directory) / "venv"
        subprocess.run([sys.executable, "-m", "venv", str(environment)], check=True)
        python = environment / (
            "Scripts/python.exe" if sys.platform == "win32" else "bin/python"
        )
        subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-index",
                "--no-deps",
                str(path.resolve()),
            ],
            check=True,
        )
        expected_scripts = sorted(required_scripts.items())
        code = (
            "from importlib.metadata import distribution; "
            "d=distribution('singleaxis-fabric'); "
            f"assert d.version == {expected_version!r}; "
            "assert d.locate_file('fabric/py.typed').is_file(); "
            "eps=sorted((e.name,e.value) for e in d.entry_points if e.group=='console_scripts'); "
            f"assert eps == {expected_scripts!r}, eps"
        )
        subprocess.run([str(python), "-I", "-c", code], check=True)


def qualify_python_dist(
    dist_dir: Path,
    policy: dict[str, Any],
    expected_version: str,
    *,
    smoke_install: bool,
) -> list[dict[str, Any]]:
    wheels = sorted(dist_dir.glob("*.whl"))
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise QualificationError(
            f"{dist_dir}: expected exactly one wheel and one .tar.gz sdist"
        )
    records = [
        inspect_wheel(wheels[0], policy, expected_version),
        inspect_sdist(sdists[0], policy, expected_version),
    ]
    if smoke_install:
        smoke_install_wheel(
            wheels[0],
            expected_version,
            policy["python_distribution"]["required_console_scripts"],
        )
    return records


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--chart-dir", type=Path, required=True)
    parser.add_argument("--chart-package", type=Path)
    parser.add_argument("--dist-dir", type=Path)
    parser.add_argument("--stamp-chart", action="store_true")
    parser.add_argument("--smoke-install", action="store_true")
    parser.add_argument("--workflow-evidence", type=Path)
    parser.add_argument("--commit-sha")
    parser.add_argument("--output", type=Path, required=True)
    return parser


def _verify_workflow_evidence(
    path: Path, sha: str, policy: dict[str, Any]
) -> list[dict[str, Any]]:
    evidence = json.loads(path.read_text(encoding="utf-8"))
    if evidence.get("commit_sha") != sha:
        raise QualificationError(
            "workflow evidence does not match the release commit SHA"
        )
    records = evidence.get("required_workflows")
    if not isinstance(records, list):
        raise QualificationError("workflow evidence has no required_workflows list")
    observed = {
        record.get("workflow") for record in records if isinstance(record, dict)
    }
    expected = set(policy["required_workflows"])
    if observed != expected:
        raise QualificationError(
            "workflow evidence does not cover the exact release policy"
        )
    return records


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = _load_policy(args.policy)
        semver, python_version = release_versions(args.tag)
        if args.stamp_chart:
            stamp_chart(args.chart_dir, policy, semver)
        verify_chart(args.chart_dir, policy, semver)
        artifacts: list[dict[str, Any]] = []
        if args.dist_dir is not None:
            artifacts = qualify_python_dist(
                args.dist_dir,
                policy,
                python_version,
                smoke_install=args.smoke_install,
            )
        chart_artifact = None
        if args.chart_package is not None:
            chart_artifact = inspect_chart_package(args.chart_package, semver)
        workflow_records: list[dict[str, Any]] = []
        if args.workflow_evidence is not None:
            if args.commit_sha is None:
                raise QualificationError(
                    "--commit-sha is required with --workflow-evidence"
                )
            workflow_records = _verify_workflow_evidence(
                args.workflow_evidence, args.commit_sha, policy
            )
    except (
        QualificationError,
        OSError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
    ) as exc:
        print(f"release qualification failed: {exc}", file=sys.stderr)
        return 1

    manifest = {
        "schema_version": "fabric.release-qualification/v1",
        "tag": args.tag,
        "version": semver,
        "python_version": python_version,
        "commit_sha": args.commit_sha,
        "policy_sha256": _sha256(args.policy),
        "workflow_evidence": workflow_records,
        "artifacts": artifacts,
        "helm": {
            "chart": "fabric",
            "version": semver,
            "first_party_app_charts": policy["helm"]["first_party_app_charts"],
            "artifact": chart_artifact,
        },
        "expected_images": [f"{name}:{semver}" for name in policy["images"]],
        "qualified": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"qualified Fabric release {args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
