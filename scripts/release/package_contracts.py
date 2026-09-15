# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Build and qualify the deterministic public Fabric contracts archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

try:
    from .qualify_release import QualificationError, release_versions
except ImportError:  # pragma: no cover - direct script execution
    from qualify_release import QualificationError, release_versions


SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ContractFile:
    relative_path: PurePosixPath
    content: bytes
    sha256: str


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_relative_path(raw: str, *, context: str) -> PurePosixPath:
    if not raw or "\\" in raw or any(ord(character) < 32 for character in raw):
        raise QualificationError(f"{context}: unsafe path {raw!r}")
    path = PurePosixPath(raw)
    if (
        path.is_absolute()
        or path.as_posix() != raw
        or any(
            part in {"", ".", ".."} or SAFE_COMPONENT_RE.fullmatch(part) is None
            for part in path.parts
        )
    ):
        raise QualificationError(f"{context}: unsafe path {raw!r}")
    return path


def _read_stable_regular_file(path: Path) -> bytes:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise QualificationError(f"{path}: contract members must be regular files")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise QualificationError(f"{path}: cannot safely open contract member") from exc
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise QualificationError(f"{path}: member changed while being opened")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read()
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        opened.st_size != len(content)
        or after.st_size != opened.st_size
        or after.st_mtime_ns != opened.st_mtime_ns
    ):
        raise QualificationError(f"{path}: member changed while being read")
    return content


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise QualificationError(f"manifest contains duplicate JSON key {key!r}")
        result[key] = value
    return result


def _load_manifest(path: Path, content: bytes) -> dict[str, Any]:
    try:
        value = json.loads(content, object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QualificationError(f"{path}: manifest is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise QualificationError(f"{path}: manifest root must be an object")
    return value


def _manifest_pins(
    manifest: dict[str, Any], *, context: str
) -> dict[PurePosixPath, str]:
    pins: dict[PurePosixPath, str] = {}

    def visit(value: Any, location: str) -> None:
        if isinstance(value, dict):
            path_fields = [field for field in ("path", "fixture") if field in value]
            if len(path_fields) > 1:
                raise QualificationError(
                    f"{context}:{location}: artifact entry has multiple path fields"
                )
            if path_fields:
                raw_path = value[path_fields[0]]
                digest = value.get("sha256")
                if not isinstance(raw_path, str):
                    raise QualificationError(
                        f"{context}:{location}: pinned path must be a string"
                    )
                path = _validate_relative_path(
                    raw_path, context=f"{context}:{location}"
                )
                if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
                    raise QualificationError(
                        f"{context}:{location}: {path} lacks a lowercase SHA-256 pin"
                    )
                if path in pins:
                    raise QualificationError(f"{context}: duplicate pin for {path}")
                pins[path] = digest
            for key, child in value.items():
                visit(child, f"{location}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{location}[{index}]")

    visit(manifest, "$")
    return pins


def _iter_contract_files(
    root: Path,
    *,
    included_families: frozenset[str] | None = None,
    included_versions: dict[str, frozenset[str]] | None = None,
) -> tuple[ContractFile, ...]:
    if root.is_symlink() or not root.is_dir():
        raise QualificationError(f"{root}: contracts root must be a real directory")
    files: list[ContractFile] = []
    casefold_paths: dict[str, PurePosixPath] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = PurePosixPath(path.relative_to(root).as_posix())
        if included_families is not None and relative.parts[0] not in included_families:
            continue
        if (
            included_versions is not None
            and len(relative.parts) >= 2
            and relative.parts[1]
            not in included_versions.get(relative.parts[0], frozenset())
        ):
            continue
        _validate_relative_path(relative.as_posix(), context=str(root))
        if path.is_symlink():
            raise QualificationError(f"{path}: symlinks are not permitted")
        if path.is_dir():
            continue
        content = _read_stable_regular_file(path)
        folded = relative.as_posix().casefold()
        if folded in casefold_paths:
            raise QualificationError(
                f"case-insensitive contract path collision: {casefold_paths[folded]} and {relative}"
            )
        casefold_paths[folded] = relative
        files.append(
            ContractFile(
                relative_path=relative,
                content=content,
                sha256=_sha256_bytes(content),
            )
        )
    if not files:
        raise QualificationError(f"{root}: contracts directory is empty")
    return tuple(files)


def validate_contract_tree(
    root: Path,
    *,
    manifest_name: str,
    included_families: frozenset[str] | None = None,
    included_versions: dict[str, frozenset[str]] | None = None,
) -> tuple[tuple[ContractFile, ...], dict[str, tuple[str, ...]]]:
    files = _iter_contract_files(
        root,
        included_families=included_families,
        included_versions=included_versions,
    )
    by_path = {member.relative_path: member for member in files}
    families: dict[str, tuple[str, ...]] = {}

    top_level = sorted(root.iterdir(), key=lambda path: path.name)
    if included_families is not None:
        available = {path.name for path in top_level if path.is_dir()}
        missing = sorted(included_families - available)
        if missing:
            raise QualificationError(
                f"{root}: configured public contract families are missing: "
                f"{', '.join(missing)}"
            )
        top_level = [path for path in top_level if path.name in included_families]
    if not top_level:
        raise QualificationError(f"{root}: no contract families found")
    for family_path in top_level:
        _validate_relative_path(family_path.name, context=str(root))
        if family_path.is_symlink() or not family_path.is_dir():
            raise QualificationError(
                f"{family_path}: contract family entries must be real directories"
            )
        versions: list[str] = []
        for version_path in sorted(family_path.iterdir(), key=lambda path: path.name):
            if (
                included_versions is not None
                and version_path.name not in included_versions[family_path.name]
            ):
                continue
            _validate_relative_path(version_path.name, context=str(family_path))
            if version_path.is_symlink() or not version_path.is_dir():
                raise QualificationError(
                    f"{version_path}: family entries must be version directories"
                )
            versions.append(version_path.name)
            version_relative = PurePosixPath(family_path.name, version_path.name)
            manifest_relative = version_relative / manifest_name
            manifest_member = by_path.get(manifest_relative)
            if manifest_member is None:
                raise QualificationError(f"{version_path}: missing {manifest_name}")
            manifest = _load_manifest(
                root / manifest_relative.as_posix(), manifest_member.content
            )
            pins = _manifest_pins(manifest, context=manifest_relative.as_posix())
            version_files = {
                PurePosixPath(*member.relative_path.parts[2:]): member
                for member in files
                if member.relative_path.parts[:2] == version_relative.parts
            }
            for pinned_path, expected_digest in pins.items():
                pinned_member = version_files.get(pinned_path)
                if pinned_member is None:
                    raise QualificationError(
                        f"{manifest_relative}: pinned file does not exist: {pinned_path}"
                    )
                if pinned_member.sha256 != expected_digest:
                    raise QualificationError(
                        f"{manifest_relative}: SHA-256 mismatch for {pinned_path}"
                    )
            unpinned_json = sorted(
                path.as_posix()
                for path in version_files
                if path.suffix == ".json"
                and path.name != manifest_name
                and path not in pins
            )
            if unpinned_json:
                raise QualificationError(
                    f"{manifest_relative}: unpinned JSON: {', '.join(unpinned_json)}"
                )
        if not versions:
            raise QualificationError(
                f"{family_path}: configured public contract versions are missing"
            )
        families[family_path.name] = tuple(versions)
    return files, families


def _archive_members(
    files: Iterable[ContractFile], *, archive_root: str
) -> tuple[dict[str, Any], ...]:
    return tuple(
        {
            "path": f"{archive_root}/contracts/{member.relative_path.as_posix()}",
            "sha256": member.sha256,
            "size": len(member.content),
        }
        for member in files
    )


def _write_archive(
    archive: Path,
    files: tuple[ContractFile, ...],
    *,
    archive_root: str,
) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    with archive.open("wb") as raw_stream:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw_stream, compresslevel=9, mtime=0
        ) as gzip_stream:
            with tarfile.open(
                fileobj=gzip_stream, mode="w", format=tarfile.PAX_FORMAT
            ) as tar:
                for member in files:
                    info = tarfile.TarInfo(
                        f"{archive_root}/contracts/{member.relative_path.as_posix()}"
                    )
                    info.size = len(member.content)
                    info.mode = 0o644
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = 0
                    tar.addfile(info, io.BytesIO(member.content))


def _verify_archive(
    archive: Path, expected_members: tuple[dict[str, Any], ...]
) -> None:
    with tarfile.open(archive, mode="r:gz") as tar:
        observed = tar.getmembers()
        names = [member.name for member in observed]
        expected_names = [str(member["path"]) for member in expected_members]
        if names != expected_names or len(names) != len(set(names)):
            raise QualificationError(f"{archive}: member inventory is not exact")
        for member, expected in zip(observed, expected_members, strict=True):
            if (
                not member.isfile()
                or member.mode != 0o644
                or member.uid != 0
                or member.gid != 0
                or member.uname != ""
                or member.gname != ""
                or member.mtime != 0
                or member.size != expected["size"]
            ):
                raise QualificationError(
                    f"{archive}: unstable metadata for {member.name}"
                )
            stream = tar.extractfile(member)
            if stream is None or _sha256_bytes(stream.read()) != expected["sha256"]:
                raise QualificationError(
                    f"{archive}: content mismatch for {member.name}"
                )


def _load_contract_policy(path: Path) -> tuple[dict[str, Any], str]:
    content = path.read_bytes()
    try:
        policy = json.loads(content)
        config = policy["contracts"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise QualificationError(f"{path}: missing contracts release policy") from exc
    if not isinstance(config, dict):
        raise QualificationError(f"{path}: contracts policy must be an object")
    if config.get("manifest_name") != "manifest.json":
        raise QualificationError(
            f"{path}: contracts manifest_name must be manifest.json"
        )
    if config.get("archive_prefix") != "singleaxis-fabric-contracts":
        raise QualificationError(f"{path}: unsupported contracts archive_prefix")
    if config.get("require_sha256_for_json") is not True:
        raise QualificationError(
            f"{path}: contracts policy must require SHA-256 pins for JSON"
        )
    public_families = config.get("public_families")
    if (
        not isinstance(public_families, list)
        or not public_families
        or any(
            not isinstance(family, str) or SAFE_COMPONENT_RE.fullmatch(family) is None
            for family in public_families
        )
        or len(public_families) != len(set(public_families))
    ):
        raise QualificationError(
            f"{path}: contracts public_families is required and must be a non-empty unique list"
        )
    public_versions = config.get("public_versions")
    if (
        not isinstance(public_versions, dict)
        or set(public_versions) != set(public_families)
        or any(
            not isinstance(versions, list)
            or not versions
            or any(
                not isinstance(version, str)
                or SAFE_COMPONENT_RE.fullmatch(version) is None
                for version in versions
            )
            or len(versions) != len(set(versions))
            for versions in public_versions.values()
        )
    ):
        raise QualificationError(
            f"{path}: contracts public_versions must exactly map every public family "
            "to a non-empty unique version list"
        )
    return config, _sha256_bytes(content)


def package_contracts(
    contracts_dir: Path,
    policy_path: Path,
    version: str,
    output_dir: Path,
) -> dict[str, Any]:
    semver, _ = release_versions(version)
    config, policy_sha256 = _load_contract_policy(policy_path)
    files, families = validate_contract_tree(
        contracts_dir,
        manifest_name=str(config["manifest_name"]),
        included_families=frozenset(config["public_families"]),
        included_versions={
            family: frozenset(versions)
            for family, versions in config["public_versions"].items()
        },
    )
    archive_root = f"{config['archive_prefix']}-{semver}"
    filename = f"{archive_root}.tar.gz"
    archive = output_dir / filename
    members = _archive_members(files, archive_root=archive_root)
    _write_archive(archive, files, archive_root=archive_root)
    _verify_archive(archive, members)
    archive_sha256 = _sha256_file(archive)
    return {
        "schema_version": "fabric.contracts-qualification/v1",
        "qualified": True,
        "version": semver,
        "policy_sha256": policy_sha256,
        "families": [
            {"name": name, "versions": list(versions)}
            for name, versions in sorted(families.items())
        ],
        "archive": {
            "filename": filename,
            "sha256": archive_sha256,
            "member_count": len(members),
            "members": list(members),
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contracts-dir", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        qualification = package_contracts(
            args.contracts_dir, args.policy, args.version, args.output_dir
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(qualification, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        archive = qualification["archive"]
        checksum = args.output_dir / "SHA256SUMS.contracts"
        checksum.write_text(
            f"{archive['sha256']}  {archive['filename']}\n", encoding="utf-8"
        )
    except (OSError, QualificationError, KeyError, TypeError) as exc:
        print(f"contract qualification failed: {exc}", file=sys.stderr)
        return 1
    archive = qualification["archive"]
    family_count = len(qualification["families"])
    print(
        f"qualified {archive['filename']} sha256={archive['sha256']} "
        f"members={archive['member_count']} families={family_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
