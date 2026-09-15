# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Adversarial tests for the deterministic public contracts archive."""

from __future__ import annotations

import hashlib
import json
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from release import package_contracts as packaging  # noqa: E402
from release.qualify_release import QualificationError  # noqa: E402


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _policy(tmp_path: Path) -> Path:
    path = tmp_path / "release-policy.json"
    path.write_text(
        json.dumps(
            {
                "contracts": {
                    "archive_prefix": "singleaxis-fabric-contracts",
                    "manifest_name": "manifest.json",
                    "require_sha256_for_json": True,
                    "public_families": ["activity", "connect"],
                    "public_versions": {
                        "activity": ["v1"],
                        "connect": ["v2alpha1"],
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def _scoped_policy(tmp_path: Path, families: list[str]) -> Path:
    path = _policy(tmp_path)
    policy = json.loads(path.read_text(encoding="utf-8"))
    policy["contracts"]["public_families"] = families
    policy["contracts"]["public_versions"] = {
        family: policy["contracts"]["public_versions"][family] for family in families
    }
    path.write_text(json.dumps(policy), encoding="utf-8")
    return path


def test_release_policy_requires_explicit_public_family_allowlist(
    tmp_path: Path,
) -> None:
    contracts = tmp_path / "contracts"
    _family(contracts, "activity", "v1")
    policy = _policy(tmp_path)
    value = json.loads(policy.read_text(encoding="utf-8"))
    del value["contracts"]["public_families"]
    policy.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(QualificationError, match="public_families is required"):
        packaging.package_contracts(contracts, policy, "v1.2.3", tmp_path / "out")


def test_release_policy_requires_exact_public_versions(tmp_path: Path) -> None:
    contracts = tmp_path / "contracts"
    _family(contracts, "activity", "v1")
    _family(contracts, "connect", "v2alpha1")
    policy = _policy(tmp_path)
    value = json.loads(policy.read_text(encoding="utf-8"))
    del value["contracts"]["public_versions"]
    policy.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(QualificationError, match="public_versions"):
        packaging.package_contracts(contracts, policy, "v1.2.3", tmp_path / "out")


def _family(
    root: Path,
    family: str = "activity",
    version: str = "v1",
    *,
    manifest: dict[str, object] | None = None,
) -> Path:
    directory = root / family / version
    (directory / "schema").mkdir(parents=True)
    schema = b'{"type":"object"}\n'
    (directory / "schema" / "contract.schema.json").write_bytes(schema)
    (directory / "README.md").write_text(f"# {family}\n", encoding="utf-8")
    value = manifest or {
        "contract": f"singleaxis.fabric.{family}",
        "version": version,
        "schema": {
            "path": "schema/contract.schema.json",
            "sha256": _sha256(schema),
        },
    }
    (directory / "manifest.json").write_text(
        json.dumps(value, indent=2) + "\n", encoding="utf-8"
    )
    return directory


def test_archive_is_deterministic_generic_and_has_fixed_metadata(
    tmp_path: Path,
) -> None:
    contracts = tmp_path / "contracts"
    _family(contracts, "activity", "v1")
    _family(contracts, "connect", "v2alpha1")
    policy = _policy(tmp_path)

    first = packaging.package_contracts(contracts, policy, "v1.2.3", tmp_path / "first")
    second = packaging.package_contracts(
        contracts, policy, "v1.2.3", tmp_path / "second"
    )

    assert first == second
    assert [family["name"] for family in first["families"]] == [
        "activity",
        "connect",
    ]
    archive = tmp_path / "first" / first["archive"]["filename"]
    assert archive.name == "singleaxis-fabric-contracts-1.2.3.tar.gz"
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
    assert [member.name for member in members] == [
        record["path"] for record in first["archive"]["members"]
    ]
    assert all(
        member.isfile()
        and member.mode == 0o644
        and member.uid == 0
        and member.gid == 0
        and member.mtime == 0
        for member in members
    )


def test_missing_manifest_fails_closed(tmp_path: Path) -> None:
    contracts = tmp_path / "contracts"
    version = contracts / "assurance" / "v1"
    version.mkdir(parents=True)
    (version / "schema.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(QualificationError, match="missing manifest.json"):
        packaging.validate_contract_tree(contracts, manifest_name="manifest.json")


def test_release_archive_contains_only_configured_public_families(
    tmp_path: Path,
) -> None:
    contracts = tmp_path / "contracts"
    _family(contracts, "activity", "v1")
    _family(contracts, "assurance", "v1")
    policy = _scoped_policy(tmp_path, ["activity"])

    result = packaging.package_contracts(
        contracts, policy, "v1.2.3", tmp_path / "output"
    )

    assert result["families"] == [{"name": "activity", "versions": ["v1"]}]
    assert all(
        "/contracts/activity/" in member["path"]
        for member in result["archive"]["members"]
    )


def test_release_archive_contains_only_configured_public_versions(
    tmp_path: Path,
) -> None:
    contracts = tmp_path / "contracts"
    _family(contracts, "activity", "v1")
    _family(contracts, "activity", "v2")
    _family(contracts, "connect", "v2alpha1")
    policy = _policy(tmp_path)
    value = json.loads(policy.read_text(encoding="utf-8"))
    value["contracts"]["public_versions"]["activity"] = ["v2"]
    policy.write_text(json.dumps(value), encoding="utf-8")

    result = packaging.package_contracts(
        contracts, policy, "v1.2.3", tmp_path / "output"
    )

    assert result["families"] == [
        {"name": "activity", "versions": ["v2"]},
        {"name": "connect", "versions": ["v2alpha1"]},
    ]
    assert not any(
        "/activity/v1/" in member["path"] for member in result["archive"]["members"]
    )


def test_unpinned_json_fails_closed(tmp_path: Path) -> None:
    contracts = tmp_path / "contracts"
    version = _family(contracts)
    (version / "fixture.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(QualificationError, match="unpinned JSON: fixture.json"):
        packaging.validate_contract_tree(contracts, manifest_name="manifest.json")


def test_wrong_or_missing_digest_fails_closed(tmp_path: Path) -> None:
    contracts = tmp_path / "contracts"
    _family(
        contracts,
        manifest={
            "schema": {
                "path": "schema/contract.schema.json",
                "sha256": "0" * 64,
            }
        },
    )
    with pytest.raises(QualificationError, match="SHA-256 mismatch"):
        packaging.validate_contract_tree(contracts, manifest_name="manifest.json")

    manifest = contracts / "activity" / "v1" / "manifest.json"
    manifest.write_text(
        json.dumps({"schema": {"path": "schema/contract.schema.json"}}),
        encoding="utf-8",
    )
    with pytest.raises(QualificationError, match="lacks a lowercase SHA-256 pin"):
        packaging.validate_contract_tree(contracts, manifest_name="manifest.json")


@pytest.mark.parametrize("path", ["../outside.json", "/absolute.json", "a\\b.json"])
def test_manifest_traversal_and_non_posix_paths_are_rejected(
    tmp_path: Path, path: str
) -> None:
    contracts = tmp_path / "contracts"
    _family(
        contracts,
        manifest={"artifact": {"path": path, "sha256": "0" * 64}},
    )
    with pytest.raises(QualificationError, match="unsafe path"):
        packaging.validate_contract_tree(contracts, manifest_name="manifest.json")


def test_symlink_member_is_rejected(tmp_path: Path) -> None:
    contracts = tmp_path / "contracts"
    version = _family(contracts)
    target = tmp_path / "outside.json"
    target.write_text("{}\n", encoding="utf-8")
    link = version / "linked.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")
    with pytest.raises(QualificationError, match="symlinks are not permitted"):
        packaging.validate_contract_tree(contracts, manifest_name="manifest.json")


def test_unsafe_and_case_colliding_members_are_rejected(tmp_path: Path) -> None:
    contracts = tmp_path / "contracts"
    version = _family(contracts)
    (version / "unsafe name.md").write_text("unsafe\n", encoding="utf-8")
    with pytest.raises(QualificationError, match="unsafe path"):
        packaging.validate_contract_tree(contracts, manifest_name="manifest.json")

    (version / "unsafe name.md").unlink()
    (version / "Alpha.txt").write_text("upper\n", encoding="utf-8")
    (version / "alpha.txt").write_text("lower\n", encoding="utf-8")
    if (
        len([path for path in version.iterdir() if path.name.lower() == "alpha.txt"])
        < 2
    ):
        pytest.skip("case-colliding files are unavailable on this filesystem")
    with pytest.raises(
        QualificationError, match="case-insensitive contract path collision"
    ):
        packaging.validate_contract_tree(contracts, manifest_name="manifest.json")


def test_duplicate_manifest_keys_are_rejected(tmp_path: Path) -> None:
    contracts = tmp_path / "contracts"
    version = _family(contracts)
    (version / "manifest.json").write_text(
        '{"version":"v1","version":"v2"}\n', encoding="utf-8"
    )
    with pytest.raises(QualificationError, match="duplicate JSON key"):
        packaging.validate_contract_tree(contracts, manifest_name="manifest.json")


def test_release_policy_and_workflow_have_one_build_once_contract_path() -> None:
    root = Path(__file__).resolve().parents[2]
    policy = json.loads(
        (root / "scripts/release/release-policy.json").read_text(encoding="utf-8")
    )
    assert policy["contracts"]["archive_prefix"] == "singleaxis-fabric-contracts"
    assert policy["contracts"]["manifest_name"] == "manifest.json"
    assert policy["contracts"]["require_sha256_for_json"] is True
    assert "assurance" not in policy["contracts"]["public_families"]
    assert "management" not in policy["contracts"]["public_families"]
    assert "lifecycle" not in policy["contracts"]["public_families"]
    assert policy["contracts"]["public_versions"]["activity"] == ["v2"]

    workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
    qualify_start = workflow.index("  qualify-release:\n")
    qualify_end = workflow.index("  changelog:\n", qualify_start)
    qualify = workflow[qualify_start:qualify_end]
    github_release = workflow[workflow.index("  github-release:\n") :]

    assert "needs: [verify-tag, changelog]" in qualify
    assert workflow.count("python scripts/release/package_contracts.py") == 1
    assert "name: qualified-contracts" in qualify
    assert "qualification/contracts/*.tar.gz" in qualify
    assert "qualification/contracts/SHA256SUMS.contracts" in qualify
    assert "qualification/contracts/contracts-qualification.json" in qualify
    assert "name: qualified-contracts" in github_release
    assert "sha256sum --check SHA256SUMS.contracts" in github_release


def test_repository_contract_tree_is_release_qualifiable() -> None:
    root = Path(__file__).resolve().parents[2]
    members, families = packaging.validate_contract_tree(
        root / "contracts", manifest_name="manifest.json"
    )
    assert members
    assert families
    assert all(versions for versions in families.values())
