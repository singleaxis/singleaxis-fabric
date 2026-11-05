# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Adversarial scanner labels must not inherit a permissive substring."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("license_text", "allowed"),
    [
        ("MIT WITH Commons Clause", False),
        ("MIT; Proprietary", False),
        # pip-licenses joins classifiers with "; ": every one must be allowed.
        ("Apache Software License; BSD License", True),
        ("Apache Software License; Not a license", False),
        ("Apache Software License; GPL", False),
        ("MIT;", False),
        ("Not MIT licensed", False),
        ("MIT AND", False),
        ("MIT OR", False),
        ("() OR MIT", False),
        ("(MIT)(Apache-2.0) OR MIT", False),
        ("Not MIT licensed OR MIT", False),
        ("MIT OR OR Apache-2.0", False),
        ("(MIT OR Apache-2.0]", False),
        ("Apache-2.0 WITH unknown-exception", False),
        ("MIT OR GPL-3.0", True),
        ("MIT OR Apache-2.0 AND GPL-3.0", True),
        ("GPL-3.0 AND (MIT OR Apache-2.0)", False),
        ("Apache Software License", True),
        # Official protobuf7.36.2 wheel METADATA and LICENSE were compared;
        # exact artifact URLs/hashes are retained in the provenance ledger.
        ("3-Clause BSD License", True),
        ("3-Clause BSD License WITH unknown-exception", False),
        ("MIT-0", True),
        # A near-miss of an allowed id must not pass by prefix match.
        ("MIT-CMU", False),
        ("MIT License (MIT)", True),
    ],
)
def test_license_expression_fail_closed(
    tmp_path: Path, license_text: str, allowed: bool
) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps([{"Name": "fixture", "Version": "1", "License": license_text}])
    )
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/license_check.py"),
            "--policy",
            str(ROOT / ".github/license-allowlist.txt"),
            "--pip",
            f"fixture={inventory}",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == (0 if allowed else 1), result.stdout + result.stderr


def test_conflicting_same_version_inventory_cannot_hide_denied_license(
    tmp_path: Path,
) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            [
                {"Name": "fixture", "Version": "1", "License": "MIT"},
                {"Name": "fixture", "Version": "1", "License": "Proprietary"},
            ]
        )
    )
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/license_check.py"),
            "--policy",
            str(ROOT / ".github/license-allowlist.txt"),
            "--pip",
            f"fixture={inventory}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr


@pytest.mark.parametrize(
    ("licenses", "expected"),
    [
        (["MIT OR Apache-2.0", "GPL-3.0"], 1),
        (["MIT) OR (MIT", "GPL-3.0"], 2),
        (["MIT OR Apache-2.0", "BSD-3-Clause"], 0),
    ],
)
def test_npm_license_array_keeps_each_expression_conjunctive(
    tmp_path: Path, licenses: list[str], expected: int
) -> None:
    inventory = tmp_path / "npm.json"
    inventory.write_text(json.dumps({"fixture@1": {"licenses": licenses}}))
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/license_check.py"),
            "--policy",
            str(ROOT / ".github/license-allowlist.txt"),
            "--npm",
            f"fixture={inventory}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == expected, result.stdout + result.stderr


@pytest.mark.parametrize(
    ("kind", "body"),
    [
        ("pip", "[]"),
        ("npm", "{}"),
        ("go", ""),
        ("pip", "{}"),
        ("npm", "[]"),
        ("pip", '[{"Name":"","License":"MIT"}]'),
        ("npm", '{"fixture@1":null}'),
        ("go", "missing-fields\n"),
    ],
)
def test_each_inventory_must_have_valid_nonempty_records(
    tmp_path: Path, kind: str, body: str
) -> None:
    good = tmp_path / "good.json"
    good.write_text(json.dumps([{"Name": "present", "Version": "1", "License": "MIT"}]))
    bad = tmp_path / "bad.txt"
    bad.write_text(body)
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/license_check.py"),
            "--policy",
            str(ROOT / ".github/license-allowlist.txt"),
            "--pip",
            f"present={good}",
            f"--{kind}",
            f"missing={bad}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert "missing" in result.stderr


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        # The declared release without scanner metadata takes the declaration.
        ({"Name": "declared-fixture", "Version": "1.0", "License": "UNKNOWN"}, 0),
        ({"Name": "Declared-Fixture", "Version": "1.0", "License": ""}, 0),
        # Another version is not reviewed.
        ({"Name": "declared-fixture", "Version": "1.1", "License": "UNKNOWN"}, 1),
        # A reported license is never replaced, so a denied one still fails.
        ({"Name": "declared-fixture", "Version": "1.0", "License": "GPL-3.0"}, 1),
        # A declaration is classified like any license: a denied one fails.
        ({"Name": "denied-fixture", "Version": "1.0", "License": "UNKNOWN"}, 1),
    ],
)
def test_declared_license_fills_only_missing_metadata(
    tmp_path: Path, row: dict[str, str], expected: int
) -> None:
    policy = tmp_path / "policy.txt"
    policy.write_text(
        (ROOT / ".github/license-allowlist.txt").read_text()
        + "\nDECLARE python declared-fixture 1.0 Apache-2.0\n"
        + "DECLARE python denied-fixture 1.0 GPL-3.0\n"
    )
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps([row]))
    report = tmp_path / "report.json"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/license_check.py"),
            "--policy",
            str(policy),
            "--pip",
            f"fixture={inventory}",
            "--json",
            str(report),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == expected, result.stdout + result.stderr
    if expected == 0:
        (dependency,) = json.loads(report.read_text())["dependencies"]
        assert dependency["spdx"] == "Apache-2.0"
        assert "declared in policy" in dependency["detail"]


def test_malformed_declaration_is_a_policy_error(tmp_path: Path) -> None:
    policy = tmp_path / "policy.txt"
    policy.write_text("ALLOW MIT\nDECLARE python only-a-name\n")
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps([{"Name": "fixture", "Version": "1", "License": "MIT"}])
    )
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/license_check.py"),
            "--policy",
            str(policy),
            "--pip",
            f"fixture={inventory}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert "DECLARE" in result.stderr
