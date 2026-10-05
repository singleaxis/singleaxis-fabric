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
        ("MIT-0", False),
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
