#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Prove exact historical exceptions do not allow a credential in a new commit."""

from __future__ import annotations

import json
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    scanner = shutil.which("gitleaks")
    if scanner is None:
        raise SystemExit("gitleaks is required; this gate was not run")
    baseline = (root / ".gitleaksignore").read_text()
    with tempfile.TemporaryDirectory(prefix="fabric-secret-baseline-") as directory:
        fixture = Path(directory)
        (fixture / ".gitleaksignore").write_text(baseline)
        # Deliberately fake, never-issued test input. It exists only in this
        # disposable local repository and is never sent to any service.
        marker = "ghp_" + secrets.token_hex(18)
        (fixture / "new-credential.txt").write_text("token = " + marker + "\n")
        for command in (
            ["git", "init", "--quiet"],
            ["git", "add", "."],
            [
                "git",
                "-c",
                "user.name=Fabric fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "synthetic scanner probe",
            ],
        ):
            subprocess.run(command, cwd=fixture, check=True, capture_output=True)
        report = fixture / "redacted-report.json"
        result = subprocess.run(
            [
                scanner,
                "detect",
                "--source",
                str(fixture),
                "--redact",
                "--exit-code",
                "1",
                "--report-format",
                "json",
                "--report-path",
                str(report),
            ],
            cwd=fixture,
            capture_output=True,
        )
        findings = json.loads(report.read_bytes()) if report.exists() else []
        if result.returncode != 1 or not any(
            item.get("File") == "new-credential.txt"
            and item.get("RuleID") == "github-pat"
            for item in findings
        ):
            raise SystemExit(
                json.dumps(
                    {
                        "baseline_probe": "failed",
                        "scanner_exit_code": result.returncode,
                        "finding_rules": [item.get("RuleID") for item in findings],
                    }
                )
            )
        print(
            json.dumps(
                {"historical_baseline_probe": "passed", "new_commit_rejected": True}
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
