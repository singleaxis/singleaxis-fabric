# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Run bounded C0-C10 fixture checks and retain exact commands and test artifacts.

No live model, cloud service or production authorization is exercised. A passing
fixture never promotes a whole capture level or a production verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "qualification/capture-level-matrix.json"


def fixture_status(returncode: int, junit: Path) -> tuple[str, int]:
    """Refuse to credit skipped, missing, malformed or failed test evidence."""
    if returncode != 0:
        return "FAILED", 0
    try:
        cases = list(ET.parse(junit).getroot().iter("testcase"))
    except (OSError, ET.ParseError):
        return "UNVERIFIED", 0
    if not cases:
        return "UNVERIFIED", 0
    if any(
        case.find("failure") is not None or case.find("error") is not None
        for case in cases
    ):
        return "FAILED", len(cases)
    if any(case.find("skipped") is not None for case in cases):
        return "UNVERIFIED", len(cases)
    return "LOCAL_FIXTURE_PASSED", len(cases)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument(
        "--python", default=sys.executable, help="SDK development environment Python"
    )
    parser.add_argument(
        "--timeout", type=int, default=180, help="Per-level timeout in seconds"
    )
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("timeout must be positive")
    output = args.evidence_dir.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(output, 0o700)
    matrix = json.loads(MATRIX.read_text())
    report = {
        "schema_version": "fabric.capture-acceptance-run/v1",
        "production_verdict": "NO_GO",
        "scope": "Selected local fixture assertions only; unimplemented target scenarios remain explicit",
        "matrix_sha256": hashlib.sha256(MATRIX.read_bytes()).hexdigest(),
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "scenarios": [],
    }
    unsuccessful = False
    for scenario in matrix["scenarios"]:
        row = dict(scenario)
        nodes = scenario["acceptance"]["pytest_nodes"]
        directory = output / scenario["level"]
        directory.mkdir(mode=0o700)
        if not nodes:
            row.update(status="NOT_IMPLEMENTED", observed_result=None)
        else:
            junit = directory / "junit.xml"
            command = [
                args.python,
                "-m",
                "pytest",
                "-q",
                "--no-cov",
                "-o",
                "addopts=",
                "-o",
                f"cache_dir={directory / 'cache'}",
                f"--basetemp={directory / 'fixtures'}",
                f"--junitxml={junit}",
                *nodes,
            ]
            row["command"] = command
            row["source_hashes"] = {
                node.split("::", 1)[0]: hashlib.sha256(
                    (ROOT / node.split("::", 1)[0]).read_bytes()
                ).hexdigest()
                for node in nodes
            }
            started = time.monotonic()
            with (directory / "command.log").open("wb") as log:
                try:
                    completed = subprocess.run(
                        command,
                        cwd=ROOT,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        timeout=args.timeout,
                        check=False,
                    )
                    code = completed.returncode
                    status, count = fixture_status(code, junit)
                except subprocess.TimeoutExpired:
                    code, status, count = None, "TIMED_OUT", 0
                except OSError:
                    code, status, count = None, "UNEXECUTED", 0
            row.update(
                status=status,
                observed_result={
                    "exit_code": code,
                    "test_cases": count,
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "scope": scenario["acceptance"]["tested_claim"],
                },
            )
            row["evidence"] = [
                {
                    "path": str(path.relative_to(output)),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
                for path in (directory / "command.log", junit)
                if path.is_file()
            ]
            unsuccessful |= status != "LOCAL_FIXTURE_PASSED"
        report["scenarios"].append(row)
        (output / "capture-matrix.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"{row['level']}: {row['status']}", flush=True)
    print(
        json.dumps(
            {
                "report": str(output / "capture-matrix.json"),
                "production_verdict": "NO_GO",
            }
        )
    )
    return 1 if unsuccessful else 0


if __name__ == "__main__":
    raise SystemExit(main())
