# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Runs a pytest-driven gate of spec 055 §9.2 and writes its JSON report (unit 055-t17).

The parity, negative-row and Fabric Node gates are pytest modules; their CI jobs run them
through this wrapper so each job, like the passivity and privacy jobs, uploads one JSON
report naming the exact build it ran on, and the reports of the claimed tuples can be
committed under ``qualification/node-wire/results/``:

    python qualification/node-wire/report.py --gate parity --node "$(command -v node)" \\
        --out parity-24.4.0-linux-x64-glibc.json -- scripts/tests/test_node_wire_capture_e2e.py

A report (``fabric.node-wire-gate-report/v1``) names the gate, the tuple (Node patch,
bundled undici, platform), the source commit, every test with its outcome, and
``result``: ``passed`` only when at least one test ran and none failed, errored or was
skipped. Exits with pytest's code (2 when pytest passed but the report says otherwise).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET  # noqa: S405 - pytest's own junit output
from pathlib import Path
from typing import Any


def runtime_tuple(node: str) -> dict[str, str]:
    code = (
        "const glibc = process.report?.getReport()?.header?.glibcVersionRuntime !== undefined;"
        "const p = process.platform === 'darwin' ? `darwin-${process.arch}` :"
        " `linux-${process.arch}-${glibc ? 'glibc' : 'musl'}`;"
        "console.log(JSON.stringify({node: process.versions.node,"
        " undici: process.versions.undici, platform: p}))"
    )
    out = subprocess.run(  # noqa: S603
        [node, "-e", code], capture_output=True, text=True, check=True
    ).stdout
    result: dict[str, str] = json.loads(out)
    return result


def outcomes(junit: Path) -> list[dict[str, Any]]:
    tests = []
    for case in ET.parse(junit).getroot().iter("testcase"):  # noqa: S314
        outcome = "passed"
        for child in case:
            if child.tag in ("failure", "error"):
                outcome = "failed" if child.tag == "failure" else "error"
            elif child.tag == "skipped":
                outcome = "skipped"
        tests.append(
            {
                "test": f"{case.get('classname', '')}::{case.get('name', '')}",
                "outcome": outcome,
                "seconds": round(float(case.get("time", "0")), 3),
            }
        )
    return tests


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--gate", required=True)
    parser.add_argument("--node", required=True, help="the Node binary the gate ran on")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    extra = [a for a in args.pytest_args if a != "--"]
    with tempfile.TemporaryDirectory(prefix="f055-t17-report-") as scratch:
        junit = Path(scratch) / "junit.xml"
        done = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "pytest", "-v", f"--junitxml={junit}", *extra],
            check=False,
        )
        tests = outcomes(junit) if junit.exists() else []
    passed = bool(tests) and all(t["outcome"] == "passed" for t in tests)
    report = {
        "schema": "fabric.node-wire-gate-report/v1",
        "gate": args.gate,
        "tuple": runtime_tuple(args.node),
        "source_sha": os.environ.get("FABRIC_SOURCE_SHA", "unknown"),
        "tests": tests,
        "result": "passed" if passed else "failed",
    }
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", "utf-8")
    if done.returncode != 0:
        return done.returncode
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
