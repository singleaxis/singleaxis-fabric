# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Fixtures for the Node.js branch of ``fabric run`` (spec 055 §13.1): an installed
``@singleaxis/fabric`` with a chosen qualification table, and a Node binary probe that
answers a chosen build without starting Node."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

#: A build the tables below qualify, and the platform they qualify it on.
BUILD = {"node": "24.22.3", "undici": "7.30.2", "platform": "linux-x64-glibc"}
REPORT = "sha256:" + "ab" * 32


def tuple_for(build: dict[str, Any], claim: str = "active") -> dict[str, Any]:
    return {
        "point": "wire.ts.undici",
        "node": build["node"],
        "undici": build["undici"],
        "undici_origin": "bundled",
        "platform": build["platform"],
        "boundary": "pre_decompression",
        "claim": claim,
        **({"report_sha256": REPORT} if claim == "active" else {}),
    }


def table(
    tuples: list[dict[str, Any]] | None = None,
    gates: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "fabric.wire-qualification/v1",
        "gates": gates or {"TS-1U": "passed", "TS-1D": "passed", "TS-1H": "not_passed"},
        "tuples": [tuple_for(BUILD)] if tuples is None else tuples,
    }


def install_package(
    project: Path,
    qualification: dict[str, Any] | None = None,
    *,
    register: bool = True,
    version: str = "0.13.0",
) -> Path:
    """``node_modules/@singleaxis/fabric`` in ``project`` with the package's exports, an
    inert preload (so a real Node resolves ``--import=@singleaxis/fabric/register``) and
    the table. Returns the package directory."""
    root = project / "node_modules" / "@singleaxis" / "fabric"
    (root / "dist").mkdir(parents=True, exist_ok=True)
    exports: dict[str, Any] = {".": {"import": "./dist/index.js"}}
    if register:
        exports["./register"] = {"import": "./dist/register.js", "require": "./dist/register.cjs"}
        (root / "dist" / "register.js").write_text("// inert test preload\n")
        (root / "dist" / "register.cjs").write_text("// inert test preload\n")
    if qualification is not None:
        exports["./wire-qualification.json"] = "./dist/wire-qualification.json"
        (root / "dist" / "wire-qualification.json").write_text(json.dumps(qualification))
    manifest = {"name": "@singleaxis/fabric", "version": version, "exports": exports}
    (root / "package.json").write_text(json.dumps(manifest))
    return root


class NodeProbe:
    """A ``subprocess.run`` stand-in that answers the Node probe with ``build`` and
    counts the calls (``fail``: Node exits with an error)."""

    def __init__(self, build: dict[str, Any] | None = None, *, fail: bool = False) -> None:
        self.build = build if build is not None else dict(BUILD)
        self.fail = fail
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        if self.fail:
            return subprocess.CompletedProcess(argv, 1, "", "boom")
        answer = {"kind": "node", **self.build}
        return subprocess.CompletedProcess(argv, 0, json.dumps(answer) + "\n", "")


def fake_node(directory: Path) -> Path:
    """An executable named ``node`` (never started: the probe is a ``NodeProbe``)."""
    directory.mkdir(parents=True, exist_ok=True)
    node = directory / "node"
    node.write_text("#!/bin/sh\nexit 1\n")
    node.chmod(0o755)
    return node
