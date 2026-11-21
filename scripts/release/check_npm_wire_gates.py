# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 055 §9.4: an npm tarball that exports the zero-code preload
(``@singleaxis/fabric/register``) may be published only once the qualification gates the
preload depends on have passed: ``TS-1U`` (``wire.ts.undici``) and ``TS-1D`` (protection,
spool, sender and readback), in the tarball's own ``dist/wire-qualification.json``. Until
unit 055-t17 flips them, no tarball with the preload can reach npm.

    python scripts/release/check_npm_wire_gates.py --tarball qualification/npm/x.tgz

Exits 1 with the cause and the fix when the tarball would be refused."""

from __future__ import annotations

import argparse
import json
import sys
import tarfile
from pathlib import Path
from typing import Any

REQUIRED_GATES = ("TS-1U", "TS-1D")
PRELOAD_EXPORT = "./register"
TABLE = "package/dist/wire-qualification.json"


def _member(archive: tarfile.TarFile, name: str) -> Any:
    try:
        handle = archive.extractfile(name)
    except KeyError:
        return None
    if handle is None:
        return None
    with handle:
        return json.loads(handle.read().decode("utf-8"))


def problems(tarball: Path) -> list[str]:
    """Why ``tarball`` may not be published (empty when it may)."""
    with tarfile.open(tarball, "r:gz") as archive:
        manifest = _member(archive, "package/package.json")
        table = _member(archive, TABLE)
    if not isinstance(manifest, dict):
        return [f"{tarball.name} has no package/package.json"]
    exports = manifest.get("exports")
    if not isinstance(exports, dict) or PRELOAD_EXPORT not in exports:
        return []
    if not isinstance(table, dict) or not isinstance(table.get("gates"), dict):
        return [
            (
                f"{tarball.name} exports {PRELOAD_EXPORT} but carries no {TABLE} with "
                "gates: build it with `npm run build` so the qualification table ships "
                "beside the wire core"
            )
        ]
    out = []
    for gate in REQUIRED_GATES:
        state = table["gates"].get(gate)
        if state != "passed":
            out.append(
                f"{tarball.name} exports @singleaxis/fabric/register while qualification "
                f"gate {gate} is {state!r}, so an unqualified capture build would reach "
                "npm. Fix: publish only after the gates pass (spec 055 unit 055-t17 flips "
                "them in sdk/typescript/wire-qualification.json), or remove the "
                "./register export from sdk/typescript/package.json for this release"
            )
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tarball", type=Path, required=True)
    args = parser.parse_args(argv)
    found = problems(args.tarball)
    for problem in found:
        print(f"npm release refused: {problem}", file=sys.stderr)
    if not found:
        print(
            f"{args.tarball.name}: the preload's qualification gates allow publication"
        )
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
