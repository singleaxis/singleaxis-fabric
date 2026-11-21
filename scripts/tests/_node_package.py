# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The packed ``@singleaxis/fabric`` tarball, installed into an application directory
for the Node.js tests of spec 055 §9.4 (unit 055-t14): the tests run the package as a
customer installs it, never the source tree.

``FABRIC_TEST_NODE_TARBALL`` names the tarball (``npm run package:qualified`` writes it);
``FABRIC_TEST_NODE`` the Node binary (default: ``node`` on ``PATH``). The application
directory also holds the exact model clients of ``qualification/node-wire/package.json``
(installed from its lock file) and the client scripts of ``qualification/node-wire/clients``.

The table in the tarball activates capture only on the builds it lists as ``active``
(spec 055 §9.4). Where it does not list this machine's build (a developer's laptop),
the installed copy of the table gains one ``active`` tuple for it, as the source-tree e2e
does (§9.5: tests activate capture through the table); the package's code is unchanged.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
HARNESS = REPO / "qualification" / "node-wire"
SDK = REPO / "sdk" / "typescript"


def node_binary() -> str | None:
    """A Node 24.4+ binary (the first build that publishes the body channels), or None."""
    node = os.environ.get("FABRIC_TEST_NODE") or shutil.which("node")
    if node is None:
        return None
    try:
        version = subprocess.run(  # noqa: S603
            [node, "-p", "process.versions.node"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
    except OSError:
        return None
    parts = [int(p) for p in version.split(".")[:2] if p.isdigit()]
    ok = len(parts) == 2 and (parts[0] > 24 or (parts[0] == 24 and parts[1] >= 4))
    return node if ok else None


def tarball() -> Path | None:
    value = os.environ.get("FABRIC_TEST_NODE_TARBALL")
    return Path(value) if value and Path(value).is_file() else None


def missing() -> str | None:
    """Why the packaged-Node tests cannot run here, or None."""
    if node_binary() is None:
        return "needs Node.js 24.4 or newer (FABRIC_TEST_NODE)"
    if tarball() is None:
        return "needs the packed tarball (FABRIC_TEST_NODE_TARBALL, from npm run package:qualified)"
    if shutil.which("npm") is None:
        return "needs npm"
    return None


def _run(args: list[str], cwd: Path) -> None:
    env = {**os.environ, "npm_config_update_notifier": "false", "npm_config_fund": "false"}
    env.pop("NODE_OPTIONS", None)
    done = subprocess.run(  # noqa: S603
        args, cwd=cwd, env=env, capture_output=True, text=True, timeout=600, check=False
    )
    assert done.returncode == 0, f"{' '.join(args)}\n{done.stdout}\n{done.stderr}"


def runtime_tuple(node: str) -> dict[str, Any]:
    """This machine's Node patch, bundled undici and native prebuild target."""
    code = (
        "const glibc = process.report?.getReport()?.header?.glibcVersionRuntime !== undefined;"
        "const arch = process.arch;"
        "const platform = process.platform === 'darwin' ? `darwin-${arch}` :"
        " `linux-${arch}-${glibc ? 'glibc' : 'musl'}`;"
        "console.log(JSON.stringify({node: process.versions.node,"
        " undici: process.versions.undici, platform}))"
    )
    out = subprocess.run(  # noqa: S603
        [node, "-e", code], capture_output=True, text=True, check=True
    ).stdout
    result: dict[str, Any] = json.loads(out)
    return result


def install_app(directory: Path) -> Path:
    """An application directory with the tarball and the pinned model clients installed.
    Returns the installed package's root."""
    node = node_binary()
    package = tarball()
    assert node is not None and package is not None
    directory.mkdir(parents=True, exist_ok=True)
    for name in ("package.json", "package-lock.json"):
        shutil.copy(HARNESS / name, directory / name)
    for script in (HARNESS / "clients").iterdir():
        shutil.copy(script, directory / script.name)
    npm = shutil.which("npm") or "npm"
    _run([npm, "ci", "--ignore-scripts", "--no-audit"], directory)
    _run(
        [npm, "install", "--no-save", "--ignore-scripts", "--no-audit", str(package)],
        directory,
    )
    root = directory / "node_modules" / "@singleaxis" / "fabric"
    assert (root / "package.json").is_file()
    activate_here(root, runtime_tuple(node))
    return root


def activate_here(root: Path, build: dict[str, Any]) -> bool:
    """Adds an ``active`` tuple for ``build`` to the installed table when it lists none.
    Returns whether it did."""
    path = root / "dist" / "wire-qualification.json"
    table: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    listed = any(
        t.get("point") == "wire.ts.undici"
        and t.get("claim") == "active"
        and isinstance(t.get("report_sha256"), str)
        and t.get("node") == build["node"]
        and t.get("platform") == build["platform"]
        and t.get("undici") == build["undici"]
        for t in table["tuples"]
    )
    if listed:
        return False
    table["tuples"].append(
        {
            "point": "wire.ts.undici",
            "node": build["node"],
            "undici": build["undici"],
            "undici_origin": "bundled",
            "platform": build["platform"],
            "boundary": "pre_decompression",
            "claim": "active",
            "report_sha256": "sha256:" + "0" * 64,
        }
    )
    path.write_text(json.dumps(table, indent=2) + "\n", encoding="utf-8")
    return True
