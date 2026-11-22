# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The zero-code Node.js path of ``fabric run`` (spec 055 §13.1, spec 058 §5.5 step 3).

``fabric run`` appends ``--import=@singleaxis/fabric/register`` to ``NODE_OPTIONS`` and sets
``FABRIC_WIRE_AUTOLOAD=1`` only when all three hold:

1. the command's runtime is Node.js;
2. ``@singleaxis/fabric/wire-qualification.json`` resolves from the agent's working
   directory (the way Node resolves the preload: ``node_modules`` up the directory tree),
   with ``gates.TS-1U`` and ``gates.TS-1D`` both ``passed`` and a ``./register`` export;
3. the Node.js build (its version, bundled undici and platform) is an ``active`` tuple of
   ``wire.ts.undici`` in that table, as the SDK's own manifest decides it.

Otherwise nothing changes and the reason is a catalogue finding with its fix. This module
reads files and asks the Node binary its version once (cached by path and modification
time, like the Python interpreter probe); it never runs the agent's code."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import _runstate
from ._report import Finding

PACKAGE = "@singleaxis/fabric"
PRELOAD = f"--import={PACKAGE}/register"
INSTALL_LINE = f"npm i {PACKAGE}"
UPGRADE_LINE = f"npm i {PACKAGE}@latest"
POINT = "wire.ts.undici"
GATES = ("TS-1U", "TS-1D")
PROBE_TIMEOUT_S = 15.0
#: What the Node probe runs: the version, the bundled undici and the platform as the SDK
#: names its native prebuild target (``linux-x64-glibc``, ``darwin-arm64``). Nothing of
#: the agent's project is loaded (``-e`` with ``NODE_OPTIONS`` cleared).
_PROBE = (
    "const r=process.report;let g=true;"
    "if(process.platform==='linux'&&r&&typeof r.getReport==='function'){"
    "r.excludeNetwork=true;const h=r.getReport().header||{};"
    "g=typeof h.glibcVersionRuntime==='string';}"
    "const a=process.arch,p=process.platform;"
    "const t=p==='darwin'?`darwin-${a}`:p==='linux'?`linux-${a}-${g?'glibc':'musl'}`:`${p}-${a}`;"
    "console.log(JSON.stringify({kind:'node',node:process.versions.node,"
    "undici:process.versions.undici??null,platform:t}))"
)
#: Every spelling of the preload a ``NODE_OPTIONS`` may already hold.
_PRELOAD_FLAGS = ("--import", "--require", "-r")


@dataclass(frozen=True)
class Decision:
    """The outcome of the three conditions: ``preload`` when all hold, else ``finding``."""

    preload: bool
    finding: Finding | None = None
    build: dict[str, Any] | None = None


def probe(
    node: Path, state_dir: Path | None, runner: Callable[..., Any] = subprocess.run
) -> dict[str, Any]:
    """Ask ``node`` its version, bundled undici and platform; cached by path and mtime."""
    cached = _runstate.cached_probe(state_dir, node)
    if cached is not None and cached.get("kind") == "node":
        return cached
    env = {k: v for k, v in os.environ.items() if not k.startswith("NODE_")}
    try:
        result = runner(
            [str(node), "-e", _PROBE],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_S,
            check=False,
            stdin=subprocess.DEVNULL,
            env=env,
        )
        answer = (
            json.loads(result.stdout.strip().splitlines()[-1]) if result.returncode == 0 else {}
        )
    except subprocess.TimeoutExpired:
        return {"kind": "node", "error": f"did not answer in {PROBE_TIMEOUT_S:g} s"}
    except (OSError, ValueError, IndexError):
        return {"kind": "node", "error": "could not be started"}
    if not isinstance(answer, dict) or not isinstance(answer.get("node"), str):
        return {"kind": "node", "error": "did not say its version"}
    clean = {
        "kind": "node",
        "node": answer["node"],
        "undici": answer.get("undici") if isinstance(answer.get("undici"), str) else None,
        "platform": str(answer.get("platform") or ""),
    }
    _runstate.store_probe(state_dir, node, clean)
    return clean


def find_package(cwd: Path) -> Path | None:
    """The ``@singleaxis/fabric`` directory Node would resolve from ``cwd``: the first
    ``node_modules/@singleaxis/fabric/package.json`` up the directory tree."""
    for directory in (cwd, *cwd.parents):
        candidate = directory / "node_modules" / "@singleaxis" / "fabric"
        if (candidate / "package.json").is_file():
            return candidate
    return None


def _export_target(entry: Any) -> str | None:
    """A conditional export's file (``import`` first, then ``default``, ``require``)."""
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        for condition in ("import", "default", "require", "node"):
            if condition in entry:
                found = _export_target(entry[condition])
                if found is not None:
                    return found
    return None


#: The conditions Node matches when it resolves ``--import`` (an ESM import), in the
#: order of the export object's own keys.
_IMPORT_CONDITIONS = frozenset({"node", "import", "module-sync", "default"})


def _import_target(entry: Any) -> str | None:
    """The file Node's ESM resolver picks from a conditional export: the first key of the
    object (in its own order) that is an import condition and resolves."""
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        for condition, value in entry.items():
            if condition in _IMPORT_CONDITIONS:
                found = _import_target(value)
                if found is not None:
                    return found
    return None


def _inside(package: Path, target: str) -> Path | None:
    """``target`` (a ``./`` export path) as a file inside ``package``, else ``None``."""
    path = (package / target).resolve()
    return path if package.resolve() in path.parents and path.is_file() else None


def load_table(package: Path) -> tuple[dict[str, Any] | None, str | None]:  # noqa: PLR0911 - one return per reason
    """The package's qualification table through its ``exports`` (``None`` and why when
    the package has no preload or no table)."""
    try:
        manifest = json.loads((package / "package.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None, "its package.json cannot be read"
    exports = manifest.get("exports") if isinstance(manifest, dict) else None
    version = manifest.get("version") if isinstance(manifest, dict) else None
    named = f"{PACKAGE} {version}" if isinstance(version, str) else PACKAGE
    if not isinstance(exports, dict) or "./register" not in exports:
        return None, f"{named} has no zero-code preload (./register)"
    # A preload Node cannot load stops the agent before its first line (ERR_MODULE_NOT_FOUND),
    # so a partial or damaged install never gets the --import entry (I3).
    preload = _import_target(exports.get("./register"))
    if preload is None or _inside(package, preload) is None:
        return None, f"{named}: its zero-code preload file is missing (a partial install)"
    target = _export_target(exports.get("./wire-qualification.json"))
    if target is None:
        return None, f"{named} has no qualification table"
    path = (package / target).resolve()
    if package.resolve() not in path.parents:
        return None, f"{named} names a qualification table outside the package"
    try:
        table = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None, f"{named}: its qualification table cannot be read"
    if not isinstance(table, dict) or not isinstance(table.get("tuples"), list):
        return None, f"{named}: its qualification table is malformed"
    gates: dict[str, Any] = table["gates"] if isinstance(table.get("gates"), dict) else {}
    unpassed = [gate for gate in GATES if gates.get(gate) != "passed"]
    if unpassed:
        return None, f"{named}: gates {', '.join(unpassed)} not passed"
    return table, None


def active_tuples(table: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The ``active`` tuples of ``wire.ts.undici`` with a report (what the SDK activates)."""
    return [
        t
        for t in table.get("tuples", [])
        if isinstance(t, dict)
        and t.get("point") == POINT
        and t.get("claim") == "active"
        and isinstance(t.get("report_sha256"), str)
    ]


def listed(tuples: list[dict[str, Any]], platform: str | None = None) -> str:
    """The qualified builds, for a finding's detail: ``24.4.0, 24.22.3 on linux-x64-glibc``."""
    by_platform: dict[str, list[str]] = {}
    for t in tuples:
        if platform is None or t.get("platform") == platform:
            by_platform.setdefault(str(t.get("platform")), []).append(str(t.get("node")))
    return "; ".join(f"Node {', '.join(v)} on {p}" for p, v in sorted(by_platform.items()))


def package_decision(cwd: Path) -> tuple[dict[str, Any] | None, Finding | None]:
    """Condition 2: the table of the package that resolves from ``cwd``, else the finding."""
    package = find_package(cwd)
    if package is None:
        return None, Finding("FC-098", f"not found from {cwd}; install with: {INSTALL_LINE}")
    table, why = load_table(package)
    if table is None:
        return None, Finding("FC-099", f"{why}; upgrade with: {UPGRADE_LINE}")
    if not active_tuples(table):
        why = "its table claims no Node.js build"
        return None, Finding("FC-099", f"{why}; upgrade with: {UPGRADE_LINE}")
    return table, None


def build_decision(table: Mapping[str, Any], build: Mapping[str, Any]) -> Finding | None:
    """Condition 3: this Node build is an ``active`` tuple, else the finding."""
    tuples = active_tuples(table)
    if build.get("error"):
        return Finding("FC-100", f"node {build['error']}; qualified: {listed(tuples)}")
    platform = str(build.get("platform") or "")
    here = [t for t in tuples if t.get("platform") == platform]
    if not here:
        return Finding("FC-101", f"{platform or 'this platform'}; qualified: {listed(tuples)}")
    for t in here:
        # As the SDK's ``activeTuple``: the bundled undici must equal the tuple's, and a
        # tuple without one never matches a Node that reports one.
        if t.get("node") == build.get("node") and t.get("undici") == build.get("undici"):
            return None
    return Finding(
        "FC-100", f"Node {build.get('node')} on {platform}; qualified: {listed(tuples, platform)}"
    )


def decide(
    node: Path | None,
    cwd: Path,
    state_dir: Path | None,
    runner: Callable[..., Any] = subprocess.run,
) -> Decision:
    """The three conditions of spec 055 §13.1, in order (the runtime is already Node;
    ``node`` is the binary the command starts, ``None`` when it is not found)."""
    table, finding = package_decision(cwd)
    if table is None:
        return Decision(False, finding)
    if node is None:
        tuples = active_tuples(table)
        return Decision(False, Finding("FC-100", f"node not found; qualified: {listed(tuples)}"))
    build = probe(node, state_dir, runner)
    finding = build_decision(table, build)
    return Decision(finding is None, finding, build)


def has_preload(node_options: str) -> bool:
    """Whether ``NODE_OPTIONS`` already loads Fabric's preload (any spelling)."""
    try:
        words = shlex.split(node_options)
    except ValueError:
        words = node_options.split()
    target = f"{PACKAGE}/register"
    for index, word in enumerate(words):
        flag, _, value = word.partition("=")
        if flag in _PRELOAD_FLAGS and value == target:
            return True
        if word in _PRELOAD_FLAGS and index + 1 < len(words) and words[index + 1] == target:
            return True
    return False


def append_preload(node_options: str | None) -> str:
    """``NODE_OPTIONS`` with the preload appended, never replaced (I2); unchanged when it
    already loads the preload."""
    existing = node_options or ""
    if has_preload(existing):
        return existing
    return f"{existing} {PRELOAD}" if existing.strip() else PRELOAD
