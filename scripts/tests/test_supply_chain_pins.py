# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Supply-chain pins stay pinned (OpenSSF Scorecard Pinned-Dependencies).

* every workflow and composite-action ``uses:`` names a full 40-hex commit SHA
  with a ``# vX.Y.Z`` comment (local ``./`` actions excepted; ``docker://``
  references need a ``@sha256:`` digest);
* job containers and service images are pinned by digest;
* CI and the license scripts never ``pip install`` on the job interpreter
  without hash checking, never fetch a tool with ``npx``, never ``npm install``
  outside a lockfile and never pipe a download into an interpreter;
* Dependabot covers every live manifest directory, and only live ones;
* the license-scan project scans exactly the S3 peer range the SDK declares.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
from pathlib import Path, PurePosixPath

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github/workflows").glob("*.y*ml"))
ACTIONS = sorted((ROOT / ".github/actions").glob("*/action.y*ml"))
SCRIPTS = [
    ROOT / "scripts/license_scan.sh",
    *sorted((ROOT / "scripts/ci").glob("*.sh")),
]

USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>\S+)(?P<rest>.*)$")
PINNED = re.compile(r"^[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"^\s+# v\d+\.\d+\.\d+$")


def _uses_lines() -> list[tuple[str, int, str, str]]:
    found = []
    for path in [*WORKFLOWS, *ACTIONS]:
        for number, line in enumerate(path.read_text().splitlines(), 1):
            match = USES.match(line)
            if match:
                found.append(
                    (str(path.relative_to(ROOT)), number, match["ref"], match["rest"])
                )
    return found


def test_workflows_and_actions_exist() -> None:
    assert WORKFLOWS
    assert len(_uses_lines()) > 50


def test_every_uses_is_pinned_to_a_commit_sha_with_a_version_comment() -> None:
    unpinned = []
    for where, number, ref, rest in _uses_lines():
        if ref.startswith("./"):
            continue
        if ref.startswith("docker://"):
            ok = "@sha256:" in ref
        else:
            ok = bool(PINNED.match(ref)) and bool(VERSION_COMMENT.match(rest))
        if not ok:
            unpinned.append(f"{where}:{number}: {ref}{rest}")
    assert not unpinned, "unpinned or uncommented uses:\n" + "\n".join(unpinned)


def test_job_containers_and_services_are_pinned_by_digest() -> None:
    unpinned = []
    for path in WORKFLOWS:
        jobs = yaml.safe_load(path.read_text()).get("jobs", {})
        for job_id, job in jobs.items():
            images = []
            container = job.get("container")
            if container is not None:
                images.append(
                    container if isinstance(container, str) else container["image"]
                )
            images += [s["image"] for s in (job.get("services") or {}).values()]
            unpinned += [
                f"{path.name}:{job_id}: {image}"
                for image in images
                if "@sha256:" not in image
            ]
    assert not unpinned, unpinned


def _commands(text: str) -> list[list[str]]:
    """Shell commands of a script, continuation lines joined, comments dropped."""
    joined = re.sub(r"\\\n\s*", " ", text)
    commands = []
    for line in joined.splitlines():
        if line.lstrip().startswith("#"):
            continue
        for part in re.split(r"&&|\|\||;|\|", line):
            try:
                tokens = shlex.split(part, comments=True)
            except ValueError:
                tokens = part.split()
            # Drop leading VAR=value assignments (FABRIC_PYTHON=... cmd).
            while tokens and re.match(r"^[A-Z_][A-Z0-9_]*=", tokens[0]):
                tokens.pop(0)
            if tokens:
                commands.append(tokens)
    return commands


def _scripts() -> list[tuple[str, str]]:
    found = [(str(p.relative_to(ROOT)), p.read_text()) for p in SCRIPTS]
    for path in [*WORKFLOWS, *ACTIONS]:
        document = yaml.safe_load(path.read_text())
        jobs = document.get("jobs") or {"composite": document.get("runs", {})}
        for job_id, job in jobs.items():
            for index, step in enumerate(job.get("steps") or []):
                if "run" in step:
                    found.append((f"{path.name}:{job_id}[{index}]", step["run"]))
    return found


def _pip_install(tokens: list[str]) -> bool:
    # Bare interpreter only: a "${RUNNER_TEMP}/...-venv/bin/python" is a
    # throwaway customer-style install of the built wheel, not a CI tool.
    if tokens[:4] in (
        ["python", "-m", "pip", "install"],
        ["python3", "-m", "pip", "install"],
    ):
        return True
    return tokens[:2] in (["pip", "install"], ["pip3", "install"])


def test_ci_never_installs_python_packages_without_hash_checking() -> None:
    offending = []
    for where, script in _scripts():
        for tokens in _commands(script):
            if not _pip_install(tokens):
                continue
            hashed = "--require-hashes" in tokens
            # The SDK's own checkout, after its locked dependencies.
            local_project = "--no-deps" in tokens and any(
                t.startswith(("./sdk/python", "sdk/python", ".")) and "[" not in t
                for t in tokens[tokens.index("install") + 1 :]
                if not t.startswith("-")
            )
            if not (hashed or local_project):
                offending.append(f"{where}: {' '.join(tokens)}")
    assert not offending, "\n".join(offending)


def test_ci_never_fetches_unpinned_tools_or_pipes_downloads_to_a_shell() -> None:
    offending = []
    for where, script in _scripts():
        for tokens in _commands(script):
            if tokens[0] == "npx" or tokens[:2] in (["npm", "exec"], ["npm", "x"]):
                offending.append(f"{where}: {' '.join(tokens)}")
            if tokens[:2] in (["npm", "install"], ["npm", "i"]):
                offending.append(f"{where}: {' '.join(tokens)}")
        flat = re.sub(r"\\\n\s*", " ", script)
        for line in flat.splitlines():
            if re.search(
                r"\b(curl|wget)\b[^|#]*\|\s*(sudo\s+)?(ba|z)?sh\b", line
            ) or re.search(r"\b(curl|wget)\b[^|#]*\|\s*python3?\b", line):
                offending.append(f"{where}: {line.strip()}")
    assert not offending, "\n".join(offending)


ECOSYSTEM_MANIFESTS = {
    "gomod": ("go.mod",),
    "npm": ("package-lock.json",),
    "uv": ("uv.lock",),
    "docker": ("Dockerfile",),
}


def _tracked(name: str) -> set[str]:
    """Directories holding a tracked file of this name, as Dependabot spells them."""
    listed = subprocess.run(
        ["git", "ls-files", "-z", f"*{name}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split("\0")
    directories = set()
    for entry in filter(None, listed):
        path = PurePosixPath(entry)
        if path.name != name or {"testdata", "fixtures"} & set(path.parts):
            continue
        parent = path.parent.as_posix()
        directories.add("/" if parent == "." else "/" + parent)
    return directories


def _dependabot() -> dict[str, set[str]]:
    config = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    covered: dict[str, set[str]] = {}
    for entry in config["updates"]:
        directories = entry.get("directories") or [entry["directory"]]
        covered.setdefault(entry["package-ecosystem"], set()).update(directories)
    return covered


@pytest.mark.parametrize("ecosystem", sorted(ECOSYSTEM_MANIFESTS))
def test_dependabot_covers_every_live_manifest_directory(ecosystem: str) -> None:
    covered = _dependabot().get(ecosystem, set())
    present = set().union(*(_tracked(n) for n in ECOSYSTEM_MANIFESTS[ecosystem]))
    assert present <= covered, (
        f"{ecosystem}: not in dependabot.yml: {present - covered}"
    )


def test_dependabot_names_only_live_directories() -> None:
    stale = []
    for ecosystem, directories in _dependabot().items():
        for directory in directories:
            relative = directory.lstrip("/")
            matches = list(ROOT.glob(relative)) if relative else [ROOT]
            if not matches or not all(m.is_dir() for m in matches):
                stale.append(f"{ecosystem}: {directory}")
    assert not stale, stale


def test_dependabot_covers_composite_actions_and_compose() -> None:
    covered = _dependabot()
    assert {"/", "/.github/actions/*"} <= covered["github-actions"]
    assert "/deploy/compose" in covered["docker-compose"]


def test_dependabot_moves_lockstep_dependencies_together() -> None:
    # codeql-action refuses mixed versions across init/autobuild/analyze, and
    # the Collector modules are built together by OCB, so each family must
    # arrive as one grouped PR. Every entry keeps a version-update cooldown.
    config = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    entries = {entry["package-ecosystem"]: entry for entry in config["updates"]}
    actions = entries["github-actions"]["groups"]["codeql-action"]["patterns"]
    assert "github/codeql-action*" in actions
    go = entries["gomod"]
    assert (
        "go.opentelemetry.io/collector*" in go["groups"]["otel-collector"]["patterns"]
    )
    live_go = set().union(*(_tracked(n) for n in ECOSYSTEM_MANIFESTS["gomod"]))
    assert live_go <= set(go["directories"])
    assert all(entry["cooldown"]["default-days"] >= 3 for entry in config["updates"])


def test_typescript_sdk_holds_never_block_security_updates() -> None:
    # The TypeScript SDK's version-update holds: the OpenTelemetry API stays
    # inside the published peer range, context-async-hooks stays with
    # sdk-trace-node's pin, and @types/node tracks the engines floor. For
    # security updates Dependabot applies only an ignore rule's `versions`,
    # so update-types-only rules hold version updates without blocking a
    # security fix.
    config = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    (entry,) = [
        e
        for e in config["updates"]
        if e["package-ecosystem"] == "npm" and e.get("directory") == "/sdk/typescript"
    ]
    rules = {rule["dependency-name"]: rule for rule in entry["ignore"]}
    assert set(rules) == {
        "@opentelemetry/api",
        "@opentelemetry/context-async-hooks",
        "@types/node",
        "typescript",
    }
    assert all(
        set(rule) == {"dependency-name", "update-types"} for rule in rules.values()
    )
    major = "version-update:semver-major"
    minor = "version-update:semver-minor"
    assert set(rules["@opentelemetry/api"]["update-types"]) == {minor, major}
    assert rules["@opentelemetry/context-async-hooks"]["update-types"] == [major]
    assert rules["@types/node"]["update-types"] == [major]
    # typescript-eslint and tsup's dts build do not support TypeScript 7.
    assert rules["typescript"]["update-types"] == [major]

    package = json.loads((ROOT / "sdk/typescript/package.json").read_text())
    dev = package["devDependencies"]
    # A minor hold on the API is only right while every minor of the peer
    # range is tested: the unit suite on the floor (the devDependency) and
    # the README fresh-install sets (scripts/fresh-install.mjs, run in CI)
    # on every minor above it, so a widened range never ships untested.
    peer = package["peerDependencies"]["@opentelemetry/api"]
    span = re.fullmatch(r">=(\d+)\.(\d+)\.0 <(\d+)\.(\d+)\.0", peer)
    assert span, peer
    major_v, minor_v, upper_major, upper_minor = map(int, span.groups())
    assert upper_major == major_v and upper_minor > minor_v, peer
    assert dev["@opentelemetry/api"].startswith(f"{major_v}.{minor_v}.")
    readme = (ROOT / "sdk/typescript/README.md").read_text()
    installs = re.findall(
        r"<!-- fresh-install: install [^>]+ -->\n+```bash\n(npm install [^\n]+)\n```", readme
    )
    tested = {
        tuple(map(int, pin.split(".")[:2]))
        for line in installs
        for pin in re.findall(r"@opentelemetry/api@(\d+\.\d+\.\d+)", line)
    }
    assert tested == {(major_v, m) for m in range(minor_v, upper_minor)}, (peer, tested)
    workflow = (ROOT / ".github/workflows/recorder-ci.yml").read_text()
    assert "npm run test:fresh-install" in workflow
    floor = re.fullmatch(r">=(\d+)\.\d+\.\d+", package["engines"]["node"])
    assert floor, package["engines"]["node"]
    assert dev["@types/node"].split(".")[0] == floor.group(1)


def test_license_scan_project_tracks_the_sdk_peer_range() -> None:
    sdk = json.loads((ROOT / "sdk/typescript/package.json").read_text())
    scan_dir = ROOT / "scripts/license/s3-peer"
    scan = json.loads((scan_dir / "package.json").read_text())
    peer = "@aws-sdk/client-s3"
    assert scan["private"] is True
    assert scan["dependencies"] == {peer: sdk["peerDependencies"][peer]}
    lock = json.loads((scan_dir / "package-lock.json").read_text())
    assert lock["packages"][""]["dependencies"] == scan["dependencies"]
    checker = scan["devDependencies"]["license-checker-rseidelsohn"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", checker), "the scanner is an exact pin"
