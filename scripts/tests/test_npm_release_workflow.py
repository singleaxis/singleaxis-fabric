# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Supply-chain invariants for the build-once TypeScript release path."""

from __future__ import annotations

import io
import json
import re
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
RELEASE = WORKFLOWS / "release.yml"


def _workflow_publishers() -> list[Path]:
    command = re.compile(r"\bnpm\s+publish\b")
    return sorted(
        path
        for pattern in ("*.yml", "*.yaml")
        for path in WORKFLOWS.glob(pattern)
        if command.search(path.read_text(encoding="utf-8"))
    )


def _job(text: str, name: str, next_name: str) -> str:
    start = text.index(f"  {name}:\n")
    end = text.index(f"  {next_name}:\n", start)
    return text[start:end]


def test_release_workflow_is_the_only_npm_publisher() -> None:
    assert _workflow_publishers() == [RELEASE]


def test_publish_job_consumes_qualified_tarball_without_rebuilding() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    publish = _job(text, "publish-npm", "github-release")

    assert "needs: qualify-release" in publish
    assert "name: qualified-typescript-dist" in publish
    assert (
        'npm publish "${package}" --access public --tag "${dist_tag}" --provenance'
        in publish
    )
    assert (
        '*) dist_tag="latest" ;;' in publish
    )  # a stable release is the default install
    assert '*-*) dist_tag="next" ;;' in publish  # a prerelease never becomes latest
    assert "--tag beta" not in text and "dist-tag add" not in text
    assert "sha256sum --check SHA256SUMS.typescript" in publish
    assert "id-token: write" in publish
    assert "NODE_AUTH_TOKEN" not in publish
    assert "actions/checkout" not in publish
    assert "npm ci" not in publish
    assert "npm run build" not in publish
    assert "npm pack" not in publish


def test_package_is_built_once_and_attached_to_github_release() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    qualify = _job(text, "qualify-release", "changelog")
    github_release = text[text.index("  github-release:\n") :]

    assert text.count("npm run package:qualified") == 1
    assert "npm run package:qualified" in qualify
    assert '--expected-version "${VERSION}"' in qualify
    assert "--smoke" in qualify
    assert "name: qualified-typescript-dist" in qualify
    assert "publish-npm," in github_release
    assert "name: qualified-typescript-dist" in github_release


# Spec 055 §9.4 (unit 055-t14): a tarball exporting the zero-code preload is published only
# once gates TS-1U and TS-1D have passed (scripts/release/check_npm_wire_gates.py).

sys.path.insert(0, str(ROOT / "scripts" / "release"))
import check_npm_wire_gates  # noqa: E402

SDK = ROOT / "sdk" / "typescript"


def _tarball(
    tmp_path: Path, exports: dict[str, Any], gates: dict[str, str] | None
) -> Path:
    path = tmp_path / "singleaxis-fabric-1.0.0.tgz"
    with tarfile.open(path, "w:gz") as archive:

        def add(name: str, document: Any) -> None:
            data = json.dumps(document).encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))

        add("package/package.json", {"name": "@singleaxis/fabric", "exports": exports})
        if gates is not None:
            add("package/dist/wire-qualification.json", {"gates": gates, "tuples": []})
    return path


_WIRE_EXPORTS = {".": {}, "./wire": {}, "./register": {}}
_PASSED = {"TS-1U": "passed", "TS-1D": "passed", "TS-1H": "not_passed"}


@pytest.mark.parametrize(
    ("exports", "gates", "refused"),
    [
        (
            _WIRE_EXPORTS,
            {"TS-1U": "not_passed", "TS-1D": "not_passed"},
            ["TS-1U", "TS-1D"],
        ),
        (_WIRE_EXPORTS, {"TS-1U": "passed", "TS-1D": "not_passed"}, ["TS-1D"]),
        (_WIRE_EXPORTS, {"TS-1U": "not_passed", "TS-1D": "passed"}, ["TS-1U"]),
        (_WIRE_EXPORTS, None, ["carries no package/dist/wire-qualification.json"]),
        (_WIRE_EXPORTS, _PASSED, []),  # TS-1H is not required for the undici-only claim
        ({".": {}, "./wire": {}}, {"TS-1U": "not_passed", "TS-1D": "not_passed"}, []),
    ],
    ids=[
        "both-unpassed",
        "ts1d-unpassed",
        "ts1u-unpassed",
        "no-table",
        "passed",
        "no-preload",
    ],
)
def test_release_refuses_a_preload_tarball_with_an_unpassed_gate(
    tmp_path: Path,
    exports: dict[str, Any],
    gates: dict[str, str] | None,
    refused: list[str],
) -> None:
    found = check_npm_wire_gates.problems(_tarball(tmp_path, exports, gates))
    assert len(found) == len(refused), found
    for problem, needle in zip(found, refused, strict=True):
        assert needle in problem, problem
        assert "Fix:" in problem or "build it with" in problem, problem
    assert check_npm_wire_gates.main(
        ["--tarball", str(_tarball(tmp_path, exports, gates))]
    ) == (1 if refused else 0)


def test_this_tree_passes_the_gate_check_now_that_the_gates_passed(
    tmp_path: Path,
) -> None:
    """Unit 055-t17 passed TS-1U and TS-1D: a release built from this tree, which exports
    the preload, is accepted; the same tree with either gate unpassed would be refused."""
    manifest = json.loads((SDK / "package.json").read_text(encoding="utf-8"))
    table = json.loads((SDK / "wire-qualification.json").read_text(encoding="utf-8"))
    assert "./register" in manifest["exports"]
    assert {g: table["gates"][g] for g in ("TS-1U", "TS-1D")} == {
        "TS-1U": "passed",
        "TS-1D": "passed",
    }
    tarball = _tarball(tmp_path, manifest["exports"], table["gates"])
    assert check_npm_wire_gates.problems(tarball) == []
    for gate in ("TS-1U", "TS-1D"):
        unpassed = {**table["gates"], gate: "not_passed"}
        found = check_npm_wire_gates.problems(
            _tarball(tmp_path, manifest["exports"], unpassed)
        )
        assert len(found) == 1 and gate in found[0], found


def test_release_qualification_runs_the_gate_check_on_the_qualified_tarball() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    qualify = _job(text, "qualify-release", "changelog")
    assert "python scripts/release/check_npm_wire_gates.py" in qualify
    assert qualify.index("npm run package:qualified") < qualify.index(
        "check_npm_wire_gates.py"
    )
    # The tarball carries the six digest-checked prebuilds of the reusable workflow.
    assert "uses: ./.github/workflows/typescript-native-prebuilds.yml" in text
    assert "name: fabric-wire-prebuilds" in qualify
    assert "--allow-partial-prebuilds" not in text
