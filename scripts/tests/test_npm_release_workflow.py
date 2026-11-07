# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Supply-chain invariants for the build-once TypeScript release path."""

from __future__ import annotations

import re
from pathlib import Path

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
