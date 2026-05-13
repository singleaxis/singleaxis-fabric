# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``scripts/check_changelog_keep_alive.py``.

SPEC 016 §4.6: the validator that gates releases. Both the failure
mode (missing heading or link reference) and the success path
(complete keep-alive) are exercised so the script can be wired into
``release.yml`` without fear of drift.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# The script lives at scripts/check_changelog_keep_alive.py — add the
# parent directory to sys.path so we can import it as a module.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import check_changelog_keep_alive as checker  # noqa: E402


def _write(tmp_path: Path, text: str) -> Path:
    target = tmp_path / "CHANGELOG.md"
    target.write_text(text)
    return target


def test_keep_alive_complete_passes(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "# Changelog\n\n"
        "## [Unreleased]\n\n"
        "## [0.2.0] - 2026-05-01\n\n"
        "- Initial release.\n\n"
        "[Unreleased]: https://github.com/x/y/compare/v0.2.0...HEAD\n"
        "[0.2.0]: https://github.com/x/y/releases/tag/v0.2.0\n",
    )
    assert checker.main([str(path)]) == 0


def test_missing_heading_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _write(
        tmp_path,
        "# Changelog\n\n"
        "## [0.2.0] - 2026-05-01\n\n"
        "- Initial release.\n\n"
        "[Unreleased]: https://github.com/x/y/compare/v0.2.0...HEAD\n",
    )
    assert checker.main([str(path)]) == 1
    captured = capsys.readouterr()
    assert "## [Unreleased]` heading" in captured.err


def test_missing_link_ref_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _write(
        tmp_path,
        "# Changelog\n\n"
        "## [Unreleased]\n\n"
        "## [0.2.0] - 2026-05-01\n\n"
        "- Initial release.\n",
    )
    assert checker.main([str(path)]) == 1
    captured = capsys.readouterr()
    assert "[Unreleased]: <compare-url>...HEAD" in captured.err


def test_link_ref_pointing_at_tag_not_head_fails(tmp_path: Path) -> None:
    """A stale ``[Unreleased]`` link that points at a tag is still missing
    the keep-alive — without ``...HEAD`` the link drifts as soon as the
    next release ships."""
    path = _write(
        tmp_path,
        "## [Unreleased]\n\n"
        "## [0.2.0] - 2026-05-01\n\n"
        "[Unreleased]: https://github.com/x/y/releases/tag/v0.2.0\n",
    )
    assert checker.main([str(path)]) == 1


def test_real_repo_changelog_passes() -> None:
    """The actual CHANGELOG.md in the repo must satisfy the keep-alive."""
    repo_root = Path(__file__).resolve().parents[2]
    changelog = repo_root / "CHANGELOG.md"
    assert checker.main([str(changelog)]) == 0
