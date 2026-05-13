#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Validate the `[Unreleased]` keep-alive in ``CHANGELOG.md``.

SPEC 016 §4.6: every release must leave both a ``## [Unreleased]``
heading and a matching ``[Unreleased]: <compare-url>...HEAD`` link
reference in place so subsequent PRs do not fail markdownlint MD053.
The release workflow calls this script before extracting release
notes; a unit test exercises the same entry point.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

HEADING_RE = re.compile(r"(?m)^## \[Unreleased\]\s*$")
LINK_RE = re.compile(r"(?m)^\[Unreleased\]:\s+\S+\.\.\.HEAD\s*$")


def missing_keep_alive(text: str) -> list[str]:
    """Return human-readable names of any missing keep-alive parts."""
    missing: list[str] = []
    if not HEADING_RE.search(text):
        missing.append("`## [Unreleased]` heading")
    if not LINK_RE.search(text):
        missing.append("`[Unreleased]: <compare-url>...HEAD` link reference")
    return missing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default="CHANGELOG.md")
    args = parser.parse_args(argv)
    text = pathlib.Path(args.path).read_text()
    missing = missing_keep_alive(text)
    if missing:
        sys.stderr.write(
            "::error::CHANGELOG.md is missing: "
            + ", ".join(missing)
            + ". After cutting a release, restore the `## [Unreleased]` heading "
              "AND the matching `[Unreleased]: "
              "https://github.com/<org>/<repo>/compare/v<previous>...HEAD` link "
              "reference so the next PR does not fail markdownlint MD053. "
              "See CONTRIBUTING.md `## Releasing (maintainers)`.\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
