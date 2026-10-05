# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Qualification never credits missing, skipped or contradictory test evidence."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "capture_acceptance", ROOT / "scripts/qualification/run_capture_acceptance.py"
)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


@pytest.mark.parametrize(
    "code,xml,expected",
    [
        (
            0,
            '<testsuites><testsuite><testcase name="actual"/></testsuite></testsuites>',
            "LOCAL_FIXTURE_PASSED",
        ),
        (0, "<testsuite><testcase><skipped/></testcase></testsuite>", "UNVERIFIED"),
        (0, "<testsuite><testcase><failure/></testcase></testsuite>", "FAILED"),
        (0, "<testsuite><testcase><error/></testcase></testsuite>", "FAILED"),
        (0, "<testsuite/>", "UNVERIFIED"),
        (0, "<broken", "UNVERIFIED"),
        (0, None, "UNVERIFIED"),
        (1, "<testsuite><testcase/></testsuite>", "FAILED"),
    ],
)
def test_no_false_fixture_pass(
    tmp_path: Path, code: int, xml: str | None, expected: str
) -> None:
    junit = tmp_path / "junit.xml"
    if xml is not None:
        junit.write_text(xml)
    status, _ = RUNNER.fixture_status(code, junit)
    assert status == expected
