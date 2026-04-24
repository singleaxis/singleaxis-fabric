# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest

from fabric_update_agent.version import (
    VERSION_CONSTRAINT_ANNOTATION,
    VersionError,
    check,
)


def _manifest(constraint: str | None) -> dict[str, object]:
    anns = {VERSION_CONSTRAINT_ANNOTATION: constraint} if constraint is not None else {}
    return {"metadata": {"annotations": anns}}


def test_check_happy_path() -> None:
    assert check(_manifest(">=0.1,<0.2"), "0.1.0") == ">=0.1,<0.2"


def test_check_rejects_version_outside_range() -> None:
    with pytest.raises(VersionError, match="does not satisfy"):
        check(_manifest(">=0.2"), "0.1.0")


def test_check_rejects_missing_annotation() -> None:
    with pytest.raises(VersionError, match="missing annotation"):
        check(_manifest(None), "0.1.0")


def test_check_rejects_malformed_constraint() -> None:
    with pytest.raises(VersionError, match="invalid version constraint"):
        check(_manifest("not-a-specifier!!"), "0.1.0")


def test_check_rejects_invalid_installed_version() -> None:
    with pytest.raises(VersionError, match="not a valid PEP 440"):
        check(_manifest(">=0.1"), "banana")
