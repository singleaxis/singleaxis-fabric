# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A pytest plugin for the B4 step of SC-RA-1: it writes what each passivity gate measured
(the gate's own ``measured`` fixture) to ``SC_RA1_B4_OUT``, so the run can print the
measured values beside the budgets. The gates themselves decide pass or fail."""

from __future__ import annotations

import json
import os
from typing import Any

import pytest

_SEEN: dict[str, Any] = {}


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item: pytest.Item) -> Any:
    funcargs = getattr(item, "funcargs", {})
    if "measured" in funcargs:
        _SEEN[item.module.__name__.rsplit(".", 1)[-1]] = funcargs["measured"]  # type: ignore[attr-defined]
    yield


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    path = os.environ.get("SC_RA1_B4_OUT")
    if path:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(_SEEN, handle, default=str, indent=1, sort_keys=True)
