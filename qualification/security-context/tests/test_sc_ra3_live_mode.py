# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The SC-RA-3 live mode's plumbing, end to end, against a loopback stand-in for the model
endpoint: the key reaches the agent (the stand-in answers 401 without it) and nothing
else, the capture-off twin replays the capture-on run's answers byte for byte, and every
check passes. The real endpoint is run by hand (``run_sc_ra3.py --mode live``).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from sc_ra3 import check
from sc_ra3 import model as fixture
from sc_ra3._ar1 import node_dist
from sc_ra3.harness import SESSIONS, Harness, Options

KEY = "sc-ra3-stand-in-key-not-a-secret"

pytestmark = pytest.mark.skipif(node_dist() is None, reason="no built Fabric Node dist")


@pytest.fixture
def stand_in() -> Iterator[fixture.FixtureModel]:
    routes = {s.task: fixture.scripted(s.script) for s in SESSIONS}
    model = fixture.FixtureModel([], routes=routes, expect_key=KEY).start()
    yield model
    model.close()


def _files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file()]


def test_live_mode_gives_the_key_to_the_agent_only_and_replays_the_twin(
    tmp_path: Path,
    stand_in: fixture.FixtureModel,
) -> None:
    options = Options(
        out=tmp_path, mode="live", base_url=stand_in.base_url, model_key=KEY, log=lambda _: None
    )
    run = Harness(options).run()
    assert stand_in.unauthorised == 0
    # the capture-on runs only: the capture-off twins replay what it answered
    assert stand_in.requests == sum(len(s.script) for s in SESSIONS)
    failed = [c for c in check.evaluate(run) if not c.ok]
    assert failed == [], failed
    assert all(KEY.encode() not in p.read_bytes() for p in _files(tmp_path))


def test_live_mode_with_a_wrong_key_fails_loudly(
    tmp_path: Path,
    stand_in: fixture.FixtureModel,
) -> None:
    options = Options(
        out=tmp_path,
        mode="live",
        base_url=stand_in.base_url,
        model_key="sc-ra3-wrong-key",
        sessions=("approved",),
        log=lambda _: None,
    )
    run = Harness(options).run()
    assert stand_in.unauthorised >= 1
    names = {c.name for c in check.evaluate(run) if not c.ok}
    assert "ran.agents" in names
