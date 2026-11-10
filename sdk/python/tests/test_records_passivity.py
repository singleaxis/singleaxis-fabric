# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Records passivity budgets: spec 051 §4.11 rows 1-2 and spec 057 B4.

Every spec 057 records API (``record_control``, ``record_grant``, ``record_extension``,
``record_run_context``, ``Decision.record_hook`` and ``record_skill`` with the 057
keywords, and the ``control_check`` wrapper in both forms) is timed through its public
entry point with capture off and on (``tests/_records_bench.py``), and judged against
its budget on reference hardware:

- B4: an active capture point adds at most 50 us per call; capture off at most 5 us;
- 051 §4.11: a ``record_control`` with no body at most 20 us, with a ``str`` body 30 us.

The measurement is ``tests/_budget.py``'s: a fresh interpreter without coverage, warm-up,
nine batches of 300 calls each with the garbage collector paused, each batch's median
divided by the scale calibrated right before it, and the best batch judged. Only while a
budget is missed is the whole measurement repeated (three attempts at most). The budgets
are never raised. ``test_the_gate_fails_when_the_records_path_blocks`` keeps the gate
honest: a records path that sleeps twice the largest scaled budget fails every scenario.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from ._budget import LAST, MAX_SCALE, Batch, control, fresh, gate
from ._records_bench import ON_BUDGET_NS, budgets

BUDGETS = budgets()
_CODE = ("import json, sys; from tests._records_bench import measure; "
         "print(json.dumps(measure(sys.argv[1])))")  # fmt: skip


def _measure(mode: str) -> Mapping[str, list[Batch]]:
    found: Mapping[str, list[Batch]] = fresh(_CODE, mode)
    return found


@pytest.fixture(scope="module")
def measured() -> dict[str, float]:
    return gate(lambda: _measure("plain"), BUDGETS)


@pytest.mark.parametrize("scenario", sorted(BUDGETS))
def test_records_call_is_within_its_budget(measured: dict[str, float], scenario: str) -> None:
    seen = [(round(b["median_ns"]), round(b.get("cpu_ns", 0)), round(b["scale"], 2))
            for b in LAST.get(scenario, [])]  # fmt: skip
    assert measured[scenario] <= BUDGETS[scenario], (
        f"{scenario}: best batch median {measured[scenario]:.0f} ns on reference hardware "
        f"> {BUDGETS[scenario]:.0f} ns; batches (wall ns, thread cpu ns, scale): {seen}"
    )


def test_every_records_api_of_spec_057_is_benchmarked() -> None:
    names = {name.rsplit(".", 1)[0] for name in BUDGETS}
    assert names >= {"record_control", "record_grant", "record_extension",
                     "record_run_context", "record_hook", "record_skill", "control_check",
                     "control_check_scope"}  # fmt: skip
    assert all(f"{name}.off" in BUDGETS and f"{name}.on" in BUDGETS for name in names)


def test_the_gate_fails_when_the_records_path_blocks() -> None:
    """The negative control: every records API's path sleeps ``2 x 50 us x MAX_SCALE``
    before it does anything, so no batch of any scenario, off or on, meets its budget."""
    blocked: dict[str, Any] = control(lambda: _measure("block"))
    assert set(blocked) == set(BUDGETS)
    for scenario, budget in BUDGETS.items():
        assert blocked[scenario] > budget, (scenario, blocked[scenario], budget)
        assert blocked[scenario] >= 2 * ON_BUDGET_NS * 0.9, (scenario, blocked[scenario])
    assert MAX_SCALE >= 1.0


def test_the_rule_a_memo_never_changes_an_answer() -> None:
    """The bounded memo the records path keeps (``_records.CompiledChecks``) gives exactly
    the answers of the plain predicates: repeated, failing and high-cardinality strings,
    ``True`` beside ``1``, and a key whose placement depends on the capture point."""
    from fabric import _records  # noqa: PLC0415

    memoised = _records.compile_checks()
    plain = dict(memoised)  # the same predicates, no memo
    rows: list[tuple[dict[str, Any], str]] = []
    for i in range(_records._MEMO_ENTRIES + 40):  # past the bound: the id key goes volatile
        rows.append(({
            "fabric.control.kind": "policy", "fabric.control.decision": "deny",
            "fabric.control.stage": "Bad Stage", "fabric.hook.modified": True if i % 2 else 1,
            "fabric.event_id": f"{i:08x}-0000-4000-8000-000000000000",
            "fabric.process.parent_pid": 7, "unknown.key": "x",
        }, "exec.subprocess@1" if i % 3 else "sdk.records@1"))  # fmt: skip
    for attrs, point in rows * 2:
        assert _records.project_attributes(attrs, memoised, point=point) == (
            _records.project_attributes(attrs, plain, point=point)
        )
    assert memoised.memo["fabric.control.kind"] == {"policy": True}
    assert memoised.memo["fabric.control.stage"] == {"Bad Stage": False}
    assert memoised.memo["fabric.event_id"] is None  # high-cardinality: no longer kept
    assert "fabric.process.parent_pid" not in memoised.memo  # conditional: never kept


def test_the_owned_key_answer_never_changes_an_answer() -> None:
    """The remembered rule A answer for Fabric's own repeating keys
    (``RecordsInput._owned_pass``) says "every key kept as it is" exactly when the full
    projection keeps every key unchanged: valid records, each key made invalid in turn
    (also after its valid form was remembered), ``bool`` and out-of-range sequences."""
    import uuid  # noqa: PLC0415

    from fabric import _records  # noqa: PLC0415

    records = _records.RecordsInput(None)
    good: dict[str, Any] = {
        "fabric.capture.input": "records", "fabric.capture.source": "reported",
        "fabric.capture.point": "sdk.records@0.12.0", "fabric.source_id": "s-" + "a" * 32,
        "fabric.source.epoch": 3, "fabric.source.sequence": 7,
        "fabric.event_id": str(uuid.uuid4()), "fabric.attempt.uid": str(uuid.uuid4()),
        "fabric.step.kind": "control", "fabric.run.id": "r-" + "b" * 32,
        "fabric.run.scope_id": str(uuid.uuid4()), "fabric.run.segment_id": "seg-" + "c" * 32,
        "fabric.step.lifecycle_state": "completed", "fabric.step.status": "ok",
    }  # fmt: skip
    bad: dict[str, Any] = {
        "fabric.capture.source": "invented", "fabric.capture.point": "Not A Point",
        "fabric.source_id": "", "fabric.source.epoch": -1, "fabric.source.sequence": True,
        "fabric.event_id": "not-a-uuid", "fabric.attempt.uid": "x" * 40,
        "fabric.step.kind": "bogus", "fabric.run.id": None, "fabric.run.scope_id": "?",
        "fabric.run.segment_id": "seg", "fabric.step.lifecycle_state": "nope",
        "fabric.step.status": "maybe",
    }  # fmt: skip
    cases = (
        [good]
        + [{**good, key: value} for key, value in bad.items()]
        + [{**good, "fabric.source.sequence": 2**63}, {**good, "fabric.source.sequence": -5}]
    )
    for fabric in cases * 2:  # the second pass answers from what the first remembered
        static = tuple(v for k, v in fabric.items() if k not in _records._VARYING_KEYS)
        fast = records._owned_pass(
            static,
            fabric,
            fabric["fabric.source.sequence"],
            fabric["fabric.event_id"],
            fabric["fabric.attempt.uid"],
        )
        kept, dropped = _records.project_attributes(
            fabric, records._checks, point=fabric["fabric.capture.point"]
        )
        assert fast == (not dropped and kept == fabric), fabric
    assert records._owned  # answers were remembered
    static = tuple(v for k, v in good.items() if k not in _records._VARYING_KEYS)
    assert records._owned_pass(static, good, 7, good["fabric.event_id"], good["fabric.attempt.uid"])
