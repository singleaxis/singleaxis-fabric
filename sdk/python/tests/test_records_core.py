# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The records core (spec 051 §4.2, WP2-1a; pulled forward by spec 057 OD-15).

Unit and property tests: the bounded walker stops within its limits before any output
(deep, wide, cyclic and huge inputs) and never runs application code; links round-trip
through the registry check; id mapping equals the pseudonym vectors; timing; bodies under
the role's mode; handles, update records and the update cap; ``record_error`` builds
``step.error`` from class names and frames only; fault injection (emitter raises, queue
full, not installed) never reaches the caller; strict mode raises.
"""

from __future__ import annotations

import json
import math
import random
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from fabric import _records, records
from fabric._capture_types import COUNTERS, STRICT_ENV, RecordsMisuseError
from fabric._content import canonical_json
from fabric._records import compile_check
from fabric._records_api import (
    ActorRef,
    Body,
    Link,
    Timing,
    build_body,
    current_records,
    emit,
    encode_links,
    retained_digest,
    timing_window,
)
from fabric._records_keys_generated import RECORD_KEY_CHECKS
from fabric.records._handles import MAX_UPDATES, RecordHandle, error_metadata
from fabric.records._walker import MAX_DEPTH, MAX_NODES, walk

from ._records_capture import installed, records_of

VECTORS = Path(__file__).resolve().parents[3] / "contracts/coverage/v1/fixtures/vectors"


@pytest.fixture(autouse=True)
def _counters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    COUNTERS.reset()


# ----------------------------------------------------------------- the bounded walker
class Hostile:
    """An application object whose every method fails the test if Fabric calls it."""

    calls: list[str] = []  # noqa: RUF012 - a shared test ledger

    def __repr__(self) -> str:
        Hostile.calls.append("repr")
        raise AssertionError("repr called")

    def __str__(self) -> str:
        Hostile.calls.append("str")
        raise AssertionError("str called")

    def __iter__(self) -> Any:
        Hostile.calls.append("iter")
        raise AssertionError("iter called")


def test_walker_serialises_plain_json_canonically() -> None:
    value = {"b": [1, 2.5, None, True], "a": ("x", {"é": "ü"})}
    walked = walk(value, 1 << 20)
    assert walked.outcome == "ok"
    assert walked.text == '{"a":["x",{"é":"ü"}],"b":[1,2.5,null,true]}'


@pytest.mark.parametrize(
    "value,outcome",
    [
        (Hostile(), "unsupported"),
        ({"k": Hostile()}, "unsupported"),
        ({1: "non-str key"}, "unsupported"),
        ({"x": {1, 2}}, "unsupported"),
        ({"x": b"bytes inside"}, "unsupported"),
        ({"x": float("nan")}, "unsupported"),
        ({"x": float("inf")}, "unsupported"),
        ({"x": 10**5000}, "too_large"),
        ("x" * 2000, "too_large"),
    ],
)
def test_walker_refuses_without_running_application_code(value: object, outcome: str) -> None:
    Hostile.calls.clear()
    assert walk(value, 4096).outcome == outcome
    assert Hostile.calls == []


def test_walker_stops_at_depth_nodes_and_cycles_before_output() -> None:
    deep: Any = "leaf"
    for _ in range(MAX_DEPTH + 1):
        deep = [deep]
    assert walk(deep, 1 << 20).outcome == "too_large"
    cyclic: list[Any] = []
    cyclic.append(cyclic)
    assert walk(cyclic, 1 << 20).outcome == "unsupported"
    shared = {"a": 1}
    assert walk([shared, shared], 1 << 20).outcome == "ok"  # a DAG is not a cycle


def test_walker_work_is_bounded_by_its_limits_not_by_the_value() -> None:
    wide = list(range(1_000_000))
    started = time.perf_counter()
    assert walk(wide, 1 << 24).outcome == "too_large"
    assert walk({str(i): i for i in range(MAX_NODES + 1)}, 1 << 24).outcome == "too_large"
    assert time.perf_counter() - started < 0.5  # refused by the length, not by visiting


def test_walker_output_never_exceeds_the_cap_property() -> None:
    rng = random.Random(57)  # noqa: S311 - a reproducible property test, not crypto

    def value(depth: int = 0) -> Any:  # noqa: PLR0911 - one return per JSON type
        pick = rng.randrange(7 if depth < 5 else 4)
        if pick == 0:
            return rng.choice([None, True, False])
        if pick == 1:
            return rng.randrange(-(10**12), 10**12)
        if pick == 2:
            return rng.random() * 10 ** rng.randrange(-8, 8)
        if pick == 3:
            return "".join(rng.choice('ab"\\\n\u0001é😀') for _ in range(rng.randrange(40)))
        if pick == 4:
            return [value(depth + 1) for _ in range(rng.randrange(6))]
        if pick == 5:
            return tuple(value(depth + 1) for _ in range(rng.randrange(6)))
        return {f"k{rng.randrange(50)}": value(depth + 1) for _ in range(rng.randrange(6))}

    for _ in range(400):
        cap = rng.randrange(16, 4096)
        candidate = value()
        walked = walk(candidate, cap)
        if walked.outcome == "ok":
            assert walked.text is not None
            assert len(walked.text.encode("utf-8")) <= cap
            assert json.loads(walked.text) == json.loads(json.dumps(candidate))


def _stack_walk(value: Any, max_bytes: int) -> tuple[str, str | None]:  # noqa: PLR0911, PLR0912
    """The walker as first written, with an explicit stack (the reference the recursive
    walker must equal: same outcome, same text, for every value)."""
    from fabric.records import _walker  # noqa: PLC0415

    budget, nodes = max_bytes, 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    active: set[int] = set()
    exits: list[tuple[int, int]] = []
    while stack:
        while exits and len(stack) <= exits[-1][0]:
            active.discard(exits.pop()[1])
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            return "too_large", None
        kind = type(node)
        if node is None or kind is bool:
            budget -= 5
        elif kind is int:
            size = _walker._int_bytes(node)
            if size is None:
                return "too_large", None
            budget -= size
        elif kind is float:
            if not math.isfinite(node):
                return "unsupported", None
            budget -= _walker._FLOAT_BYTES
        elif kind is str:
            budget -= 2 + _walker._CHAR_BYTES * len(node)
        elif kind is dict or kind is list or kind is tuple:
            ident = id(node)
            if ident in active:
                return "unsupported", None
            budget -= 2 + len(node)
            if budget < 0 or nodes + len(stack) + len(node) > MAX_NODES:
                return "too_large", None
            active.add(ident)
            exits.append((len(stack), ident))
            if kind is dict:
                for key, child in node.items():
                    if type(key) is not str:
                        return "unsupported", None
                    budget -= 3 + _walker._CHAR_BYTES * len(key)
                    stack.append((child, depth + 1))
            else:
                stack.extend((child, depth + 1) for child in node)
        else:
            return "unsupported", None
        if budget < 0:
            return "too_large", None
    return "ok", canonical_json(value)


def test_walker_equals_the_explicit_stack_walk() -> None:
    """The recursive walker (and its reused C encoder) gives exactly the outcome and text of
    the explicit-stack walk for every value: random plain JSON at every cap, values mixing a
    refusal with an exceeded bound (which comes first depends on the visiting order), deep,
    wide, cyclic, shared and hostile values."""
    rng = random.Random(5701)  # noqa: S311 - a reproducible property test, not crypto
    shared: dict[str, Any] = {"s": [1, "x"]}

    def value(depth: int = 0) -> Any:  # noqa: PLR0911 - one return per JSON type
        pick = rng.randrange(10 if depth < 6 else 5)
        if pick == 0:
            return rng.choice([None, True, False, 0, -1, 10**30, 10**4100, 1.5, float("nan")])
        if pick == 1:
            return rng.randrange(-(10**12), 10**12)
        if pick == 2:
            return rng.random() * 10 ** rng.randrange(-8, 8)
        if pick == 3:
            return "".join(rng.choice('ab"\\\n\u0001é😀') for _ in range(rng.randrange(60)))
        if pick == 4:
            return rng.choice([b"bytes", {1, 2}, Hostile, shared, "k" * rng.randrange(300)])
        if pick in (5, 6):
            return [value(depth + 1) for _ in range(rng.randrange(8))]
        if pick == 7:
            return tuple(value(depth + 1) for _ in range(rng.randrange(5)))
        keys: list[Any] = [f"k{rng.randrange(40)}" for _ in range(rng.randrange(7))]
        if rng.random() < 0.05:
            keys.append(rng.randrange(3))  # a non-str key
        return {k: value(depth + 1) for k in keys}

    cases: list[Any] = [value() for _ in range(3000)]
    deep: Any = "leaf"
    for _ in range(MAX_DEPTH + 1):
        deep = [deep]
    cyclic: list[Any] = [1, {"a": "b"}]
    cyclic.append(cyclic)
    cases += [deep, deep[0], cyclic, [shared, shared], [deep, float("inf")],
              [float("inf"), deep], list(range(MAX_NODES)), [list(range(MAX_NODES // 2))] * 2,
              {str(i): i for i in range(50)}]  # fmt: skip
    Hostile.calls.clear()
    for case in cases:
        for cap in (16, 64, 256, 1024, 1 << 14, 1 << 22):
            walked = walk(case, cap)
            assert (walked.outcome, walked.text) == _stack_walk(case, cap), (case, cap)
    assert Hostile.calls == []
    assert {walk(c, 1 << 22).outcome for c in cases} == {"ok", "too_large", "unsupported"}


# ----------------------------------------------------------------- links
def test_links_round_trip_through_the_registry_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    check = compile_check(RECORD_KEY_CHECKS["fabric.step.links"])
    with installed(tmp_path, monkeypatch) as (_handle, _exporter):
        input_ = current_records()
        assert input_ is not None
        handle = emit("tool_call", attrs={}, records=input_)
        ref = records.record_control("approval", "request", "pending")
        encoded = encode_links(input_, [Link("caused_by", handle), Link("resolves", ref),
                                        Link("depends_on", "plan-step")])  # fmt: skip
        assert check(encoded)
        decoded = [entry.split("/", 2) for entry in encoded]
        assert decoded[0] == ["caused_by", "attempt", handle.attempt_uid]
        assert decoded[1] == ["resolves", "attempt", ref.attempt_uid]
        assert decoded[2][:2] == ["depends_on", "step"] and decoded[2][2].startswith("lbl-")
        assert "plan-step" not in json.dumps(encoded)  # a clear caller id never appears
        COUNTERS.reset()
        assert encode_links(input_, [Link("parent", handle), Link("caused_by", object())]) == []
        assert COUNTERS.api_misuse == 2


def test_v2_id_mapping_equals_the_pseudonym_vectors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    doc = json.loads((VECTORS / "pseudonym-v2.json").read_text())
    with installed(tmp_path, monkeypatch, key=b"fabric-test-id-key-not-a-secret") as (_h, _e):
        input_ = current_records()
        assert input_ is not None
        checked = 0
        for case in doc["cases"]:
            if case.get("function") != "v2" or case.get("key") != "fabric-test-id-key-not-a-secret":
                continue
            assert input_.v2(case["prefix"], case["value"]) == case["pseudonym"], case["name"]
            checked += 1
        assert checked >= 30  # every prefix, the 051/052/057 ones included


# ----------------------------------------------------------------- timing
def test_timing_window_rules() -> None:
    aware = datetime(2026, 11, 9, 10, 0, tzinfo=UTC)
    start, end, basis = timing_window(Timing(aware, aware))
    assert basis == "reported" and start == end == int(aware.timestamp() * 1e9)
    assert timing_window(Timing(5, 9))[:3] == (5, 9, "reported")
    assert timing_window(None)[2] == "not_captured"
    COUNTERS.reset()
    assert timing_window(Timing(datetime(2026, 1, 1), None))[2] == "not_captured"  # naive
    assert timing_window(Timing(9, 5))[2] == "not_captured"  # ends before it starts
    assert timing_window(Timing(-1, None))[2] == "not_captured"
    assert COUNTERS.api_misuse == 3


# ----------------------------------------------------------------- bodies and digests
def test_bodies_follow_the_role_mode_and_never_convert_objects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with installed(tmp_path, monkeypatch) as (_handle, _exporter):
        input_ = current_records()
        assert input_ is not None
        # control.checked is off by default (spec 057 OD-19): nothing is built, no digest
        assert build_body(input_, Body("control.checked", {"prompt": "x"})) is None
        assert retained_digest(input_, "control.checked", b"x") is None
        reason = build_body(input_, Body("control.reason", "because", "text/plain"))
        assert reason is not None and getattr(reason, "data", None) == "because"
        assert retained_digest(input_, "control.reason", b"x") is not None
        Hostile.calls.clear()
        refused = build_body(input_, Body("control.approval", Hostile()))
        assert refused is not None and getattr(refused, "reason", None) == "parse_failed"
        big = build_body(input_, Body("control.approval", {"x": "y" * 300_000}))
        assert big is not None and getattr(big, "reason", None) == "payload_too_large"
        assert Hostile.calls == []
        assert build_body(input_, Body("no.such.role", "x")) is None


# ----------------------------------------------------------------- handles
def test_handles_expose_ids_only_and_cap_updates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    public = {n for n in dir(RecordHandle) if not n.startswith("_")}
    assert public == {"attempt_uid", "step_id", "recorded", "link", "record_error", "unrecorded"}
    with installed(tmp_path, monkeypatch) as (handle, exporter):
        step = emit("tool_call", attrs={}, step_id="lookup")
        assert (
            step.recorded and step.attempt_uid and step.step_id and step.step_id.startswith("lbl-")
        )
        other = emit("tool_call", attrs={})
        for _ in range(MAX_UPDATES + 3):
            step.link("depends_on", other)
        assert handle.flush(10.0)
        updates = [r for r in records_of(exporter, "tool_call")
                   if r.get("fabric.step.update_of") == step.attempt_uid]  # fmt: skip
        assert len(updates) == MAX_UPDATES
        assert COUNTERS.api_misuse == 3
        assert all(r["fabric.attempt.uid"] == step.attempt_uid for r in updates)
        assert all("fabric.step.status" not in r for r in updates)  # an update has no status
    unrecorded = RecordHandle.unrecorded()
    assert (unrecorded.attempt_uid, unrecorded.step_id, unrecorded.recorded) == (None, None, False)
    unrecorded.link("caused_by", "x")
    unrecorded.record_error(ValueError("x"))


class _Loud(Exception):  # noqa: N818 - an application exception, as named
    def __str__(self) -> str:
        raise AssertionError("str called")

    def __repr__(self) -> str:
        raise AssertionError("repr called")

    @property
    def args(self) -> Any:  # type: ignore[override]
        raise AssertionError("args read")


def test_record_error_uses_class_names_and_frames_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail() -> None:
        try:
            raise KeyError("inner")
        except KeyError as inner:
            raise _Loud from inner

    try:
        fail()
    except _Loud as exc:
        meta = error_metadata(exc)
        caught = exc
    assert meta["type"].endswith("_Loud")
    assert meta["cause"] == [{"type": "KeyError"}]
    assert meta["frames"] and all(set(f) == {"file", "line", "function"} for f in meta["frames"])
    with installed(tmp_path, monkeypatch) as (handle, exporter):
        step = emit("tool_call", attrs={})
        step.record_error(caught, message="customer-formatted text")
        step.record_error(caught, message=b"bytes are dropped")  # type: ignore[arg-type]
        assert handle.flush(10.0)
        updates = [r for r in records_of(exporter) if r.get("fabric.step.update_of")]
        assert len(updates) == 2
        assert all(r["fabric.error.domain"] == "application" for r in updates)
        assert COUNTERS.api_misuse == 1


# ----------------------------------------------------------------- fail-open
def test_not_installed_records_nothing_and_returns_handles() -> None:
    ref = records.record_control("policy", "observation", "deny")
    assert (ref.recorded, ref.control_id, ref.attempt_uid) == (False, None, None)
    run = records.record_run_context(execution_mode="supervised")
    assert run.recorded is False


def test_a_raising_emitter_never_reaches_the_caller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: Any, **kwargs: Any) -> bool:
        raise RuntimeError("recorder fault")

    with installed(tmp_path, monkeypatch) as (_handle, _exporter):
        monkeypatch.setattr(_records.RecordsInput, "submit", boom)
        ref = records.record_control("policy", "observation", "deny")
        assert ref.recorded is False  # Attempt.emit is fail-open: counted, not raised
        assert COUNTERS.internal_errors >= 1
        monkeypatch.setattr(records, "record_control", records.record_control)
        monkeypatch.setenv(STRICT_ENV, "1")
        with pytest.raises(RuntimeError):
            records.record_control("policy", "observation", "deny")


def test_a_full_queue_is_a_counted_loss_never_a_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with installed(tmp_path, monkeypatch) as (handle, _exporter):
        pipeline = handle._tee.pipeline
        monkeypatch.setattr(pipeline, "submit", lambda job: False)
        started = time.perf_counter()
        ref = records.record_control("policy", "observation", "deny")
        assert time.perf_counter() - started < 0.05
        assert ref.recorded is False


def test_strict_mode_raises_misuse_with_fixed_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with installed(tmp_path, monkeypatch) as (_handle, _exporter):
        monkeypatch.setenv(STRICT_ENV, "1")
        with pytest.raises(RecordsMisuseError) as caught:
            records.record_control("policy", "request", "allow")
        assert "allow" not in str(caught.value) or "matrix" in str(caught.value)


def test_context_binds_a_default_actor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with installed(tmp_path, monkeypatch) as (handle, exporter):
        with records.context(actor=ActorRef("system", "scheduler-1")):
            records.record_control("rate_limit", "observation", "deny")
        records.record_control("rate_limit", "observation", "allow")
        assert handle.flush(10.0)
        bound, unbound = records_of(exporter, "control")
        assert bound["fabric.actor.type"] == "system" and bound["fabric.actor.id"].startswith(
            "act-"
        )
        assert unbound["fabric.actor.type"] == "unknown" and "fabric.actor.id" not in unbound


def test_context_binds_conversation_and_turn_pseudonyms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """051 X15/X16: ``context(conversation_id=, turn_id=)`` reaches every records-input
    record in scope as ``conv-``/``turn-`` pseudonyms (records-class placement, 051 §5.1);
    rule A must not drop them, and the clear ids never appear."""
    with installed(tmp_path, monkeypatch) as (handle, exporter):
        with records.context(conversation_id="CANARY-conv-1", turn_id="CANARY-turn-1"):
            records.record_control("rate_limit", "observation", "deny")
            records.record_run_context(execution_mode="supervised")
        records.record_control("rate_limit", "observation", "allow")
        assert handle.flush(10.0)
        spans = records_of(exporter)
        records_input = _records.records_input(handle)
        assert records_input is not None
        dropped = records_input.stats.snapshot()["records_keys_dropped"]
    bound, annotation, unbound = spans
    for attrs in (bound, annotation):
        assert str(attrs["fabric.conversation_id"]).startswith("conv-")
        assert str(attrs["fabric.turn_id"]).startswith("turn-")
    assert "fabric.conversation_id" not in unbound and "fabric.turn_id" not in unbound
    assert "CANARY" not in json.dumps(spans, default=str)
    assert dropped == 0
