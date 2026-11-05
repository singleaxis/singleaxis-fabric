# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""AR-1 production, hermetic replay (spec 056 §6.2 "Hermetic production replay"), plus
unit checks of the production pieces.

Run from the repository root with the SDK's interpreter::

    sdk/python/.venv/bin/python -m pytest qualification/action-record/tests -q

The end-to-end test needs the built Node (``components/otel-collector-fabric/dist`` or
``FABRIC_NODE_DIST``) and Go (it builds ``hostrecords-replay``); it skips without them
unless ``AR1_REQUIRE_NODE=1``.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from ar1 import expect, production, replay  # noqa: E402
from ar1.fixture_model import T4, T8, T9, Script  # noqa: E402
from ar1.harness import Options  # noqa: E402
from ar1.node import node_dist  # noqa: E402

REPO = HERE.parents[1]


def test_the_production_script_adds_steps_8_and_9() -> None:
    script = Script("/data", "http://[::1]:1/x", production=True)
    fed = ["call_ar1_t1_run_shell", "call_ar1_t2_fetch_url", "call_ar1_t3a_run_shell",
           "call_ar1_t3b_run_shell", T4]  # fmt: skip
    turn = script.turn(fed)
    assert turn is not None and turn[0]["tool_calls"][0]["function"]["name"] == "run_container"
    turn = script.turn([*fed, T8])
    assert turn is not None and turn[0]["tool_calls"][0]["function"]["name"] == "run_remote"
    final = script.turn([*fed, T8, T9])
    assert final is not None and final[1] == "stop"
    assert Script("/data", "http://[::1]:1/x").turn(fed) is not None  # local: the answer
    assert script.turn([*fed, T9]) is None


def test_source_ids_are_the_label_pseudonyms() -> None:
    """The ids the groups bind: what the agent emits and what print-source-id prints."""
    ebpf = production.host_source_id(production.EBPF_SOURCE_LABEL)
    assert ebpf.startswith("s-") and len(ebpf) == 34
    assert ebpf != production.host_source_id(production.QUIET_SOURCE_LABEL)
    assert production.agent_source_id().startswith("s-")


def _effect(uid: str, pid: int, start: int, command: str, *, linux: bool) -> replay.Effect:
    return replay.Effect(uid, pid, 500, start, command, start + 5_000_000,
                         start // 10_000_000 * 10_000_000 if linux else None,
                         4026531836 if linux else None)  # fmt: skip


@pytest.mark.parametrize("linux", [True, False])
def test_bind_production_shapes_the_events(linux: bool) -> None:
    """Linux-shaped effects give every event the namespace fields (H1); otherwise none
    carries them (declared_same, H2). Step 8's container is sandbox scope with its id;
    the quiet node is one container nobody reported."""
    base = 1_000_000_000_000
    effects = [
        _effect("u1", 501, base, "ls /d && sha256sum /d/a.txt", linux=linux),
        _effect("u8", 508, base + 10**9, "docker run -d --cgroup-parent x busybox sh -c a",
                linux=linux),
    ]  # fmt: skip
    container = "a" * 64
    bound = replay.bind_production(
        effects, {"u9": base + 2 * 10**9}, [base - 10**6, base + 3 * 10**9],
        peers={"model": ("127.0.0.1", 1), "fixture_host": ("::1", 2), "sandbox": ("127.0.0.2", 3)},
        visits={"fixture_ping": [base + 10**8]}, agent_ppid=1, agent_pid=500,
        container_id=container, quiet_container_id="b" * 64,
    )  # fmt: skip
    assert bound.recorded is linux
    assert bound.steps == {"u1": "1", "u8": "8", "u9": "9"}
    assert set(bound.anchors) == {"u1", "u8"} and len(bound.sandbox["u8"]) == 3
    namespaced = [("PidNS" in e) for e in [*bound.events, *bound.quiet]]
    assert all(namespaced) if linux else not any(namespaced)
    boxes = [bound.events[i] for i in bound.sandbox["u8"]]
    assert {(e["Scope"], e["ContainerID"]) for e in boxes} == {("sandbox", container)}
    assert all(e["Ppid"] != 500 for e in boxes)  # below the shim, never the agent's child
    assert {e["ContainerID"] for e in bound.quiet} == {"b" * 64}
    assert len(bound.agent_events["sandbox"]) == 2  # the provider calls at step 9's start
    anchor = bound.events[bound.anchors["u1"]]
    assert (anchor["Pid"], anchor["Ppid"]) == (501, 500)
    if linux:
        assert anchor["ProcessStartNs"] == effects[0].process_start_ns
        assert (anchor["NsPid"], anchor["NsPpid"]) == (501, 500)


def test_write_events_keeps_the_staging_order(tmp_path: Path) -> None:
    events = [{"TimeUnixNano": 3}, {"TimeUnixNano": 1}, {"TimeUnixNano": 2}]
    order = replay.write_events(tmp_path / "e.jsonl", events)
    assert order == [1, 2, 0]
    lines = [json.loads(x) for x in (tmp_path / "e.jsonl").read_text().splitlines()]
    assert [x["TimeUnixNano"] for x in lines] == [1, 2, 3]
    rows = [
        {
            "kind": "span",
            "attributes": {
                "fabric.source_id": "s-x",
                "fabric.source.sequence": q,
                "fabric.event_id": f"e{q}",
                "fabric.sensor.event_class": "exec",
            },
        }
        for q in (3, 1, 2)
    ]
    assert replay.map_event_ids(rows, "s-x", order) == {1: "e1", 2: "e2", 0: "e3"}


def test_the_fixture_docker_never_holds_the_id(tmp_path: Path) -> None:
    docker = production.FixtureDocker(tmp_path)
    assert "AR1_FIXTURE_CONTAINER_ID" in (docker.bin / "docker").read_text()
    env = docker.env({"PATH": "/usr/bin"}, "c" * 64)
    assert env["PATH"].startswith(str(docker.bin))
    assert not any(
        ("c" * 64).encode() in p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()
    )


def _live_view(unexplained_ports: list[int]) -> tuple[dict[str, Any], expect.ProductionTruth]:
    """A live-shaped view: step 4's effect anchored by the launcher's exec, its lineage
    one exec; the unexplained events agent connects to the given ports."""
    anchor, inner = "e-anchor", "e-inner"
    run_link = [{"namespace": "run", "target": "r", "link": "x"}]
    lineage = [{"namespace": "attempt", "target": "u4", "link": "process_lineage · certain"}]
    connects = [f"e-connect-{n}" for n in range(len(unexplained_ports))]
    view: dict[str, Any] = {
        "rows": [
            {"kind": "effect", "attempt_uid": "u4",
             "corroborated_by": [{"event_id": anchor, "link": "process_anchor · certain"}]},
            {"kind": "host", "event_id": inner, "event_class": "exec", "part_of": lineage},
            *({"kind": "host", "event_id": e, "event_class": "connect", "part_of": run_link}
              for e in connects),
        ],
        "unexplained_host_events": {"count": len(connects), "event_ids": connects},
        "sandbox_events_unlinked": {"count": 0},
    }  # fmt: skip
    attributes: dict[str, dict[str, Any]] = {
        anchor: {"fabric.sensor.event_class": "exec", "fabric.sensor.pid_ns": 4026531836},
        inner: {"fabric.sensor.event_class": "exec", "fabric.sensor.pid_ns": 4026532999},
        **{e: {"fabric.sensor.event_class": "connect", "fabric.sensor.peer_port": p}
           for e, p in zip(connects, unexplained_ports, strict=True)},
    }  # fmt: skip
    truth = expect.ProductionTruth(agent_pid=7, certain=True, host_attributes=attributes,
                                   uncalled_port=8443)  # fmt: skip
    return view, truth


def _live_failures(view: dict[str, Any], truth: expect.ProductionTruth) -> set[str]:
    checks = expect.Checks("live")
    expect.production_corroboration(checks, view, {"u4": "4"}, truth)
    return {c.name for c in checks.failures()}


def test_live_shape_checks_name_the_namespace_and_the_fixture_host() -> None:
    """Live mode (``exact=False``): step 4 needs an exec in another pid namespace as the
    launcher's lineage, and step 6 needs every unexplained event to be a connect to the
    fixture host's port (review, WP6-10)."""
    step4 = "step 4: an exec in another pid namespace is lineage of the launcher"
    step6 = "step 6: unexplained events are the agent's connections to the fixture host"
    view, truth = _live_view([8443])
    assert not {step4, step6} & _live_failures(view, truth)
    view, truth = _live_view([8443, 443])  # a model connection left unexplained
    assert step6 in _live_failures(view, truth)
    view, truth = _live_view([8443])
    same = dict(truth.host_attributes)
    same["e-inner"] = {**same["e-inner"], "fabric.sensor.pid_ns": 4026531836}
    assert step4 in _live_failures(view, replace(truth, host_attributes=same))


def test_ar1_production_replay(tmp_path: Path) -> None:
    """Every variant of AR-1 production against the native group Node, the host side
    replayed through the host-records library to two host groups (the quiet one
    included); see README.md."""
    required = os.environ.get("AR1_REQUIRE_NODE") == "1"
    if node_dist() is None or shutil.which("go") is None:
        if required:
            pytest.fail("AR1_REQUIRE_NODE=1: the Node dist or Go is missing")
        pytest.skip("needs the built Node dist and Go (hostrecords-replay)")
    from ar1.production_harness import PRODUCTION_VARIANTS, ProductionHarness  # noqa: PLC0415

    result = ProductionHarness(
        Options(mode="replay", out=tmp_path, variants=PRODUCTION_VARIANTS, node="required",
                log=lambda _: None)
    ).run()  # fmt: skip
    failures = {
        name: [c for c in v["checks"] if not c["passed"]]
        for name, v in result["variants"].items()
        if not v["passed"]
    }
    assert result["passed"], json.dumps(failures, indent=1)[:6000]
    assert set(result["variants"]) == {*PRODUCTION_VARIANTS, "canaries"}
    assert result["sensor"] == "replay" and result["profile"] == "production"
