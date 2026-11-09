# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spooled delivery throughput (field finding F1).

One body per content request, one request at a time, delivered at one round trip per
body: ~3-14 exchanges per second per process into a remote Node, so a busy process built
a backlog. The sender now puts several bodies in one content request and keeps a few
requests in flight. What must not change: a record's span is exported only once every
one of its bodies was accepted, and a body the Node accepted is never sent again.
"""

from __future__ import annotations

import statistics
import time
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import fabric._loss
import fabric._sequence
from fabric import wire
from fabric._loss import LossEmitter
from fabric.wire._config import config_from_env

from .test_wire_helpers import OPENAI_CHAT
from .test_wire_spool import FakeNode, install_node, model_client, records, wait_for

# The field harness's per-process rate was ~3-14 exchanges/s. At this simulated round
# trip the serial sender measured 9.3 exchanges/s (two body requests per exchange).
RTT_S = 0.05
SERIAL_RATE = 1 / (2 * RTT_S)


@pytest.fixture
def node() -> Iterator[FakeNode]:
    created = FakeNode()
    yield created
    created.close()


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    yield
    wire.uninstall()
    emitter.close(1.0)


def _backlog(node: FakeNode, spool: Path, count: int, **config: Any) -> None:
    """``count`` exchanges spooled while the Node is down, then that process closed: the
    records wait on disk for the next process (as a restarted worker's would)."""
    node.mode = "down"
    handle = install_node(node, spool, **config)
    with model_client() as client:
        for index in range(count):
            client.post(OPENAI_CHAT, json={"messages": [], "n": index})
    assert handle._tee.flush(10.0)  # every exchange is in the spool
    sender = handle._tee.sender
    handle.close(0.5)
    wire.uninstall()
    if sender is not None and sender._thread is not None:
        sender._thread.join(30.0)  # it releases the spool lock as it stops
    with node.lock:
        node.mode, node.peak = "ok", 0
        node.requests.clear()
        node.records_per_request.clear()


def _drain_rate(node: FakeNode, spool: Path, count: int, **config: Any) -> float:
    """Exchanges per second a new process delivers from a backlog of ``count``."""
    _backlog(node, spool, count, **config)
    started = time.monotonic()
    handle = install_node(node, spool, **config)
    assert wait_for(lambda: not records(spool), timeout=120.0), handle.stats()
    rate = count / (time.monotonic() - started)
    handle.close(5.0)
    wire.uninstall()
    return rate


def _span_refs(node: FakeNode) -> list[set[str]]:
    return [{s["fabric.content.request_ref"], s["fabric.content.result_ref"]}
            for s in node.named("fabric.model_call")]  # fmt: skip


def test_bodies_of_many_records_share_content_requests(node: FakeNode, tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    _backlog(node, spool, 20)
    handle = install_node(node, spool)
    assert wait_for(lambda: not records(spool), timeout=30.0)
    assert len(node.content) == 40  # every body, once
    assert Counter(attrs["object_id"] for attrs, _ in node.content).most_common(1)[0][1] == 1
    # 40 bodies in a few requests, not one request per body.
    assert len(node.records_per_request) <= 4, node.records_per_request
    assert max(node.records_per_request) > 1
    assert len(_span_refs(node)) == 20
    handle.close(5.0)


def test_a_span_is_exported_only_after_all_its_bodies_were_accepted(
    node: FakeNode, tmp_path: Path
) -> None:
    spool = tmp_path / "spool"
    config = {"content_batch_bodies": 3, "content_concurrency": 3}
    _backlog(node, spool, 12, **config)
    node.fail_content_after = 2  # two requests (6 bodies) accepted, then 503
    handle = install_node(node, spool, **config)
    assert wait_for(lambda: len(node.content) >= 6)
    assert not handle.flush(1.5)
    accepted = {attrs["object_id"] for attrs, _ in node.content}
    for refs in _span_refs(node):  # whatever was exported had all its bodies accepted
        assert refs <= accepted
    assert len(_span_refs(node)) < 12
    node.fail_content_after = None
    assert handle.flush(40.0)
    assert len(_span_refs(node)) == 12
    # Bodies accepted before the failure were not sent again (idempotent by progress).
    assert len(node.content) == 24
    assert len({attrs["object_id"] for attrs, _ in node.content}) == 24
    seen: set[str] = set()
    for kind, item in node.timeline:  # every span after both of its bodies
        if kind == "content":
            seen.add(item)
        elif "fabric.content.request_ref" in item:
            assert {item["fabric.content.request_ref"], item["fabric.content.result_ref"]} <= seen
    handle.close(5.0)


def test_a_refused_multi_body_request_is_resent_one_body_per_request(
    node: FakeNode, tmp_path: Path
) -> None:
    """A Node whose request limit is below a batch (an operator's lower
    max_request_body_size) still receives every body; none is counted rejected."""
    spool = tmp_path / "spool"
    _backlog(node, spool, 5)
    node.max_records = 1
    handle = install_node(node, spool)
    assert wait_for(lambda: not records(spool), timeout=30.0)
    assert len({attrs["object_id"] for attrs, _ in node.content}) == 10
    assert set(node.records_per_request) == {1}
    assert handle.stats().content_rejected == 0
    assert len(_span_refs(node)) == 5
    handle.close(5.0)


def test_content_requests_in_flight_are_bounded(node: FakeNode, tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    config = {"content_batch_bodies": 1, "content_concurrency": 4}
    _backlog(node, spool, 10, **config)
    node.delay_s, node.peak = 0.05, 0
    handle = install_node(node, spool, **config)
    assert wait_for(lambda: not records(spool), timeout=30.0)
    assert 2 <= node.peak <= 5, node.peak  # 4 content requests (+ at most a span export)
    handle.close(5.0)


def test_one_body_one_request_remains_available(node: FakeNode, tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    config = {"content_batch_bodies": 1, "content_concurrency": 1}
    _backlog(node, spool, 4, **config)
    node.delay_s, node.peak = 0.02, 0
    handle = install_node(node, spool, **config)
    assert wait_for(lambda: not records(spool), timeout=30.0)
    assert node.records_per_request == [1] * 8 and node.peak == 1
    handle.close(5.0)


@pytest.mark.parametrize("count", [120])
def test_spooled_delivery_rate_at_a_round_trip_floor(
    node: FakeNode, tmp_path: Path, count: int
) -> None:
    """Benchmark (median of three runs): at a 50 ms round trip a process delivers at
    least five times the serial rate, which was 1 / (2 x RTT) = 10 exchanges/s."""
    node.delay_s = RTT_S
    rates = [_drain_rate(node, tmp_path / f"spool{run}", count) for run in range(3)]
    median = statistics.median(rates)
    assert median >= 5 * SERIAL_RATE, rates


def test_delivery_settings_from_the_environment() -> None:
    config, _ = config_from_env({"FABRIC_WIRE_CONTENT_BATCH_BODIES": "8",
                                 "FABRIC_WIRE_CONTENT_CONCURRENCY": "2",
                                 "FABRIC_WIRE_DRAIN_ON_EXIT_S": "30.5"})  # fmt: skip
    assert (config.content_batch_bodies, config.content_concurrency) == (8, 2)
    assert config.drain_on_exit_s == 30.5
    default, _ = config_from_env({})
    assert (default.content_batch_bodies, default.content_concurrency) == (32, 4)
    assert default.drain_on_exit_s == 0.0  # never delays an exit unless asked


@pytest.mark.parametrize(("name", "value"), [
    ("FABRIC_WIRE_CONTENT_BATCH_BODIES", "0"), ("FABRIC_WIRE_CONTENT_BATCH_BODIES", "257"),
    ("FABRIC_WIRE_CONTENT_BATCH_BODIES", "many"), ("FABRIC_WIRE_CONTENT_CONCURRENCY", "0"),
    ("FABRIC_WIRE_CONTENT_CONCURRENCY", "17"), ("FABRIC_WIRE_DRAIN_ON_EXIT_S", "-1"),
    ("FABRIC_WIRE_DRAIN_ON_EXIT_S", "3601"), ("FABRIC_WIRE_DRAIN_ON_EXIT_S", "soon"),
])  # fmt: skip
def test_delivery_settings_out_of_bounds_are_refused(name: str, value: str) -> None:
    with pytest.raises(ValueError, match=name.removeprefix("FABRIC_WIRE_").lower()
                       if value.lstrip("-").replace(".", "").isdigit() else name):  # fmt: skip
        config_from_env({name: value})
