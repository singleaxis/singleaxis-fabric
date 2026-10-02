# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Real final HTTP dispatch, receiver truth, retries, bypass and cancellation."""

from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from fabric import (
    ByteEvidenceConfig,
    ByteEvidenceRecorder,
    CallRecorder,
    LocalFilesystemContentStore,
)
from fabric.http_dispatch import FinalHTTPAdapter, IndependentHTTPWitness, _DispatchStream


def test_physical_retries_and_direct_bypass_are_independently_visible(tmp_path: Path) -> None:
    with IndependentHTTPWitness(
        tmp_path / "receiver", responses=((503, b"retry"), (200, b"done"))
    ) as witness:
        adapter = FinalHTTPAdapter(declared_url=witness.url)
        first = adapter.request(
            "POST", witness.url, b"post-transform", operation_id="op", attempt_id="one"
        )
        second = adapter.request(
            "POST", witness.url, b"post-transform", operation_id="op", attempt_id="two"
        )
        assert (first.status, second.status) == (503, 200)
        assert adapter.reconcile(witness.inventory())["status"] == "complete"
        bypass = FinalHTTPAdapter(declared_url=witness.url)
        bypass.request("POST", witness.url, b"bypass", operation_id="other", attempt_id="hidden")
        report = adapter.reconcile(witness.inventory())
        assert report["status"] == "unverified"
        assert len(report["unobserved_receiver_ids"]) == 1
        assert report["production_complete"] is False


def test_actual_call_recorder_final_bytes_stream_and_partial_cancel(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(str(tmp_path / "bytes"), tenant_id="tenant")
    writer = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=store, roles=frozenset({"model.request.messages", "model.output.messages"})
        )
    )
    calls = CallRecorder(writer, run_id="run", agent_id="agent", source_id="source")
    try:
        with IndependentHTTPWitness(
            tmp_path / "receiver", responses=((200, b"abcdef"),)
        ) as witness:
            adapter = FinalHTTPAdapter(declared_url=witness.url, recorder=calls)
            response = adapter.request(
                "POST", witness.url, b"FINAL request", operation_id="op", attempt_id="one"
            )
            assert response.body == b"abcdef"
            stream = adapter.stream(
                "POST",
                witness.url,
                b"FINAL stream",
                operation_id="stream",
                attempt_id="two",
                chunk_size=2,
            )
            assert list(stream) == [b"ab", b"cd", b"ef"]
            assert adapter.reconcile(witness.inventory())["status"] == "complete"
            snapshot = calls.snapshot()
            contents = [store.read(event["descriptor"]["ref"]) for event in snapshot["events"]]
            assert b"FINAL request" in contents and b"FINAL stream" in contents
            assert b"ab" in contents and b"ef" in contents
            partial = adapter.stream(
                "POST",
                witness.url,
                b"partial",
                operation_id="partial",
                attempt_id="three",
                chunk_size=2,
            )
            assert next(partial) == b"ab"
            cast(_DispatchStream, partial).close()
            assert adapter.reconcile(witness.inventory())["status"] == "unverified"
            assert calls.snapshot()["calls"][-1]["status"] == "partial"
    finally:
        writer.close()


def test_unknown_route_event_cap_mutation_and_noop_observer_withhold(tmp_path: Path) -> None:
    with IndependentHTTPWitness(tmp_path / "receiver") as witness:
        adapter = FinalHTTPAdapter(declared_url=witness.url, max_observations=1)
        adapter.request(
            "POST", witness.url + "?not-declared", b"safe", operation_id="op", attempt_id="one"
        )
        assert adapter.reconcile(witness.inventory())["status"] == "unverified"
        adapter.request("POST", witness.url, b"safe", operation_id="op", attempt_id="two")
        assert adapter.dropped_observations == 1
        assert adapter.reconcile(witness.inventory())["status"] == "unverified"
        assert (
            FinalHTTPAdapter(declared_url=witness.url).reconcile(witness.inventory())["status"]
            == "unverified"
        )


def test_transport_exception_and_unconsumed_stream_remain_unknown(tmp_path: Path) -> None:
    with IndependentHTTPWitness(tmp_path / "receiver") as witness:
        url = witness.url
    adapter = FinalHTTPAdapter(declared_url=url, timeout_s=0.1)
    with pytest.raises(OSError):
        adapter.request("POST", url, b"safe", operation_id="op", attempt_id="failed")
    assert adapter.observations[-1]["terminal"] == "error"
    assert adapter.reconcile([])["status"] == "unverified"
    stream = adapter.stream("POST", url, b"safe", operation_id="op", attempt_id="never")
    assert adapter.observations[-1]["terminal"] == "pending"
    cast(_DispatchStream, stream).close()
    assert adapter.reconcile([])["status"] == "unverified"


def test_recorder_start_failure_noop_and_after_send_failure_preserve_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalFilesystemContentStore(str(tmp_path / "bytes"), tenant_id="tenant")
    writer = ByteEvidenceRecorder(
        ByteEvidenceConfig(
            store=store, roles=frozenset({"model.request.messages", "model.output.messages"})
        )
    )
    calls = CallRecorder(writer, run_id="run", agent_id="agent", source_id="source")
    try:
        with IndependentHTTPWitness(tmp_path / "receiver") as witness:
            adapter = FinalHTTPAdapter(declared_url=witness.url, recorder=calls)

            def failed(*args: object, **kwargs: object) -> object:
                raise OSError("capture failed")

            monkeypatch.setattr(calls, "call", failed)
            assert (
                adapter.request(
                    "POST", witness.url, b"one", operation_id="op", attempt_id="one"
                ).body
                == b"ok"
            )
            monkeypatch.setattr(calls, "call", lambda *args, **kwargs: None)
            assert (
                adapter.request(
                    "POST", witness.url, b"two", operation_id="op", attempt_id="two"
                ).body
                == b"ok"
            )

            def after(
                payload: bytes, delegate: Callable[[bytes], object], **kwargs: object
            ) -> None:
                delegate(payload)
                raise OSError("capture after response failed")

            monkeypatch.setattr(calls, "call", after)
            assert (
                adapter.request(
                    "POST", witness.url, b"three", operation_id="op", attempt_id="three"
                ).body
                == b"ok"
            )
            assert len(witness.inventory()) == 3
            assert adapter.reconcile(witness.inventory())["status"] == "unverified"
            monkeypatch.setattr(calls, "stream", failed)
            assert list(
                adapter.stream("POST", witness.url, b"four", operation_id="op", attempt_id="four")
            ) == [b"ok"]
            assert len(witness.inventory()) == 4
    finally:
        writer.close()


def test_cancel_before_read_makes_no_physical_request(tmp_path: Path) -> None:
    with IndependentHTTPWitness(tmp_path / "receiver") as witness:
        adapter = FinalHTTPAdapter(declared_url=witness.url)
        stream = adapter.stream("POST", witness.url, b"cancel", operation_id="op", attempt_id="one")
        cast(_DispatchStream, stream).close()
        assert adapter.observations[-1]["terminal"] == "cancelled"
        assert list(stream) == []
        assert witness.inventory() == []
        assert adapter.reconcile([])["status"] == "unverified"
        assert FinalHTTPAdapter(declared_url=witness.url).reconcile([])["status"] == "unverified"
