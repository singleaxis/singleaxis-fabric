# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Round-5 hardening (Sol re-check of fd84163), each test failing on the code it guards:

- sol3 #1: delivery receipts stay inside the spool bound and never need new disk space. A
  drainer retires another writer's delivered record by renaming it in place to its
  receipt and truncating it; receipts are counted (size + fixed overhead) and bounded by
  count, oldest first. A record whose retirement fails stays pending and is not exported
  again until it is retired.
- sol3 #2: within a ``prefix*`` match no token of any class may hold a run of more than 4
  digits (but one 8-digit date), and a suffix holds at most 6 digits outside its date.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

import fabric._loss
import fabric._sequence
from fabric import wire
from fabric._loss import LossEmitter
from fabric._model_names import expose_model, hashed_model, model_allowed
from fabric.content_store import LocalFilesystemContentStore
from fabric.reconstruct import reconstruct
from fabric.wire import WireConfig
from fabric.wire._config import config_from_env
from fabric.wire._sender import Sender
from fabric.wire._spool import RECEIPT_OVERHEAD, Spool, marker_doc

from .test_wire_helpers import OPENAI_CHAT
from .test_wire_spool import SPOOL_MIN


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    for name in ("FABRIC_WIRE_ID_KEY", "FABRIC_WIRE_LABELS", "FABRIC_SOURCE_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("OTEL_SERVICE_NAME", raising=False)
    yield
    wire.uninstall()
    emitter.close(1.0)


class _Counting(SpanExporter):
    def __init__(self) -> None:
        self.exports = 0
        self.spans: list[ReadableSpan] = []

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        self.exports += len(spans)
        self.spans.extend(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


def _drainer(root: Path, max_bytes: int = SPOOL_MIN, **kw: Any) -> tuple[Spool, _Counting, Sender]:
    spool = Spool(str(root), max_bytes, **kw)
    assert spool.try_lock()
    exporter = _Counting()
    return spool, exporter, Sender(spool, exporter, LossEmitter(), content=None,
                                   service_name="svc-drainer")  # fmt: skip


def _final(index: int) -> dict[str, Any]:
    return marker_doc(("writer", 1, index, None, None, "final"))


def _physical(root: Path) -> tuple[int, int]:
    """``(bytes the bound must cover, receipts)`` as found on disk."""
    total = receipts = 0
    for path in root.iterdir():
        if path.name.endswith(".ack"):
            receipts += 1
            total += max(path.stat().st_size, RECEIPT_OVERHEAD)
        elif path.name.endswith((".rec", ".corrupt")) or path.name.startswith(".tmp-"):
            total += path.stat().st_size
    return total, receipts


# ------------------------------------------------------ sol3 #1: receipts inside the bound


@pytest.mark.filterwarnings("ignore:This process.*fork:DeprecationWarning")
def test_receipts_of_exited_writers_stay_inside_the_spool_bound(tmp_path: Path) -> None:
    """Sol's repro: 128 writer processes each spool a record and exit; a drainer delivers
    each. Before, 128 receipts were left uncounted under a 512-byte bound."""
    root = tmp_path / "spool"
    drainer, exporter, sender = _drainer(root, 512)
    for index in range(128):
        pid = os.fork()
        if pid == 0:  # pragma: no cover - the child writes one record and exits
            code = 1
            try:
                code = 0 if Spool(str(root), 512).write(_final(index)) else 3
            finally:
                os._exit(code)
        _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0, f"writer {index} was refused"
        assert sender._drain() == "more"
        drainer.rescan()
        physical, receipts = _physical(root)
        assert drainer.bytes == physical <= drainer.max_bytes
        assert receipts <= drainer.max_receipts == drainer.receipts
    assert exporter.exports == 128 and not drainer.names()
    assert all(p.stat().st_size == 0 for p in root.glob("*.ack"))
    drainer.release()


def test_receipts_count_against_the_bound_for_a_writer_that_never_settles(
    tmp_path: Path,
) -> None:
    """Sol's single-process repro: a writer that never consumes its receipts while a
    drainer delivers 512 of its records; nothing escapes the 512-byte bound."""
    root = tmp_path / "spool"
    writer = Spool(str(root), 512)
    drainer, exporter, sender = _drainer(root, 512)
    for index in range(512):
        writer.rescan()
        assert writer.write(_final(index)) is not None
        sender._drain()
        writer.rescan()
        assert writer.bytes == _physical(root)[0] <= writer.max_bytes
    assert exporter.exports == 512
    assert len(list(root.glob("*.ack"))) <= drainer.max_receipts
    writer.release()
    drainer.release()


def test_retiring_a_delivered_record_allocates_no_new_file(tmp_path: Path) -> None:
    """Sol's ENOSPC repro: creating any new file fails. Before, the receipt could not be
    created, so the record stayed and was exported on every drain."""
    root = tmp_path / "spool"
    name = Spool(str(root), SPOOL_MIN).write(_final(0))
    assert name is not None
    drainer, exporter, sender = _drainer(root)
    original = os.open

    def no_new_files(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if flags & os.O_CREAT:
            raise OSError(errno.ENOSPC, "no space")
        return original(path, flags, *args, **kwargs)

    with patch("os.open", no_new_files):
        for _ in range(4):
            sender._drain()
    assert exporter.exports == 1
    assert not (root / name).exists() and (root / (name + ".ack")).stat().st_size == 0
    drainer.release()


@pytest.mark.parametrize("failing", ["os.rename", "os.ftruncate", "os.fsync"])
def test_a_record_whose_retirement_fails_is_not_exported_again(
    tmp_path: Path, failing: str
) -> None:
    root = tmp_path / "spool"
    writer, loss = Spool(str(root), SPOOL_MIN), LossEmitter()
    writer_sender = Sender(writer, _Counting(), loss, content=None, service_name="svc-w")
    loss.attach(lambda: None)
    name = writer.write(_final(0), reserve=True)
    assert name is not None
    drainer, exporter, sender = _drainer(root)

    def full(*args: Any, **kwargs: Any) -> Any:
        raise OSError(errno.ENOSPC, "no space")

    with patch(failing, full):
        states = [sender._drain() for _ in range(4)]
    assert states == ["retry"] * 4 and exporter.exports == 1  # was 4 exports
    assert sender._drain() == "idle" and exporter.exports == 1  # retired, not re-exported
    assert not (root / name).exists() and (root / (name + ".ack")).stat().st_size == 0
    drainer.release()
    assert writer_sender.flush(2.0)  # the writer consumes its receipt: delivered
    assert not (root / (name + ".ack")).exists()
    assert writer_sender.close(2.0)


def test_an_own_record_being_retired_is_never_a_failure(tmp_path: Path) -> None:
    """A settle (the flush helper thread) running right after the drainer unlinked its own
    delivered record must see it delivered, not gone without a receipt."""
    drainer, _, sender = _drainer(tmp_path / "spool")
    name = drainer.write(_final(0), reserve=True)
    assert name is not None
    unlink = os.unlink

    def unlink_then_settle(path: Any, *args: Any, **kwargs: Any) -> None:
        unlink(path, *args, **kwargs)
        if str(path).endswith(".rec"):
            drainer.settle()  # the concurrent flush helper

    with patch("os.unlink", unlink_then_settle):
        assert sender._drain() == "more"
    assert drainer.failed == 0 and not drainer.pending()
    drainer.release()


def test_an_own_record_whose_unlink_fails_is_retried_not_turned_into_a_receipt(
    tmp_path: Path,
) -> None:
    root = tmp_path / "spool"
    drainer, exporter, sender = _drainer(root)
    name = drainer.write(_final(0), reserve=True)
    assert name is not None

    def broken(*args: Any, **kwargs: Any) -> None:
        raise OSError(errno.EIO, "io")

    with patch("os.unlink", broken):
        assert [sender._drain() for _ in range(3)] == ["retry"] * 3
    assert exporter.exports == 1 and (root / name).exists()
    assert drainer.failed == 0 and not drainer.pending()  # delivered: flush need not wait
    assert sender._drain() == "idle" and exporter.exports == 1
    assert not list(root.glob(name + "*"))  # unlinked, no receipt
    drainer.release()


def test_rescan_finishes_a_receipt_left_untruncated(tmp_path: Path) -> None:
    """A crash between the rename and the truncation leaves a full-size receipt: it is
    counted at its size, and the drainer's rescan truncates it."""
    root = tmp_path / "spool"
    name = Spool(str(root), SPOOL_MIN).write(_final(0))
    assert name is not None
    size = (root / name).stat().st_size
    (root / name).rename(root / (name + ".ack"))
    reader = Spool(str(root), SPOOL_MIN)
    assert reader.bytes == size and reader.receipts == 1  # at its size until truncated
    drainer = Spool(str(root), SPOOL_MIN)
    assert drainer.try_lock()
    drainer.rescan()
    assert drainer.bytes == RECEIPT_OVERHEAD and (root / (name + ".ack")).stat().st_size == 0
    drainer.release()


def test_receipts_expire_oldest_first_and_their_writer_counts_a_failure(
    tmp_path: Path,
) -> None:
    """Over the count bound the oldest receipt goes; its writer can no longer prove the
    delivery, so its flush and close are ``False`` (never a false success)."""
    root = tmp_path / "spool"
    writer, loss = Spool(str(root), SPOOL_MIN), LossEmitter()
    writer_sender = Sender(writer, _Counting(), loss, content=None, service_name="svc-w")
    loss.attach(lambda: None)
    names = [writer.write(_final(i), reserve=True) for i in range(3)]
    drainer, _, sender = _drainer(root, max_receipts=2)
    assert drainer.max_receipts == 2
    for name in names:  # one at a time: distinct retirement times
        assert name is not None
        sender._retiring[name] = None
        assert sender._retire_delivered()
    assert sorted(p.name for p in root.glob("*.ack")) == [f"{n}.ack" for n in names[1:]]
    assert drainer.receipts == 2
    drainer.release()
    assert not writer_sender.flush(2.0)  # names[0]: delivered, but no longer provable
    assert not list(root.glob("*.ack"))  # the two remaining receipts were consumed
    assert writer_sender.flush(2.0)
    assert not writer_sender.close(2.0)


def test_the_receipt_count_is_configurable(tmp_path: Path) -> None:
    env = {"FABRIC_WIRE_SPOOL_DIR": str(tmp_path), "FABRIC_WIRE_SPOOL_MAX_RECEIPTS": "64"}
    config, _ = config_from_env(env)
    assert config.spool_max_receipts == 64
    assert WireConfig(spool_dir=str(tmp_path)).spool_max_receipts == 4096
    with pytest.raises(ValueError, match="spool_max_receipts"):
        WireConfig(spool_dir=str(tmp_path), spool_max_receipts=0)
    with pytest.raises(ValueError, match="SPOOL_MAX_RECEIPTS"):
        config_from_env({**env, "FABRIC_WIRE_SPOOL_MAX_RECEIPTS": "many"})
    # Receipts never take more than an eighth of the bound.
    assert Spool(str(tmp_path), SPOOL_MIN, 1 << 20).max_receipts == SPOOL_MIN // 1024


# --------------------------------------------- sol3 #2: digits in every model-name token

SOL_COUNTEREXAMPLES = (
    "gpt-4o-v919876543210", "gpt-4o-a12345678901234567890", "gpt-4o-919876543210b",
)  # fmt: skip
REAL_NAMES = (
    "gpt-4o-2024-08-06", "claude-3-5-sonnet-20240620", "llama-3.1-70b-instruct",
    "qwen2.5-72b-instruct", "gpt-4.1-mini", "o3-mini", "gemini-1.5-pro-002",
    "gpt-4o-mini-2024-07-18", "claude-3-7-sonnet-20250219", "gpt-3.5-turbo-0125",
    "grok-2-1212", "llama3.1:8b", "qwen2.5-coder:32b", "gpt-4-0613",
)  # fmt: skip


@pytest.mark.parametrize("value", SOL_COUNTEREXAMPLES)
def test_a_digit_run_in_a_version_token_is_hashed(value: str) -> None:
    assert not model_allowed(value) and expose_model(value) == hashed_model(value)


@pytest.mark.parametrize("value", REAL_NAMES)
def test_real_model_names_stay_in_the_clear(value: str) -> None:
    assert model_allowed(value) and expose_model(value) == value


@pytest.mark.parametrize(
    ("value", "allowed"),
    [
        ("gpt-4o-1234b", True), ("gpt-4o-12345b", False),  # a run of 4 is the most
        ("gpt-4o-12-3456", False), ("gpt-4o-1234-5678", False),  # 7 and 9 digits
        ("gpt-3.5-turbo-0125-2024-01-25", True),  # the date's digits do not count
        ("gpt-4o-v20240620", False),  # a date only as a whole token
    ],
)  # fmt: skip
def test_the_suffix_digit_budget(value: str, allowed: bool) -> None:
    assert model_allowed(value) is allowed


@pytest.mark.parametrize("model", SOL_COUNTEREXAMPLES)
def test_an_actual_capture_hashes_a_digit_run_model_in_telemetry_and_report(
    tmp_path: Path, model: str
) -> None:
    """Sol's tee repro: the provider answers with an identifier inside a version token."""
    exporter = _Counting()
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
    handle = wire.install(store=store, source_id="agent-a", span_exporter=exporter,
                          patch_httpx=False, spool_dir=str(tmp_path / "spool"))  # fmt: skip
    reply = {"model": model, "choices": [
        {"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]}  # fmt: skip
    transport = wire.WireTransport(httpx.MockTransport(lambda r: httpx.Response(200, json=reply)))
    with wire.run("run-1"), httpx.Client(transport=transport) as client:
        client.post(OPENAI_CHAT, json={"model": "gpt-4o", "messages": []})
    assert handle.close(5.0)
    rows: list[dict[str, Any]] = []
    for span in exporter.spans:
        context = span.context
        assert context is not None
        rows.append({
            "kind": "span", "name": span.name, "trace_id": f"{context.trace_id:032x}",
            "span_id": f"{context.span_id:016x}", "start_ns": span.start_time,
            "end_ns": span.end_time, "attributes": dict(span.attributes or {}),
            "resource": dict(span.resource.attributes),
        })  # fmt: skip
    call = next(r for r in rows if r["name"] == "fabric.model_call")["attributes"]
    assert call["gen_ai.response.model"] == "m-" + hashlib.sha256(model.encode()).hexdigest()[:16]
    assert model not in json.dumps(rows)
    path = tmp_path / "spans.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    assert model not in json.dumps(reconstruct([path], store=store))
