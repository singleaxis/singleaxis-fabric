# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Run reconstruction verifier (spec 047 §9) over synthetic captures.

A small builder plays the role of the capture worker: it writes the exact
request and response bytes (JSON, SSE, gzip) as content-v2 objects into a
real ``LocalFilesystemContentStore`` and emits the matching exchange, loss
and heartbeat spans as sink JSONL rows — with no message hashes or tool-call
ids, exactly like capture. Every stitching fact is therefore derived from
the stored bytes. Each scenario damages the capture in one specific way and
asserts the gap and verdict the spec requires. Every report is validated
against the run-reconstruction schema *and* the contract validator's
semantic rules.
"""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import sys
import types
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from fabric._sequence import run_pseudonym as rid
from fabric._sequence import source_label
from fabric.content_store.local import LocalFilesystemContentStore
from fabric.reconstruct import ReconstructInputError, reconstruct
from fabric.reconstruct.__main__ import main
from fabric.reconstruct._ids import report_tenant_id
from fabric.reconstruct._inputs import pseudonym as pid

REPO_ROOT = Path(__file__).resolve().parents[3]
CAPTURE_ROOT = REPO_ROOT / "contracts" / "capture" / "v1"
TENANT = "tenant-a"
# Current capture emits source ids as s- pseudonyms and caller run ids as r- pseudonyms
# (decisions J1, H3): the report keeps those forms; legacy clear values are projected.
SOURCE = source_label("wire-3f9a1c2b7d4e5f60")
SOURCE_2 = source_label("wire-0000000000000002")
EPOCH = 1791331200000000000
TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
RUN = f"trace:{TRACE_ID}"
GENERATED_AT = datetime(2026, 10, 8, 9, 10, tzinfo=UTC)
BASE_NS = 1_791_331_200_000_000_000
MODEL = "gpt-4o-2024-08-06"


# --------------------------------------------------------------------------
# Contract validation
# --------------------------------------------------------------------------


def _load_validator() -> types.ModuleType:
    path = REPO_ROOT / "scripts" / "contracts" / "validate_capture_contracts.py"
    spec = importlib.util.spec_from_file_location("validate_capture_contracts", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("validate_capture_contracts", module)
    spec.loader.exec_module(module)
    return module


VALIDATOR = _load_validator()
SCHEMAS = {
    relative: json.loads((CAPTURE_ROOT / relative).read_text(encoding="utf-8"))
    for relative in VALIDATOR.SCHEMAS.values()
}


def validate(document: Mapping[str, Any]) -> None:
    """Schema plus semantic rules from scripts/contracts/validate_capture_contracts.py."""

    VALIDATOR.validate_document(document, SCHEMAS)


def sha_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stamp(ns: int) -> str:
    seconds, nanos = divmod(ns, 1_000_000_000)
    return datetime.fromtimestamp(seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S") + (
        f".{nanos:09d}Z"
    )


def sse(*events: Any, done: bool = True) -> bytes:
    body = b"".join(f"data: {json.dumps(event)}\n\n".encode() for event in events)
    return body + (b"data: [DONE]\n\n" if done else b"")


# --------------------------------------------------------------------------
# Synthetic capture builder
# --------------------------------------------------------------------------


@dataclass
class Exchange:
    exchange_id: str
    source_sequence: int
    run_id: str
    span: dict[str, Any]
    request_id: str | None
    response_id: str | None


_INNERMOST: Any = object()  # exchange(): tag with the innermost open scope of its run


def scope_uuid(number: int) -> str:
    """A deterministic lowercase uuid4 for ``fabric.run.scope_id``."""

    return f"{number:08x}-0000-4000-8000-{number:012x}"


class Capture:
    """Plays the capture worker: store byte objects + exchange/loss/heartbeat spans."""

    def __init__(
        self,
        root: Path,
        *,
        store: bool = True,
        source_id: str = SOURCE,
        epoch: int = EPOCH,
        id_prefix: str = "",
    ) -> None:
        self.root = root
        self.id_prefix = id_prefix
        self.store = (
            LocalFilesystemContentStore(root=str(root / "store"), tenant_id=TENANT)
            if store
            else None
        )
        self.source_id = source_id
        self.epoch = epoch
        self.rows: list[dict[str, Any]] = []
        self.sequence = 0
        self.exchanges: list[Exchange] = []
        # Open fabric.wire.run() scopes as (run id, scope id), innermost last.
        self.open_scopes: list[tuple[str, str]] = []
        self.scope_count = 0

    def _ns(self, sequence: int) -> int:
        return BASE_NS + sequence * 1_000_000_000

    def skip(self) -> int:
        """Allocate a sequence whose span never arrives (silent loss)."""

        value = self.sequence
        self.sequence += 1
        return value

    def _put(
        self,
        exchange_id: str,
        sequence: int,
        run_id: str,
        role: str,
        data: bytes,
        *,
        media_type: str,
        content_encoding: str,
        truncated: bool,
    ) -> str:
        assert self.store is not None
        object_id = f"{exchange_id}-{role.rsplit('.', 1)[-1]}"
        descriptor: dict[str, Any] = {
            "schema_version": "fabric.content-object/v2",
            "object_id": object_id,
            "tenant_id": TENANT,
            "role": role,
            "media_type": media_type,
            "encoding": "binary",
            "content_encoding": content_encoding,
            "representation": "truncated" if truncated else "exact",
            "transformations": ["truncate"] if truncated else [],
            "provenance": "protocol",
            "boundary": "provider_bound",
            "source_id": self.source_id,
            "source_epoch": self.epoch,
            "source_sequence": sequence,
            "captured_at": stamp(self._ns(sequence)),
            "status": "truncated" if truncated else "stored",
            "run_id": run_id,
            "operation_id": exchange_id,
            "stored_byte_length": len(data),
            "stored_sha256": "sha256:" + sha_hex(data),
            "ref": self.store.evidence_ref_for(object_id),
        }
        if truncated:
            descriptor["source_byte_length"] = len(data) * 2
        else:
            descriptor["source_byte_length"] = len(data)
            descriptor["source_sha256"] = "sha256:" + sha_hex(data)
        self.store.put_bytes_object(descriptor, data)
        return object_id

    def exchange(
        self,
        request: Any,
        response: Any = None,
        *,
        api: str = "openai.chat_completions",
        run_id: str = RUN,
        response_media: str | None = None,
        response_encoding: str = "identity",
        state: str = "complete",
        truncated: str | None = None,
        store_status: str | None = None,
        http_status: int | None = 200,
        scope_id: Any = _INNERMOST,
    ) -> Exchange:
        """Capture one exchange. Dict bodies are JSON-encoded; bytes are stored as-is.

        By default the exchange carries the innermost open scope of its run
        (``scope_id=None`` forces an unscoped exchange).
        """

        scope_id = self._innermost(run_id) if scope_id is _INNERMOST else scope_id
        sequence = self.skip()
        exchange_id = f"{self.id_prefix}ex-{sequence}"
        request_bytes = request if isinstance(request, bytes) else json.dumps(request).encode()
        response_bytes: bytes | None
        if response is None:
            response_bytes = None
        elif isinstance(response, bytes):
            response_bytes = response
        else:
            response_bytes = json.dumps(response).encode()
        if response_media is None:
            response_media = (
                "text/event-stream"
                if response_bytes is not None and response_bytes.startswith(b"data:")
                else "application/json"
            )
        if response_bytes is not None and response_encoding == "gzip":
            response_bytes = gzip.compress(response_bytes)
        if truncated == "response" and response_bytes is not None:
            response_bytes = response_bytes[: len(response_bytes) // 2]
        if truncated == "request":
            request_bytes = request_bytes[: len(request_bytes) // 2]
        if store_status is None:
            store_status = "stored" if self.store is not None else "disabled"
        attrs: dict[str, Any] = {
            "fabric.wire.exchange_id": exchange_id,
            "fabric.run.id": run_id,
            "fabric.source_id": self.source_id,
            "fabric.source.epoch": self.epoch,
            "fabric.source.sequence": sequence,
            "fabric.wire.api": api,
            "fabric.wire.request_sha256": sha_hex(request_bytes),
            "fabric.wire.response_state": state,
            "fabric.wire.truncated": truncated is not None,
            "fabric.wire.store_status": store_status,
            "gen_ai.operation.name": "chat",
            "gen_ai.provider.name": "openai",
            "http.request.method": "POST",
        }
        if http_status is not None:
            attrs["http.response.status_code"] = http_status
        attrs.update({} if scope_id is None else {"fabric.run.scope_id": scope_id})
        if response_bytes is not None:
            attrs["fabric.wire.response_sha256"] = sha_hex(response_bytes)
        request_id = response_id = None
        if self.store is not None and store_status == "stored":
            request_id = self._put(
                exchange_id,
                sequence,
                run_id,
                "model.exchange.request",
                request_bytes,
                media_type="application/json",
                content_encoding="identity",
                truncated=truncated == "request",
            )
            attrs["fabric.content.request_ref"] = request_id  # bare object id (rev 4)
            if response_bytes is not None:
                response_id = self._put(
                    exchange_id,
                    sequence,
                    run_id,
                    "model.exchange.response",
                    response_bytes,
                    media_type=response_media,
                    content_encoding=response_encoding,
                    truncated=truncated == "response",
                )
                attrs["fabric.content.result_ref"] = response_id
        start = self._ns(sequence)
        span = {
            "kind": "span",
            "trace_id": TRACE_ID,
            "span_id": f"{0x00F067AA0BA90200 + sequence + 0x1000 * len(self.id_prefix):016x}",
            "parent_span_id": None,
            "name": "fabric.model_call",
            "start_ns": start,
            "end_ns": start + 500_000_000,
            "attributes": attrs,
            "resource": {"service.name": "react-agent"},
        }
        self.rows.append(span)
        exchange = Exchange(exchange_id, sequence, run_id, span, request_id, response_id)
        self.exchanges.append(exchange)
        return exchange

    def _record(self, name: str, attributes: dict[str, Any]) -> None:
        ns = self._ns(self.sequence) + 900_000_000
        self.rows.append(
            {
                "kind": "span",
                "trace_id": "a" * 32,
                "span_id": f"{len(self.rows) + 1:016x}",
                "name": name,
                "start_ns": ns,
                "end_ns": ns,
                "attributes": {
                    "fabric.source_id": self.source_id,
                    "fabric.source.epoch": self.epoch,
                    **attributes,
                },
                "resource": {"service.name": "react-agent"},
            }
        )

    def loss(
        self, reason: str, first: int, last: int | None = None, count: int | None = None
    ) -> None:
        last = first if last is None else last
        self._record(
            "fabric.capture_loss",
            {
                "fabric.loss.reason": reason,
                "fabric.loss.count": count if count is not None else last - first + 1,
                "fabric.loss.first_sequence": first,
                "fabric.loss.last_sequence": last,
            },
        )

    def heartbeat(
        self,
        last: int | None = None,
        *,
        run_id: str | None = None,
        kind: str | None = "final",
        scope_id: str | None = None,
    ) -> None:
        """A heartbeat; the default is the ``final`` one a clean close writes.

        ``kind=None`` writes a heartbeat without ``fabric.heartbeat.kind``
        (what capture before spec 047 rev 5 wrote).
        """
        attributes: dict[str, Any] = {
            "fabric.heartbeat.last_sequence": self.sequence - 1 if last is None else last
        }
        if kind is not None:
            attributes["fabric.heartbeat.kind"] = kind
        if run_id is not None:
            attributes["fabric.run.id"] = run_id
        if scope_id is not None:
            attributes["fabric.run.scope_id"] = scope_id
        self._record("fabric.capture_heartbeat", attributes)

    def periodic(self, last: int | None = None) -> None:
        self.heartbeat(last, kind="periodic")

    def _innermost(self, run_id: str) -> str | None:
        return next((scope for run, scope in reversed(self.open_scopes) if run == run_id), None)

    def new_scope(self) -> str:
        self.scope_count += 1
        return scope_uuid(self.scope_count + 0x100 * len(self.id_prefix))

    def run_start(self, run_id: str, scope_id: str | None = None) -> str:
        """Enter a ``fabric.wire.run()`` block: a new scope and its run_start marker."""

        scope_id = scope_id or self.new_scope()
        self.open_scopes.append((run_id, scope_id))
        self.heartbeat(run_id=run_id, kind="run_start", scope_id=scope_id)
        return scope_id

    def run_end(self, run_id: str, scope_id: str | None = None) -> str:
        """Leave a block: by default the innermost open scope of ``run_id``.

        Without an open scope (its run_start was lost) a fresh scope id is used.
        """

        scope_id = scope_id or self._innermost(run_id) or self.new_scope()
        if (run_id, scope_id) in self.open_scopes:
            self.open_scopes.remove((run_id, scope_id))
        self.heartbeat(run_id=run_id, kind="run_end", scope_id=scope_id)
        return scope_id

    def repeat(self) -> None:
        """Re-export the last record under a new span id (a retried export)."""

        row = dict(self.rows[-1])
        row["span_id"] = f"{len(self.rows) + 1:016x}"
        self.rows.append(row)

    def object_path(self, object_id: str) -> Path:
        return self.root / "store" / TENANT / "evidence" / object_id

    def write(self, name: str = "spans.jsonl") -> Path:
        path = self.root / name
        path.write_text("".join(json.dumps(row) + "\n" for row in self.rows), encoding="utf-8")
        return path

    def reconstruct(self, **kwargs: Any) -> dict[str, Any]:
        kwargs.setdefault("store", self.store)
        kwargs.setdefault("generated_at", GENERATED_AT)
        document = reconstruct([self.write()], **kwargs)
        validate(document)
        return document


@pytest.fixture
def capture(tmp_path: Path) -> Capture:
    return Capture(tmp_path)


def only_run(document: Mapping[str, Any]) -> dict[str, Any]:
    runs = document["runs"]
    assert len(runs) == 1, [run["run_id"] for run in runs]
    return dict(runs[0])


def run_by_id(document: Mapping[str, Any], run_id: str) -> dict[str, Any]:
    return next(dict(run) for run in document["runs"] if run["run_id"] == run_id)


def gap_types(run: Mapping[str, Any]) -> list[str]:
    return [gap["gap_type"] for gap in run["gaps"]]


def real_gaps(run: Mapping[str, Any]) -> list[tuple[str, str | None]]:
    """``(gap_type, reason)`` of every gap that affects the verdict."""
    return [(gap["gap_type"], gap.get("reason")) for gap in run["gaps"] if gap["effect"] != "info"]


# --------------------------------------------------------------------------
# Conversations (real wire shapes)
# --------------------------------------------------------------------------

SYSTEM = {"role": "system", "content": "You are a weather agent."}
USER = {"role": "user", "content": "Weather in Paris and Rome?"}
TOOLS = [{"type": "function", "function": {"name": "get_weather", "parameters": {}}}]


def tool_call(call_id: str, city: str) -> dict[str, Any]:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": "get_weather", "arguments": json.dumps({"city": city})},
    }


def assistant_calls(call_id: str, city: str) -> dict[str, Any]:
    return {"role": "assistant", "content": None, "tool_calls": [tool_call(call_id, city)]}


def tool_result(call_id: str, text: str) -> dict[str, Any]:
    return {"role": "tool", "tool_call_id": call_id, "content": text}


def chat_response(message: dict[str, Any], rid: str, finish: str = "stop") -> dict[str, Any]:
    return {
        "id": rid,
        "object": "chat.completion",
        "model": MODEL,
        "choices": [{"index": 0, "message": {**message, "refusal": None}, "finish_reason": finish}],
        "usage": {"prompt_tokens": 20, "completion_tokens": 5, "total_tokens": 25},
    }


def chat_request(messages: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {"model": "gpt-4o", "messages": messages, "tools": TOOLS, **extra}


def react_turns() -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """A three-step ReAct loop: two tool calls, then the final answer."""

    first = [SYSTEM, USER]
    second = [*first, assistant_calls("call_a", "Paris"), tool_result("call_a", "18C")]
    third = [*second, assistant_calls("call_b", "Rome"), tool_result("call_b", "24C")]
    return [
        (chat_request(first), chat_response(assistant_calls("call_a", "Paris"), "chatcmpl-0")),
        (chat_request(second), chat_response(assistant_calls("call_b", "Rome"), "chatcmpl-1")),
        (
            chat_request(third),
            chat_response({"role": "assistant", "content": "Paris 18C, Rome 24C."}, "chatcmpl-2"),
        ),
    ]


def react_run(capture: Capture, *, heartbeat: bool = True, **kwargs: Any) -> list[Exchange]:
    exchanges = [capture.exchange(req, rsp, **kwargs) for req, rsp in react_turns()]
    if heartbeat:
        capture.heartbeat()
    return exchanges


# --------------------------------------------------------------------------
# Clean run
# --------------------------------------------------------------------------


def test_clean_three_turn_react_run_is_complete(capture: Capture) -> None:
    react_run(capture)
    document = capture.reconstruct()
    run = only_run(document)
    assert run["verdict"] == "complete_for_declared_scope"
    assert run["checks"] == {
        "sequence": "passed",
        "loss": "passed",
        "tail": "passed",
        "bytes": "passed",
        "stitching": "passed",
    }
    assert run["gaps"] == []
    assert run["declared_scope"] == {
        "windows": [
            {
                "source_id": SOURCE,
                "source_epoch": EPOCH,
                "first_sequence": 0,
                "last_sequence": 2,
                "heartbeat_sequence": 2,
                "closed_by": "final_heartbeat",
            }
        ],
    }
    assert run["threads"] == [{"thread_id": "thread-0", "exchange_ids": ["ex-0", "ex-1", "ex-2"]}]
    first, second, third = run["exchanges"]
    assert "continues_exchange_id" not in first
    assert second["continues_exchange_id"] == "ex-0"
    assert third["continues_exchange_id"] == "ex-1"
    assert [ex["input_message_count"] for ex in run["exchanges"]] == [2, 4, 6]
    assert [ex["output_message_count"] for ex in run["exchanges"]] == [1, 1, 1]
    assert first["tool_call_ids_emitted"] == [pid("call_a")]
    assert second["tool_call_ids_consumed"] == [pid("call_a")]
    assert third["tool_call_ids_consumed"] == [pid("call_a"), pid("call_b")]
    assert third["tool_call_ids_emitted"] == []
    assert first["model"] == MODEL
    assert first["response_id"] == pid("chatcmpl-0")
    assert first["parse_status"] == "ok"
    assert first["objects"]["request"]["verification"] == "verified"
    assert first["objects"]["response"]["object_id"] == "ex-0-response"
    assert document["sources"] == [
        {
            "source_id": SOURCE,
            "source_epoch": EPOCH,
            "exchanges": 3,
            "heartbeat_sequence": 2,
            "missing_sequences": [],
            "loss_ranges": [],
            "final_heartbeat_sequence": 2,
        }
    ]
    tenant = report_tenant_id(TENANT)  # the report never names the tenant in clear (J1)
    assert document["inputs"]["store"] == {"kind": "local", "tenant_id": tenant}


def test_report_carries_no_content(capture: Capture) -> None:
    react_run(capture)
    text = json.dumps(capture.reconstruct())
    for needle in ("Paris 18C", "weather agent", "18C", "get_weather"):
        assert needle not in text


def test_report_is_deterministic(capture: Capture) -> None:
    react_run(capture)
    assert capture.reconstruct() == capture.reconstruct()


# --------------------------------------------------------------------------
# Completeness: sequences, losses, heartbeats
# --------------------------------------------------------------------------


def test_dropped_exchange_span_is_a_sequence_gap(capture: Capture) -> None:
    turns = react_turns()
    capture.exchange(*turns[0])
    capture.skip()  # ex-1's span never arrives and no loss record names it
    capture.exchange(*turns[2])
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert run["checks"]["sequence"] == "failed"
    gap = next(g for g in run["gaps"] if g["gap_type"] == "sequence_gap")
    assert (gap["first_sequence"], gap["last_sequence"]) == (1, 1)
    # call_b was emitted by the missing exchange.
    unmatched = [
        g for g in run["gaps"] if g["gap_type"] == "unmatched_tool_call" and g["effect"] != "info"
    ]
    assert [(g["tool_call_id"], g["reason"]) for g in unmatched] == [
        (pid("call_b"), "consumed_not_emitted")
    ]


def test_queue_full_loss_is_partial_for_adjacent_runs_only(capture: Capture) -> None:
    first_turn = react_turns()[0]
    runs = ["trace:" + digit * 32 for digit in "123"]
    capture.exchange(*first_turn, run_id=runs[0])  # 0
    capture.exchange(*first_turn, run_id=runs[0])  # 1
    lost = capture.skip()  # 2
    capture.loss("queue_full", lost)
    capture.exchange(*first_turn, run_id=runs[1])  # 3
    capture.exchange(*first_turn, run_id=runs[1])  # 4
    capture.exchange(*first_turn, run_id=runs[2])  # 5
    capture.exchange(*first_turn, run_id=runs[2])  # 6
    capture.heartbeat()
    document = capture.reconstruct()
    for run_id in runs[:2]:
        run = run_by_id(document, run_id)
        assert run["verdict"] == "partial"
        assert run["checks"]["loss"] == "failed"
        assert run["checks"]["sequence"] == "passed"
        assert run["gaps"][0] == {
            "gap_type": "loss",
            "effect": "partial",
            "source_id": SOURCE,
            "source_epoch": EPOCH,
            "first_sequence": 2,
            "last_sequence": 2,
            "reason": "queue_full",
        }
    assert run_by_id(document, runs[2])["verdict"] == "complete_for_declared_scope"
    (source,) = document["sources"]
    assert source["missing_sequences"] == [[2, 2]]
    assert source["loss_ranges"] == [
        {"reason": "queue_full", "first_sequence": 2, "last_sequence": 2, "count": 1}
    ]


def test_missing_range_split_into_loss_and_unexplained_parts(capture: Capture) -> None:
    capture.exchange(*react_turns()[0])
    for _ in range(3):
        capture.skip()
    capture.loss("shutdown", 1, 2)
    capture.exchange(*react_turns()[0])
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    ranges = [
        (g["gap_type"], g["first_sequence"], g["last_sequence"], g.get("reason"))
        for g in run["gaps"]
        if g["gap_type"] in ("loss", "sequence_gap")
    ]
    assert ranges == [("loss", 1, 2, "shutdown"), ("sequence_gap", 3, 3, None)]
    assert run["checks"]["sequence"] == "failed"
    assert run["checks"]["loss"] == "failed"


def test_loss_inside_open_run_window_is_partial_via_markers(capture: Capture) -> None:
    scoped = rid("agent-run-7")
    other = "trace:" + "9" * 32
    capture.exchange(*react_turns()[0], run_id=other)  # 0
    capture.run_start(scoped)  # last_sequence 0
    capture.exchange(*react_turns()[0], run_id=scoped)  # 1
    capture.exchange(*react_turns()[0], run_id=other)  # 2
    capture.skip()  # 3: lost while the scoped run was open
    capture.loss("internal_error", 3)
    capture.exchange(*react_turns()[0], run_id=other)  # 4
    capture.run_end(scoped)  # last_sequence 4
    capture.exchange(*react_turns()[0], run_id=other)  # 5
    capture.heartbeat()
    run = run_by_id(capture.reconstruct(), scoped)
    assert run["verdict"] == "partial"
    window = run["declared_scope"]["windows"][0]
    assert (window["first_sequence"], window["last_sequence"]) == (1, 4)
    assert window["closed_by"] == "run_markers"
    assert [g["gap_type"] for g in run["gaps"] if g["effect"] != "info"] == ["loss"]


def test_without_run_end_a_later_loss_is_never_complete(capture: Capture) -> None:
    """Review fix: a run_start without its run_end leaves the run's end unknown."""
    scoped = rid("agent-run-8")
    other = "trace:" + "9" * 32
    capture.run_start(scoped)  # -1
    capture.exchange(*react_turns()[0], run_id=scoped)  # 0
    capture.exchange(*react_turns()[0], run_id=other)  # 1
    capture.skip()  # 2
    capture.loss("queue_full", 2)
    capture.exchange(*react_turns()[0], run_id=other)  # 3
    capture.heartbeat()
    document = capture.reconstruct()
    run = run_by_id(document, scoped)
    window = run["declared_scope"]["windows"][0]
    assert (window["first_sequence"], window["last_sequence"]) == (0, 0)
    assert "closed_by" not in window
    assert run["verdict"] == "unverified"
    found = {
        (g["gap_type"], g["effect"], g.get("reason")) for g in run["gaps"] if g["effect"] != "info"
    }
    assert found == {
        ("loss", "unverified", "queue_full"),
        ("tail_unverified", "unverified", "run_not_closed"),
    }
    assert run_by_id(document, other)["verdict"] == "partial"


def test_run_killed_inside_scope_is_not_complete(capture: Capture) -> None:
    """Review fix: run_start, two calls, flush, then a crash before run_end."""
    capture.run_start(rid("agent-run-k"))  # -1
    capture.exchange(*react_turns()[0], run_id=rid("agent-run-k"))  # 0
    capture.exchange(*react_turns()[0], run_id=rid("agent-run-k"))  # 1
    capture.periodic()  # 1
    # seq 2 is allocated, then SIGKILL: no span, no loss, no run_end.
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"
    assert run["checks"]["tail"] == "failed"
    assert [(g["gap_type"], g.get("reason")) for g in run["gaps"] if g["effect"] != "info"] == [
        ("tail_unverified", "run_not_closed")
    ]


def test_back_to_back_runs_and_reread_files_dedupe_by_logical_identity(
    capture: Capture, tmp_path: Path
) -> None:
    """Back-to-back run() blocks repeat a last_sequence; a re-read file repeats spans."""
    scoped = rid("agent-run-p")
    capture.run_start(scoped)  # -1
    capture.exchange(*react_turns()[0], run_id=scoped)  # 0
    capture.run_end(scoped)  # 0
    capture.run_start(scoped)  # 0 (same last_sequence as the run_end, other kind)
    capture.exchange(*react_turns()[0], run_id=scoped)  # 1
    capture.run_end(scoped)  # 1
    assert only_run(capture.reconstruct())["verdict"] == "complete_for_observed_scopes"
    path = capture.write()
    document = reconstruct([path, path], store=capture.store, generated_at=GENERATED_AT)
    validate(document)
    assert only_run(document)["verdict"] == "complete_for_observed_scopes"
    assert [scope["verdict"] for scope in document["scopes"]] == ["complete_for_declared_scope"] * 2


def test_interleaved_unscoped_run_with_a_lost_last_call_is_not_complete(
    capture: Capture, tmp_path: Path
) -> None:
    """Review fix: R's lost last call sits between S's calls; R must not be complete."""
    r_run, s_run = "trace:" + "1" * 32, "trace:" + "2" * 32
    capture.exchange(*react_turns()[0], run_id=r_run)  # 0
    capture.exchange(*react_turns()[0], run_id=s_run)  # 1
    capture.skip()  # 2: R's second call, dropped
    capture.loss("queue_full", 2)
    capture.exchange(*react_turns()[0], run_id=s_run)  # 3
    capture.heartbeat()
    document = capture.reconstruct()
    r_report = run_by_id(document, r_run)
    assert r_report["verdict"] == "unverified"
    real = [(g["gap_type"], g["effect"]) for g in r_report["gaps"] if g["effect"] != "info"]
    assert real == [("loss", "unverified")]
    assert run_by_id(document, s_run)["verdict"] == "partial"
    argv = ["--spans", str(capture.write()), "--store-root", str(tmp_path / "store")]
    assert main([*argv, "--tenant", TENANT, "--run", r_run]) == 1


def test_unscoped_run_ignores_losses_before_its_first_call(capture: Capture) -> None:
    capture.exchange(*react_turns()[0], run_id="trace:" + "1" * 32)  # 0
    capture.skip()  # 1
    capture.loss("queue_full", 1)
    capture.exchange(*react_turns()[0], run_id="trace:" + "1" * 32)  # 2
    capture.exchange(*react_turns()[0], run_id="trace:" + "3" * 32)  # 3
    capture.exchange(*react_turns()[0], run_id="trace:" + "3" * 32)  # 4
    capture.heartbeat()
    document = capture.reconstruct()
    assert run_by_id(document, "trace:" + "3" * 32)["verdict"] == "complete_for_declared_scope"


def test_marker_only_run_with_lost_calls_is_partial(capture: Capture) -> None:
    capture.run_start(rid("agent-run-9"))  # -1
    capture.skip()  # 0: the run's only call, lost
    capture.loss("queue_full", 0)
    capture.run_end(rid("agent-run-9"))  # 0
    run = only_run(capture.reconstruct())
    assert run["exchanges"] == []
    assert run["verdict"] == "partial"
    assert run["checks"]["bytes"] == "not_applicable"


def test_missing_heartbeat_is_an_unverified_tail(capture: Capture) -> None:
    react_run(capture, heartbeat=False)
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"
    assert run["checks"]["tail"] == "failed"
    assert run["gaps"] == [
        {
            "gap_type": "tail_unverified",
            "effect": "unverified",
            "source_id": SOURCE,
            "source_epoch": EPOCH,
            "reason": "no_final_heartbeat",
        }
    ]
    assert "closed_by" not in run["declared_scope"]["windows"][0]


def test_periodic_heartbeat_never_closes_a_run(capture: Capture) -> None:
    turns = react_turns()
    capture.exchange(*turns[0])
    capture.exchange(*turns[1])
    capture.periodic()  # covers every call so far, but the process went on
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"
    assert real_gaps(run) == [("tail_unverified", "no_final_heartbeat")]


def test_heartbeat_reveals_lost_tail_exchange(capture: Capture) -> None:
    turns = react_turns()
    capture.exchange(*turns[0])
    capture.exchange(*turns[1])
    capture.skip()  # final call allocated but never exported
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert "sequence_gap" in gap_types(run)


# --------------------------------------------------------------------------
# Tail evidence: heartbeat kinds and the rev-5 verdict rule (re-review fixes)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["periodic", None])
def test_lost_final_call_after_a_heartbeat_without_markers_is_unverified(
    capture: Capture, kind: str | None
) -> None:
    """Codex re-review report1 #4 / report3 #3.

    Exchange 0 and a heartbeat at 0 arrive; call 1 is allocated and the
    process dies before anything else is exported. Without a final heartbeat
    nothing proves call 1 never happened, so the run is not complete. A
    heartbeat without a kind (pre-rev-5 capture) is treated the same way.
    """
    capture.exchange(*react_turns()[0])  # 0
    capture.heartbeat(kind=kind)  # last_sequence 0
    capture.skip()  # 1: allocated, then process death
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"
    assert [g for g in run["gaps"] if g["effect"] != "info"] == [
        {
            "gap_type": "tail_unverified",
            "effect": "unverified",
            "source_id": SOURCE,
            "source_epoch": EPOCH,
            "reason": "no_final_heartbeat",
        }
    ]


def test_retried_run_start_never_closes_a_run(capture: Capture) -> None:
    """Codex re-review report1 #5 / report3 #2.

    The Node stored the run_start but its acknowledgement was lost, so the
    retry exported the same record again under a new span id. Counting spans
    made two markers look like an entry/exit pair. Deduplicated by logical
    identity it is one run_start without a run_end.
    """
    scoped = rid("open-run")
    capture.run_start(scoped)  # -1
    capture.repeat()  # the retry: same record, new span id
    capture.exchange(*react_turns()[0], run_id=scoped)  # 0
    capture.periodic()  # 0
    capture.skip()  # 1: the run's second call, lost with the process
    rows = [row for row in capture.rows if row["name"] == "fabric.capture_heartbeat"]
    assert rows[0]["span_id"] != rows[1]["span_id"]
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"
    assert real_gaps(run) == [("tail_unverified", "run_not_closed")]


def test_retried_run_start_with_a_final_heartbeat_is_still_unverified(capture: Capture) -> None:
    scoped = rid("open-run")
    capture.run_start(scoped)
    capture.repeat()  # retry duplicate
    capture.exchange(*react_turns()[0], run_id=scoped)
    capture.heartbeat()  # final: the run had markers, so only markers can close it
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"
    assert ("tail_unverified", "run_not_closed") in real_gaps(run)


def test_clean_final_heartbeat_completes_an_unmarked_run(capture: Capture) -> None:
    react_run(capture)  # three exchanges, then the final heartbeat of a clean close
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_declared_scope"
    assert run["declared_scope"]["windows"][0]["closed_by"] == "final_heartbeat"


def test_closed_run_markers_complete_a_run_without_a_final_heartbeat(capture: Capture) -> None:
    scoped = rid("agent-run-c")
    capture.run_start(scoped)
    capture.repeat()  # a retried duplicate is harmless
    for request, response in react_turns():
        capture.exchange(request, response, run_id=scoped)
    capture.run_end(scoped)
    capture.repeat()  # so is a retried run_end
    capture.exchange(*react_turns()[0], run_id="trace:" + "5" * 32)  # later, other work
    capture.skip()  # a later loss belongs to other work: the run's end is proven
    run = run_by_id(capture.reconstruct(), scoped)
    assert run["verdict"] == "complete_for_observed_scopes"
    window = run["declared_scope"]["windows"][0]
    assert (window["first_sequence"], window["last_sequence"], window["closed_by"]) == (
        0,
        2,
        "run_markers",
    )
    assert window["scope_id"] == run["scopes"][0]["scope_id"]


def test_second_run_block_without_its_run_end_is_not_closed(capture: Capture) -> None:
    scoped = rid("agent-run-twice")
    capture.run_start(scoped)  # -1
    capture.exchange(*react_turns()[0], run_id=scoped)  # 0
    capture.run_end(scoped)  # 0
    capture.run_start(scoped)  # 0
    capture.exchange(*react_turns()[0], run_id=scoped)  # 1
    capture.periodic()  # 1; the second block's run_end never arrives
    capture.skip()  # 2: lost
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"
    assert ("tail_unverified", "run_not_closed") in real_gaps(run)


def test_exchange_after_run_end_is_outside_the_markers(capture: Capture) -> None:
    scoped = rid("agent-run-leak")
    capture.run_start(scoped)  # -1
    capture.exchange(*react_turns()[0], run_id=scoped)  # 0
    capture.run_end(scoped)  # 0
    capture.exchange(*react_turns()[0], run_id=scoped)  # 1: a task that outlived the block
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"
    assert ("tail_unverified", "exchange_outside_run_markers") in real_gaps(run)


def test_run_end_alone_never_closes_a_run(capture: Capture) -> None:
    capture.exchange(*react_turns()[0], run_id=rid("agent-run-e"))  # 0
    capture.run_end(rid("agent-run-e"))  # 0; the run_start was lost
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"


def test_open_run_with_only_a_run_start_is_reported_unverified(capture: Capture) -> None:
    capture.run_start(rid("agent-run-s"))  # -1
    capture.skip()  # 0: its only call, lost with the process
    capture.periodic()
    run = only_run(capture.reconstruct())
    assert run["run_id"] == rid("agent-run-s")
    assert run["verdict"] == "partial"  # sequence 0 is known missing inside its window
    assert ("tail_unverified", "run_not_closed") in real_gaps(run)


def test_activity_after_the_final_heartbeat_reopens_the_epoch(capture: Capture) -> None:
    """A final heartbeat proves the epoch's end only if nothing came after it."""
    capture.exchange(*react_turns()[0], run_id="trace:" + "1" * 32)  # 0
    capture.heartbeat()  # final at 0
    capture.exchange(*react_turns()[0], run_id="trace:" + "2" * 32)  # 1: the epoch went on
    document = capture.reconstruct()
    for run in document["runs"]:
        assert run["verdict"] == "unverified"
        assert real_gaps(run) == [("tail_unverified", "activity_after_final_heartbeat")]


def test_an_unscoped_exchange_on_another_source_keeps_a_scoped_run_open(tmp_path: Path) -> None:
    first = Capture(tmp_path, id_prefix="a")
    first.run_start(rid("agent-run-m"))
    first.exchange(*react_turns()[0], run_id=rid("agent-run-m"))
    first.run_end(rid("agent-run-m"))
    second = Capture(tmp_path, source_id=SOURCE_2, id_prefix="b")
    second.exchange(*react_turns()[0], run_id=rid("agent-run-m"))
    second.heartbeat()  # final, but the run is scoped and this call is in no scope
    first.rows.extend(second.rows)
    run = only_run(first.reconstruct())
    assert run["verdict"] == "unverified"
    assert ("tail_unverified", "exchange_outside_run_markers") in real_gaps(run)
    unscoped = [w for w in run["declared_scope"]["windows"] if "scope_id" not in w]
    assert [(w["source_id"], "closed_by" in w) for w in unscoped] == [(SOURCE_2, False)]


@pytest.mark.parametrize(
    "attributes",
    [
        {"fabric.heartbeat.kind": "shutdown"},  # outside the closed vocabulary
        {"fabric.heartbeat.kind": "run_end"},  # a marker that names no run
        {"fabric.heartbeat.kind": "run_end", "fabric.run.id": rid("agent-run-x")},  # 047: no scope
        {
            "fabric.heartbeat.kind": "run_end",
            "fabric.run.id": rid("agent-run-x"),
            "fabric.run.scope_id": "00000001-0000-4000-8000-00000000000Z",  # not a uuid4
        },
        {"fabric.heartbeat.kind": "final", "fabric.run.id": rid("agent-run-x")},
    ],
)
def test_malformed_heartbeat_kinds_never_close_a_run(
    capture: Capture, attributes: dict[str, Any]
) -> None:
    capture.run_start(rid("agent-run-x"))
    capture.exchange(*react_turns()[0], run_id=rid("agent-run-x"))
    capture._record(
        "fabric.capture_heartbeat",
        {"fabric.heartbeat.last_sequence": capture.sequence - 1, **attributes},
    )
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"


def test_codex_tail_probe_spans_are_never_complete(tmp_path: Path) -> None:
    """The re-review probe shapes, replayed exactly as pre-rev-5 capture exported them.

    Kind-less heartbeats (with and without a run id) are neither markers nor
    a final heartbeat, so neither the lost-final-call capture nor the
    retried-marker capture can be complete.
    """
    for retried in (False, True):
        capture = Capture(tmp_path / str(retried))
        run_id = rid("open-run") if retried else RUN
        if retried:
            capture.heartbeat(run_id=run_id, kind=None)  # entry marker
            capture.heartbeat(run_id=run_id, kind=None)  # its retry, new span id
        capture.exchange(*react_turns()[0], run_id=run_id)
        capture.heartbeat(kind=None)
        capture.skip()
        assert only_run(capture.reconstruct())["verdict"] == "unverified"


def test_two_epochs_are_accounted_separately(tmp_path: Path) -> None:
    first = Capture(tmp_path, id_prefix="a")
    react_run(first)
    second = Capture(tmp_path, epoch=EPOCH + 1, id_prefix="b")
    second.exchange(*react_turns()[0])
    second.skip()
    second.heartbeat()
    first.rows.extend(second.rows)
    document = first.reconstruct()
    run = only_run(document)
    assert [w["source_epoch"] for w in run["declared_scope"]["windows"]] == [EPOCH, EPOCH + 1]
    assert run["verdict"] == "partial"
    assert [s["missing_sequences"] for s in document["sources"]] == [[], [[1, 1]]]


# --------------------------------------------------------------------------
# Bytes
# --------------------------------------------------------------------------


def test_flipped_stored_byte_is_a_digest_mismatch(capture: Capture) -> None:
    exchanges = react_run(capture)
    assert exchanges[1].response_id is not None
    path = capture.object_path(exchanges[1].response_id)
    data = bytearray(path.read_bytes())
    data[10] ^= 0x01
    path.write_bytes(bytes(data))
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert run["checks"]["bytes"] == "failed"
    gap = next(g for g in run["gaps"] if g["gap_type"] == "digest_mismatch")
    assert gap == {
        "gap_type": "digest_mismatch",
        "effect": "partial",
        "exchange_id": "ex-1",
        "object_role": "response",
        "reason": "content_digest",
    }
    exchange = run["exchanges"][1]
    assert exchange["objects"]["response"]["verification"] == "digest_mismatch"
    assert exchange["parse_status"] == "not_checked"
    assert run["checks"]["stitching"] == "skipped"


def test_descriptor_disagreement_is_a_digest_mismatch(capture: Capture) -> None:
    exchanges = react_run(capture)
    assert exchanges[0].request_id is not None
    meta = capture.object_path(exchanges[0].request_id).parent / "meta"
    sidecar = meta / f"{exchanges[0].request_id}.json"
    descriptor = json.loads(sidecar.read_text())
    descriptor["operation_id"] = "ex-99"
    sidecar.write_text(json.dumps(descriptor))
    run = only_run(capture.reconstruct())
    gap = next(g for g in run["gaps"] if g["gap_type"] == "digest_mismatch")
    assert gap["reason"] == "sidecar_mismatch"
    assert run["verdict"] == "partial"


def test_deleted_object_is_a_missing_object(capture: Capture) -> None:
    exchanges = react_run(capture)
    assert exchanges[2].request_id is not None
    capture.object_path(exchanges[2].request_id).unlink()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    gap = next(g for g in run["gaps"] if g["gap_type"] == "missing_object")
    assert gap == {
        "gap_type": "missing_object",
        "effect": "partial",
        "exchange_id": "ex-2",
        "object_role": "request",
        "reason": "absent",
    }
    assert run["exchanges"][2]["objects"]["request"]["verification"] == "missing"


def test_store_failure_without_ref_is_a_missing_object(capture: Capture) -> None:
    turns = react_turns()
    capture.exchange(*turns[0])
    capture.exchange(*turns[1], store_status="failed")
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    missing = [g for g in run["gaps"] if g["gap_type"] == "missing_object"]
    assert {(g["object_role"], g["reason"]) for g in missing} == {
        ("request", "not_stored"),
        ("response", "not_stored"),
    }
    assert run["exchanges"][1]["objects"]["request"]["verification"] == "not_stored"


def test_omitting_the_store_is_unverified(capture: Capture) -> None:
    react_run(capture)
    run = only_run(capture.reconstruct(store=None))
    assert run["verdict"] == "unverified"
    assert run["checks"]["bytes"] == "skipped"
    assert run["checks"]["stitching"] == "skipped"
    assert run["gaps"] == []
    assert run["exchanges"][0]["objects"]["request"]["verification"] == "not_checked"
    assert len(run["threads"]) == 3


def test_store_disabled_at_capture_is_unverified(tmp_path: Path) -> None:
    capture = Capture(tmp_path, store=False)
    react_run(capture)
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id=TENANT)
    run = only_run(capture.reconstruct(store=store))
    assert run["verdict"] == "unverified"
    assert run["checks"]["bytes"] == "skipped"


def test_truncated_response_is_partial(capture: Capture) -> None:
    turns = react_turns()
    capture.exchange(*turns[0])
    capture.exchange(*turns[1], truncated="response")
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    gap = next(g for g in run["gaps"] if g["gap_type"] == "truncated")
    assert gap["object_role"] == "response"
    assert run["exchanges"][1]["objects"]["response"]["verification"] == "verified"
    assert run["exchanges"][1]["parse_status"] == "truncated"
    assert "unparsed_exchange" not in gap_types(run)


def test_spans_carry_bare_object_ids_that_resolve_through_the_store(capture: Capture) -> None:
    exchanges = react_run(capture)
    attributes = exchanges[0].span["attributes"]
    assert attributes["fabric.content.request_ref"] == exchanges[0].request_id
    assert "/" not in attributes["fabric.content.result_ref"]
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_declared_scope"
    objects = run["exchanges"][0]["objects"]
    assert objects["request"]["object_id"] == exchanges[0].request_id
    assert objects["request"]["verification"] == "verified"


def test_store_objects_are_resolved_by_object_id_not_recorded_path(capture: Capture) -> None:
    """Legacy spans (rev 3) carry a full ref; only its last segment is used."""

    react_run(capture)
    for row in capture.rows:
        attributes = row["attributes"]
        for key in ("fabric.content.request_ref", "fabric.content.result_ref"):
            if key in attributes:
                object_id = attributes[key].rsplit("/", 1)[-1]
                attributes[key] = f"file:///elsewhere/other/{object_id}"
    document = capture.reconstruct()
    run = only_run(document)
    assert run["verdict"] == "complete_for_declared_scope"
    assert run["exchanges"][0]["objects"]["request"]["verification"] == "verified"


def test_report_never_names_a_store_location(capture: Capture) -> None:
    """Codex re-review report2: the report carried each object's resolved path."""
    react_run(capture)
    document = capture.reconstruct()
    text = json.dumps(document)
    assert str(capture.root / "store") not in text
    assert "file://" not in text
    for entry in only_run(document)["exchanges"]:
        for checked in entry["objects"].values():
            assert set(checked) <= {"object_id", "sha256", "byte_length", "verification"}


def test_conflicting_duplicate_span_is_a_digest_mismatch(capture: Capture) -> None:
    exchanges = react_run(capture)
    duplicate = json.loads(json.dumps(exchanges[1].span))
    duplicate["attributes"]["fabric.wire.response_state"] = "closed_early"
    capture.rows.append(duplicate)
    capture.rows.append(json.loads(json.dumps(exchanges[0].span)))  # identical: ignored
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    gaps = [g for g in run["gaps"] if g["gap_type"] == "digest_mismatch"]
    assert [(g.get("exchange_id"), g.get("first_sequence"), g["reason"]) for g in gaps] == [
        (None, 1, "conflicting_claim"),  # the window holding the conflicted sequence
        ("ex-1", None, "conflicting_duplicate"),
    ]
    assert run["counts"]["exchanges"] == 3


def test_invalid_span_values_unplace_the_exchange(capture: Capture) -> None:
    exchanges = react_run(capture)
    exchanges[1].span["attributes"]["fabric.wire.response_state"] = "transport_error"
    exchanges[2].span["attributes"]["fabric.wire.request_sha256"] = "sha256:" + "0" * 64
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert [ex["exchange_id"] for ex in run["exchanges"]] == ["ex-0"]


# --------------------------------------------------------------------------
# Stitching from stored bytes
# --------------------------------------------------------------------------


def test_prefix_break_is_recorded_not_judged(capture: Capture) -> None:
    turns = react_turns()
    capture.exchange(*turns[0])
    rewritten = [SYSTEM, {"role": "user", "content": "Only Paris, please."}]
    capture.exchange(chat_request(rewritten), turns[1][1])
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_declared_scope"
    breaks = [g for g in run["gaps"] if g["gap_type"] == "prefix_break"]
    assert breaks == [
        {
            "gap_type": "prefix_break",
            "effect": "info",
            "exchange_id": "ex-1",
            "reason": "history_rewritten",
        }
    ]
    assert len(run["threads"]) == 1
    assert "continues_exchange_id" not in run["exchanges"][1]


def test_unrelated_conversation_starts_a_new_thread(capture: Capture) -> None:
    capture.exchange(*react_turns()[0])
    other = chat_request([{"role": "user", "content": "Unrelated"}])
    capture.exchange(other, chat_response({"role": "assistant", "content": "ok"}, "chatcmpl-9"))
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert len(run["threads"]) == 2


def test_tool_call_consumed_but_never_emitted_is_partial(capture: Capture) -> None:
    capture.exchange(*react_turns()[0])
    messages = [SYSTEM, USER, assistant_calls("call_z", "Oslo"), tool_result("call_z", "2C")]
    capture.exchange(
        chat_request(messages), chat_response({"role": "assistant", "content": "x"}, "c-1")
    )
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert run["checks"]["stitching"] == "failed"
    gaps = {(g.get("tool_call_id"), g["effect"], g["reason"]) for g in run["gaps"]}
    assert (pid("call_z"), "partial", "consumed_not_emitted") in gaps
    assert (pid("call_a"), "info", "emitted_not_consumed") in gaps


def test_tool_result_before_run_start_is_info(capture: Capture) -> None:
    capture.exchange(*react_turns()[1])
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_declared_scope"
    reasons = {(g["tool_call_id"], g["reason"]) for g in run["gaps"]}
    assert (pid("call_a"), "consumed_before_run") in reasons


def test_previous_response_id_chain_is_stitched(capture: Capture) -> None:
    api = "openai.responses"
    first = {"model": "gpt-4o", "input": "Weather in Paris?", "tools": TOOLS}
    first_out = {
        "id": "resp_1",
        "model": MODEL,
        "status": "completed",
        "output": [
            {
                "type": "function_call",
                "id": "fc_1",
                "call_id": "call_r1",
                "name": "get_weather",
                "arguments": "{}",
                "status": "completed",
            }
        ],
    }
    second = {
        "model": "gpt-4o",
        "previous_response_id": "resp_1",
        "input": [{"type": "function_call_output", "call_id": "call_r1", "output": "18C"}],
    }
    second_out = {
        "id": "resp_2",
        "model": MODEL,
        "status": "completed",
        "output": [
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "18C", "annotations": []}],
            }
        ],
    }
    capture.exchange(first, first_out, api=api)
    capture.exchange(second, second_out, api=api)
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_declared_scope"
    assert run["exchanges"][1]["previous_response_id"] == pid("resp_1")
    assert run["exchanges"][1]["continues_exchange_id"] == "ex-0"
    assert run["exchanges"][0]["tool_call_ids_emitted"] == [pid("call_r1")]
    assert len(run["threads"]) == 1


def test_unresolved_previous_response_is_partial(capture: Capture) -> None:
    request = {"model": "gpt-4o", "previous_response_id": "resp_gone", "input": "next"}
    response = {"id": "resp_3", "model": MODEL, "status": "completed", "output": []}
    capture.exchange(request, response, api="openai.responses")
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert run["gaps"] == [
        {
            "gap_type": "unresolved_previous_response",
            "effect": "partial",
            "exchange_id": "ex-0",
            "previous_response_id": pid("resp_gone"),
        }
    ]


def test_gzip_encoded_stored_response_is_decoded(capture: Capture) -> None:
    exchanges = react_run(capture, response_encoding="gzip")
    assert exchanges[0].response_id is not None
    stored = capture.object_path(exchanges[0].response_id).read_bytes()
    assert stored[:2] == b"\x1f\x8b"  # stored exactly as received: compressed
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_declared_scope"
    assert run["exchanges"][2]["continues_exchange_id"] == "ex-1"


def test_unknown_content_encoding_is_unparsed(capture: Capture) -> None:
    react_run(capture, response_encoding="unknown")
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"
    gaps = [g for g in run["gaps"] if g["gap_type"] == "unparsed_exchange"]
    assert {g["reason"] for g in gaps} == {"undecodable_encoding"}
    assert run["checks"]["stitching"] == "failed"


def _chunk(delta: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "id": "chatcmpl-s",
        "model": MODEL,
        "choices": [{"index": 0, "delta": delta, **extra}],
    }


def test_streamed_sse_response_is_stitched(capture: Capture) -> None:
    first = chat_request([SYSTEM, USER], stream=True)
    opening = {
        "index": 0,
        "id": "call_s1",
        "type": "function",
        "function": {"name": "get_weather", "arguments": '{"city":'},
    }
    stream = sse(
        _chunk({"role": "assistant"}),
        _chunk({"tool_calls": [opening]}),
        _chunk(
            {"tool_calls": [{"index": 0, "function": {"arguments": ' "Paris"}'}}]},
            finish_reason="tool_calls",
        ),
    )
    capture.exchange(first, stream)
    resend = assistant_calls("call_s1", "Paris")
    second = chat_request([SYSTEM, USER, resend, tool_result("call_s1", "18C")], stream=True)
    capture.exchange(second, sse(_chunk({"role": "assistant", "content": "18C"})))
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_declared_scope", run["gaps"]
    first_ex, second_ex = run["exchanges"]
    assert first_ex["tool_call_ids_emitted"] == [pid("call_s1")]
    assert first_ex["response_id"] == pid("chatcmpl-s")
    assert second_ex["continues_exchange_id"] == "ex-0"


def test_stream_closed_at_its_terminal_event_stitches_normally(capture: Capture) -> None:
    """Clients that stop reading at [DONE] end as closed_early, which is not a gap."""

    first = chat_request([SYSTEM, USER], stream=True)
    call = {"index": 0, "id": "call_c1", "type": "function", "function": {"name": "f"}}
    stream = sse(
        _chunk({"role": "assistant", "tool_calls": [call]}), _chunk({}, finish_reason="tool_calls")
    )
    capture.exchange(first, stream, state="closed_early")
    second = chat_request(
        [SYSTEM, USER, assistant_calls("call_c1", "x"), tool_result("call_c1", "ok")]
    )
    capture.exchange(second, chat_response({"role": "assistant", "content": "done"}, "c-2"))
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_declared_scope", run["gaps"]
    assert run["exchanges"][0]["response_state"] == "closed_early"
    assert run["exchanges"][0]["tool_call_ids_emitted"] == [pid("call_c1")]


def test_unparsed_request_is_unverified(capture: Capture) -> None:
    capture.exchange(b"not json at all", chat_response({"role": "assistant", "content": "x"}, "c"))
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"
    assert run["gaps"][0]["gap_type"] == "unparsed_exchange"
    assert run["gaps"][0]["reason"] == "not_json"
    assert run["exchanges"][0]["parse_status"] == "not_json"


def test_http_error_page_is_not_an_unparsed_exchange(capture: Capture) -> None:
    capture.exchange(
        chat_request([SYSTEM, USER]),
        b"<html>502 Bad Gateway</html>",
        response_media="text/html",
        http_status=502,
    )
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_declared_scope"
    assert run["exchanges"][0]["output_message_count"] == 0


def test_transport_error_without_response_is_stitched(capture: Capture) -> None:
    turns = react_turns()
    capture.exchange(turns[0][0], None, state="error", http_status=None)
    capture.exchange(*turns[0])  # the retry continues the failed attempt's thread
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_declared_scope"
    assert "response" not in run["exchanges"][0]["objects"]
    assert run["exchanges"][1]["continues_exchange_id"] == "ex-0"


def test_embeddings_are_their_own_thread(capture: Capture) -> None:
    request = {"model": "text-embedding-3-small", "input": ["a", "b"]}
    response = {"object": "list", "data": [], "model": "text-embedding-3-small"}
    capture.exchange(request, response, api="openai.embeddings")
    capture.exchange(request, response, api="openai.embeddings")
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_declared_scope"
    assert len(run["threads"]) == 2
    assert run["exchanges"][0]["input_message_count"] == 2


# --------------------------------------------------------------------------
# Runs and options
# --------------------------------------------------------------------------


def test_run_filter_and_run_order(capture: Capture) -> None:
    capture.exchange(*react_turns()[0], run_id="run-b")
    capture.exchange(*react_turns()[0], run_id="run-a")
    capture.heartbeat()
    document = capture.reconstruct()
    # Legacy clear run ids are reported as their r- pseudonyms (J1) and selected either way.
    assert [run["run_id"] for run in document["runs"]] == sorted([rid("run-a"), rid("run-b")])
    filtered = capture.reconstruct(run_ids=["run-b"])
    assert [run["run_id"] for run in filtered["runs"]] == [rid("run-b")]
    assert capture.reconstruct(run_ids=[rid("run-b")])["runs"] == filtered["runs"]
    assert capture.reconstruct(run_ids=["nope"])["runs"] == []


def test_reconstruct_rejects_bad_options(capture: Capture) -> None:
    react_run(capture)
    path = capture.write()
    with pytest.raises(ReconstructInputError):
        reconstruct([])
    with pytest.raises(ReconstructInputError):
        reconstruct([path], store=capture.store, tenant_id="other-tenant")
    with pytest.raises(ReconstructInputError):
        reconstruct([path], store=object(), tenant_id=TENANT)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def test_cli_exit_zero_for_complete_run(capture: Capture, tmp_path: Path) -> None:
    react_run(capture)
    spans = str(capture.write())
    out = tmp_path / "report.json"
    argv = ["--spans", spans, "--store-root", str(tmp_path / "store"), "--tenant", TENANT]
    assert main([*argv, "--out", str(out)]) == 0
    document = json.loads(out.read_text())
    validate(document)
    assert only_run(document)["verdict"] == "complete_for_declared_scope"


def test_cli_exit_one_for_unverified(capture: Capture, capsys: pytest.CaptureFixture[str]) -> None:
    react_run(capture)
    assert main(["--spans", str(capture.write())]) == 1  # no store: unverified
    validate(json.loads(capsys.readouterr().out))


def test_cli_exit_one_when_no_run_is_reconstructed(tmp_path: Path) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    assert main(["--spans", str(empty)]) == 1


@pytest.mark.parametrize(
    "argv",
    [
        ["--spans", "/nonexistent/spans.jsonl"],
        ["--store-root", "/tmp"],
        ["--spans", "SPANS", "--store-root", "/nonexistent-store", "--tenant", TENANT],
        ["--spans", "SPANS", "--store-root", "STORE"],
        ["--spans", "SPANS", "--tenant", TENANT],
        ["--spans", "SPANS", "--store-uri", "https://bucket/prefix", "--tenant", TENANT],
        ["--spans", "SPANS", "--scan-store"],
        ["--spans", "SPANS", "--recompute-digests"],
        ["--spans", "SPANS", "--scope", "bytes"],
        ["--spans", "SPANS", "--local", "STORE", "--tenant", TENANT],
    ],
)
def test_cli_usage_errors_exit_two(capture: Capture, argv: list[str]) -> None:
    react_run(capture)
    spans = str(capture.write())
    store = str(capture.root / "store")
    resolved = [spans if item == "SPANS" else store if item == "STORE" else item for item in argv]
    with pytest.raises(SystemExit) as raised:
        raise SystemExit(main(resolved))
    assert raised.value.code == 2


def test_cli_malformed_span_file_exits_two(tmp_path: Path) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"kind": "span", "trace_id": 12}\nnot json\n')
    assert main(["--spans", str(bad)]) == 2


def test_truncated_body_without_ref_is_only_truncated(capture: Capture) -> None:
    turns = react_turns()
    capture.exchange(*turns[0])
    exchange = capture.exchange(*turns[1])
    attributes = exchange.span["attributes"]
    del attributes["fabric.content.result_ref"]
    attributes["fabric.wire.store_status"] = "partial"
    attributes["fabric.wire.truncated"] = True
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert [g["gap_type"] for g in run["gaps"] if g["effect"] != "info"] == ["truncated"]
    assert run["exchanges"][1]["objects"]["response"]["verification"] == "not_stored"


def test_ref_without_a_valid_object_id_is_missing(capture: Capture) -> None:
    exchanges = react_run(capture)
    exchanges[0].span["attributes"]["fabric.content.request_ref"] = "file:///x/not an id"
    run = only_run(capture.reconstruct())
    gap = next(g for g in run["gaps"] if g["gap_type"] == "missing_object")
    assert gap["reason"] == "invalid_ref"


class _FlakyStore:
    """A store whose reads fail in the ways S3 and broken disks do."""

    tenant_id = TENANT

    def __init__(self, inner: LocalFilesystemContentStore, mode: str) -> None:
        self.inner = inner
        self.mode = mode

    def evidence_ref_for(self, object_id: str) -> str:
        return self.inner.evidence_ref_for(object_id)

    def read(self, uri: str) -> Any:
        if self.mode == "s3_absent":
            error = RuntimeError("NoSuchKey")
            error.response = {"Error": {"Code": "NoSuchKey"}}  # type: ignore[attr-defined]
            raise error
        if self.mode == "read_error":
            raise RuntimeError("disk on fire")
        if self.mode == "not_bytes":
            return "text"
        return self.inner.read(uri)

    def read_descriptor(self, uri: str) -> Any:
        if self.mode == "descriptor_error":
            raise RuntimeError("bad sidecar")
        return self.inner.read_descriptor(uri)


@pytest.mark.parametrize(
    ("mode", "gap_type", "reason"),
    [
        ("s3_absent", "missing_object", "absent"),
        ("read_error", "missing_object", "read_error"),
        ("not_bytes", "missing_object", "read_error"),
        ("descriptor_error", "digest_mismatch", "sidecar_mismatch"),
    ],
)
def test_store_read_failures_never_raise(
    capture: Capture, mode: str, gap_type: str, reason: str
) -> None:
    react_run(capture)
    assert capture.store is not None
    run = only_run(capture.reconstruct(store=_FlakyStore(capture.store, mode)))
    assert run["verdict"] == "partial"
    assert {(g["gap_type"], g["reason"]) for g in run["gaps"] if g["effect"] == "partial"} == {
        (gap_type, reason)
    }


# --------------------------------------------------------------------------
# Provider-derived identifiers in the report (report2 finding 4)
# --------------------------------------------------------------------------

FREE_TEXT_MODEL = "Prompt: patient Alice has HIV. API key sk-live-secret"


def m_digest(value: str) -> str:
    return "m-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def test_model_pattern_is_the_shared_capture_pattern() -> None:
    """One definition (fabric._model_names) for capture, fabricguard parity and the verifier."""
    inputs = importlib.import_module("fabric.reconstruct._inputs")
    shared = importlib.import_module("fabric._model_names")
    assert inputs.MODEL_RE is shared.MODEL_PATTERN
    assert inputs.MODEL_RE.pattern == r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"


@pytest.mark.parametrize("store", [True, False])
def test_free_text_model_never_reaches_the_report(tmp_path: Path, store: bool) -> None:
    capture = Capture(tmp_path, store=store)
    request, response = react_turns()[0]
    exchange = capture.exchange(
        {**request, "model": FREE_TEXT_MODEL}, {**response, "model": FREE_TEXT_MODEL}
    )
    exchange.span["attributes"]["gen_ai.response.model"] = FREE_TEXT_MODEL
    capture.heartbeat()
    document = capture.reconstruct()
    entry = only_run(document)["exchanges"][0]
    assert entry["model"] == m_digest(FREE_TEXT_MODEL)  # spec 048 §7: digest, never text
    text = json.dumps(document)
    for needle in ("Alice", "sk-live-secret", "Prompt"):
        assert needle not in text


def test_body_model_wins_over_the_span_value(capture: Capture) -> None:
    """The body is what capture derived the span value from; it is exposed by the same rule."""
    request, response = react_turns()[0]
    exchange = capture.exchange(request, {**response, "model": FREE_TEXT_MODEL})
    exchange.span["attributes"]["gen_ai.response.model"] = MODEL
    capture.heartbeat()
    entry = only_run(capture.reconstruct())["exchanges"][0]
    assert entry["model"] == m_digest(FREE_TEXT_MODEL)


@pytest.mark.parametrize(
    "bad",
    [
        f"{MODEL}\n",
        "gpt 4o",
        "-gpt",
        "m" * 129,
        # Codex re-review report2 #1: a credential-bearing URL passed the old pattern.
        "https://user:sk-live-secret@example.com/private",
        "a://b",
        "gpt-4o@vendor",
        "gpt+4o",
        "gpt-4o://x",  # allowlisted prefix, but a URL
    ],
)
def test_model_outside_the_capture_pattern_is_reported_as_a_digest(
    capture: Capture, bad: str
) -> None:
    request, response = react_turns()[0]
    exchange = capture.exchange(request, {**response, "model": bad})
    exchange.span["attributes"]["gen_ai.response.model"] = bad
    capture.heartbeat()
    document = capture.reconstruct()
    assert only_run(document)["exchanges"][0]["model"] == m_digest(bad)
    assert "sk-live-secret" not in json.dumps(document)


@pytest.mark.parametrize(
    "good",
    ["gpt-4o:latest", "claude-sonnet-4-5", "o3-mini", "text-embedding-3-small"],
)
def test_allowlisted_model_names_are_kept(capture: Capture, good: str) -> None:
    request, response = react_turns()[0]
    capture.exchange(request, {**response, "model": good})
    capture.heartbeat()
    assert only_run(capture.reconstruct())["exchanges"][0]["model"] == good


MODEL_VECTORS = json.loads(
    (CAPTURE_ROOT / "fixtures" / "model-names" / "model-exposure-v1.json").read_text("utf-8")
)


@pytest.mark.parametrize("case", MODEL_VECTORS["cases"], ids=lambda case: case["name"])
def test_report_model_follows_the_shared_exposure_vectors(
    tmp_path: Path, case: Mapping[str, Any]
) -> None:
    """Decision H4: capture, fabricguard and the verifier share one set of vectors.

    The value arrives both in the stored response body (what the verifier
    parses) and on the span (an older capture's raw value); either way the
    report exposes exactly the vector's ``exposed`` form.
    """
    for where in ("body", "span"):
        capture = Capture(tmp_path / where)
        request, response = react_turns()[0]
        if where == "body":
            capture.exchange(request, {**response, "model": case["value"]})
        else:
            exchange = capture.exchange(_modelless_request(), None, state="error", http_status=None)
            exchange.span["attributes"]["gen_ai.response.model"] = case["value"]
        capture.heartbeat()
        document = capture.reconstruct(model_allowlist=case["allowlist"])
        assert only_run(document)["exchanges"][0]["model"] == case["exposed"], where
        if not case["allowed"]:
            assert json.dumps(case["value"]) not in json.dumps(document)


@pytest.mark.parametrize(
    "unlisted", ["accounts/fireworks/models/llama-v3p1", "m" * 128, "a:/b", "my-private-ft-model"]
)
def test_pattern_valid_but_unlisted_models_are_digests(capture: Capture, unlisted: str) -> None:
    """Codex 'raw model exposure': a valid-looking name is not necessarily a public one."""
    request, response = react_turns()[0]
    exchange = capture.exchange(request, {**response, "model": unlisted})
    exchange.span["attributes"]["gen_ai.response.model"] = unlisted
    capture.heartbeat()
    document = capture.reconstruct()
    assert only_run(document)["exchanges"][0]["model"] == m_digest(unlisted)
    allowed = capture.reconstruct(model_allowlist=[unlisted])
    assert only_run(allowed)["exchanges"][0]["model"] == unlisted


def test_model_allowlist_prefix_entries(capture: Capture) -> None:
    request, response = react_turns()[0]
    capture.exchange(request, {**response, "model": "acme-ft-2026-01"})
    capture.heartbeat()
    document = capture.reconstruct(model_allowlist=["acme-ft-*"])
    assert only_run(document)["exchanges"][0]["model"] == "acme-ft-2026-01"
    other = capture.reconstruct(model_allowlist=["acme-ft-2026-02"])
    assert only_run(other)["exchanges"][0]["model"] == m_digest("acme-ft-2026-01")


def _modelless_request() -> dict[str, Any]:
    """A request body without a model, so the report falls back to the span value."""
    return {k: v for k, v in react_turns()[0][0].items() if k != "model"}


@pytest.mark.parametrize(
    "span_value",
    [
        "m-0123456789abcdef",  # capture already exposed it as a digest
        MODEL,  # allowlisted
    ],
)
def test_span_model_values_already_exposed_are_kept(capture: Capture, span_value: str) -> None:
    exchange = capture.exchange(_modelless_request(), None, state="error", http_status=None)
    exchange.span["attributes"]["gen_ai.response.model"] = span_value
    capture.heartbeat()
    assert only_run(capture.reconstruct())["exchanges"][0]["model"] == span_value


def test_unlisted_span_model_is_digested(capture: Capture) -> None:
    """A span from older capture (047) may carry an unlisted raw value."""
    exchange = capture.exchange(_modelless_request(), None, state="error", http_status=None)
    exchange.span["attributes"]["gen_ai.response.model"] = "acme-secret-ft"
    capture.heartbeat()
    document = capture.reconstruct()
    assert only_run(document)["exchanges"][0]["model"] == m_digest("acme-secret-ft")
    assert "acme-secret-ft" not in json.dumps(document)


@pytest.mark.parametrize("entries", [["*"], ["gpt 4o"], ["a://b*"], [""], [" gpt-x"]])
def test_reconstruct_rejects_bad_model_allowlist_entries(
    capture: Capture, entries: list[str]
) -> None:
    react_run(capture)
    with pytest.raises(ReconstructInputError) as raised:
        capture.reconstruct(model_allowlist=entries)
    for entry in entries:
        if len(entry.strip()) > 1:
            assert entry.strip() not in str(raised.value)


def _cli_model(capture: Capture, argv: list[str], tmp_path: Path) -> str:
    out = tmp_path / "model-report.json"
    store = ["--store-root", str(tmp_path / "store"), "--tenant", TENANT]
    assert main(["--spans", str(capture.write()), *store, *argv, "--out", str(out)]) == 0
    document = json.loads(out.read_text())
    validate(document)
    return str(only_run(document)["exchanges"][0]["model"])


def test_cli_model_allowlist_flag_and_environment(
    capture: Capture, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request, response = react_turns()[0]
    capture.exchange(request, {**response, "model": "acme-ft-1"})
    capture.heartbeat()
    monkeypatch.delenv("FABRIC_WIRE_MODEL_ALLOWLIST", raising=False)
    assert _cli_model(capture, [], tmp_path) == m_digest("acme-ft-1")
    assert _cli_model(capture, ["--model-allowlist", "acme-ft-*"], tmp_path) == "acme-ft-1"
    monkeypatch.setenv("FABRIC_WIRE_MODEL_ALLOWLIST", "other, acme-ft-1")
    assert _cli_model(capture, [], tmp_path) == "acme-ft-1"
    # The flag replaces the environment default.
    assert _cli_model(capture, ["--model-allowlist", "other"], tmp_path) == m_digest("acme-ft-1")


@pytest.mark.parametrize("source", ["flag", "env"])
def test_cli_bad_model_allowlist_exits_two_without_echo(
    capture: Capture,
    source: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    react_run(capture)
    marker = "sk-live-SECRET one"
    argv = ["--spans", str(capture.write())]
    if source == "flag":
        argv += ["--model-allowlist", marker]
    else:
        monkeypatch.setenv("FABRIC_WIRE_MODEL_ALLOWLIST", marker)
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert "SECRET" not in captured.err + captured.out


def test_provider_ids_with_a_trailing_newline_are_pseudonymised(capture: Capture) -> None:
    first = [SYSTEM, USER]
    second = [*first, assistant_calls("call_a\n", "Paris"), tool_result("call_a\n", "18C")]
    capture.exchange(
        chat_request(first), chat_response(assistant_calls("call_a\n", "Paris"), "chatcmpl-0\n")
    )
    capture.exchange(
        chat_request(second), chat_response({"role": "assistant", "content": "ok"}, "c-1")
    )
    capture.heartbeat()
    run = only_run(capture.reconstruct())  # schema-validated: ids match the pseudonym pattern
    first_entry, second_entry = run["exchanges"]
    assert first_entry["response_id"] == pid("chatcmpl-0\n")
    (emitted,) = first_entry["tool_call_ids_emitted"]
    assert emitted == pid("call_a\n")
    assert second_entry["tool_call_ids_consumed"] == [emitted]
    assert run["verdict"] == "complete_for_declared_scope"


@pytest.mark.parametrize(
    "raw",
    ["patient-123-45-6789", "alice@example.com", "sk-live-secret", "chatcmpl-B9x2kQ"],
)
def test_provider_ids_never_reach_the_report_but_still_correlate(
    capture: Capture, raw: str
) -> None:
    """Codex re-review report2 #1: valid-looking personal ids passed through unchanged.

    Response, previous-response and tool-call ids are pseudonymised the same
    way everywhere in the report, so stitching and tool-call matching still
    work while the provider's value never appears.
    """
    tool_id, response_id = f"{raw}-call", f"{raw}-resp"
    first = [SYSTEM, USER]
    second = [*first, assistant_calls(tool_id, "Paris"), tool_result(tool_id, "18C")]
    capture.exchange(
        chat_request(first), chat_response(assistant_calls(tool_id, "Paris"), response_id)
    )
    capture.exchange(
        chat_request(second), chat_response({"role": "assistant", "content": "ok"}, "c-1")
    )
    responses = {
        "model": "gpt-4o",
        "previous_response_id": response_id,
        "input": "next",
    }
    capture.exchange(
        responses,
        {"id": f"{raw}-next", "model": MODEL, "status": "completed", "output": []},
        api="openai.responses",
    )
    capture.exchange(
        {"model": "gpt-4o", "previous_response_id": f"{raw}-gone", "input": "x"},
        {"id": f"{raw}-last", "model": MODEL, "status": "completed", "output": []},
        api="openai.responses",
    )
    capture.heartbeat()
    document = capture.reconstruct()
    assert raw not in json.dumps(document)
    run = only_run(document)
    first_entry, second_entry, third_entry, _ = run["exchanges"]
    assert first_entry["tool_call_ids_emitted"] == [pid(tool_id)]
    assert second_entry["tool_call_ids_consumed"] == [pid(tool_id)]
    assert second_entry["continues_exchange_id"] == first_entry["exchange_id"]
    assert first_entry["response_id"] == pid(response_id)
    assert third_entry["previous_response_id"] == pid(response_id)
    assert third_entry["continues_exchange_id"] == first_entry["exchange_id"]
    unresolved = next(g for g in run["gaps"] if g["gap_type"] == "unresolved_previous_response")
    assert unresolved["previous_response_id"] == pid(f"{raw}-gone")


def test_span_response_id_is_pseudonymised_like_the_body_one(capture: Capture) -> None:
    """Older capture exported gen_ai.response.id; it maps to the same pseudonym."""
    (exchange,) = [capture.exchange(react_turns()[0][0], None, state="error", http_status=None)]
    exchange.span["attributes"]["gen_ai.response.id"] = "patient-123-45-6789"
    capture.heartbeat()
    document = capture.reconstruct()
    assert "patient-123-45-6789" not in json.dumps(document)
    assert only_run(document)["exchanges"][0]["response_id"] == pid("patient-123-45-6789")
