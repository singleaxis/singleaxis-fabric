# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Run reconstruction verifier (spec 042 §10) over synthetic captures.

A small builder plays the role of the wire tee: it writes exact request,
response and ``fabric.llm-exchange/v1`` record objects into a real
``LocalFilesystemContentStore`` and emits the matching OTLP-projected spans
as sink JSONL rows. Each scenario then damages the capture in one specific
way and asserts the gap and verdict the spec requires. Every report is
validated against the run-reconstruction schema *and* the contract
validator's semantic rules.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import types
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from fabric.content_store.local import LocalFilesystemContentStore
from fabric.reconstruct import ReconstructInputError, reconstruct
from fabric.reconstruct.__main__ import main

REPO_ROOT = Path(__file__).resolve().parents[3]
CAPTURE_ROOT = REPO_ROOT / "contracts" / "capture" / "v1"
TENANT = "tenant-a"
SOURCE = "wire-3f9a1c2b7d4e5f60"
EPOCH = 1791331200000000000
TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
GENERATED_AT = datetime(2026, 10, 7, 9, 10, tzinfo=UTC)
BASE_NS = 1_791_331_200_000_000_000


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


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8", "surrogatepass"
    )


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def message_digest(message: Mapping[str, Any]) -> str:
    # Synthetic messages are already in fabric.stitch/v1 projected form.
    return sha(canonical(message))


def stamp(ns: int) -> str:
    seconds, nanos = divmod(ns, 1_000_000_000)
    return datetime.fromtimestamp(seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S") + (
        f".{nanos:09d}Z"
    )


# --------------------------------------------------------------------------
# Synthetic capture builder
# --------------------------------------------------------------------------


@dataclass
class Exchange:
    exchange_id: str
    source_sequence: int
    run_sequence: int
    run_id: str
    objects: dict[str, str] = field(default_factory=dict)
    span: dict[str, Any] = field(default_factory=dict)


class Capture:
    """Plays the wire tee: store objects + exchange/loss/watermark spans."""

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
        self.run_sequences: dict[str, int] = {}
        self.cumulative: dict[str, int] = {}
        self.exchanges: list[Exchange] = []

    # -- allocation ------------------------------------------------------

    def _next(self) -> int:
        value = self.sequence
        self.sequence += 1
        return value

    def _next_run(self, run_id: str) -> int:
        value = self.run_sequences.get(run_id, 0)
        self.run_sequences[run_id] = value + 1
        return value

    def _ns(self, sequence: int) -> int:
        return BASE_NS + sequence * 1_000_000_000

    # -- store -------------------------------------------------------------

    def _descriptor(
        self, object_id: str, role: str, data: bytes, exchange: Exchange, **extra: Any
    ) -> dict[str, Any]:
        assert self.store is not None
        descriptor: dict[str, Any] = {
            "schema_version": "fabric.content-object/v2",
            "object_id": object_id,
            "tenant_id": TENANT,
            "role": role,
            "media_type": "application/json",
            "encoding": "binary",
            "representation": "exact",
            "provenance": "protocol",
            "boundary": "provider_bound",
            "source_id": self.source_id,
            "source_epoch": self.epoch,
            "source_sequence": exchange.source_sequence,
            "captured_at": stamp(self._ns(exchange.source_sequence)),
            "status": "stored",
            "run_id": exchange.run_id,
            "operation_id": exchange.exchange_id,
            "source_byte_length": len(data),
            "source_sha256": sha(data),
            "stored_byte_length": len(data),
            "stored_sha256": sha(data),
            "ref": self.store.evidence_ref_for(object_id),
        }
        descriptor.update(extra)
        return descriptor

    def _put(self, descriptor: Mapping[str, Any], data: bytes) -> None:
        assert self.store is not None
        self.store.put_bytes_object(descriptor, data)

    def _body(self, object_id: str, role: str, data: bytes) -> dict[str, Any]:
        assert self.store is not None
        return {
            "object_id": object_id,
            "role": role,
            "media_type": "application/json",
            "content_encoding": "identity",
            "representation": "exact",
            "status": "stored",
            "source_byte_length": len(data),
            "source_sha256": sha(data),
            "stored_byte_length": len(data),
            "stored_sha256": sha(data),
            "ref": self.store.evidence_ref_for(object_id),
        }

    # -- exchanges ---------------------------------------------------------

    def exchange(  # noqa: PLR0912, PLR0915 - mirrors one wire exchange end to end
        self,
        messages: Sequence[Mapping[str, Any]],
        output: Sequence[Mapping[str, Any]],
        *,
        run_id: str = "run-react-1",
        basis: str = "explicit",
        api: str = "openai.chat_completions",
        response_id: str | None = None,
        previous_response_id: str | None = None,
        emit_span: bool = True,
        store_objects: bool = True,
        store_status: str = "stored",
        consumed: Sequence[str] | None = None,
        emitted: Sequence[str] | None = None,
    ) -> Exchange:
        sequence = self._next()
        exchange = Exchange(
            exchange_id=f"ex-{self.id_prefix}{sequence}",
            source_sequence=sequence,
            run_sequence=self._next_run(run_id),
            run_id=run_id,
        )
        self.exchanges.append(exchange)
        if consumed is None:
            consumed = _consumed(api, messages)
        if emitted is None:
            emitted = _emitted(api, output)
        request_doc: dict[str, Any] = {"model": "gpt-4o"}
        if api == "openai.responses":
            request_doc["input"] = list(messages)
            if previous_response_id:
                request_doc["previous_response_id"] = previous_response_id
            response_doc: dict[str, Any] = {"id": response_id, "output": list(output)}
        else:
            request_doc["messages"] = list(messages)
            response_doc = {
                "id": response_id,
                "choices": [
                    {"index": index, "message": message, "finish_reason": "stop"}
                    for index, message in enumerate(output)
                ],
            }
        request_bytes = json.dumps(request_doc).encode()
        response_bytes = json.dumps(response_doc).encode()
        input_digests = [message_digest(message) for message in messages]
        output_digests = [message_digest(message) for message in output]
        storing = self.store is not None and store_objects and store_status != "disabled"
        ids = {
            "request": f"{exchange.exchange_id}-req",
            "response": f"{exchange.exchange_id}-rsp",
            "record": f"{exchange.exchange_id}-rec",
        }
        span_id = f"{0xA000 + sequence:016x}"
        record_bytes = b""
        if storing:
            exchange.objects = ids
            self._put(
                self._descriptor(ids["request"], "model.exchange.request", request_bytes, exchange),
                request_bytes,
            )
            self._put(
                self._descriptor(
                    ids["response"],
                    "model.exchange.response",
                    response_bytes,
                    exchange,
                    links=[{"relation": "result_of", "object_id": ids["request"]}],
                ),
                response_bytes,
            )
            record = self._record(
                exchange,
                api=api,
                basis=basis,
                span_id=span_id,
                request_bytes=request_bytes,
                response_bytes=response_bytes,
                ids=ids,
                input_digests=input_digests,
                output_digests=output_digests,
                messages=messages,
                output=output,
                consumed=consumed,
                emitted=emitted,
                response_id=response_id,
                previous_response_id=previous_response_id,
            )
            validate(record)
            record_bytes = canonical(record)
            self._put(
                self._descriptor(
                    ids["record"],
                    "model.exchange.record",
                    record_bytes,
                    exchange,
                    media_type="application/vnd.singleaxis.fabric.llm-exchange+json",
                    representation="canonicalized",
                    provenance="inferred",
                    links=[
                        {"relation": "derived_from", "object_id": ids["request"]},
                        {"relation": "derived_from", "object_id": ids["response"]},
                    ],
                ),
                record_bytes,
            )
        attributes: dict[str, Any] = {
            "gen_ai.operation.name": "chat",
            "gen_ai.provider.name": "openai",
            "gen_ai.request.model": "gpt-4o",
            "fabric.source_id": self.source_id,
            "fabric.source.epoch": self.epoch,
            "fabric.source.sequence": sequence,
            "fabric.source.component": "wire",
            "fabric.run.id": run_id,
            "fabric.run.id_basis": basis,
            "fabric.run.sequence": exchange.run_sequence,
            "fabric.wire.exchange_id": exchange.exchange_id,
            "fabric.wire.fidelity": "exact_wire",
            "fabric.wire.api": api,
            "fabric.wire.endpoint_id": "openai",
            "fabric.wire.request_body_sha256": sha(request_bytes)[7:],
            "fabric.wire.response_body_sha256": sha(response_bytes)[7:],
            "fabric.wire.request_body_bytes": len(request_bytes),
            "fabric.wire.response_body_bytes": len(response_bytes),
            "fabric.wire.input.message_count": len(messages),
            "fabric.wire.output.message_count": len(output),
            "fabric.wire.input.message_hashes_offset": max(0, len(messages) - 64),
            "fabric.wire.response_state": "complete",
            "fabric.wire.truncated": False,
            "fabric.wire.parse_status": "ok",
            "fabric.wire.store_status": store_status if self.store is not None else "disabled",
        }
        if input_digests:
            attributes["fabric.wire.input.message_hashes"] = [d[7:] for d in input_digests[-64:]]
        if output_digests:
            attributes["fabric.wire.output.message_hashes"] = [d[7:] for d in output_digests[:64]]
        if consumed:
            attributes["fabric.wire.input.tool_call_ids"] = list(consumed)
        if emitted:
            attributes["fabric.wire.output.tool_call_ids"] = list(emitted)
        if response_id:
            attributes["gen_ai.response.id"] = response_id
        if previous_response_id:
            attributes["gen_ai.request.previous_response.id"] = previous_response_id
        if storing and self.store is not None:
            store = self.store
            attributes["fabric.wire.exchange_ref"] = store.evidence_ref_for(ids["record"])
            attributes["fabric.wire.exchange_sha256"] = sha(record_bytes)[7:]
            attributes["fabric.content.request_ref"] = store.evidence_ref_for(ids["request"])
            attributes["fabric.content.result_ref"] = store.evidence_ref_for(ids["response"])
        exchange.span = {
            "kind": "span",
            "trace_id": TRACE_ID,
            "span_id": span_id,
            "parent_span_id": "a3ce929d0e0e4736",
            "name": "fabric.model_call",
            "start_ns": self._ns(sequence),
            "end_ns": self._ns(sequence) + 500_000_000,
            "resource": {"service.name": "react-agent"},
            "attributes": attributes,
            "events": [],
        }
        if emit_span:
            self.rows.append(exchange.span)
        return exchange

    def _record(
        self,
        exchange: Exchange,
        *,
        api: str,
        basis: str,
        span_id: str,
        request_bytes: bytes,
        response_bytes: bytes,
        ids: Mapping[str, str],
        input_digests: Sequence[str],
        output_digests: Sequence[str],
        messages: Sequence[Mapping[str, Any]],
        output: Sequence[Mapping[str, Any]],
        consumed: Sequence[str],
        emitted: Sequence[str],
        response_id: str | None,
        previous_response_id: str | None,
    ) -> dict[str, Any]:
        request: dict[str, Any] = {
            "body": self._body(ids["request"], "model.exchange.request", request_bytes),
            "model": "gpt-4o",
            "stream": False,
            "message_count": len(input_digests),
            "message_digests": list(input_digests),
            "message_roles": [str(m.get("role") or m.get("type")) for m in messages],
            "tool_call_ids_consumed": list(dict.fromkeys(consumed)),
            "parse_status": "ok",
        }
        if previous_response_id:
            request["previous_response_id"] = previous_response_id
        response: dict[str, Any] = {
            "state": "complete",
            "body": self._body(ids["response"], "model.exchange.response", response_bytes),
            "model": "gpt-4o",
            "finish_reasons": ["stop"],
            "message_count": len(output_digests),
            "message_digests": list(output_digests),
            "message_roles": [str(m.get("role") or m.get("type")) for m in output],
            "tool_calls": [{"id": call_id, "name": "get_weather"} for call_id in emitted],
            "parse_status": "ok",
        }
        if response_id:
            response["response_id"] = response_id
        return {
            "schema_version": "fabric.llm-exchange/v1",
            "exchange_id": exchange.exchange_id,
            "tenant_id": TENANT,
            "fidelity": "exact_wire",
            "source": {
                "source_id": self.source_id,
                "source_epoch": self.epoch,
                "source_sequence": exchange.source_sequence,
                "component": "wire",
            },
            "run": {
                "run_id": exchange.run_id,
                "basis": basis,
                "run_sequence": exchange.run_sequence,
            },
            "trace": {"trace_id": TRACE_ID, "span_id": span_id},
            "endpoint": {
                "endpoint_id": "openai",
                "api": api,
                "provider_name": "openai",
                "http_method": "POST",
                "http_status_code": 200,
            },
            "timing": {
                "started_at": stamp(self._ns(exchange.source_sequence)),
                "ended_at": stamp(self._ns(exchange.source_sequence) + 500_000_000),
            },
            "request": request,
            "response": response,
            "capture": {
                "digest_projection": "fabric.stitch/v1",
                "truncated": False,
                "store_status": "stored",
                "loss_record_ids": [],
            },
        }

    # -- loss and watermarks ----------------------------------------------

    def loss(
        self,
        reason: str,
        affected: Sequence[Exchange | int],
        *,
        count: int | None = None,
        record_id: str | None = None,
        attributed: bool = True,
    ) -> str:
        sequence = self._next()
        record_id = record_id or f"loss-{sequence}"
        lost = count if count is not None else max(1, len(affected))
        self.cumulative[reason] = self.cumulative.get(reason, 0) + lost
        sequences, run_ids, run_sequences = [], [], []
        for item in affected:
            if isinstance(item, Exchange):
                sequences.append(item.source_sequence)
                run_ids.append(item.run_id if attributed else "")
                run_sequences.append(item.run_sequence if attributed else -1)
            else:
                sequences.append(item)
                run_ids.append("")
                run_sequences.append(-1)
        attributes = self._record_attributes(sequence, record_id, "loss")
        attributes.update(
            {
                "fabric.loss.reason": reason,
                "fabric.loss.count": lost,
                "fabric.loss.affected_truncated": False,
            }
        )
        if sequences:
            attributes["fabric.loss.affected_sequences"] = sequences
            attributes["fabric.loss.affected_run_ids"] = run_ids
            attributes["fabric.loss.affected_run_sequences"] = run_sequences
        self.rows.append(self._record_span(sequence, "fabric.capture_loss", attributes))
        return record_id

    def watermark(self, *, run_id: str | None = None, run_high_water: int | None = None) -> int:
        sequence = self._next()
        attributes = self._record_attributes(sequence, f"wm-{sequence}", "watermark")
        attributes["fabric.loss.count"] = 0
        if run_id is not None:
            attributes["fabric.run.id"] = run_id
            attributes["fabric.run.high_water_sequence"] = (
                run_high_water
                if run_high_water is not None
                else self.run_sequences.get(run_id, 0) - 1
            )
        self.rows.append(self._record_span(sequence, "fabric.capture_watermark", attributes))
        return sequence

    def _record_attributes(self, sequence: int, record_id: str, kind: str) -> dict[str, Any]:
        reasons = sorted(self.cumulative)
        return {
            "fabric.source_id": self.source_id,
            "fabric.source.epoch": self.epoch,
            "fabric.source.sequence": sequence,
            "fabric.source.component": "wire",
            "fabric.loss.record_id": record_id,
            "fabric.loss.record_kind": kind,
            "fabric.loss.high_water_sequence": sequence,
            "fabric.loss.cumulative_total": sum(self.cumulative.values()),
            "fabric.loss.cumulative_reasons": reasons,
            "fabric.loss.cumulative_counts": [self.cumulative[r] for r in reasons],
        }

    def _record_span(self, sequence: int, name: str, attributes: dict[str, Any]) -> dict[str, Any]:
        ns = self._ns(sequence)
        return {
            "kind": "span",
            "trace_id": f"{sequence + 1:032x}",
            "span_id": f"{0xB000 + sequence:016x}",
            "parent_span_id": None,
            "name": name,
            "start_ns": ns,
            "end_ns": ns,
            "resource": {"service.name": "react-agent"},
            "attributes": attributes,
            "events": [],
        }

    # -- output -------------------------------------------------------------

    def write(self, name: str = "records.jsonl") -> Path:
        path = self.root / name
        with path.open("w", encoding="utf-8") as stream:
            stream.write(json.dumps({"kind": "log", "body": "ignored"}) + "\n")
            for row in self.rows:
                stream.write(json.dumps(row) + "\n")
        return path

    def object_path(self, object_id: str) -> Path:
        return self.root / "store" / TENANT / "evidence" / object_id

    def reconstruct(self, **kwargs: Any) -> dict[str, Any]:
        kwargs.setdefault("store", self.store)
        kwargs.setdefault("generated_at", GENERATED_AT)
        document = reconstruct([self.write()], **kwargs)
        validate(document)
        return document


def _consumed(api: str, messages: Sequence[Mapping[str, Any]]) -> list[str]:
    if api == "openai.responses":
        return [m["call_id"] for m in messages if m.get("type") == "function_call_output"]
    return [m["tool_call_id"] for m in messages if m.get("role") == "tool"]


def _emitted(api: str, output: Sequence[Mapping[str, Any]]) -> list[str]:
    if api == "openai.responses":
        return [m["call_id"] for m in output if m.get("type") == "function_call"]
    return [call["id"] for m in output for call in m.get("tool_calls", [])]


# --------------------------------------------------------------------------
# ReAct conversation fixtures (already in fabric.stitch/v1 projected form)
# --------------------------------------------------------------------------

SYSTEM = {"role": "system", "content": "You are a travel agent. Use tools."}
USER = {"role": "user", "content": "Weather in Paris and Rome?"}


def call(call_id: str, city: str) -> dict[str, Any]:
    return {
        "role": "assistant",
        "tool_calls": [
            {
                "id": call_id,
                "type": "function",
                "function": {"name": "get_weather", "arguments": json.dumps({"city": city})},
            }
        ],
    }


def result(call_id: str, text: str) -> dict[str, Any]:
    return {"role": "tool", "tool_call_id": call_id, "content": text}


FINAL = {"role": "assistant", "content": "Paris 18C rain, Rome 24C sun."}


def react_turns() -> list[tuple[list[dict[str, Any]], list[dict[str, Any]]]]:
    turn0 = [SYSTEM, USER]
    out0 = [call("call_paris", "Paris")]
    turn1 = [*turn0, *out0, result("call_paris", "18C, rain")]
    out1 = [call("call_rome", "Rome")]
    turn2 = [*turn1, *out1, result("call_rome", "24C, sun")]
    return [(turn0, out0), (turn1, out1), (turn2, [FINAL])]


def react_run(
    capture: Capture,
    *,
    close: bool = True,
    skip: Callable[[int], bool] = lambda index: False,
    **kwargs: Any,
) -> list[Exchange]:
    exchanges = []
    for index, (messages, output) in enumerate(react_turns()):
        exchanges.append(
            capture.exchange(
                messages,
                output,
                response_id=f"chatcmpl-{index}",
                emit_span=not skip(index),
                store_objects=not skip(index),
                **kwargs,
            )
        )
    if close:
        capture.watermark(run_id=kwargs.get("run_id", "run-react-1"))
    return exchanges


def gap_types(run: Mapping[str, Any]) -> list[str]:
    return [gap["gap_type"] for gap in run["gaps"]]


def gaps_of(run: Mapping[str, Any], gap_type: str) -> list[dict[str, Any]]:
    return [gap for gap in run["gaps"] if gap["gap_type"] == gap_type]


def only_run(document: Mapping[str, Any]) -> dict[str, Any]:
    assert len(document["runs"]) == 1, [run["run_id"] for run in document["runs"]]
    run: dict[str, Any] = document["runs"][0]
    return run


@pytest.fixture
def capture(tmp_path: Path) -> Iterator[Capture]:
    yield Capture(tmp_path)


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------


def test_clean_three_turn_react_run_is_complete(capture: Capture) -> None:
    react_run(capture)
    document = capture.reconstruct()
    run = only_run(document)

    assert run["verdict"] == "complete_for_declared_scope"
    assert run["gaps"] == []
    assert run["checks"] == {
        "sequence": "passed",
        "loss": "passed",
        "tail": "passed",
        "bytes": "passed",
        "stitching": "passed",
    }
    assert run["run_id"] == "run-react-1"
    assert run["run_id_basis"] == "explicit"
    assert run["declared_scope"] == {
        "capture_surfaces": ["exact_wire"],
        "bytes": True,
        "through": [{"source_id": SOURCE, "source_epoch": EPOCH, "through_source_sequence": 3}],
    }
    assert run["threads"] == [{"thread_id": "thread-0", "exchange_ids": ["ex-0", "ex-1", "ex-2"]}]
    ex0, ex1, ex2 = run["exchanges"]
    assert "continues_exchange_id" not in ex0
    assert ex1["continues_exchange_id"] == "ex-0"
    assert ex2["continues_exchange_id"] == "ex-1"
    assert ex1["tool_call_ids_consumed"] == ["call_paris"]
    assert ex1["tool_call_ids_emitted"] == ["call_rome"]
    assert ex2["input_message_count"] == 6
    assert ex0["origin"] == "span_and_store"
    assert ex0["trace_id"] == TRACE_ID
    for exchange in run["exchanges"]:
        assert {obj["verification"] for obj in exchange["objects"].values()} == {"verified"}
        assert set(exchange["objects"]) == {"request", "response", "record"}
    assert document["sources"] == [
        {
            "source_id": SOURCE,
            "source_epoch": EPOCH,
            "component": "wire",
            "observed_records": 4,
            "high_water_sequence": 3,
            "missing_sequences": [],
            "watermark_sequence": 3,
            "cumulative_lost": 0,
        }
    ]
    assert document["inputs"]["store"] == {"kind": "local", "tenant_id": TENANT}
    assert document["inputs"]["span_files"][0]["format"] == "sink_jsonl"
    assert document["inputs"]["span_files"][0]["records"] == 4


def test_report_carries_no_content(capture: Capture) -> None:
    react_run(capture)
    text = json.dumps(capture.reconstruct())
    for needle in ("Paris 18C", "travel agent", "Weather in Paris", "get_weather", "24C, sun"):
        assert needle not in text


def test_missing_exchange_span_and_object_is_a_sequence_gap(capture: Capture) -> None:
    react_run(capture, skip=lambda index: index == 1)
    run = only_run(capture.reconstruct())

    assert run["verdict"] == "partial"
    assert run["checks"]["sequence"] == "failed"
    sequence_gaps = gaps_of(run, "sequence_gap")
    assert sequence_gaps == [
        {
            "gap_type": "sequence_gap",
            "effect": "partial",
            "source_id": SOURCE,
            "source_epoch": EPOCH,
            "run_sequences": [1],
            "reason": "run_sequence_missing",
        },
        {
            "gap_type": "sequence_gap",
            "effect": "partial",
            "source_id": SOURCE,
            "source_epoch": EPOCH,
            "sequences": [1],
            "reason": "source_sequence_missing",
        },
    ]
    # The tool call emitted by the lost exchange is consumed without a producer.
    unmatched = gaps_of(run, "unmatched_tool_call")
    assert {
        "gap_type": "unmatched_tool_call",
        "effect": "partial",
        "exchange_id": "ex-2",
        "tool_call_id": "call_rome",
        "reason": "consumed_not_emitted",
    } in unmatched
    assert [ex["exchange_id"] for ex in run["exchanges"]] == ["ex-0", "ex-2"]


def test_loss_record_explains_dropped_exchange_and_makes_run_partial(capture: Capture) -> None:
    exchanges = react_run(capture, close=False, skip=lambda index: index == 1)
    record_id = capture.loss("queue_full", [exchanges[1]])
    capture.watermark(run_id="run-react-1")
    document = capture.reconstruct()
    run = only_run(document)

    assert run["verdict"] == "partial"
    assert gaps_of(run, "sequence_gap") == []
    assert run["checks"]["sequence"] == "passed"
    assert run["checks"]["loss"] == "failed"
    assert gaps_of(run, "loss_record") == [
        {
            "gap_type": "loss_record",
            "effect": "partial",
            "source_id": SOURCE,
            "source_epoch": EPOCH,
            "sequences": [1],
            "run_sequences": [1],
            "loss_record_id": record_id,
            "reason": "queue_full",
        }
    ]
    assert document["sources"][0]["missing_sequences"] == [[1, 1]]
    assert document["sources"][0]["cumulative_lost"] == 1


def test_unattributed_loss_after_run_start_is_partial(capture: Capture) -> None:
    exchanges = react_run(capture, close=False)
    capture.loss("internal_error", [], count=2)
    capture.watermark()
    run = only_run(capture.reconstruct())
    assert exchanges
    assert run["verdict"] == "partial"
    assert gaps_of(run, "loss_record")[0]["reason"] == "internal_error"


def test_loss_after_run_close_does_not_taint_closed_run(capture: Capture) -> None:
    react_run(capture)
    capture.loss("internal_error", [], count=1)
    capture.watermark()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_declared_scope"


def test_prefix_break_is_recorded_not_judged(capture: Capture) -> None:
    turns = react_turns()
    capture.exchange(*turns[0], response_id="chatcmpl-0")
    capture.exchange(*turns[1], response_id="chatcmpl-1")
    # The agent compacts its history: the user turn is replaced by a summary.
    summary = {"role": "user", "content": "Summary: Paris is 18C. Now check Rome."}
    rewritten = [SYSTEM, summary, call("call_rome", "Rome"), result("call_rome", "24C, sun")]
    capture.exchange(rewritten, [FINAL], response_id="chatcmpl-2")
    capture.watermark(run_id="run-react-1")
    run = only_run(capture.reconstruct())

    assert run["verdict"] == "complete_for_declared_scope"
    assert gaps_of(run, "prefix_break") == [
        {
            "gap_type": "prefix_break",
            "effect": "info",
            "exchange_id": "ex-2",
            "reason": "history_rewritten",
        }
    ]
    assert "continues_exchange_id" not in run["exchanges"][2]
    assert run["threads"] == [{"thread_id": "thread-0", "exchange_ids": ["ex-0", "ex-1", "ex-2"]}]
    assert run["checks"]["stitching"] == "passed"


def test_unrelated_conversation_starts_a_new_thread(capture: Capture) -> None:
    react_run(capture, close=False)
    other = [{"role": "system", "content": "Summarize."}, {"role": "user", "content": "x"}]
    capture.exchange(other, [{"role": "assistant", "content": "y"}])
    capture.watermark(run_id="run-react-1")
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_declared_scope"
    assert [thread["thread_id"] for thread in run["threads"]] == ["thread-0", "thread-1"]
    assert run["threads"][1]["exchange_ids"] == ["ex-3"]


def test_tool_call_emitted_but_never_consumed_is_info(capture: Capture) -> None:
    turns = react_turns()
    capture.exchange(*turns[0], response_id="chatcmpl-0")
    capture.exchange(*turns[1], response_id="chatcmpl-1")
    capture.watermark(run_id="run-react-1")
    run = only_run(capture.reconstruct())

    assert run["verdict"] == "complete_for_declared_scope"
    assert gaps_of(run, "unmatched_tool_call") == [
        {
            "gap_type": "unmatched_tool_call",
            "effect": "info",
            "exchange_id": "ex-1",
            "tool_call_id": "call_rome",
            "reason": "emitted_not_consumed",
        }
    ]


def test_tool_call_consumed_but_never_emitted_is_partial(capture: Capture) -> None:
    turns = react_turns()
    capture.exchange(*turns[0], response_id="chatcmpl-0")
    capture.exchange(*turns[1], consumed=["call_paris", "call_ghost"], response_id="chatcmpl-1")
    capture.exchange(*turns[2], response_id="chatcmpl-2")
    capture.watermark(run_id="run-react-1")
    run = only_run(capture.reconstruct())

    assert run["verdict"] == "partial"
    assert run["checks"]["stitching"] == "failed"
    assert {
        "gap_type": "unmatched_tool_call",
        "effect": "partial",
        "exchange_id": "ex-1",
        "tool_call_id": "call_ghost",
        "reason": "consumed_not_emitted",
    } in run["gaps"]


def test_tool_result_before_run_start_is_info(capture: Capture) -> None:
    turns = react_turns()
    # The run begins mid-conversation: its first request already carries a result.
    capture.exchange(*turns[1], response_id="chatcmpl-1")
    capture.exchange(*turns[2], response_id="chatcmpl-2")
    capture.watermark(run_id="run-react-1")
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_declared_scope"
    assert gaps_of(run, "unmatched_tool_call") == [
        {
            "gap_type": "unmatched_tool_call",
            "effect": "info",
            "exchange_id": "ex-0",
            "tool_call_id": "call_paris",
            "reason": "consumed_before_run",
        }
    ]


def test_corrupted_object_is_a_digest_mismatch(capture: Capture) -> None:
    exchanges = react_run(capture)
    path = capture.object_path(exchanges[1].objects["response"])
    data = bytearray(path.read_bytes())
    data[5] ^= 0x01
    path.chmod(0o600)
    path.write_bytes(bytes(data))
    run = only_run(capture.reconstruct())

    assert run["verdict"] == "partial"
    assert run["checks"]["bytes"] == "failed"
    assert gaps_of(run, "digest_mismatch") == [
        {
            "gap_type": "digest_mismatch",
            "effect": "partial",
            "exchange_id": "ex-1",
            "object_role": "response",
            "reason": "content_digest",
        }
    ]
    assert run["exchanges"][1]["objects"]["response"]["verification"] == "digest_mismatch"


def test_corrupted_sidecar_is_a_digest_mismatch(capture: Capture) -> None:
    exchanges = react_run(capture)
    meta = capture.object_path("meta") / f"{exchanges[0].objects['request']}.json"
    descriptor = json.loads(meta.read_text())
    descriptor["stored_byte_length"] += 1
    meta.chmod(0o600)
    meta.write_text(json.dumps(descriptor))
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert gaps_of(run, "digest_mismatch")[0]["reason"] == "sidecar_mismatch"


def test_missing_object_is_reported(capture: Capture) -> None:
    exchanges = react_run(capture)
    capture.object_path(exchanges[0].objects["request"]).unlink()
    run = only_run(capture.reconstruct())

    assert run["verdict"] == "partial"
    assert run["checks"]["bytes"] == "failed"
    assert gaps_of(run, "missing_object") == [
        {
            "gap_type": "missing_object",
            "effect": "partial",
            "exchange_id": "ex-0",
            "object_role": "request",
            "reason": "absent",
        }
    ]
    assert run["exchanges"][0]["objects"]["request"]["verification"] == "missing"


def test_missing_record_object_falls_back_to_span(capture: Capture) -> None:
    exchanges = react_run(capture)
    capture.object_path(exchanges[2].objects["record"]).unlink()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert [gap.get("object_role") for gap in gaps_of(run, "missing_object")] == ["record"]
    assert run["exchanges"][2]["origin"] == "span"
    assert run["exchanges"][2]["continues_exchange_id"] == "ex-1"
    assert run["exchanges"][2]["objects"]["request"]["verification"] == "verified"


def test_removing_final_watermark_is_unverified(capture: Capture) -> None:
    react_run(capture, close=False)
    run = only_run(capture.reconstruct())

    assert run["verdict"] == "unverified"
    assert run["checks"]["tail"] == "failed"
    assert gaps_of(run, "tail_unverified") == [
        {
            "gap_type": "tail_unverified",
            "effect": "unverified",
            "source_id": SOURCE,
            "source_epoch": EPOCH,
            "reason": "no_watermark",
        }
    ]
    assert run["declared_scope"]["through"] == []


def test_periodic_watermark_proves_tail(capture: Capture) -> None:
    react_run(capture, close=False)
    capture.watermark()
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_declared_scope"
    assert run["declared_scope"]["through"][0]["through_source_sequence"] == 3


def test_run_close_watermark_exposes_lost_tail_exchanges(capture: Capture) -> None:
    react_run(capture, close=False)
    capture.watermark(run_id="run-react-1", run_high_water=4)
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert any(gap.get("run_sequences") == [3, 4] for gap in gaps_of(run, "sequence_gap"))


def test_previous_response_id_chain_is_stitched(capture: Capture) -> None:
    user = {"type": "message", "role": "user", "content": "Book Paris."}
    fn_call = {"type": "function_call", "call_id": "fc_1", "name": "book", "arguments": "{}"}
    fn_out = {"type": "function_call_output", "call_id": "fc_1", "output": "ok"}
    done = {"type": "message", "role": "assistant", "content": [{"type": "output_text"}]}
    api = "openai.responses"
    capture.exchange([user], [fn_call], api=api, response_id="resp_0")
    capture.exchange([fn_out], [done], api=api, response_id="resp_1", previous_response_id="resp_0")
    capture.watermark(run_id="run-react-1")
    run = only_run(capture.reconstruct())

    assert run["verdict"] == "complete_for_declared_scope"
    assert run["exchanges"][1]["continues_exchange_id"] == "ex-0"
    assert run["exchanges"][1]["previous_response_id"] == "resp_0"
    assert run["threads"] == [{"thread_id": "thread-0", "exchange_ids": ["ex-0", "ex-1"]}]
    assert gaps_of(run, "unmatched_tool_call") == []


def test_unresolved_previous_response_is_partial(capture: Capture) -> None:
    fn_out = {"type": "function_call_output", "call_id": "fc_1", "output": "ok"}
    done = {"type": "message", "role": "assistant", "content": [{"type": "output_text"}]}
    api = "openai.responses"
    capture.exchange([{"type": "message", "role": "user", "content": "hi"}], [done], api=api)
    capture.exchange([fn_out], [done], api=api, previous_response_id="resp_lost", consumed=[])
    capture.watermark(run_id="run-react-1")
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert gaps_of(run, "unresolved_previous_response") == [
        {
            "gap_type": "unresolved_previous_response",
            "effect": "partial",
            "exchange_id": "ex-1",
            "previous_response_id": "resp_lost",
        }
    ]


def test_store_disabled_is_unverified(tmp_path: Path) -> None:
    capture = Capture(tmp_path, store=False)
    react_run(capture)
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "unverified"
    assert run["checks"]["bytes"] == "skipped"
    disabled = gaps_of(run, "missing_object")
    assert {gap["reason"] for gap in disabled} == {"store_disabled"}
    assert {gap["effect"] for gap in disabled} == {"unverified"}


def test_bytes_scope_without_store_is_skipped(capture: Capture) -> None:
    react_run(capture)
    run = only_run(capture.reconstruct(store=None))
    assert run["verdict"] == "unverified"
    assert run["checks"]["bytes"] == "skipped"
    assert run["exchanges"][0]["objects"]["record"]["verification"] == "not_checked"


def test_metadata_scope_without_store_is_complete(capture: Capture) -> None:
    react_run(capture)
    document = capture.reconstruct(store=None, scope="metadata")
    run = only_run(document)
    assert run["verdict"] == "complete_for_declared_scope"
    assert run["checks"]["bytes"] == "not_applicable"
    assert run["declared_scope"]["bytes"] is False
    assert "store" not in document["inputs"]


def test_metadata_scope_ignores_byte_damage(capture: Capture) -> None:
    exchanges = react_run(capture)
    capture.object_path(exchanges[0].objects["request"]).unlink()
    run = only_run(capture.reconstruct(scope="metadata"))
    assert run["verdict"] == "complete_for_declared_scope"
    assert run["exchanges"][0]["objects"]["request"]["verification"] == "not_checked"


def test_otlp_hashes_withheld_without_store_skips_stitching(capture: Capture) -> None:
    react_run(capture)
    for row in capture.rows:
        for key in ("fabric.wire.input.message_hashes", "fabric.wire.output.message_hashes"):
            row["attributes"].pop(key, None)
    run = only_run(capture.reconstruct(store=None, scope="metadata"))
    assert run["checks"]["stitching"] == "skipped"
    assert run["verdict"] == "unverified"


def test_otlp_windows_alone_stitch_the_run(capture: Capture) -> None:
    react_run(capture)
    run = only_run(capture.reconstruct(store=None, scope="metadata"))
    assert [ex.get("continues_exchange_id") for ex in run["exchanges"]] == [None, "ex-0", "ex-1"]
    assert {ex["origin"] for ex in run["exchanges"]} == {"span"}


def test_span_dropped_but_record_recovered_from_store_scan(capture: Capture) -> None:
    exchanges = react_run(capture, close=False)
    capture.rows.remove(exchanges[1].span)
    capture.loss("span_dropped", [exchanges[1]])
    capture.watermark(run_id="run-react-1")

    without_scan = only_run(capture.reconstruct())
    assert without_scan["verdict"] == "partial"

    run = only_run(capture.reconstruct(scan_store=True))
    assert run["verdict"] == "complete_for_declared_scope"
    assert run["exchanges"][1]["origin"] == "store"
    assert run["exchanges"][1]["objects"]["record"]["verification"] == "verified"
    assert [gap["effect"] for gap in gaps_of(run, "loss_record")] == ["info"]


def test_conflicting_duplicate_span_is_a_digest_mismatch(capture: Capture) -> None:
    exchanges = react_run(capture)
    duplicate = json.loads(json.dumps(exchanges[0].span))
    duplicate["attributes"]["fabric.wire.output.tool_call_ids"] = ["call_other"]
    capture.rows.append(duplicate)
    capture.rows.append(json.loads(json.dumps(exchanges[1].span)))  # identical: deduped
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert gaps_of(run, "digest_mismatch") == [
        {
            "gap_type": "digest_mismatch",
            "effect": "partial",
            "exchange_id": "ex-0",
            "reason": "conflicting_duplicate",
        }
    ]
    assert run["counts"]["exchanges"] == 3


def test_span_disagreeing_with_record_is_flagged(capture: Capture) -> None:
    exchanges = react_run(capture)
    attributes = exchanges[2].span["attributes"]
    attributes["fabric.wire.input.message_hashes"][1] = "0" * 64
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "partial"
    assert gaps_of(run, "digest_mismatch")[0]["reason"] == "span_record_disagree"


def test_unparsed_exchange_is_unverified(capture: Capture) -> None:
    react_run(capture)
    for row in capture.rows:
        if row["attributes"].get("fabric.wire.exchange_id") == "ex-0":
            row["attributes"]["fabric.wire.parse_status"] = "not_json"
    run = only_run(capture.reconstruct(store=None, scope="metadata"))
    assert run["verdict"] == "unverified"
    assert gaps_of(run, "unparsed_exchange")[0]["reason"] == "not_json"


def test_runs_are_split_and_sorted(capture: Capture) -> None:
    react_run(capture, run_id="run-b", close=False)
    capture.exchange([SYSTEM, USER], [FINAL], run_id="run-a")
    capture.watermark(run_id="run-a")
    capture.watermark(run_id="run-b")
    document = capture.reconstruct()
    assert [run["run_id"] for run in document["runs"]] == ["run-a", "run-b"]
    assert {run["verdict"] for run in document["runs"]} == {"complete_for_declared_scope"}
    selected = capture.reconstruct(run_ids=["run-b"])
    assert [run["run_id"] for run in selected["runs"]] == ["run-b"]


def test_interleaved_run_gap_inside_window_counts_for_both(capture: Capture) -> None:
    turns = react_turns()
    capture.exchange(*turns[0], run_id="run-a")
    capture.exchange([SYSTEM, USER], [FINAL], run_id="run-b", emit_span=False, store_objects=False)
    capture.exchange(*turns[1], run_id="run-a")
    capture.watermark(run_id="run-a")
    run_a = only_run(capture.reconstruct(run_ids=["run-a"]))
    # Sequence 1 is unaccounted for inside run-a's window: it may have been run-a's.
    assert run_a["verdict"] == "partial"
    assert gaps_of(run_a, "sequence_gap")[0]["sequences"] == [1]


def test_lost_run_with_only_a_loss_record_is_reported(capture: Capture) -> None:
    lost = capture.exchange([SYSTEM, USER], [FINAL], run_id="run-lost", emit_span=False)
    capture.loss("queue_full", [lost])
    capture.watermark()
    run = only_run(capture.reconstruct())
    assert run["run_id"] == "run-lost"
    assert run["exchanges"] == []
    assert run["verdict"] == "partial"
    assert run["checks"]["stitching"] == "not_applicable"


def test_two_sources_sharing_a_run_id_are_reported_separately(tmp_path: Path) -> None:
    first = Capture(tmp_path)
    first.exchange([SYSTEM, USER], [FINAL], run_id="run-shared")
    first.watermark(run_id="run-shared")
    second = Capture(tmp_path, source_id="gateway-0011223344556677", epoch=EPOCH + 5, id_prefix="g")
    second.exchange([SYSTEM, USER], [FINAL], run_id="run-shared")
    second.watermark(run_id="run-shared")
    first.rows.extend(second.rows)
    document = first.reconstruct()
    assert [(run["run_id"], run["exchanges"][0]["source_id"]) for run in document["runs"]] == [
        ("run-shared", "gateway-0011223344556677"),
        ("run-shared", SOURCE),
    ]
    assert len(document["sources"]) == 2


def test_report_is_deterministic(capture: Capture) -> None:
    exchanges = react_run(capture, close=False)
    capture.loss("queue_full", [exchanges[1]])
    first = capture.reconstruct()
    second = capture.reconstruct()
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_store_objects_are_resolved_by_object_id_not_recorded_path(capture: Capture) -> None:
    react_run(capture)
    for row in capture.rows:
        attributes = row["attributes"]
        if "fabric.wire.exchange_ref" in attributes:
            object_id = attributes["fabric.wire.exchange_ref"].rsplit("/", 1)[-1]
            attributes["fabric.wire.exchange_ref"] = f"file:///elsewhere/other/{object_id}"
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_declared_scope"
    record = run["exchanges"][0]["objects"]["record"]
    assert record["ref"].startswith(f"file://{capture.root / 'store'}")


# --------------------------------------------------------------------------
# --recompute-digests
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _Keys:
    input_digests: tuple[str, ...]
    output_digests: tuple[str, ...]
    tool_call_ids_consumed: tuple[str, ...]
    tool_calls: tuple[tuple[str, str | None], ...]
    response_id: str | None
    previous_response_id: str | None


def _fake_stitch(tamper: bool = False) -> types.ModuleType:
    module = types.ModuleType("fabric.wire._stitch")

    def extract_stitch_keys(api: str, request_bytes: bytes, *args: Any) -> _Keys:
        request = json.loads(request_bytes)
        response = json.loads(args[3])
        messages = request["messages"]
        output = [choice["message"] for choice in response["choices"]]
        inputs = tuple(message_digest(m) for m in messages)
        if tamper:
            inputs = tuple(reversed(inputs))
        return _Keys(
            inputs,
            tuple(message_digest(m) for m in output),
            tuple(_consumed(api, messages)),
            tuple((call_id, "get_weather") for call_id in _emitted(api, output)),
            response.get("id"),
            None,
        )

    module.extract_stitch_keys = extract_stitch_keys  # type: ignore[attr-defined]
    return module


def test_recompute_digests_confirms_recorded_keys(
    capture: Capture, monkeypatch: pytest.MonkeyPatch
) -> None:
    react_run(capture)
    monkeypatch.setitem(sys.modules, "fabric.wire._stitch", _fake_stitch())
    document = capture.reconstruct(recompute_digests=True)
    assert document["inputs"]["recompute_digests"] is True
    assert only_run(document)["verdict"] == "complete_for_declared_scope"


def test_recompute_digests_flags_disagreeing_record(
    capture: Capture, monkeypatch: pytest.MonkeyPatch
) -> None:
    react_run(capture)
    monkeypatch.setitem(sys.modules, "fabric.wire._stitch", _fake_stitch(tamper=True))
    run = only_run(capture.reconstruct(recompute_digests=True))
    assert run["verdict"] == "partial"
    assert {gap["reason"] for gap in gaps_of(run, "digest_mismatch")} == {
        "recomputed_keys_disagree"
    }


def test_recompute_digests_without_stitch_module_is_input_error(
    capture: Capture, monkeypatch: pytest.MonkeyPatch
) -> None:
    react_run(capture)
    monkeypatch.setitem(sys.modules, "fabric.wire._stitch", None)
    with pytest.raises(ReconstructInputError):
        capture.reconstruct(recompute_digests=True)
    path = capture.write()
    code = main(
        [
            "--spans",
            str(path),
            "--store-root",
            str(capture.root / "store"),
            "--tenant",
            TENANT,
            "--recompute-digests",
        ]
    )
    assert code == 2


def test_recompute_digests_with_real_stitch_projection(capture: Capture) -> None:
    stitch = pytest.importorskip("fabric.wire._stitch")
    if not callable(getattr(stitch, "extract_stitch_keys", None)):
        pytest.skip("fabric.wire._stitch.extract_stitch_keys not available yet")
    react_run(capture)
    run = only_run(capture.reconstruct(recompute_digests=True))
    assert gaps_of(run, "digest_mismatch") == []
    assert run["verdict"] == "complete_for_declared_scope"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _cli(capture: Capture, *extra: str) -> int:
    return main(
        [
            "--spans",
            str(capture.write()),
            "--store-root",
            str(capture.root / "store"),
            "--tenant",
            TENANT,
            *extra,
        ]
    )


def test_cli_exit_zero_for_complete_run(
    capture: Capture, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    react_run(capture)
    out = tmp_path / "report.json"
    assert _cli(capture, "--out", str(out)) == 0
    document = json.loads(out.read_text())
    validate(document)
    assert document["runs"][0]["verdict"] == "complete_for_declared_scope"
    assert "complete_for_declared_scope" in capsys.readouterr().err


def test_cli_exit_one_for_partial_run(capture: Capture, capsys: pytest.CaptureFixture[str]) -> None:
    exchanges = react_run(capture)
    capture.object_path(exchanges[0].objects["request"]).unlink()
    assert _cli(capture) == 1
    document = json.loads(capsys.readouterr().out)
    validate(document)
    assert document["runs"][0]["verdict"] == "partial"


def test_cli_exit_one_when_no_run_is_reconstructed(capture: Capture) -> None:
    react_run(capture)
    assert _cli(capture, "--run", "run-unknown") == 1


def test_cli_local_alias_and_scope_flag(capture: Capture) -> None:
    react_run(capture)
    code = main(
        [
            "--spans",
            str(capture.write()),
            "--local",
            str(capture.root / "store"),
            "--tenant",
            TENANT,
            "--scope",
            "metadata",
        ]
    )
    assert code == 0


@pytest.mark.parametrize(
    "argv",
    [
        ["--spans", "/nonexistent/spans.jsonl"],
        ["--store-root", "/tmp"],
        ["--spans", "SPANS", "--store-root", "/nonexistent-store", "--tenant", TENANT],
        ["--spans", "SPANS", "--store-root", "STORE"],
        ["--spans", "SPANS", "--tenant", TENANT],
        ["--spans", "SPANS", "--scan-store"],
        ["--spans", "SPANS", "--store-uri", "https://bucket/prefix", "--tenant", TENANT],
        ["--spans", "SPANS", "--scope", "everything"],
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
