# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Cross-workstream integration for spec 047 (rev 3, store-only stitching).

The wire tee, sequencing/loss, the capture pipeline and the offline verifier
are tested separately in ``test_wire_*``, ``test_loss_*`` and
``test_reconstruct_*``. Here the *real* components run
end to end: captured spans are written to a sink JSONL file exactly as an
exporter would, the bytes land in a real local store, and
:func:`fabric.reconstruct.reconstruct` must reach the verdicts of spec 047
§12. Capture spans carry no message hashes or tool-call ids, so every
stitching result below is derived offline from the stored bytes. Every report
is checked against the run-reconstruction-v1 schema and the contract
validator's semantic rules.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx
import pytest
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult

import fabric._loss
import fabric._sequence
from fabric import wire
from fabric._loss import LossEmitter
from fabric._model_names import hashed_model
from fabric.content_store import LocalFilesystemContentStore
from fabric.reconstruct import reconstruct, run_id_pseudonym
from fabric.reconstruct._inputs import pseudonym

from .test_wire_helpers import capture_schemas, load_validator

REPO_ROOT = Path(__file__).resolve().parents[3]
EXAMPLE = REPO_ROOT / "examples" / "wire-capture" / "react_agent.py"
TENANT = "tenant-int"
RUN_ID = "run-int-1"
#: What capture emits for RUN_ID (H3): only the pseudonym leaves the process.
EMITTED_RUN_ID = run_id_pseudonym(RUN_ID)
MODEL_URL = "http://model.local/v1/chat/completions"
VALIDATOR = load_validator()
SCHEMAS = capture_schemas()
RAW_MARKERS = ("Lisbon", "get_weather", "sk-test-not-a-key", "Celsius")


class JsonlSpanExporter(SpanExporter):
    """Sink-JSONL rows (``{"kind": "span", ...}``) as the demo sink writes them."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            for span in spans:
                context = span.get_span_context()
                assert context is not None
                handle.write(
                    json.dumps(
                        {
                            "kind": "span",
                            "trace_id": f"{context.trace_id:032x}",
                            "span_id": f"{context.span_id:016x}",
                            "parent_span_id": (
                                f"{span.parent.span_id:016x}" if span.parent else None
                            ),
                            "name": span.name,
                            "start_ns": span.start_time,
                            "end_ns": span.end_time,
                            "resource": dict(span.resource.attributes),
                            "attributes": {
                                key: list(value) if isinstance(value, tuple) else value
                                for key, value in (span.attributes or {}).items()
                            },
                        }
                    )
                    + "\n"
                )
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


@pytest.fixture(autouse=True)
def _isolated_process_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")  # 050 R8: clear emits run ids
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    yield
    wire.uninstall()
    emitter.close(1.0)


def _provider(spans_path: Path) -> TracerProvider:
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(JsonlSpanExporter(spans_path)))
    return provider


def _tool_message(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [m for m in messages if m.get("role") == "tool"]


def _fake_model(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    step = len(_tool_message(body["messages"]))
    if step < 2:  # two tool turns, then the answer
        name = "get_weather" if step == 0 else "c_to_f"
        message: dict[str, Any] = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": f"call_{step}",
                    "type": "function",
                    "function": {"name": name, "arguments": '{"x": 1}'},
                }
            ],
        }
        finish = "tool_calls"
    else:
        message = {"role": "assistant", "content": "It is 64 F in Lisbon."}
        finish = "stop"
    return httpx.Response(
        200,
        headers={"x-request-id": f"req_{step}"},
        json={
            "id": f"chatcmpl-int-{step}",
            "object": "chat.completion",
            "model": "demo-model",
            "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        },
    )


def _react(client: httpx.Client) -> str:
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": "Use tools. Report Celsius as F."},
        {"role": "user", "content": "Weather in Lisbon?"},
    ]
    for _ in range(5):
        response = client.post(
            MODEL_URL,
            headers={"authorization": "Bearer sk-test-not-a-key"},
            json={"model": "demo-model", "messages": messages},
        )
        message = response.json()["choices"][0]["message"]
        messages.append(message)
        if not message.get("tool_calls"):
            return str(message["content"])
        for call in message["tool_calls"]:
            messages.append({"role": "tool", "tool_call_id": call["id"], "content": "18"})
    raise AssertionError("agent did not finish")


class _FailingResponses:
    """A store that refuses every ``model.exchange.response`` write."""

    def __init__(self, inner: LocalFilesystemContentStore) -> None:
        self._inner = inner
        self.tenant_id = inner.tenant_id

    def evidence_ref_for(self, object_id: str) -> str:
        return self._inner.evidence_ref_for(object_id)

    def put_bytes_object(self, descriptor: Mapping[str, Any], content: bytes) -> Any:
        if descriptor.get("role") == "model.exchange.response":
            raise OSError("simulated store outage")
        return self._inner.put_bytes_object(descriptor, content)


def _capture_wire_run(tmp_path: Path, *, store: Any = None) -> tuple[Path, Any]:
    spans_path = tmp_path / "spans.jsonl"
    provider = _provider(spans_path)
    local = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id=TENANT)
    handle = wire.install(
        store=local if store is None else store(local),
        tracer_provider=provider,
        extra_endpoints=(
            wire.EndpointMatcher(
                endpoint_id="fake-model",
                dialect="openai",
                hosts=frozenset({"model.local"}),
                schemes=frozenset({"http"}),
            ),
        ),
        patch_httpx=False,
    )
    handle._tee.pipeline._backoffs = ()  # one store attempt: outages fail fast
    transport = wire.WireTransport(httpx.MockTransport(_fake_model))
    with httpx.Client(transport=transport) as client, wire.run(RUN_ID):
        assert _react(client) == "It is 64 F in Lisbon."
    assert handle.flush(10.0)
    handle.close()
    provider.shutdown()
    return spans_path, local


def _verify(spans: Path, store: Any, **kwargs: Any) -> dict[str, Any]:
    document: dict[str, Any] = reconstruct([spans], store=store, tenant_id=TENANT, **kwargs)
    VALIDATOR.validate_document(document, SCHEMAS)
    return document


def _only_run(document: Mapping[str, Any], run_id: str = EMITTED_RUN_ID) -> dict[str, Any]:
    runs: list[dict[str, Any]] = [r for r in document["runs"] if r["run_id"] == run_id]
    assert len(runs) == 1, document["runs"]
    return runs[0]


def _gap_types(run: Mapping[str, Any]) -> set[str]:
    return {gap["gap_type"] for gap in run["gaps"]}


def _rows(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text("utf-8").splitlines() if line]


def _write_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), "utf-8")


# ---------------------------------------------------------------- wire -> verify


def test_wire_react_run_reconstructs_complete(tmp_path: Path) -> None:
    spans, store = _capture_wire_run(tmp_path)

    document = _verify(spans, store)
    run = _only_run(document)

    # H5: a scoped run claims only its observed scopes; each scope is complete.
    assert run["verdict"] == "complete_for_observed_scopes"
    assert [(s["run_id"], s["verdict"]) for s in document["scopes"]] == [
        (EMITTED_RUN_ID, "complete_for_declared_scope")
    ]
    assert run["gaps"] == []
    assert set(run["checks"].values()) == {"passed"}
    assert len(run["exchanges"]) == 3
    assert [t["exchange_ids"] for t in run["threads"]] == [
        [exchange["exchange_id"] for exchange in run["exchanges"]]
    ]
    emitted = [ids for e in run["exchanges"] for ids in e["tool_call_ids_emitted"]]
    consumed = [ids for e in run["exchanges"] for ids in e["tool_call_ids_consumed"]]
    # E6: provider-derived ids are pseudonymised, with correlation preserved.
    assert emitted == [pseudonym("call_0"), pseudonym("call_1")]
    assert sorted(set(consumed)) == sorted({pseudonym("call_0"), pseudonym("call_1")})
    assert [e["source_sequence"] for e in run["exchanges"]] == [0, 1, 2]
    assert all(
        obj["verification"] == "verified" for e in run["exchanges"] for obj in e["objects"].values()
    )


def test_exchange_spans_carry_no_message_level_keys(tmp_path: Path) -> None:
    spans, _ = _capture_wire_run(tmp_path)
    exchanges = [r for r in _rows(spans) if r["name"] == "fabric.model_call"]
    assert len(exchanges) == 3
    for row in exchanges:
        keys = set(row["attributes"])
        assert not {k for k in keys if "hash" in k or "tool_call" in k or "message" in k}
        assert "fabric.run.sequence" not in keys
        assert row["attributes"]["fabric.wire.store_status"] == "stored"
        # Spec 048 F7: a model name outside the allowlist leaves only as a digest.
        assert row["attributes"]["gen_ai.response.model"] == hashed_model("demo-model")


def test_spans_and_report_carry_no_content(tmp_path: Path) -> None:
    spans, store = _capture_wire_run(tmp_path)
    report = json.dumps(_verify(spans, store))
    span_text = spans.read_text("utf-8")
    for marker in (*RAW_MARKERS, RUN_ID):
        assert marker not in span_text
        assert marker not in report
    assert EMITTED_RUN_ID in span_text and EMITTED_RUN_ID in report
    # The bytes did reach the customer store (headers never do).
    stored = b"".join(p.read_bytes() for p in (tmp_path / "store").rglob("*") if p.is_file())
    assert b"Lisbon" in stored
    assert b"sk-test-not-a-key" not in stored


def test_dropped_exchange_span_is_partial(tmp_path: Path) -> None:
    spans, store = _capture_wire_run(tmp_path)
    rows = _rows(spans)
    middle = next(r for r in rows if r["attributes"].get("fabric.source.sequence") == 1)
    _write_rows(spans, [r for r in rows if r is not middle])

    run = _only_run(_verify(spans, store))

    assert run["verdict"] == "partial"
    assert "sequence_gap" in _gap_types(run)


def test_deleted_store_object_is_missing_object(tmp_path: Path) -> None:
    spans, store = _capture_wire_run(tmp_path)
    row = next(r for r in _rows(spans) if r["attributes"].get("fabric.source.sequence") == 1)
    object_id = row["attributes"]["fabric.content.result_ref"]
    (tmp_path / "store" / TENANT / "evidence" / object_id).unlink()

    run = _only_run(_verify(spans, store))

    assert run["verdict"] == "partial"
    assert "missing_object" in _gap_types(run)


def test_flipped_stored_byte_is_digest_mismatch(tmp_path: Path) -> None:
    spans, store = _capture_wire_run(tmp_path)
    row = next(r for r in _rows(spans) if r["attributes"].get("fabric.source.sequence") == 0)
    object_id = row["attributes"]["fabric.content.request_ref"]
    target = tmp_path / "store" / TENANT / "evidence" / object_id
    data = bytearray(target.read_bytes())
    data[0] ^= 0x01
    target.write_bytes(bytes(data))

    run = _only_run(_verify(spans, store))

    assert run["verdict"] == "partial"
    assert "digest_mismatch" in _gap_types(run)


def test_removed_heartbeats_are_unverified(tmp_path: Path) -> None:
    spans, store = _capture_wire_run(tmp_path)
    rows = _rows(spans)
    kept = [r for r in rows if r["name"] != "fabric.capture_heartbeat"]
    assert len(kept) < len(rows)
    _write_rows(spans, kept)

    run = _only_run(_verify(spans, store))

    assert run["verdict"] == "unverified"
    assert "tail_unverified" in _gap_types(run)


def test_store_outage_is_a_missing_object_not_a_digest_mismatch(tmp_path: Path) -> None:
    spans, store = _capture_wire_run(tmp_path, store=_FailingResponses)
    statuses = {
        r["attributes"]["fabric.wire.store_status"]
        for r in _rows(spans)
        if r["name"] == "fabric.model_call"
    }
    assert statuses == {"partial"}

    run = _only_run(_verify(spans, store))

    assert run["verdict"] == "partial"
    reasons = {(g["gap_type"], g.get("reason"), g.get("object_role")) for g in run["gaps"]}
    assert reasons == {("missing_object", "not_stored", "response")}
    # The request bodies did reach the store and still verify.
    assert {e["objects"]["request"]["verification"] for e in run["exchanges"]} == {"verified"}


# ------------------------------------------------------------------- example


def test_wire_capture_example_runs_to_a_complete_verdict(tmp_path: Path) -> None:
    result = subprocess.run(  # noqa: S603 - fixed interpreter and repo script
        [sys.executable, str(EXAMPLE), "--out-dir", str(tmp_path / "out")],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads((tmp_path / "out" / "report.json").read_text("utf-8"))
    VALIDATOR.validate_document(report, SCHEMAS)
    assert [run["verdict"] for run in report["runs"]] == ["complete_for_observed_scopes"]
    assert {scope["verdict"] for scope in report["scopes"]} == {"complete_for_declared_scope"}
    assert [run["gaps"] for run in report["runs"]] == [[]]
