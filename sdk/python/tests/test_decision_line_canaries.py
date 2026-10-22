# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""v0.8.1 privacy canaries for the decision line (spec 049 §7.6, spec 051 §8.3).

A canary is planted in every field the v0.8.1 fixes cover: idempotency keys, document
ids, MCP and tool-span tool names, the memory store id, the checkpoint step name, tags,
exception text, provider and caller correlation ids (previous response, response, tool
call, request, data source), side-effect ids and labels, interaction metadata, store
error text and low-entropy payloads (whose digests would reveal them). In the pseudonymous identity
mode, with and without ``FABRIC_WIRE_ID_KEY``, no canary and no digest of a canary
payload may appear in telemetry (the in-memory spans and their OTLP projection), in the
SDK's logs or in the governed content spool and store."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.exporter.otlp.proto.common.trace_encoder import encode_spans
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import ContentCaptureConfig, Fabric, FabricConfig, LocalFilesystemContentStore
from fabric.content_store import ContentRef
from fabric.integrations.mcp import InstrumentedMCPSession

KEY = b"fabric-test-id-key-not-a-secret"
TENANT = "acme"
CANARIES = {
    "idempotency": "CANARY-idem-q8z",
    "tool_idempotency": "CANARY-tool-idem-q8z",
    "document": "CANARY-doc-q8z",
    "tool_name": "CANARY_tool_q8z",
    "store": "CANARY-store-q8z",
    "step": "CANARY-step-q8z",
    "tag": "canary:CANARY-tag-q8z",
    "memory_tag": "CANARY-memory-tag-q8z",
    "exception": "CANARY-exception-text-q8z",
    "previous_response": "CANARY-prev-q8z",
    "response": "CANARY-response-q8z",
    "tool_call": "CANARY-call-q8z",
    "request": "CANARY-request-q8z",
    "data_source": "CANARY-datasource-q8z",
    "side_effect_id": "CANARY-effect-q8z",
    "target_system": "CANARY-patient-crm-q8z",
    "operation": "CANARY-update-jane-q8z",
    "metadata": "CANARY-metadata-q8z",
    "store_error": "CANARY-store-error-q8z",
}
PAYLOADS = ["yes", "no", "CANARY-payload-q8z"]  # low entropy: digests are lookups
DIGESTS = [hashlib.sha256(p.encode()).hexdigest() for p in PAYLOADS]


class CanaryError(Exception):
    pass


class _Session:
    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> Any:
        return {"content": [PAYLOADS[1]]}

    async def list_tools(self) -> Any:
        return [{"name": CANARIES["tool_name"], "description": "d", "inputSchema": {}}]


def _exercise(client: Fabric) -> None:
    with (
        pytest.raises(CanaryError),
        client.execution(),
        client.decision(session_id="s", request_id=CANARIES["request"]) as dec,
    ):
        dec.record_side_effect(
            "other", target_system=CANARIES["target_system"], operation=CANARIES["operation"],
            idempotency_key=CANARIES["idempotency"], side_effect_id=CANARIES["side_effect_id"],
            parent_tool_call_id=CANARIES["tool_call"],
            request_payload=PAYLOADS[0], result_payload=PAYLOADS[1],
        )  # fmt: skip
        dec.record_replay_metadata()
        with (
            pytest.raises(CanaryError),
            dec.tool_call(CANARIES["tool_name"], call_id=CANARIES["tool_call"]) as tool,
        ):
            tool.set_idempotency(idempotent=True, key=CANARIES["tool_idempotency"])
            tool.set_arguments(PAYLOADS[0])
            tool.set_result(PAYLOADS[1])
            raise CanaryError(CANARIES["exception"])
        with (
            pytest.raises(CanaryError),
            dec.llm_call(
                provider="openai", model="m", previous_response_id=CANARIES["previous_response"]
            ) as llm,
        ):
            llm.set_response(response_id=CANARIES["response"])
            raise CanaryError(CANARIES["exception"])
        dec.record_retrieval(
            "rag", query=PAYLOADS[2], result_count=1, data_source_id=CANARIES["data_source"],
            result_hashes=[DIGESTS[2]], source_document_ids=[CANARIES["document"]],
        )  # fmt: skip
        dec.remember(kind="semantic", content=PAYLOADS[0], store_id=CANARIES["store"],
                     tags=[CANARIES["memory_tag"]])  # fmt: skip
        dec.recall(kind="semantic", key="k", content=PAYLOADS[1], store_id=CANARIES["store"])
        dec.forget("semantic", "k", store_id=CANARIES["store"])
        dec.checkpoint(CANARIES["step"])
        dec.record_interaction("message.send", "t", payload=PAYLOADS[2], tags=[CANARIES["tag"]],
                               metadata={"note": CANARIES["metadata"]})  # fmt: skip
        session = InstrumentedMCPSession(_Session(), dec)
        asyncio.run(session.list_tools())
        asyncio.run(session.call_tool(CANARIES["tool_name"], {"q": PAYLOADS[0]}))
        raise CanaryError(CANARIES["exception"])


# Governed content keeps its decision bindings (request id, tool-call id) as given: the
# content store is the customer's protected destination for content, which carries the
# same ids in its bodies (spec 049 §2.9 line 279, as for the session binding).
CONTENT_BINDINGS = frozenset({"request", "tool_call"})


def _assert_clean(
    blob: str, where: str, *, skip: frozenset[str] = frozenset(), digests: bool = True
) -> None:
    for name, canary in CANARIES.items():
        if name not in skip:
            assert canary not in blob, f"{name} canary in {where}"
    if digests:
        for digest in DIGESTS:
            assert digest not in blob, f"payload digest in {where}"


def _telemetry(exporter: InMemorySpanExporter) -> str:
    spans = exporter.get_finished_spans()
    otlp: str = encode_spans(spans).SerializeToString().decode("utf-8", "replace")
    readable = json.dumps(
        [
            [s.name, dict(s.attributes or {}), s.status.description,
             [[e.name, dict(e.attributes or {})] for e in s.events]]
            for s in spans
        ],
        default=str,
    )  # fmt: skip
    return otlp + readable


def _files(root: Path) -> str:
    return "".join(
        path.read_bytes().decode("utf-8", "replace") for path in root.rglob("*") if path.is_file()
    )


@pytest.mark.parametrize("keyed", [True, False], ids=["with-key", "without-key"])
def test_no_canary_leaves_the_process_in_pseudonymous_mode(
    span_exporter: InMemorySpanExporter,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    keyed: bool,
) -> None:
    monkeypatch.delenv("FABRIC_WIRE_ID_KEY", raising=False)
    monkeypatch.delenv("FABRIC_WIRE_LABELS", raising=False)
    monkeypatch.delenv("FABRIC_RECORDS_STRICT", raising=False)
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id=TENANT)
    capture = ContentCaptureConfig(
        store=store, roles=frozenset({"model.output.messages"}), durability="spooled",
        spool_dir=str(tmp_path / "spool"),
    )  # fmt: skip
    config = FabricConfig(tenant_id=TENANT, agent_id="bot", identity_mode="pseudonymous")
    client = Fabric(config, id_key=KEY if keyed else None, content_capture=capture)
    with caplog.at_level(logging.DEBUG):
        _exercise(client)
        client.flush_content(timeout_s=5)
    _assert_clean(_telemetry(span_exporter), "telemetry")
    logs = "\n".join(record.getMessage() + (record.exc_text or "") for record in caplog.records)
    _assert_clean(logs, "logs")
    written = [path for path in tmp_path.rglob("*") if path.is_file()]
    assert written, "the governed path wrote nothing to scan"
    _assert_clean(_files(tmp_path), "spool and store", skip=CONTENT_BINDINGS)


def test_canaries_are_visible_in_clear_mode(span_exporter: InMemorySpanExporter) -> None:
    """The control: the same calls in the clear mode export the v0.8.0 values, so the
    pseudonymous test above is not passing vacuously."""
    config = FabricConfig(tenant_id=TENANT, agent_id="bot", identity_mode="clear")
    _exercise(Fabric(config, id_key=KEY))
    blob = _telemetry(span_exporter)
    for name, canary in CANARIES.items():
        if name in {"metadata", "store_error"}:
            continue  # hashed or never recorded, in every mode
        assert canary in blob, name
    assert DIGESTS[2] in blob


class _LeakyStore:
    """A legacy store whose error message echoes the payload."""

    def put(self, content: str, *, key_hint: str | None = None) -> ContentRef:
        raise RuntimeError(CANARIES["store_error"] + content)

    def close(self) -> None:
        pass


def test_store_errors_never_reach_logs_or_telemetry(
    span_exporter: InMemorySpanExporter, caplog: pytest.LogCaptureFixture
) -> None:
    config = FabricConfig(tenant_id=TENANT, agent_id="bot", identity_mode="pseudonymous")
    client = Fabric(config, id_key=KEY, content_store=_LeakyStore())
    with caplog.at_level(logging.DEBUG), client.decision(session_id="s", request_id="r") as dec:
        dec.remember(kind="semantic", content=PAYLOADS[2])
        dec.record_side_effect("other", target_system="crm", operation="u",
                               request_payload=PAYLOADS[0])  # fmt: skip
        client.flush_content(timeout_s=5)
    assert client.content_store_stats() == {
        "enqueued": 2, "stored": 0, "dropped": 0, "failed": 2, "pending": 0,
    }  # fmt: skip
    logs = "\n".join(
        record.getMessage() + (record.exc_text or "") + repr(record.exc_info)
        for record in caplog.records
    )
    _assert_clean(logs, "logs")
    assert PAYLOADS[2] not in logs
    # The legacy store retains memory and side-effect payloads, so their digests may
    # appear (049 §7.5); no canary may.
    _assert_clean(_telemetry(span_exporter), "telemetry", digests=False)
