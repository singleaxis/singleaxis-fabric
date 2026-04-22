# Copyright 2026 AI5 Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Retrieval recording — span events + rolling aggregates."""

from __future__ import annotations

import hashlib

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic import ValidationError

from fabric import (
    Fabric,
    FabricConfig,
    RetrievalRecord,
    RetrievalSource,
)
from fabric.decision import ATTR_RETRIEVAL_COUNT, ATTR_RETRIEVAL_SOURCES


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="support-bot"))


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# -- RetrievalRecord model -----------------------------------------------------


def test_from_query_hashes_the_query() -> None:
    record = RetrievalRecord.from_query(
        source=RetrievalSource.RAG,
        query="What is the PTO policy?",
        result_count=3,
    )
    assert record.query_hash == _sha("What is the PTO policy?")
    assert record.source is RetrievalSource.RAG
    assert record.result_count == 3
    assert record.result_hashes == ()
    assert record.source_document_ids == ()
    assert record.latency_ms is None


def test_from_query_accepts_string_source() -> None:
    record = RetrievalRecord.from_query(source="kg", query="q", result_count=1)
    assert record.source is RetrievalSource.KG


def test_from_query_rejects_unknown_source() -> None:
    with pytest.raises(ValueError, match="blockchain"):
        RetrievalRecord.from_query(source="blockchain", query="q", result_count=1)


def test_from_query_rejects_empty_query() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        RetrievalRecord.from_query(source="rag", query="", result_count=0)


def test_model_rejects_non_hex_query_hash() -> None:
    with pytest.raises(ValidationError):
        RetrievalRecord(source=RetrievalSource.RAG, query_hash="not-a-hash", result_count=1)


def test_model_rejects_extra_fields() -> None:
    payload = {
        "source": "rag",
        "query_hash": _sha("q"),
        "result_count": 1,
        "leak": "nope",
    }
    with pytest.raises(ValidationError):
        RetrievalRecord.model_validate(payload)


# -- Decision.record_retrieval -------------------------------------------------


def test_record_retrieval_emits_span_event(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.record_retrieval(
            RetrievalSource.RAG,
            query="What is the PTO policy?",
            result_count=4,
            result_hashes=["a" * 64, "b" * 64],
            source_document_ids=["doc-1", "doc-2"],
            latency_ms=87,
        )

    span = span_exporter.get_finished_spans()[0]
    events = [ev for ev in span.events if ev.name == "fabric.retrieval"]
    assert len(events) == 1
    attrs = dict(events[0].attributes or {})
    assert attrs["fabric.retrieval.source"] == "rag"
    assert attrs["fabric.retrieval.query_hash"] == _sha("What is the PTO policy?")
    assert attrs["fabric.retrieval.result_count"] == 4
    assert attrs["fabric.retrieval.result_hashes"] == ("a" * 64, "b" * 64)
    assert attrs["fabric.retrieval.source_document_ids"] == ("doc-1", "doc-2")
    assert attrs["fabric.retrieval.latency_ms"] == 87


def test_record_retrieval_omits_optional_attrs_when_unset(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.record_retrieval("kg", query="entity:Q42", result_count=0)

    event = next(
        ev for ev in span_exporter.get_finished_spans()[0].events if ev.name == "fabric.retrieval"
    )
    attrs = dict(event.attributes or {})
    assert attrs["fabric.retrieval.source"] == "kg"
    assert attrs["fabric.retrieval.result_count"] == 0
    assert "fabric.retrieval.result_hashes" not in attrs
    assert "fabric.retrieval.source_document_ids" not in attrs
    assert "fabric.retrieval.latency_ms" not in attrs


def test_record_retrieval_updates_rolling_span_aggregates(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        dec.record_retrieval("rag", query="q1", result_count=2)
        dec.record_retrieval("kg", query="q2", result_count=1)
        dec.record_retrieval("rag", query="q3", result_count=0)

    attrs = dict(span_exporter.get_finished_spans()[0].attributes or {})
    assert attrs[ATTR_RETRIEVAL_COUNT] == 3
    # Sorted, deduped.
    assert attrs[ATTR_RETRIEVAL_SOURCES] == ("kg", "rag")


def test_record_retrieval_returns_and_stores_record() -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        r1 = dec.record_retrieval("rag", query="q1", result_count=1)
        r2 = dec.record_retrieval("memory", query="q2", result_count=0)
        assert dec.retrievals == (r1, r2)
        assert r1.source is RetrievalSource.RAG
        assert r2.source is RetrievalSource.MEMORY


def test_record_retrieval_never_exposes_raw_query_on_span(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    raw_query = "patient SSN 123-45-6789 symptoms X Y Z"
    with client.decision(session_id="s", request_id="r") as dec:
        dec.record_retrieval("rag", query=raw_query, result_count=1)

    span = span_exporter.get_finished_spans()[0]
    all_values: list[object] = list((span.attributes or {}).values())
    for ev in span.events:
        all_values.extend((ev.attributes or {}).values())
    serialized = repr(all_values)
    assert raw_query not in serialized
    assert "SSN" not in serialized
    assert "123-45-6789" not in serialized


def test_record_retrieval_requires_live_span() -> None:
    client = _client()
    dec = client.decision(session_id="s", request_id="r")
    with pytest.raises(RuntimeError, match="has not been entered"):
        dec.record_retrieval("rag", query="q", result_count=1)


def test_retrievals_empty_by_default() -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as dec:
        assert dec.retrievals == ()
