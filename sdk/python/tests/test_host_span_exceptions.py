# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""v0.8.1 (spec 049 §7.6, spec 051 §4.9): in the pseudonymous identity mode a host span
records only the exception class: no message, no stack trace, no message in the status.
The ``clear`` mode keeps the OpenTelemetry default."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import Fabric, FabricConfig

KEY = b"fabric-test-id-key-not-a-secret"
SECRET = "canary-exception-text-patient-jane"  # noqa: S105 - a canary, not a secret


class PatientLookupError(Exception):
    pass


def _client(mode: str) -> Fabric:
    config = FabricConfig(tenant_id="acme", agent_id="bot", identity_mode=mode)  # type: ignore[arg-type]
    return Fabric(config, id_key=KEY)


def _raise_everywhere(client: Fabric) -> None:
    with (
        pytest.raises(PatientLookupError),
        client.execution(),
        client.decision(session_id="s", request_id="r") as dec,
    ):
        with pytest.raises(PatientLookupError), dec.llm_call(provider="openai", model="m"):
            raise PatientLookupError(SECRET)
        with pytest.raises(PatientLookupError), dec.tool_call("lookup"):
            raise PatientLookupError(SECRET)
        with pytest.raises(KeyboardInterrupt), dec.tool_call("lookup"):
            raise KeyboardInterrupt(SECRET)
        raise PatientLookupError(SECRET)


def _exception_events(exporter: InMemorySpanExporter) -> list[dict[str, Any]]:
    return [
        dict(event.attributes or {})
        for span in exporter.get_finished_spans()
        for event in span.events
        if event.name == "exception"
    ]


def test_pseudonymous_host_spans_record_the_class_only(
    span_exporter: InMemorySpanExporter,
) -> None:
    _raise_everywhere(_client("pseudonymous"))
    events = _exception_events(span_exporter)
    assert len(events) == 5  # llm, tool, tool (BaseException), decision, execution
    for attrs in events:
        assert set(attrs) == {"exception.type"}
        assert attrs["exception.type"] in {
            f"{__name__}.PatientLookupError", "KeyboardInterrupt",
        }  # fmt: skip
    spans = span_exporter.get_finished_spans()
    blob = json.dumps(
        [
            [
                dict(s.attributes or {}),
                s.status.description,
                [dict(e.attributes or {}) for e in s.events],
            ]
            for s in spans
        ],
        default=str,
    )
    assert SECRET not in blob
    assert "Traceback" not in blob


def test_clear_mode_keeps_the_opentelemetry_exception_event(
    span_exporter: InMemorySpanExporter,
) -> None:
    _raise_everywhere(_client("clear"))
    events = _exception_events(span_exporter)
    assert len(events) == 5
    for attrs in events:
        assert attrs["exception.message"] == SECRET
        assert "Traceback" in attrs["exception.stacktrace"]


def test_async_tool_call_exception_is_class_only(span_exporter: InMemorySpanExporter) -> None:
    async def run() -> None:
        with _client("pseudonymous").decision(session_id="s", request_id="r") as dec:
            async with dec.tool_call("lookup"):
                raise PatientLookupError(SECRET)

    with pytest.raises(PatientLookupError):
        asyncio.run(run())
    for attrs in _exception_events(span_exporter):
        assert set(attrs) == {"exception.type"}
