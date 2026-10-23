# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""v0.8.1 (spec 049 §7.1 rules 2-3, §7.1 rule 6): a failing recorder never escapes a
reporting API, and on exit from a decision, delegate, LLM or tool block the application's
own exception object propagates unchanged."""

from __future__ import annotations

from typing import Any

import pytest
from opentelemetry import trace

from fabric import Fabric, FabricConfig


class RecorderDownError(RuntimeError):
    pass


class AppError(Exception):
    pass


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))


def _break(span: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def down(*args: object, **kwargs: object) -> None:
        raise RecorderDownError("recorder-down")

    for name in ("add_event", "set_attribute", "set_attributes", "set_status",
                 "record_exception", "update_name"):  # fmt: skip
        monkeypatch.setattr(span, name, down)


def test_reporting_apis_fail_open(monkeypatch: pytest.MonkeyPatch) -> None:
    with _client().decision(session_id="s", request_id="r") as dec:
        _break(trace.get_current_span(), monkeypatch)
        dec.record_interaction("message.send", "t")
        dec.remember(kind="semantic", content="c", store_id="st")
        dec.recall(kind="semantic", key="k", content="c")
        dec.forget("semantic", "k")
        dec.record_retrieval("rag", query="q", result_count=0, data_source_id="ds")
        dec.record_side_effect("other", target_system="crm", operation="u")
        dec.checkpoint("step")
        dec.record_replay_metadata()
        dec.record_skill("skill", "1")
        dec.record_hook("h", "pre_tool")
        dec.record_file_access("/tmp/x", "read")
        dec.set_attribute("k", "v")
        with dec.delegate("helper") as sub:
            assert sub.to_agent == "helper"
    assert dec.capture_health["status"] == "partial"


def test_application_exception_survives_a_failing_recorder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    boom = AppError("app")
    with pytest.raises(AppError) as info, _client().decision(session_id="s", request_id="r"):
        _break(trace.get_current_span(), monkeypatch)
        raise boom
    assert info.value is boom


def test_delegate_and_child_blocks_keep_the_application_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    boom = AppError("app")
    with _client().decision(session_id="s", request_id="r") as dec:
        with pytest.raises(AppError) as info, dec.delegate("helper"):
            _break(trace.get_current_span(), monkeypatch)
            raise boom
        assert info.value is boom
        with pytest.raises(AppError) as info, dec.tool_call("lookup") as tool:
            _break(trace.get_current_span(), monkeypatch)
            tool.set_result("r")
            tool.set_result_count(1)
            raise boom
        assert info.value is boom
        with pytest.raises(AppError) as info, dec.llm_call(provider="openai", model="m") as llm:
            _break(trace.get_current_span(), monkeypatch)
            llm.set_usage(input_tokens=1, output_tokens=1)
            llm.set_response(response_id="resp", finish_reasons=["stop"])
            raise boom
        assert info.value is boom


def test_a_failing_tracer_never_reaches_the_application(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client()

    def down(*args: object, **kwargs: object) -> None:
        raise RecorderDownError("tracer-down")

    monkeypatch.setattr(client.tracer, "start_as_current_span", down)
    ran = []
    with client.decision(session_id="s", request_id="r") as dec:
        dec.record_interaction("message.send", "t")
        dec.remember(kind="semantic", content="c")
        with dec.tool_call("lookup") as tool:
            tool.set_result("r")
        with dec.llm_call(provider="openai", model="m"):
            ran.append(1)
    assert ran == [1]
