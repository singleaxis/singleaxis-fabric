# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""v0.8.1 (spec 049 §7.1, §7.6): Fabric's diagnostics never carry an exception message or
a traceback (they can hold payload text), and a failing log handler never changes what
the application gets."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterator
from typing import Any

import pytest

from fabric import Fabric, FabricConfig
from fabric.content_store import ContentRef
from fabric.integrations.mcp import traced_call_tool

CANARY = "CANARY-payload-q8z"


class _LeakyStore:
    """A legacy store whose failure message echoes the payload (as many SDKs do)."""

    def put(self, content: str, *, key_hint: str | None = None) -> ContentRef:
        raise RuntimeError("CANARY-content=" + content)

    def close(self) -> None:
        pass


class _RaisingHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        raise OSError("logger-down")


@pytest.fixture()
def raising_handler() -> Iterator[None]:
    handler = _RaisingHandler(level=logging.DEBUG)
    root = logging.getLogger("fabric")
    previous = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        yield
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)


def _logs(caplog: pytest.LogCaptureFixture) -> str:
    return "\n".join(
        record.getMessage() + (record.exc_text or "") + repr(record.exc_info)
        for record in caplog.records
    )


def test_store_failure_logs_the_exception_class_only(caplog: pytest.LogCaptureFixture) -> None:
    client = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"), content_store=_LeakyStore())
    with caplog.at_level(logging.DEBUG), client.decision(session_id="s", request_id="r") as d:
        d.remember(kind="semantic", content=CANARY)
        d.record_side_effect("other", target_system="crm", operation="u", request_payload=CANARY)
        client.flush_content(timeout_s=5)
    logs = _logs(caplog)
    assert "RuntimeError" in logs
    assert CANARY not in logs
    assert "Traceback" not in logs
    assert all(record.exc_info is None for record in caplog.records)


class _HostileResult:
    @property
    def isError(self) -> bool:  # noqa: N802 - MCP field name
        raise RuntimeError("inspecting the result failed")


class _Session:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.calls = 0

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> Any:
        self.calls += 1
        return self.result


@pytest.mark.usefixtures("raising_handler")
def test_mcp_diagnostics_fail_open_after_the_call() -> None:
    result = _HostileResult()
    session = _Session(result)
    with Fabric(FabricConfig(tenant_id="acme", agent_id="bot")).decision(
        session_id="s", request_id="r"
    ) as dec:
        assert asyncio.run(traced_call_tool(dec, session, "t")) is result
    assert session.calls == 1


@pytest.mark.usefixtures("raising_handler")
def test_mcp_diagnostics_fail_open_before_the_call() -> None:
    session = _Session("ok")
    dec = Fabric(FabricConfig(tenant_id="acme", agent_id="bot")).decision(
        session_id="s", request_id="r"
    )  # never entered: the span cannot open, the diagnostic fires, its handler raises
    assert asyncio.run(traced_call_tool(dec, session, "t")) == "ok"
    assert session.calls == 1
