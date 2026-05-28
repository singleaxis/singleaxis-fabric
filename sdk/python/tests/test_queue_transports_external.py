# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for the NATS / Redis / SQS judge-queue transports.

None of nats-py / redis / boto3 are dev dependencies. Each test injects
a fake module via ``monkeypatch.setitem(sys.modules, ...)`` that records
what the transport published, then asserts the JSON body round-trips
back to an equal JudgeRequest.
"""

from __future__ import annotations

import json
import sys
from types import ModuleType, SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from fabric import (
    JudgeContext,
    JudgeRequest,
    NATSQueueTransport,
    QueueTransport,
    RedisStreamTransport,
    SQSQueueTransport,
    ToolCallSnapshot,
)
from fabric.queue_transports._serialize import request_from_dict


def _req(rubric: str = "rubric-1") -> JudgeRequest:
    return JudgeRequest(
        request_id=uuid4(),
        decision_id="decision-1",
        rubric_id=rubric,
        dimensions=("faithfulness",),
        context=JudgeContext(
            user_input="hi",
            tool_calls=(ToolCallSnapshot(name="lookup", args={"k": "v"}),),
        ),
        payload_ref=None,
    )


# --------------------------------------------------------------------------- #
# NATS
# --------------------------------------------------------------------------- #


def _fake_nats(recorder: dict[str, Any]) -> ModuleType:
    module = ModuleType("nats")

    class _Conn:
        async def publish(self, subject: str, payload: bytes) -> None:
            recorder["subject"] = subject
            recorder["payload"] = payload

        async def flush(self) -> None:
            recorder["flushed"] = True

        async def drain(self) -> None:
            recorder["drained"] = True

    async def connect(servers: Any) -> _Conn:
        recorder["servers"] = servers
        recorder["connects"] = recorder.get("connects", 0) + 1
        return _Conn()

    module.connect = connect  # type: ignore[attr-defined]
    return module


def test_nats_enqueue_publishes_round_tripping_body(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "nats", _fake_nats(recorder))
    transport = NATSQueueTransport(subject="custom.subject")
    request = _req()
    transport.enqueue(request)
    assert recorder["subject"] == "custom.subject"
    assert recorder["flushed"] is True
    assert recorder["servers"] == "nats://localhost:4222"
    rebuilt = request_from_dict(json.loads(recorder["payload"].decode()))
    assert rebuilt == request


def test_nats_connection_is_lazy_and_reused(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "nats", _fake_nats(recorder))
    transport = NATSQueueTransport()
    assert "connects" not in recorder  # no connection at construction
    transport.enqueue(_req())
    transport.enqueue(_req())
    assert recorder["connects"] == 1  # one connection, reused


def test_nats_close_drains(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "nats", _fake_nats(recorder))
    transport = NATSQueueTransport()
    transport.enqueue(_req())
    transport.close()
    assert recorder["drained"] is True


def test_nats_close_without_enqueue_is_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "nats", _fake_nats(recorder))
    transport = NATSQueueTransport()
    transport.close()  # must not raise
    assert "drained" not in recorder


def test_nats_satisfies_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "nats", _fake_nats({}))
    assert isinstance(NATSQueueTransport(), QueueTransport)


def test_nats_missing_dep_raises_on_enqueue(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "nats", None)
    transport = NATSQueueTransport()
    with pytest.raises(ImportError, match=r"singleaxis-fabric\[nats\]"):
        transport.enqueue(_req())


# --------------------------------------------------------------------------- #
# Redis
# --------------------------------------------------------------------------- #


def _fake_redis(recorder: dict[str, Any]) -> ModuleType:
    module = ModuleType("redis")

    class _Client:
        def xadd(
            self,
            stream: str,
            fields: dict[str, str],
            maxlen: int | None = None,
            approximate: bool = False,
        ) -> None:
            recorder["stream"] = stream
            recorder["fields"] = fields
            recorder["maxlen"] = maxlen
            recorder["approximate"] = approximate

        def close(self) -> None:
            recorder["closed"] = True

    class _Redis:
        @staticmethod
        def from_url(url: str) -> _Client:
            recorder["url"] = url
            recorder["clients"] = recorder.get("clients", 0) + 1
            return _Client()

    module.Redis = _Redis  # type: ignore[attr-defined]
    return module


def test_redis_enqueue_xadds_round_tripping_body(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "redis", _fake_redis(recorder))
    transport = RedisStreamTransport(stream="fabric:custom")
    request = _req()
    transport.enqueue(request)
    assert recorder["stream"] == "fabric:custom"
    assert recorder["maxlen"] == 100_000
    assert recorder["approximate"] is True
    assert recorder["url"] == "redis://localhost:6379/0"
    rebuilt = request_from_dict(json.loads(recorder["fields"]["data"]))
    assert rebuilt == request


def test_redis_no_maxlen_skips_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "redis", _fake_redis(recorder))
    transport = RedisStreamTransport(maxlen=None)
    transport.enqueue(_req())
    assert recorder["maxlen"] is None
    assert recorder["approximate"] is False


def test_redis_client_is_lazy_and_reused(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "redis", _fake_redis(recorder))
    transport = RedisStreamTransport()
    assert "clients" not in recorder
    transport.enqueue(_req())
    transport.enqueue(_req())
    assert recorder["clients"] == 1


def test_redis_close_closes_client(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "redis", _fake_redis(recorder))
    transport = RedisStreamTransport()
    transport.enqueue(_req())
    transport.close()
    assert recorder["closed"] is True


def test_redis_close_without_client_is_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "redis", _fake_redis(recorder))
    transport = RedisStreamTransport()
    transport.close()  # must not raise
    assert "closed" not in recorder


def test_redis_satisfies_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "redis", _fake_redis({}))
    assert isinstance(RedisStreamTransport(), QueueTransport)


def test_redis_missing_dep_raises_on_enqueue(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "redis", None)
    transport = RedisStreamTransport()
    with pytest.raises(ImportError, match=r"singleaxis-fabric\[redis\]"):
        transport.enqueue(_req())


# --------------------------------------------------------------------------- #
# SQS
# --------------------------------------------------------------------------- #


def _fake_boto3(recorder: dict[str, Any]) -> ModuleType:
    module = ModuleType("boto3")

    def send_message(QueueUrl: str, MessageBody: str) -> dict[str, str]:  # noqa: N803
        recorder["queue_url"] = QueueUrl
        recorder["body"] = MessageBody
        return {"MessageId": "m-1"}

    def client(service: str, region_name: str | None = None) -> SimpleNamespace:
        recorder["service"] = service
        recorder["region_name"] = region_name
        recorder["clients"] = recorder.get("clients", 0) + 1
        return SimpleNamespace(send_message=send_message)

    module.client = client  # type: ignore[attr-defined]
    return module


def test_sqs_enqueue_sends_round_tripping_body(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "boto3", _fake_boto3(recorder))
    transport = SQSQueueTransport(queue_url="https://sqs/q", region_name="us-east-1")
    request = _req()
    transport.enqueue(request)
    assert recorder["service"] == "sqs"
    assert recorder["queue_url"] == "https://sqs/q"
    assert recorder["region_name"] == "us-east-1"
    rebuilt = request_from_dict(json.loads(recorder["body"]))
    assert rebuilt == request


def test_sqs_client_is_lazy_and_reused(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "boto3", _fake_boto3(recorder))
    transport = SQSQueueTransport(queue_url="https://sqs/q")
    assert "clients" not in recorder
    transport.enqueue(_req())
    transport.enqueue(_req())
    assert recorder["clients"] == 1
    assert recorder["region_name"] is None


def test_sqs_close_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "boto3", _fake_boto3(recorder))
    transport = SQSQueueTransport(queue_url="https://sqs/q")
    transport.enqueue(_req())
    transport.close()  # must not raise; no teardown to assert
    # A subsequent enqueue re-creates the client (close cleared the handle).
    transport.enqueue(_req())
    assert recorder["clients"] == 2


def test_sqs_satisfies_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "boto3", _fake_boto3({}))
    assert isinstance(SQSQueueTransport(queue_url="https://sqs/q"), QueueTransport)


def test_sqs_missing_dep_raises_on_enqueue(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "boto3", None)
    transport = SQSQueueTransport(queue_url="https://sqs/q")
    with pytest.raises(ImportError, match=r"singleaxis-fabric\[aws\]"):
        transport.enqueue(_req())
