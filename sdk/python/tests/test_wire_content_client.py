# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Content transport (spec 048 §3): OTLP/HTTP protobuf log records, results, settings."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
    ExportLogsServiceResponse,
)

import fabric.wire._content as content_module
from fabric.tracing import otlp_signal_settings
from fabric.wire._content import NodeContentClient, content_client_from_env, encode_content_request

from .test_wire_helpers import CAPTURE, capture_schemas, load_validator
from .test_wire_spool import FakeNode, any_value

VALIDATOR = load_validator()
SCHEMAS = {
    **capture_schemas(),
    "schema/content-log-record-v1.schema.json": json.loads(
        (CAPTURE / "schema/content-log-record-v1.schema.json").read_text("utf-8")
    ),
}


def _fixture(name: str) -> dict[str, Any]:
    return dict(json.loads((CAPTURE / "fixtures/valid" / name).read_text("utf-8")))


def _descriptor(name: str) -> dict[str, Any]:
    attrs = _fixture(name)["attributes"]
    return {k: v for k, v in attrs.items() if k != "event_class"}


def _decode(payload: bytes) -> tuple[dict[str, Any], dict[str, Any], Any]:
    request = ExportLogsServiceRequest.FromString(payload)
    (resource_logs,) = request.resource_logs
    (scope_logs,) = resource_logs.scope_logs
    (record,) = scope_logs.log_records
    resource = {kv.key: any_value(kv.value) for kv in resource_logs.resource.attributes}
    assert scope_logs.scope.name == "fabric.wire"
    return resource, {kv.key: any_value(kv.value) for kv in record.attributes}, record


@pytest.mark.parametrize(
    "fixture", ["content-log-record-request.json", "content-log-record-truncated.json"]
)
def test_encoding_round_trips_exact_bytes_and_typed_attributes(fixture: str) -> None:
    descriptor = _descriptor(fixture)
    body = bytes(range(256)) * 3
    body = body[: descriptor["stored_byte_length"]] if descriptor["stored_byte_length"] <= len(
        body) else body + b"\0" * (descriptor["stored_byte_length"] - len(body))  # fmt: skip
    descriptor["stored_sha256"] = "sha256:" + hashlib.sha256(body).hexdigest()
    if descriptor["representation"] != "truncated":
        descriptor["source_sha256"] = descriptor["stored_sha256"]
    resource, attrs, record = _decode(encode_content_request(descriptor, body, service_name="svc"))
    assert resource == {"service.name": "svc"}
    assert record.body.WhichOneof("value") == "bytes_value" and record.body.bytes_value == body
    assert attrs == {"event_class": "content", **descriptor}
    typed = {kv.key: kv.value.WhichOneof("value") for kv in
             ExportLogsServiceRequest.FromString(encode_content_request(
                 descriptor, body, service_name="svc")).resource_logs[0].scope_logs[0]
             .log_records[0].attributes}  # fmt: skip
    assert typed["stored_byte_length"] == typed["source_epoch"] == "int_value"
    assert typed["transformations"] == "array_value" and typed["object_id"] == "string_value"
    captured = datetime.fromisoformat(descriptor["captured_at"])
    assert record.time_unix_nano == int(captured.timestamp() * 1_000_000) * 1000
    assert not record.trace_id and not record.span_id and not record.severity_text
    VALIDATOR.validate_document({
        "schema_version": "fabric.content-log-record/v1", "attributes": attrs,
        "body": {"byte_length": len(body), "sha256": descriptor["stored_sha256"]},
    }, SCHEMAS)  # fmt: skip


def _client(node: FakeNode, **kwargs: Any) -> NodeContentClient:
    return NodeContentClient(node.url + "/v1/logs", headers=kwargs.get("headers", {}),
                             timeout_s=2.0, verify=True, cert=None, service_name="svc")  # fmt: skip


@pytest.fixture
def node() -> Any:
    created = FakeNode()
    yield created
    created.close()


def test_send_results(node: FakeNode, monkeypatch: pytest.MonkeyPatch) -> None:
    descriptor, body = _descriptor("content-log-record-request.json"), b"x" * 73
    client = _client(node, headers={"authorization": "Bearer t"})
    assert client.send(descriptor, body) == "ok"
    assert node.content[0][1] == body
    path, headers = node.requests[-1]
    assert path == "/v1/logs" and headers["Content-Type"] == "application/x-protobuf"
    assert headers["authorization"] == "Bearer t"
    node.mode = "reject"
    assert client.send(descriptor, body) == "rejected"
    node.mode = "down"
    assert client.send(descriptor, body) == "retry"
    node.close()
    assert client.send(descriptor, body) == "retry"  # connection refused
    unencodable = {**descriptor, "stored_byte_length": True}
    assert client.send(unencodable, body) == "rejected"
    client.close()


@pytest.mark.parametrize(
    ("status", "rejected", "expected"),
    [(200, 0, "ok"), (202, 1, "rejected"), (400, 0, "rejected"), (413, 0, "rejected"),
     (415, 0, "rejected"), (422, 0, "rejected"), (401, 0, "retry"), (403, 0, "retry"),
     (404, 0, "retry"), (429, 0, "retry"), (500, 0, "retry"), (503, 0, "retry")],
)  # fmt: skip
def test_status_mapping(
    monkeypatch: pytest.MonkeyPatch, status: int, rejected: int, expected: str
) -> None:
    response = ExportLogsServiceResponse()
    response.partial_success.rejected_log_records = rejected

    class Reply:
        status_code, content = status, response.SerializeToString()

    client = NodeContentClient("http://node/v1/logs", headers={}, timeout_s=1, verify=True,
                               cert=None, service_name="svc")  # fmt: skip
    monkeypatch.setattr(client._session, "post", lambda *a, **k: Reply())
    assert client.send(_descriptor("content-log-record-request.json"), b"x" * 73) == expected


def test_settings_prefer_the_logs_variables(tmp_path: Path) -> None:
    ca, cert, key = (tmp_path / n for n in ("ca.pem", "cert.pem", "key.pem"))
    for path in (ca, cert, key):
        path.write_text("pem")
    env = {
        "OTEL_EXPORTER_OTLP_HEADERS": "authorization=general,x-a=1",
        "OTEL_EXPORTER_OTLP_LOGS_HEADERS": "authorization=Bearer%20logs%2Ctoken",
        "OTEL_EXPORTER_OTLP_CERTIFICATE": str(ca),
        "OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE": str(cert),
        "OTEL_EXPORTER_OTLP_CLIENT_KEY": str(key),
        "OTEL_EXPORTER_OTLP_TIMEOUT": "7",
        "FABRIC_WIRE_CONTENT_ENDPOINT": "https://node:4319/v1/logs",
    }
    settings = otlp_signal_settings("logs", env)
    assert settings.headers == {"authorization": "Bearer logs,token"}  # LOGS wins as a whole
    assert (settings.certificate, settings.client_certificate, settings.client_key) == (
        str(ca), str(cert), str(key))  # fmt: skip
    assert settings.timeout_s == 7.0
    client = content_client_from_env(env)
    assert client._endpoint == "https://node:4319/v1/logs"  # used as given
    assert client._session.verify == str(ca) and client._session.cert == (str(cert), str(key))
    assert client._session.headers["authorization"] == "Bearer logs,token"


@pytest.mark.parametrize(
    "env",
    [
        {"FABRIC_WIRE_CONTENT_ENDPOINT": "https://user:sk-secret@node:4319/v1/logs"},
        {"FABRIC_WIRE_CONTENT_ENDPOINT": "https://node:4319/v1/logs?token=sk-secret"},
        {"FABRIC_WIRE_CONTENT_ENDPOINT": "https://node:4319/v1/logs#sk-secret"},
        {"FABRIC_WIRE_CONTENT_ENDPOINT": "https://node:4319/v1/logs",
         "OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE": "/nonexistent/sk-secret.pem"},
        {"FABRIC_WIRE_CONTENT_ENDPOINT": "https://node:4319/v1/logs",
         "OTEL_EXPORTER_OTLP_HEADERS": "authorization=sk-secret,broken"},
        {"FABRIC_WIRE_CONTENT_ENDPOINT": "https://node:4319/v1/logs",
         "OTEL_EXPORTER_OTLP_LOGS_CLIENT_KEY": __file__},
        {"FABRIC_WIRE_CONTENT_ENDPOINT": "https://node:4319/v1/logs",
         "OTEL_EXPORTER_OTLP_TIMEOUT": "sk-secret"},
        {},
    ],
)  # fmt: skip
def test_bad_settings_fail_without_echo(env: dict[str, str]) -> None:
    with pytest.raises(ValueError) as raised:
        content_client_from_env(env)
    assert "sk-secret" not in str(raised.value) and raised.value.__cause__ is None


def test_the_content_client_is_never_teed(node: FakeNode, tmp_path: Path) -> None:
    """``requests`` is not httpx: an installed tee (patching httpx) never sees Node traffic."""
    assert "httpx" not in content_module.__dict__
    assert type(_client(node)._session).__module__.startswith("requests")
