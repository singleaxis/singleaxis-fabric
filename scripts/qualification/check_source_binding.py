#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Exercise dedicated synthetic source auth, then inspect durable OTLP readback.

This is an isolated CI fixture. Its bearer credential is never printed or
written to the report. It does not attest exclusive ownership of the token.
"""

from __future__ import annotations

import argparse
import json
import ssl
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

import grpc
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
    ExportLogsServiceResponse,
)
from opentelemetry.proto.collector.logs.v1.logs_service_pb2_grpc import LogsServiceStub

CANARY = b"SOURCE_BINDING_PRIVATE_CANARY"
TENANT = "synthetic"
SOURCE = "dispatcher"


def _record(
    request: ExportLogsServiceRequest,
    record_id: str,
    *,
    tenant: str | None = TENANT,
    source: str | None = SOURCE,
) -> None:
    record = request.resource_logs.add().scope_logs.add().log_records.add()
    record.event_name = "agent.evidence.call"
    record.body.string_value = CANARY.decode()
    fields: dict[str, str | int] = {
        "event_class": "evidence",
        "schema_version": "agent.evidence.event/v1",
        "record_id": record_id,
        "run_id": "source-binding-qualification",
        "agent_id": "fixture-agent",
        "operation_id": record_id,
        "attempt_id": "attempt-1",
        "call_id": record_id,
        "source_epoch": 1,
        "source_sequence": 1,
        "boundary": "tool",
        "provenance": "caller_reported",
        "status": "observed",
        "observed_at": "2026-09-30T00:00:00Z",
        "call_phase": "start",
        "call_kind": "tool",
        "unapproved_private": CANARY.decode(),
    }
    if tenant is not None:
        fields["tenant_id"] = tenant
    if source is not None:
        fields["source_id"] = source
    for key, value in fields.items():
        attr = record.attributes.add()
        attr.key = key
        if isinstance(value, int):
            attr.value.int_value = value
        else:
            attr.value.string_value = value


def _request(
    prefix: str,
    case: str,
    *,
    tenant: str | None = TENANT,
    source: str | None = SOURCE,
    mixed: bool = False,
) -> tuple[ExportLogsServiceRequest, list[str]]:
    request = ExportLogsServiceRequest()
    ids = [f"{prefix}-{case}-a"]
    _record(request, ids[0], tenant=tenant, source=source)
    if mixed:
        ids.append(f"{prefix}-{case}-b")
        _record(request, ids[1], source="forged-source")
    return request, ids


MAX_HTTP_RESPONSE_BYTES = 1024 * 1024


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _response_bytes(response) -> bytes:
    body = response.read(MAX_HTTP_RESPONSE_BYTES + 1)
    if len(body) > MAX_HTTP_RESPONSE_BYTES:
        raise ValueError("source-binding HTTP response exceeds bounded size")
    return body


def _http(
    url: str, payload: bytes, context: ssl.SSLContext, bearer: str | None
) -> tuple[int, int]:
    destination = urlsplit(url)
    if (
        destination.scheme != "https"
        or not destination.hostname
        or destination.username is not None
        or destination.password is not None
        or "#" in url
    ):
        raise ValueError(
            "source-binding destination must be HTTPS without userinfo or fragment"
        )
    # Validate the port before constructing a request with credentials.
    if destination.port is not None and not 1 <= destination.port <= 65535:
        raise ValueError("source-binding destination has invalid port")
    headers = {"Content-Type": "application/x-protobuf"}
    if bearer is not None:
        headers["Authorization"] = bearer
    req = Request(url, data=payload, method="POST", headers=headers)
    opener = build_opener(HTTPSHandler(context=context), _NoRedirect())
    try:
        with opener.open(req, timeout=10) as response:
            code, body = response.status, _response_bytes(response)
    except HTTPError as error:
        with error:
            code, body = error.code, _response_bytes(error)
    except URLError:
        return 0, 0
    rejected = 0
    if code == 200:
        parsed = ExportLogsServiceResponse()
        parsed.ParseFromString(body)
        rejected = parsed.partial_success.rejected_log_records
    return code, rejected


def _grpc(
    stub: LogsServiceStub, request: ExportLogsServiceRequest, bearer: str | None
) -> tuple[str, int]:
    metadata = (("authorization", bearer),) if bearer is not None else ()
    try:
        response = stub.Export(request, metadata=metadata, timeout=10)
        return "OK", response.partial_success.rejected_log_records
    except grpc.RpcError as error:
        return error.code().name, 0


def exercise(args: argparse.Namespace) -> None:
    token = args.bearer_token_file.read_bytes()
    if not 32 <= len(token) <= 4096 or any(
        byte <= 0x20 or byte >= 0x7F for byte in token
    ):
        raise AssertionError("test credential is not a safe singleton token")
    bearer = "Bearer " + token.decode("ascii")
    context = ssl.create_default_context(cafile=str(args.ca_cert))
    context.load_cert_chain(str(args.client_cert), str(args.client_key))
    channel_creds = grpc.ssl_channel_credentials(
        root_certificates=args.ca_cert.read_bytes(),
        private_key=args.client_key.read_bytes(),
        certificate_chain=args.client_cert.read_bytes(),
    )
    prefix = "bind-" + uuid.uuid4().hex
    negative: list[str] = []
    checks: list[dict[str, str | int]] = []
    with grpc.secure_channel(args.grpc_target, channel_creds) as channel:
        grpc.channel_ready_future(channel).result(timeout=15)
        stub = LogsServiceStub(channel)
        cases = [
            ("missing-bearer", None, TENANT, SOURCE, False, "auth"),
            (
                "wrong-bearer",
                "Bearer invalid-credential",
                TENANT,
                SOURCE,
                False,
                "auth",
            ),
            ("empty-bearer", "Bearer ", TENANT, SOURCE, False, "auth"),
            ("forged-tenant", bearer, "forged-tenant", SOURCE, False, "identity"),
            ("forged-source", bearer, TENANT, "forged-source", False, "identity"),
            ("missing-tenant", bearer, None, SOURCE, False, "identity"),
            ("missing-source", bearer, TENANT, None, False, "identity"),
            ("mixed-batch", bearer, TENANT, SOURCE, True, "identity"),
        ]
        for transport in ("http", "grpc"):
            for name, header, tenant, source, mixed, category in cases:
                request, ids = _request(
                    prefix,
                    transport + "-" + name,
                    tenant=tenant,
                    source=source,
                    mixed=mixed,
                )
                negative.extend(ids)
                if transport == "http":
                    outcome, rejected = _http(
                        args.http_url, request.SerializeToString(), context, header
                    )
                    accepted = outcome == 200 and rejected == 0
                    if category == "auth" and outcome not in {401, 403}:
                        raise AssertionError(
                            f"HTTP {name} did not fail authentication: {outcome}"
                        )
                else:
                    outcome, rejected = _grpc(stub, request, header)
                    accepted = outcome == "OK" and rejected == 0
                    if category == "auth" and outcome != "UNAUTHENTICATED":
                        raise AssertionError(
                            f"gRPC {name} did not fail authentication: {outcome}"
                        )
                if accepted:
                    raise AssertionError(f"{transport} {name} was accepted")
                if category == "identity":
                    explicit_rejection = (
                        outcome == 400
                        if transport == "http"
                        else outcome == "INVALID_ARGUMENT"
                    )
                    if not explicit_rejection:
                        raise AssertionError(
                            f"{transport} {name} lacked non-retryable client rejection: {outcome}"
                        )
                checks.append(
                    {
                        "transport": transport,
                        "case": name,
                        "outcome": str(outcome),
                        "rejected": rejected,
                    }
                )
        valid, positive = _request(prefix, "grpc-valid")
        outcome, rejected = _grpc(stub, valid, bearer)
        if outcome != "OK" or rejected:
            raise AssertionError(f"valid authenticated gRPC source rejected: {outcome}")
    report = {
        "schema_version": "fabric.source-binding-qualification/v1",
        "record_prefixes": [prefix + "-"],
        "positive_record_id": positive[0],
        "negative_record_ids": negative,
        "checks": checks,
        "qualification": "NO_GO",
    }
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "auth_and_identity_rejections": len(checks),
                "grpc_valid_accepted": True,
                "qualification": "NO_GO",
            }
        )
    )


def rotation(args: argparse.Namespace) -> None:
    previous = json.loads(args.report.read_text())
    old = args.old_token_file.read_bytes()
    new = args.new_token_file.read_bytes()
    if len(old) < 32 or len(new) < 32 or old == new:
        raise AssertionError("rotation fixture tokens are invalid")
    context = ssl.create_default_context(cafile=str(args.ca_cert))
    context.load_cert_chain(str(args.client_cert), str(args.client_key))
    channel_creds = grpc.ssl_channel_credentials(
        root_certificates=args.ca_cert.read_bytes(),
        private_key=args.client_key.read_bytes(),
        certificate_chain=args.client_cert.read_bytes(),
    )
    old_header = "Bearer " + old.decode("ascii")
    new_header = "Bearer " + new.decode("ascii")
    positive: list[str] = []
    prefix = "rotate-" + uuid.uuid4().hex
    deadline = time.monotonic() + args.timeout_seconds
    with grpc.secure_channel(args.grpc_target, channel_creds) as channel:
        stub = LogsServiceStub(channel)
        while time.monotonic() < deadline:
            http_req, http_ids = _request(prefix, "http-" + uuid.uuid4().hex)
            grpc_req, grpc_ids = _request(prefix, "grpc-" + uuid.uuid4().hex)
            http_code, http_rejected = _http(
                args.http_url, http_req.SerializeToString(), context, new_header
            )
            grpc_code, grpc_rejected = _grpc(stub, grpc_req, new_header)
            if http_code == 200 and not http_rejected:
                positive.extend(http_ids)
            if grpc_code == "OK" and not grpc_rejected:
                positive.extend(grpc_ids)
            if (
                http_code == 200
                and not http_rejected
                and grpc_code == "OK"
                and not grpc_rejected
            ):
                old_http, old_http_ids = _request(
                    prefix, "old-http-" + uuid.uuid4().hex
                )
                old_grpc, old_grpc_ids = _request(
                    prefix, "old-grpc-" + uuid.uuid4().hex
                )
                old_http_code, _ = _http(
                    args.http_url, old_http.SerializeToString(), context, old_header
                )
                old_grpc_code, _ = _grpc(stub, old_grpc, old_header)
                if old_http_code == 200:
                    positive.extend(old_http_ids)
                if old_grpc_code == "OK":
                    positive.extend(old_grpc_ids)
                if old_http_code == 401 and old_grpc_code == "UNAUTHENTICATED":
                    previous["rotation_new_record_ids"] = positive
                    previous["record_prefixes"].append(prefix + "-")
                    previous["rotation_old_rejected_record_ids"] = (
                        old_http_ids + old_grpc_ids
                    )
                    previous["rotation_both_protocols_verified"] = True
                    args.report.write_text(
                        json.dumps(previous, indent=2, sort_keys=True) + "\n"
                    )
                    print(
                        json.dumps(
                            {
                                "rotation_both_protocols_verified": True,
                                "qualification": "NO_GO",
                            }
                        )
                    )
                    return
            time.sleep(5)
    raise AssertionError(
        "new bearer was not accepted and old bearer rejected on both protocols within the rotation deadline"
    )


def verify(args: argparse.Namespace) -> None:
    report = json.loads(args.report.read_text())
    negative = set(
        report["negative_record_ids"]
        + report.get("rotation_old_rejected_record_ids", [])
    )
    positive = {
        report["positive_record_id"],
        *report.get("rotation_new_record_ids", []),
    }
    observed: dict[str, int] = {}
    files = sorted(args.sink_dir.glob("*.otlp"))
    if not files:
        raise AssertionError("controlled sink has no durable readback files")
    for path in files:
        raw = path.read_bytes()
        if CANARY in raw or b"file://" in raw:
            raise AssertionError("source-binding private bytes leaked to destination")
        request = ExportLogsServiceRequest()
        request.ParseFromString(raw)
        for resource in request.resource_logs:
            for scope in resource.scope_logs:
                for record in scope.log_records:
                    attrs = {
                        item.key: item.value.string_value
                        for item in record.attributes
                        if item.value.WhichOneof("value") == "string_value"
                    }
                    record_id = attrs.get("record_id", "")
                    if record_id not in negative and record_id not in positive:
                        if any(
                            record_id.startswith(prefix)
                            for prefix in report["record_prefixes"]
                        ):
                            raise AssertionError(
                                "unaccounted source-binding operation reached destination"
                            )
                        continue
                    if record.body.WhichOneof("value") is not None:
                        raise AssertionError(
                            "source-binding evidence body escaped guard"
                        )
                    if "unapproved_private" in attrs:
                        raise AssertionError(
                            "unapproved source attribute escaped guard"
                        )
                    if (
                        attrs.get("tenant_id") != TENANT
                        or attrs.get("source_id") != SOURCE
                    ):
                        raise AssertionError(
                            "bound source identity changed at destination"
                        )
                    observed[record_id] = observed.get(record_id, 0) + 1
    if negative & observed.keys():
        raise AssertionError("rejected source record reached durable destination")
    if any(observed.get(record_id) != 1 for record_id in positive):
        raise AssertionError(
            "valid or rotated source record missing or duplicated at destination"
        )
    report["durable_readback_verified"] = True
    report["durable_positive_records"] = len(positive)
    report["durable_negative_records"] = 0
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "durable_positive_records": len(positive),
                "durable_negative_records": 0,
                "qualification": "NO_GO",
            }
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    exercise_parser = sub.add_parser("exercise")
    exercise_parser.add_argument("--http-url", required=True)
    exercise_parser.add_argument("--grpc-target", required=True)
    exercise_parser.add_argument("--ca-cert", required=True, type=Path)
    exercise_parser.add_argument("--client-cert", required=True, type=Path)
    exercise_parser.add_argument("--client-key", required=True, type=Path)
    exercise_parser.add_argument("--bearer-token-file", required=True, type=Path)
    exercise_parser.add_argument("--report", required=True, type=Path)
    rotation_parser = sub.add_parser("rotation")
    rotation_parser.add_argument("--http-url", required=True)
    rotation_parser.add_argument("--grpc-target", required=True)
    rotation_parser.add_argument("--ca-cert", required=True, type=Path)
    rotation_parser.add_argument("--client-cert", required=True, type=Path)
    rotation_parser.add_argument("--client-key", required=True, type=Path)
    rotation_parser.add_argument("--old-token-file", required=True, type=Path)
    rotation_parser.add_argument("--new-token-file", required=True, type=Path)
    rotation_parser.add_argument("--timeout-seconds", type=int, default=180)
    rotation_parser.add_argument("--report", required=True, type=Path)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--sink-dir", required=True, type=Path)
    verify_parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "exercise":
        exercise(args)
    elif args.command == "rotation":
        rotation(args)
    else:
        verify(args)


if __name__ == "__main__":
    main()
