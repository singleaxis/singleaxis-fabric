# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Content transport to the Fabric Node (spec 048 §3): one OTLP/HTTP protobuf LogRecord
per body over ``requests`` (never teed). Never logs a URL, header, body or message."""

from __future__ import annotations

import contextlib
import logging
import os
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from .. import tracing
from .._export_diagnostics import sanitized_export_diagnostics

Result = Literal["ok", "retry", "rejected"]
_LOG = logging.getLogger("fabric.wire")
_PERMANENT = frozenset({400, 413, 415, 422})
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_ORPHANED: list[object] = []  # sessions a forked child replaced (see _live_session)


def _value(value: Any) -> dict[str, Any]:
    if isinstance(value, bool) or not isinstance(value, (str, int, list)):
        raise TypeError("descriptor values are strings, integers or string lists")
    if isinstance(value, list):
        return {"array_value": {"values": [{"string_value": str(v)} for v in value]}}
    return {"int_value": value} if isinstance(value, int) else {"string_value": value}


def encode_content_request(
    descriptor: Mapping[str, Any], body: bytes | memoryview, *, service_name: str
) -> bytes:
    """One ``ExportLogsServiceRequest``: resource ``service.name``, scope ``fabric.wire``,
    one ``LogRecord`` (exact bytes, the closed attribute set, ``captured_at`` as time)."""
    from opentelemetry.proto.collector.logs.v1 import logs_service_pb2  # noqa: PLC0415

    attrs = {"event_class": "content", **descriptor}
    captured = datetime.fromisoformat(str(descriptor["captured_at"])) - _EPOCH
    record = {
        "time_unix_nano": captured // timedelta(microseconds=1) * 1000,
        "body": {"bytes_value": bytes(body)},
        "attributes": [{"key": k, "value": _value(v)} for k, v in attrs.items()],
    }
    resource = {"attributes": [{"key": "service.name", "value": _value(service_name)}]}
    scope = {"scope": {"name": "fabric.wire"}, "log_records": [record]}
    request = logs_service_pb2.ExportLogsServiceRequest(
        resource_logs=[{"resource": resource, "scope_logs": [scope]}]  # type: ignore[list-item]
    )
    return bytes(request.SerializeToString())


class NodeContentClient:
    """POSTs content log records; ``send`` never raises. Redirects are never followed: a 3xx
    is a delivery failure retried later (H1), so content never reaches another host. The
    endpoint must be verified HTTPS or loopback HTTP (the metadata delivery rule), and TLS
    verification cannot be turned off."""

    def __init__(
        self, endpoint: str, *, headers: Mapping[str, str], timeout_s: float,
        verify: str | bool, cert: tuple[str, str] | None, service_name: str,
        proxy: str | None = None,
    ) -> None:  # fmt: skip
        tracing.check_content_endpoint_url("FABRIC_WIRE_CONTENT_ENDPOINT", endpoint)
        if verify is not True and not (isinstance(verify, str) and verify):
            raise ValueError("content delivery TLS verification cannot be disabled")
        self._endpoint, self._timeout, self._service = endpoint, timeout_s, service_name
        self._settings = dict(headers), verify, cert, proxy
        self._session = self._new_session()

    def _new_session(self) -> Any:
        """A session that never redirects and never takes a proxy from the environment
        (loopback: always direct; HTTPS: only the explicit ``proxy``)."""
        headers, verify, cert, proxy = self._settings
        session = tracing.no_redirect_session()
        session.headers.update(headers)
        session.verify, session.cert = verify, cert
        self._pid = os.getpid()
        return tracing.pin_delivery_proxies(session, self._endpoint, proxy)

    def _live_session(self) -> Any:
        """This process's session: a forked child builds its own before delivering (the
        parent's connection pools may hold locks no thread of the child will release); the
        parent's is kept, never closed, so no pool finalizer runs in the child."""
        if self._pid != os.getpid():
            _ORPHANED.append(self._session)
            self._session = self._new_session()
        return self._session

    def send(self, descriptor: Mapping[str, Any], body: bytes | memoryview) -> Result:
        """``ok`` (2xx only); ``rejected`` (400/413/415/422, a rejected record or an
        unencodable one: never retried); else ``retry`` (3xx included)."""
        from opentelemetry.proto.collector.logs.v1 import logs_service_pb2  # noqa: PLC0415

        try:
            payload = encode_content_request(descriptor, body, service_name=self._service)
            with sanitized_export_diagnostics():
                response = self._live_session().post(
                    self._endpoint, data=payload, timeout=self._timeout, allow_redirects=False,
                    headers={"Content-Type": "application/x-protobuf"},
                )  # fmt: skip
            code, content = int(response.status_code), response.content
        except OSError as exc:  # every requests error (connection, TLS, timeout)
            _LOG.debug("fabric.wire: content delivery will be retried (%s)", type(exc).__name__)
            return "retry"
        except Exception as exc:  # the record itself cannot be encoded
            _LOG.warning("fabric.wire: content record not encodable (%s)", type(exc).__name__)
            return "rejected"
        if 200 <= code < 300:  # noqa: PLR2004 - an unparsable 2xx body still means accepted
            with contextlib.suppress(Exception):
                reply = logs_service_pb2.ExportLogsServiceResponse.FromString(content or b"")
                code = 422 if reply.partial_success.rejected_log_records else code
            if code != 422:  # noqa: PLR2004
                return "ok"
        if code in _PERMANENT:
            _LOG.warning("fabric.wire: content record rejected by the Node (HTTP %d)", code)
            return "rejected"
        _LOG.debug("fabric.wire: content delivery will be retried (HTTP %d)", code)
        return "retry"

    def close(self) -> None:
        self._session.close()


def content_client_from_env(
    environ: Mapping[str, str], *, endpoint: str | None = None, service_name: str | None = None
) -> NodeContentClient:
    """The Node content client: ``FABRIC_WIRE_CONTENT_ENDPOINT`` (or ``endpoint``) plus the
    ``OTEL_EXPORTER_OTLP_LOGS_*`` > ``OTEL_EXPORTER_OTLP_*`` TLS, header and timeout settings."""
    try:
        # requests ships inline types only from 2.34; older releases need the ignore.
        import requests  # type: ignore[import-untyped, unused-ignore]  # noqa: F401, PLC0415
        from opentelemetry.proto.collector.logs.v1 import logs_service_pb2  # noqa: F401, PLC0415
    except ImportError:
        raise ValueError("node mode needs the [otlp] extra (requests, protobuf)") from None
    url = (endpoint or environ.get("FABRIC_WIRE_CONTENT_ENDPOINT") or "").strip()
    if not url:
        raise ValueError("node mode needs FABRIC_WIRE_CONTENT_ENDPOINT")
    tracing.check_content_endpoint_url("FABRIC_WIRE_CONTENT_ENDPOINT", url)
    s = tracing.otlp_signal_settings("logs", environ)
    cert = (s.client_certificate, s.client_key) if s.client_certificate and s.client_key else None
    return NodeContentClient(
        url, headers=s.headers, timeout_s=s.timeout_s, verify=s.certificate or True, cert=cert,
        service_name=service_name or tracing.capture_service_name(environ),
        proxy=tracing.delivery_proxy_from_env(environ),
    )  # fmt: skip
