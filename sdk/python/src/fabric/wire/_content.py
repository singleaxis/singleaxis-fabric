# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Content transport to the Fabric Node (spec 048 §3): OTLP/HTTP protobuf LogRecords, one
per body, over ``requests`` (never teed); several bodies may share one request (§3,
amended: the Node's receiver acknowledges a whole request once its durable queue holds
it). Never logs a URL, header, body or message."""

from __future__ import annotations

import contextlib
import logging
import os
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from .. import tracing
from .._export_diagnostics import sanitized_export_diagnostics
from ._config import MAX_CONTENT_CONCURRENCY

Result = Literal["ok", "retry", "rejected"]
_LOG = logging.getLogger("fabric.wire")
_PERMANENT = frozenset({400, 413, 415, 422})
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_ORPHANED: list[object] = []  # sessions a forked child replaced (see _live_session)


def _value(value: Any) -> dict[str, Any]:
    """An OTLP AnyValue: strings, integers, arrays of them, and (049 §4.3: ``links``)
    arrays of key-value maps, as the Node's closed parser reads them."""
    if isinstance(value, dict):
        return {"kvlist_value": {"values": [{"key": k, "value": _value(v)}
                                            for k, v in value.items()]}}  # fmt: skip
    if isinstance(value, bool) or not isinstance(value, (str, int, list)):
        raise TypeError("descriptor values are strings, integers, lists or maps")
    if isinstance(value, list):
        return {"array_value": {"values": [
            _value(v) if isinstance(v, (dict, int)) else {"string_value": str(v)}
            for v in value
        ]}}  # fmt: skip
    return {"int_value": value} if isinstance(value, int) else {"string_value": value}


def _log_record(descriptor: Mapping[str, Any], body: bytes | memoryview) -> dict[str, Any]:
    """One content ``LogRecord``: exact bytes, the closed attribute set, ``captured_at`` as
    time; raises for a descriptor that cannot be encoded."""
    attrs = {"event_class": "content", **descriptor}
    captured = datetime.fromisoformat(str(descriptor["captured_at"])) - _EPOCH
    return {
        "time_unix_nano": captured // timedelta(microseconds=1) * 1000,
        "body": {"bytes_value": bytes(body)},
        "attributes": [{"key": k, "value": _value(v)} for k, v in attrs.items()],
    }


def _request(records: Sequence[Mapping[str, Any]], service_name: str) -> bytes:
    from opentelemetry.proto.collector.logs.v1 import logs_service_pb2  # noqa: PLC0415

    resource = {"attributes": [{"key": "service.name", "value": _value(service_name)}]}
    scope = {"scope": {"name": "fabric.wire"}, "log_records": list(records)}
    request = logs_service_pb2.ExportLogsServiceRequest(
        resource_logs=[{"resource": resource, "scope_logs": [scope]}]  # type: ignore[list-item]
    )
    return bytes(request.SerializeToString())


def encode_content_request(
    descriptor: Mapping[str, Any], body: bytes | memoryview, *, service_name: str
) -> bytes:
    """One ``ExportLogsServiceRequest``: resource ``service.name``, scope ``fabric.wire``,
    one ``LogRecord`` (exact bytes, the closed attribute set, ``captured_at`` as time)."""
    return _request([_log_record(descriptor, body)], service_name)


def encode_content_records(
    items: Sequence[tuple[Mapping[str, Any], bytes | memoryview]], *, service_name: str
) -> bytes:
    """One ``ExportLogsServiceRequest`` carrying one ``LogRecord`` per ``(descriptor,
    body)``, in order, under one resource and one ``fabric.wire`` scope."""
    return _request([_log_record(d, b) for d, b in items], service_name)


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
        # requests ships inline types only from 2.34; older releases need the ignore.
        from requests.adapters import HTTPAdapter  # type: ignore[import-untyped, unused-ignore]  # noqa: PLC0415

        headers, verify, cert, proxy = self._settings
        session = tracing.no_redirect_session()
        # One pooled connection per content request in flight: the default pool (10) would
        # discard extra connections with a urllib3 warning past content_concurrency 10.
        for scheme in ("https://", "http://"):
            session.mount(scheme, HTTPAdapter(pool_maxsize=MAX_CONTENT_CONCURRENCY))
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
        try:
            payload = encode_content_request(descriptor, body, service_name=self._service)
        except Exception as exc:  # the record itself cannot be encoded
            _LOG.warning("fabric.wire: content record not encodable (%s)", type(exc).__name__)
            return "rejected"
        result, code = self._post(payload)
        if result == "rejected" and code:
            _LOG.warning("fabric.wire: content record rejected by the Node (HTTP %d)", code)
        return result

    def send_many(
        self, items: Sequence[tuple[Mapping[str, Any], bytes | memoryview]]
    ) -> list[Result]:
        """Several bodies in one request; per item, as :meth:`send`. The Node acknowledges a
        request as a whole once its durable queue holds it, and stores identical bytes
        again as a replay, so a retried request is idempotent. A request refused as a whole
        (400/413/415/422) or with rejected records is sent again one body per request, so
        only the refused bodies count as rejected (and a Node with a lower request size
        limit still takes every body). An unencodable record is rejected on its own."""
        if len(items) <= 1:
            return [self.send(d, b) for d, b in items]
        results: list[Result] = ["rejected"] * len(items)
        records, positions = [], []
        for index, (descriptor, body) in enumerate(items):
            try:
                records.append(_log_record(descriptor, body))
                positions.append(index)
            except Exception as exc:
                _LOG.warning("fabric.wire: content record not encodable (%s)",
                             type(exc).__name__)  # fmt: skip
        if not records:
            return results
        payload = b""
        try:
            payload = _request(records, self._service)
        except Exception:  # never expected once each record encoded: one by one instead
            result: Result = "rejected"
        else:
            result = self._post(payload)[0]
        del records, payload  # the copies of the bodies: freed before any one-by-one resend
        if result == "rejected":
            for index in positions:
                results[index] = self.send(*items[index])
        else:
            for index in positions:
                results[index] = result
        return results

    def _post(self, payload: bytes) -> tuple[Result, int]:
        """POST one encoded request: ``ok``, ``rejected`` (permanent, or a reply with
        rejected records) or ``retry``, and the HTTP status (0 without a response)."""
        from opentelemetry.proto.collector.logs.v1 import logs_service_pb2  # noqa: PLC0415

        try:
            with sanitized_export_diagnostics():
                response = self._live_session().post(
                    self._endpoint, data=payload, timeout=self._timeout, allow_redirects=False,
                    headers={"Content-Type": "application/x-protobuf"},
                )  # fmt: skip
            code, content = int(response.status_code), response.content
        except OSError as exc:  # every requests error (connection, TLS, timeout)
            _LOG.debug("fabric.wire: content delivery will be retried (%s)", type(exc).__name__)
            return "retry", 0
        except Exception as exc:  # as before batching: anything else is not retried
            _LOG.warning("fabric.wire: content record not encodable (%s)", type(exc).__name__)
            return "rejected", 0
        if 200 <= code < 300:  # noqa: PLR2004 - an unparsable 2xx body still means accepted
            with contextlib.suppress(Exception):
                reply = logs_service_pb2.ExportLogsServiceResponse.FromString(content or b"")
                code = 422 if reply.partial_success.rejected_log_records else code
            if code != 422:  # noqa: PLR2004
                return "ok", code
        if code in _PERMANENT:
            return "rejected", code
        _LOG.debug("fabric.wire: content delivery will be retried (HTTP %d)", code)
        return "retry", code

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
