# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""OpenTelemetry plumbing used by the Fabric SDK.

The SDK never installs a global tracer provider on the host's behalf; it fetches
tracers via ``opentelemetry.trace.get_tracer``. ``install_default_provider`` is a
convenience for tests and small agents. ``gen_ai.client.*`` metrics come from the
global metrics API (:func:`get_meter`) and no-op until the host installs a
``MeterProvider`` (or passes ``meter_provider=`` to :func:`install_default_provider`).
Capture components use :func:`build_private_provider` or
:func:`build_capture_span_exporter`, never the global provider.
"""

from __future__ import annotations

import contextlib
import importlib
import logging
import os
import re
import threading
import weakref
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote, urlsplit

from opentelemetry import metrics, trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, SpanLimits, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.sdk.trace.sampling import ALWAYS_ON, Sampler

from ._version import __version__

_LOG = logging.getLogger("fabric")

FABRIC_SDK_NAME = "singleaxis-fabric-python"
"""``service.name`` fallback applied when the host hasn't set one."""

GEN_AI_SCHEMA_URL = "https://opentelemetry.io/schemas/gen-ai/1.42.0"
"""Schema URL for the GenAI semantic conventions emitted by Fabric."""

_MAX_ATTR_VALUE_LEN = 4096
"""String-attribute cap on Fabric-built providers (hosts' own providers set their own)."""

_NOOP_PROVIDER_WARNED = False
_SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PRIVATE_PROVIDERS: weakref.WeakSet[TracerProvider] = weakref.WeakSet()
_EXPORT_SCOPE = threading.local()
_EXPORTER_LOGGERS = (
    "opentelemetry.exporter.otlp.proto.http.trace_exporter",
    "opentelemetry.exporter.otlp.proto.grpc.exporter",
    "opentelemetry.exporter.otlp.proto.grpc.trace_exporter",
    "opentelemetry.util.re", "urllib3.connectionpool", "urllib3.util.retry",
)  # fmt: skip
# OTLP env header syntax (opentelemetry.util.re, liberal form): anything else is refused
# here, so the OTel parser never logs a malformed (credential-bearing) header.
_HEADER_RE = re.compile(
    r"[ \t]*[\x21\x23-\x27\x2a\x2b\x2d\x2e\x30-\x39\x41-\x5a\x5e-\x7a\x7c\x7e]+[ \t]*="
    r"[ \t]*[\x20\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*[ \t]*"
)
_GRPC_CREDENTIAL_PROVIDERS = (
    "OTEL_PYTHON_EXPORTER_OTLP_GRPC_TRACES_CREDENTIAL_PROVIDER",
    "OTEL_PYTHON_EXPORTER_OTLP_GRPC_CREDENTIAL_PROVIDER",
)


def _provider_has_span_processors(provider: object) -> bool:
    """Best-effort: a real ``TracerProvider`` has span processors (``True`` when unknown)."""
    processor = getattr(provider, "_active_span_processor", None)
    processors = getattr(processor, "_span_processors", None)
    if isinstance(processors, tuple):
        return bool(processors)
    return True


def _warn_if_noop_provider() -> None:
    """One-shot WARN when spans would be silently dropped: the OTel no-op default
    (``ProxyTracerProvider``) or a real ``TracerProvider`` with zero span processors."""
    global _NOOP_PROVIDER_WARNED  # noqa: PLW0603
    if _NOOP_PROVIDER_WARNED:
        return
    provider = trace.get_tracer_provider()
    if type(provider).__name__ == "ProxyTracerProvider":
        _LOG.warning(
            "fabric.tracing: no OpenTelemetry TracerProvider is configured; Fabric decision "
            "spans will have zero trace IDs and be dropped. Call fabric.install_default_provider"
            "(...) or wire OTel yourself before opening a Decision. See docs/quickstart.md step 2."
        )
        _NOOP_PROVIDER_WARNED = True
        return
    if isinstance(provider, TracerProvider) and not _provider_has_span_processors(provider):
        _LOG.warning(
            "fabric.tracing: the installed TracerProvider has no span processors; Fabric spans "
            "will be recorded but never exported. Add a SpanProcessor/exporter, pass exporter= "
            "to install_default_provider, or set OTEL_EXPORTER_OTLP_ENDPOINT with the [otlp] "
            "extra installed."
        )
        _NOOP_PROVIDER_WARNED = True


def get_tracer() -> trace.Tracer:
    """Return the tracer the SDK emits spans with."""
    _warn_if_noop_provider()
    return trace.get_tracer(
        FABRIC_SDK_NAME,
        __version__,
        schema_url=GEN_AI_SCHEMA_URL,
    )


def get_meter() -> metrics.Meter:
    """The meter for standard GenAI client instruments (no-op without a MeterProvider)."""

    return metrics.get_meter(
        FABRIC_SDK_NAME,
        __version__,
        schema_url=GEN_AI_SCHEMA_URL,
    )


def _resolve_default_exporter(exporter: SpanExporter | None) -> SpanExporter | None:
    """``exporter``, else an ``OTLPSpanExporter`` when an OTLP endpoint is set and the
    ``[otlp]`` extra is installed, else ``None``."""
    if exporter is not None:
        return exporter
    if otlp_endpoint_configured():
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # noqa: PLC0415
                OTLPSpanExporter,
            )
        except ImportError:
            _LOG.warning(
                "fabric.tracing: OTEL_EXPORTER_OTLP_ENDPOINT is set but the OTLP "
                "exporter package is not installed; spans will not be exported. "
                "Install `singleaxis-fabric[otlp]` (or "
                "opentelemetry-exporter-otlp-proto-http)."
            )
            return None
        return OTLPSpanExporter()
    return None


def _new_provider(
    service_name: str | None,
    resource_attributes: dict[str, Any] | None,
    sampler: Sampler | None = None,
) -> TracerProvider:
    attrs: dict[str, Any] = {
        "service.name": service_name or os.environ.get("OTEL_SERVICE_NAME", FABRIC_SDK_NAME),
        "fabric.sdk.version": __version__,
    }
    if resource_attributes:
        attrs.update(resource_attributes)
    return TracerProvider(
        sampler=sampler,
        resource=Resource.create(attrs),
        span_limits=SpanLimits(max_span_attribute_length=_MAX_ATTR_VALUE_LEN),
    )


def install_default_provider(
    *,
    service_name: str | None = None,
    exporter: SpanExporter | None = None,
    resource_attributes: dict[str, Any] | None = None,
    meter_provider: metrics.MeterProvider | None = None,
) -> TracerProvider:
    """Install a :class:`TracerProvider` on the global OTel API and return it.

    For tests, examples and small agents; production hosts configure OTel themselves.
    Without ``exporter`` an OTLP exporter is built from the standard env when an endpoint
    is set (else a WARN: every span would be dropped). ``meter_provider`` is installed
    globally when given. An already-installed real provider is returned unchanged, with
    a WARN: replacing it is an OTel anti-pattern.
    """
    existing = trace.get_tracer_provider()
    if isinstance(existing, TracerProvider):
        _LOG.warning(
            "fabric.tracing: TracerProvider already installed; "
            "ignoring install_default_provider() request and returning the "
            "existing provider. Configure OTel once at process startup."
        )
        return existing
    resolved_exporter = _resolve_default_exporter(exporter)
    provider = _new_provider(service_name, resource_attributes)
    if resolved_exporter is not None:
        provider.add_span_processor(BatchSpanProcessor(resolved_exporter))
    else:
        _LOG.warning(
            "fabric.tracing: install_default_provider() called without an "
            "exporter; the provider has no span processor and every Fabric "
            "span will be recorded then dropped. Pass exporter=..., set "
            "OTEL_EXPORTER_OTLP_ENDPOINT (with the [otlp] extra), or wire "
            "your own TracerProvider."
        )
    trace.set_tracer_provider(provider)
    if meter_provider is not None:
        metrics.set_meter_provider(meter_provider)
    # Latch the noop warning only when the install ships spans (zero processors still lose).
    global _NOOP_PROVIDER_WARNED  # noqa: PLW0603
    _NOOP_PROVIDER_WARNED = resolved_exporter is not None
    return provider


def otlp_endpoint_configured() -> bool:
    """Whether the standard env names an OTLP traces endpoint."""
    names = ("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT")
    return any(os.environ.get(name) for name in names)


def _safe_log_arg(value: object) -> object:
    if isinstance(value, (bool, int, float)):
        return value  # status codes, retry counts, backoff seconds
    if isinstance(value, Enum):
        return value.name  # e.g. a gRPC status code
    if isinstance(value, BaseException):
        return type(value).__name__
    return "<redacted>"  # URLs, reason phrases, error details: never echoed


class _SanitizedExportDiagnostics(logging.Filter):
    """Inside Fabric's exports only, reduce exporter log records to codes and class names."""

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(_EXPORT_SCOPE, "active", False):
            args = record.args if isinstance(record.args, tuple) else ()
            if not isinstance(record.msg, str) or (record.args and not args):
                record.msg, args = "OTLP exporter diagnostic (%s)", (type(record.msg).__name__,)
            exc = record.exc_info[1] if record.exc_info else None
            record.args = tuple(_safe_log_arg(arg) for arg in args)
            if exc is not None:  # the traceback text may carry the exception message
                record.msg = f"{record.msg} [{type(exc).__name__}]"
            record.exc_info = record.exc_text = record.stack_info = None
        return True


_DIAGNOSTICS_FILTER = _SanitizedExportDiagnostics()


@contextlib.contextmanager
def sanitized_export_diagnostics() -> Iterator[None]:
    """Sanitize exporter and HTTP-client log records emitted on this thread inside the block.

    Fabric does not patch the OTel library: a filter on the exporter, OTLP header parser
    and urllib3 loggers rewrites only records produced while a Fabric-owned export or
    construction runs on this thread, so the host's own exporters log exactly as before.
    """
    for name in _EXPORTER_LOGGERS:
        logging.getLogger(name).addFilter(_DIAGNOSTICS_FILTER)  # idempotent
    previous = getattr(_EXPORT_SCOPE, "active", False)
    _EXPORT_SCOPE.active = True
    try:
        yield
    finally:
        _EXPORT_SCOPE.active = previous


@dataclass(frozen=True, slots=True)
class OtlpSettings:
    """One OTLP signal's resolved settings (signal-specific variable first, then general)."""

    endpoint: str | None
    headers: Mapping[str, str]
    certificate: str | None
    client_certificate: str | None
    client_key: str | None
    timeout_s: float
    protocol: str


def otlp_signal_settings(
    signal: Literal["traces", "logs"], environ: Mapping[str, str] = os.environ
) -> OtlpSettings:
    """Resolve ``OTEL_EXPORTER_OTLP_<SIGNAL>_*`` > ``OTEL_EXPORTER_OTLP_*`` (043 §3);
    ``ValueError`` naming only the variable for an endpoint with userinfo, query or fragment
    (042 E8), malformed headers, an unreadable TLS file, a lone key/cert or a bad timeout."""

    def pick(suffix: str) -> tuple[str, str] | None:
        names = (f"OTEL_EXPORTER_OTLP_{signal.upper()}_{suffix}", f"OTEL_EXPORTER_OTLP_{suffix}")
        for name in names:
            if value := environ.get(name, "").strip():
                return name, value
        return None

    if (endpoint := pick("ENDPOINT")) is not None:
        check_endpoint_url(*endpoint)
    headers: dict[str, str] = {}
    if (raw := pick("HEADERS")) is not None:
        for item in filter(None, re.split(r"[ \t]*,[ \t]*", raw[1])):
            if not _HEADER_RE.fullmatch(item):
                raise ValueError(f"{raw[0]} must be k=v pairs separated by commas")
            key, _, value = item.partition("=")
            headers[unquote(key).strip().lower()] = unquote(value).strip()
    files = {suffix: pick(suffix) for suffix in ("CERTIFICATE", "CLIENT_CERTIFICATE", "CLIENT_KEY")}
    for found in filter(None, files.values()):
        _read_tls_file(*found)
    if (files["CLIENT_KEY"] is None) is not (files["CLIENT_CERTIFICATE"] is None):
        raise ValueError("OTLP client key and client certificate must be configured together")
    timeout = pick("TIMEOUT")
    try:
        timeout_s = float(timeout[1]) if timeout else 10.0
    except ValueError:
        raise ValueError(f"{timeout[0] if timeout else 'timeout'} must be a number") from None
    path = {k: v[1] if v else None for k, v in files.items()}
    return OtlpSettings(
        endpoint[1] if endpoint else None, headers, path["CERTIFICATE"],
        path["CLIENT_CERTIFICATE"], path["CLIENT_KEY"], timeout_s,
        (pick("PROTOCOL") or ("", "http/protobuf"))[1],
    )  # fmt: skip


def check_endpoint_url(name: str, value: str) -> None:
    """Reject a URL with userinfo, a query or a fragment; the error never echoes it (042 E8)."""
    try:
        parts = urlsplit(value.strip())
        _ = parts.port  # an invalid port raises here, not later inside the exporter
    except ValueError:
        raise ValueError(f"{name} is not a valid URL") from None
    if "@" in parts.netloc or parts.query or parts.fragment or "?" in value or "#" in value:
        raise ValueError(f"{name} must not carry credentials, a query or a fragment")


def _read_tls_file(name: str, path: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError:
        raise ValueError(f"the file named by {name} is not readable") from None


def _refuse_redirect(response: Any, *args: Any, **kwargs: Any) -> Any:
    """Response hook: any 3xx is a delivery failure, raised before requests could follow it
    (no body or header is ever re-sent elsewhere). Fixed text: no URL or location."""
    if 300 <= int(getattr(response, "status_code", 0)) < 400:  # noqa: PLR2004
        import requests  # type: ignore[import-untyped]  # noqa: PLC0415

        with contextlib.suppress(Exception):
            response.close()
        raise requests.exceptions.TooManyRedirects("redirect refused by Fabric delivery")
    return response


def no_redirect_session(session: Any = None) -> Any:
    """``session`` (default: a new ``requests.Session``) hardened for Fabric delivery (H1): it
    never follows a redirect, and every 3xx response raises ``TooManyRedirects`` (an
    ``OSError``), so delivery fails and is retried later, never counted as success."""
    import requests  # noqa: PLC0415

    session = requests.Session() if session is None else session
    if not isinstance(session, requests.Session):
        raise ValueError("Fabric delivery needs a requests session")
    session.max_redirects = 0
    hooks = session.hooks.setdefault("response", [])
    if _refuse_redirect not in hooks:
        hooks.insert(0, _refuse_redirect)
    return session


def _harden_exporter_session(exporter: object) -> None:
    """Make the OTLP/HTTP exporter's ``requests`` session refuse redirects (H1); a session
    that cannot be found fails construction rather than delivering with redirects on."""
    session = getattr(exporter, "_session", None)
    if session is None:
        raise ValueError("the OTLP exporter session cannot be hardened")
    no_redirect_session(session)


def _grpc_credentials(settings: OtlpSettings) -> Any:
    """gRPC channel credentials with CA, client key and client certificate resolved one by
    one; ``None`` when none is set. (The gRPC exporter resolves the three as a group, which
    silently drops client credentials when the variables mix scopes.)"""
    if any(os.environ.get(name) for name in _GRPC_CREDENTIAL_PROVIDERS):
        return None  # a credential-provider plugin owns the channel credentials
    ca, cert, key = settings.certificate, settings.client_certificate, settings.client_key
    if ca is None and key is None:
        return None
    grpc = importlib.import_module("grpc")
    return grpc.ssl_channel_credentials(
        root_certificates=_read_tls_file("CA", ca) if ca else None,
        private_key=_read_tls_file("key", key) if key else None,
        certificate_chain=_read_tls_file("cert", cert) if cert else None,
    )


class _GuardedExporter(SpanExporter):
    """Exports under sanitized diagnostics; an exception becomes ``FAILURE`` (class name only)."""

    def __init__(self, inner: SpanExporter) -> None:
        self._inner = inner

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        try:
            with sanitized_export_diagnostics():
                return self._inner.export(spans)
        except Exception as exc:
            _LOG.warning("fabric: span export failed (%s)", type(exc).__name__)
            return SpanExportResult.FAILURE

    def shutdown(self) -> None:
        with contextlib.suppress(Exception), sanitized_export_diagnostics():
            self._inner.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        try:
            with sanitized_export_diagnostics():
                return self._inner.force_flush(timeout_millis)
        except Exception:
            return False


def guarded_exporter(exporter: SpanExporter) -> SpanExporter:
    """``exporter`` under sanitized diagnostics, exceptions as ``FAILURE`` (idempotent)."""
    return exporter if isinstance(exporter, _GuardedExporter) else _GuardedExporter(exporter)


def _otlp_exporter() -> SpanExporter | None:
    """The OTLP exporter the standard env selects (``None`` without an endpoint)."""
    settings = otlp_signal_settings("traces")
    if settings.protocol not in ("http/protobuf", "grpc"):
        raise ValueError("OTLP protocol must be http/protobuf or grpc for Fabric capture")
    if settings.endpoint is None:
        return None
    name = "http" if settings.protocol == "http/protobuf" else "grpc"
    try:
        module = importlib.import_module(f"opentelemetry.exporter.otlp.proto.{name}.trace_exporter")
    except ImportError:
        raise ValueError(f"OTLP {name} needs opentelemetry-exporter-otlp-proto-{name}") from None
    try:
        with sanitized_export_diagnostics():
            credentials = _grpc_credentials(settings) if name == "grpc" else None
            exporter: SpanExporter = (
                module.OTLPSpanExporter() if credentials is None
                else module.OTLPSpanExporter(credentials=credentials)
            )  # fmt: skip
            if name == "http":  # its own (or a credential plugin's) session, never redirecting
                _harden_exporter_session(exporter)
    except Exception as exc:
        raise ValueError(f"OTLP span exporter construction failed ({type(exc).__name__})") from None
    return exporter


def build_capture_span_exporter() -> SpanExporter:
    """The capture-path span exporter (spec 043 §8): the OTLP exporter the env selects
    (042 D3), every export, flush and shutdown under sanitized diagnostics, exceptions as
    ``FAILURE``. ``ValueError`` (fixed text) when none can be built."""
    exporter = _otlp_exporter()
    if exporter is None:
        raise ValueError("Fabric capture needs an OTLP traces endpoint")
    return guarded_exporter(exporter)


def is_private_provider(provider: object) -> bool:
    """Whether ``provider`` was built by :func:`build_private_provider` (Fabric shuts it down)."""
    return isinstance(provider, TracerProvider) and provider in _PRIVATE_PROVIDERS


def build_private_provider(*, exporter: SpanExporter | None = None) -> TracerProvider:
    """A :class:`TracerProvider` for Fabric's direct capture path, never installed globally.

    The exporter is ``exporter``, else the OTLP exporter of
    :func:`build_capture_span_exporter` when an OTLP endpoint is set (otherwise none, with
    a WARN); either is guarded (sanitized diagnostics, exceptions as ``FAILURE``). The
    resource is only ``service.name`` (a valid ``OTEL_SERVICE_NAME``, else
    ``fabric-wire``); sampling is ``ALWAYS_ON``. Spans a failed or evicted export loses
    stay sequence gaps the verifier reports (spec 042 §6); the spool (spec 043) closes
    them. No exit handler of its own: ``fabric.wire`` shuts it down within its budget.
    """
    resolved = exporter if exporter is not None else _otlp_exporter()
    provider = TracerProvider(
        sampler=ALWAYS_ON,
        resource=Resource({"service.name": capture_service_name()}),
        span_limits=SpanLimits(max_span_attribute_length=_MAX_ATTR_VALUE_LEN),
        shutdown_on_exit=False,
    )
    _PRIVATE_PROVIDERS.add(provider)
    if resolved is not None:
        provider.add_span_processor(BatchSpanProcessor(guarded_exporter(resolved)))
    else:
        _LOG.warning(
            "fabric.tracing: build_private_provider() has no exporter; spans on this "
            "private provider will be recorded then dropped. Pass exporter=... or set "
            "OTEL_EXPORTER_OTLP_ENDPOINT (with the [otlp] extra)."
        )
    return provider


def capture_service_name() -> str:
    """``OTEL_SERVICE_NAME`` when it is a safe name, else ``fabric-wire`` (042 D3)."""
    name = os.environ.get("OTEL_SERVICE_NAME", "")
    return name if _SERVICE_NAME_RE.fullmatch(name) else "fabric-wire"
