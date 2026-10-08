# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""OpenTelemetry plumbing used by the Fabric SDK.

The SDK does not install a global tracer provider on behalf of the
host application — that is the host's choice. Instead we always fetch
a tracer via ``opentelemetry.trace.get_tracer`` and let the host
configure exporters. ``install_default_provider`` is offered as a
convenience for tests and small agents that have no provider of their
own.

Metrics
-------

``gen_ai.client.*`` instruments (token usage, operation duration, TTFT,
time-per-chunk, tool duration) are created on the global OTel *metrics*
API via :func:`get_meter`. Without a real ``MeterProvider`` installed
they silently no-op — the API returns a proxy meter that discards every
recording. Hosts that want the metrics must install a
:class:`opentelemetry.sdk.metrics.MeterProvider` (e.g. wired to an OTLP
metric exporter) at process level, or pass ``meter_provider=`` to
:func:`install_default_provider` / a ``Meter`` to :class:`Fabric`.
"""

from __future__ import annotations

import contextlib
import importlib
import logging
import os
import re
import threading
import weakref
from collections.abc import Iterator
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from opentelemetry import metrics, trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import SpanLimits, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter
from opentelemetry.sdk.trace.sampling import ALWAYS_ON, Sampler

from ._version import __version__

_LOG = logging.getLogger("fabric")

FABRIC_SDK_NAME = "singleaxis-fabric-python"
"""``service.name`` fallback applied when the host hasn't set one."""

GEN_AI_SCHEMA_URL = "https://opentelemetry.io/schemas/gen-ai/1.42.0"
"""Schema URL for the GenAI semantic conventions emitted by Fabric."""

_MAX_ATTR_VALUE_LEN = 4096
"""Cap exported string-attribute length on the SDK's default provider so a
pathological multi-MB value can't bloat a span or get rejected by a backend.
Generous for any hash/identifier/short text; hosts that wire their own
TracerProvider choose their own SpanLimits."""

_NOOP_PROVIDER_WARNED = False
_SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PRIVATE_PROVIDERS: weakref.WeakSet[TracerProvider] = weakref.WeakSet()
_EXPORT_SCOPE = threading.local()
_EXPORTER_LOGGERS = (
    "opentelemetry.exporter.otlp.proto.http.trace_exporter",
    "opentelemetry.exporter.otlp.proto.grpc.exporter",
    "opentelemetry.exporter.otlp.proto.grpc.trace_exporter",
)
_GRPC_CREDENTIAL_PROVIDERS = (
    "OTEL_PYTHON_EXPORTER_OTLP_GRPC_TRACES_CREDENTIAL_PROVIDER",
    "OTEL_PYTHON_EXPORTER_OTLP_GRPC_CREDENTIAL_PROVIDER",
)


def _provider_has_span_processors(provider: object) -> bool:
    """Best-effort check that a real ``TracerProvider`` ships spans.

    Reads the SDK's internal ``_active_span_processor._span_processors``
    tuple. Any deviation in those internals (renames across OTel versions,
    a non-SDK provider) answers ``True`` — better to under-warn than to
    false-warn on a provider we cannot inspect.
    """
    processor = getattr(provider, "_active_span_processor", None)
    processors = getattr(processor, "_span_processors", None)
    if isinstance(processors, tuple):
        return bool(processors)
    return True


def _warn_if_noop_provider() -> None:
    """Emit a one-shot WARN if spans would be silently dropped.

    Two silent-drop shapes are caught: the OTel no-op default
    (``ProxyTracerProvider`` — every span gets an all-zero trace_id and
    disappears), and a real ``TracerProvider`` with zero span processors
    (spans are recorded but never exported — the same silent loss one
    level down). Hosts that copy a minimal ``Fabric(...)`` example without
    ``install_default_provider`` or their own OTel wiring hit the first;
    an ``install_default_provider()`` call with no exporter hits the
    second.
    """
    global _NOOP_PROVIDER_WARNED  # noqa: PLW0603
    if _NOOP_PROVIDER_WARNED:
        return
    provider = trace.get_tracer_provider()
    # OTel ships a ProxyTracerProvider as the global default until set.
    if type(provider).__name__ == "ProxyTracerProvider":
        _LOG.warning(
            "fabric.tracing: no OpenTelemetry TracerProvider is configured; "
            "Fabric decision spans will have zero trace IDs and be dropped. "
            "Call fabric.install_default_provider(...) or wire OTel yourself "
            "before opening a Decision. See docs/quickstart.md step 2."
        )
        _NOOP_PROVIDER_WARNED = True
        return
    if isinstance(provider, TracerProvider) and not _provider_has_span_processors(provider):
        _LOG.warning(
            "fabric.tracing: the installed TracerProvider has no span "
            "processors; Fabric spans will be recorded but never exported. "
            "Add a SpanProcessor/exporter, pass exporter= to "
            "install_default_provider, or set OTEL_EXPORTER_OTLP_ENDPOINT "
            "with the [otlp] extra installed."
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
    """Return the meter used for standard GenAI client instruments.

    Without a global ``MeterProvider`` installed, the returned meter is
    the OTel no-op proxy: every ``gen_ai.client.*`` instrument records
    into the void. See the module docstring — install a MeterProvider (or
    pass ``meter_provider=`` to :func:`install_default_provider`) to make
    the metrics live.
    """

    return metrics.get_meter(
        FABRIC_SDK_NAME,
        __version__,
        schema_url=GEN_AI_SCHEMA_URL,
    )


def _resolve_default_exporter(exporter: SpanExporter | None) -> SpanExporter | None:
    """Return ``exporter``, or default-construct an OTLP exporter.

    When ``OTEL_EXPORTER_OTLP_ENDPOINT`` (or the signal-specific
    ``OTEL_EXPORTER_OTLP_TRACES_ENDPOINT``) is set and no explicit
    exporter was passed, the standard OTLP env configuration should
    work: construct ``OTLPSpanExporter`` — it reads the endpoint and
    headers from the same env vars — when the ``[otlp]`` extra is
    installed. Returns ``None`` when neither path produces an exporter.
    """
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
    """Install a :class:`TracerProvider` on the global OTel API.

    Intended for tests, examples, and small agents without their own
    OTel wiring. Production deployments should configure OTel at the
    process level and let the SDK reuse the global provider.

    Returns the newly-installed provider so callers can attach
    additional exporters or processors.

    ``exporter`` is optional but recommended: without one the provider
    has no span processor and every span is silently dropped — a WARN is
    emitted so the gap is loud. When
    ``OTEL_EXPORTER_OTLP_ENDPOINT``/``OTEL_EXPORTER_OTLP_TRACES_ENDPOINT``
    is set and no exporter is given, an ``OTLPSpanExporter`` is
    default-constructed (reads the same env vars) when the ``[otlp]``
    extra is installed, so the standard env configuration "just works".

    ``meter_provider``, when given, is installed on the global OTel
    metrics API via ``metrics.set_meter_provider`` so the
    ``gen_ai.client.*`` instruments actually record. Without a real
    ``MeterProvider`` those metrics silently no-op (see module docstring).

    If a real ``TracerProvider`` is already installed, a WARN is emitted
    and the existing provider is returned unchanged. Re-install of an
    already-configured provider is an OTel anti-pattern (the OTel API
    docs explicitly disallow it), so the SDK refuses to silently
    replace it.
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
    # Latch the noop warning only when the install actually ships spans.
    # A zero-processor provider still loses every span silently, so leave
    # the latch unset and let _warn_if_noop_provider flag that shape too.
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
    """Sanitize the OTLP exporter's log records emitted on this thread inside the block.

    Fabric does not patch the OTel library: a filter on the exporter modules' loggers
    rewrites only records produced while a Fabric-owned export runs on this thread, so
    the host's own exporters log exactly as before.
    """
    for name in _EXPORTER_LOGGERS:
        logging.getLogger(name).addFilter(_DIAGNOSTICS_FILTER)  # idempotent
    previous = getattr(_EXPORT_SCOPE, "active", False)
    _EXPORT_SCOPE.active = True
    try:
        yield
    finally:
        _EXPORT_SCOPE.active = previous


def _check_otlp_endpoint() -> None:
    """Reject an effective OTLP traces endpoint with userinfo, a query or a fragment.

    Such a URL can carry credentials into exporter logs; the error never echoes it.
    """
    name = next(
        (n for n in ("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT")
         if os.environ.get(n)),
        None,
    )  # fmt: skip
    if name is None:
        return
    value = os.environ[name].strip()
    try:
        parts = urlsplit(value)
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


def _grpc_credentials() -> Any:
    """gRPC channel credentials with CA, client key and client certificate resolved one by
    one (traces-specific variable first, then the general one); ``None`` when none is set.

    The gRPC exporter itself resolves the three as a group, which silently drops client
    credentials when the variables mix scopes.
    """
    if any(os.environ.get(name) for name in _GRPC_CREDENTIAL_PROVIDERS):
        return None  # a credential-provider plugin owns the channel credentials

    def pick(suffix: str) -> tuple[str, str] | None:
        for name in (f"OTEL_EXPORTER_OTLP_TRACES_{suffix}", f"OTEL_EXPORTER_OTLP_{suffix}"):
            if value := os.environ.get(name, "").strip():
                return name, value
        return None

    ca, key, cert = pick("CERTIFICATE"), pick("CLIENT_KEY"), pick("CLIENT_CERTIFICATE")
    if ca is None and key is None and cert is None:
        return None
    if (key is None) is not (cert is None):
        raise ValueError("OTLP client key and client certificate must be configured together")
    try:
        grpc = importlib.import_module("grpc")
    except ImportError as exc:
        raise ValueError("OTLP grpc needs opentelemetry-exporter-otlp-proto-grpc") from exc
    return grpc.ssl_channel_credentials(
        root_certificates=_read_tls_file(*ca) if ca else None,
        private_key=_read_tls_file(*key) if key else None,
        certificate_chain=_read_tls_file(*cert) if cert else None,
    )


def _private_exporter() -> SpanExporter | None:
    """The OTLP exporter the standard protocol env selects; ``ValueError`` when unusable."""
    names = ("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "OTEL_EXPORTER_OTLP_PROTOCOL")
    protocol = next((v.strip() for n in names if (v := os.environ.get(n))), "http/protobuf")
    if protocol not in ("http/protobuf", "grpc"):
        raise ValueError("OTLP protocol must be http/protobuf or grpc for Fabric capture")
    if not otlp_endpoint_configured():
        return None
    _check_otlp_endpoint()
    if protocol == "http/protobuf":
        return _resolve_default_exporter(None)  # warns when the package is missing
    try:
        module = importlib.import_module("opentelemetry.exporter.otlp.proto.grpc.trace_exporter")
    except ImportError as exc:
        raise ValueError("OTLP grpc needs opentelemetry-exporter-otlp-proto-grpc") from exc
    credentials = _grpc_credentials()
    exporter: SpanExporter = (
        module.OTLPSpanExporter() if credentials is None
        else module.OTLPSpanExporter(credentials=credentials)
    )  # fmt: skip
    return exporter


def is_private_provider(provider: object) -> bool:
    """Whether ``provider`` was built by :func:`build_private_provider` (Fabric shuts it down)."""
    return isinstance(provider, TracerProvider) and provider in _PRIVATE_PROVIDERS


def build_private_provider(*, exporter: SpanExporter | None = None) -> TracerProvider:
    """Build a :class:`TracerProvider` for Fabric's own use, never installed globally.

    Used by capture components (the wire tee) that must emit spans without taking over
    the host's OTel setup: this never calls ``trace.set_tracer_provider``. The exporter
    is ``exporter``, else the OTLP exporter selected by
    ``OTEL_EXPORTER_OTLP_TRACES_PROTOCOL`` / ``OTEL_EXPORTER_OTLP_PROTOCOL``
    (``http/protobuf`` by default, or ``grpc``) when an OTLP endpoint is set. Any
    other protocol, ``grpc`` without its package, an endpoint with userinfo, a query
    or a fragment, or an unreadable TLS file raises ``ValueError``. Without an
    exporter the provider has no span processor and a WARN is logged.

    The resource is only ``service.name`` (a valid ``OTEL_SERVICE_NAME``, else
    ``fabric-wire``): ``OTEL_RESOURCE_ATTRIBUTES`` and detectors are ignored, so no
    host attribute leaves the process on capture spans. The provider always samples
    (``ALWAYS_ON``): capture spans are the record (spec 042 §6). The exporter is
    wrapped in :class:`fabric._loss.LossExporter`: exchange spans of a failed export
    become ``span_dropped`` losses, and failed loss/heartbeat records are retried.

    The provider registers no exit handler of its own (OTel's would export inline and
    unbounded on the exiting thread); ``fabric.wire`` flushes and shuts it down at exit
    within its shutdown budget.
    """
    from ._loss import LossExporter  # noqa: PLC0415 - _loss imports this module

    resolved_exporter = exporter if exporter is not None else _private_exporter()
    name = os.environ.get("OTEL_SERVICE_NAME", "")
    name = name if _SERVICE_NAME_RE.match(name) else "fabric-wire"
    provider = TracerProvider(
        sampler=ALWAYS_ON,
        resource=Resource({"service.name": name}),
        span_limits=SpanLimits(max_span_attribute_length=_MAX_ATTR_VALUE_LEN),
        shutdown_on_exit=False,
    )
    _PRIVATE_PROVIDERS.add(provider)
    if resolved_exporter is not None:
        # Spans evicted from a full batch queue never reach LossExporter; they stay
        # sequence gaps, which the verifier reports as partial (spec 042 §6).
        provider.add_span_processor(BatchSpanProcessor(LossExporter(resolved_exporter)))
    else:
        _LOG.warning(
            "fabric.tracing: build_private_provider() has no exporter; spans "
            "on this private provider will be recorded then dropped. Pass "
            "exporter=... or set OTEL_EXPORTER_OTLP_ENDPOINT (with the [otlp] "
            "extra)."
        )
    return provider
