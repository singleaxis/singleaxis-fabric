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

Wire capture
------------

Capture components (spec 047/048 LLM wire capture) use
:func:`build_private_provider` or :func:`build_capture_span_exporter`, never
the global provider, unless ``FABRIC_WIRE_TRACER=global`` selects an
unprotected host provider (a Fabric-protected global provider never carries
wire spans; see ``fabric.wire``).
"""

from __future__ import annotations

import contextlib
import importlib
import logging
import os
import re
import weakref
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote, urlsplit

from opentelemetry import metrics, trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, SpanLimits, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.sdk.trace.sampling import ALWAYS_ON

from ._export_diagnostics import sanitized_export_diagnostics
from ._sequence import LABELS_ENV, id_key_from_env, label_pseudonym
from ._span_protection import MetadataOnlySpanExporter
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
        # Prevalidate the header variables as wire delivery does: OpenTelemetry's own parser
        # logs a malformed (credential-bearing) header verbatim. The exporter keeps main's
        # behaviour (a malformed pair is skipped); only the diagnostics change.
        for name in ("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "OTEL_EXPORTER_OTLP_HEADERS"):
            if not _headers_well_formed(os.environ.get(name, "")):
                _LOG.warning(
                    "fabric.tracing: %s is not k=v pairs separated by commas; "
                    "malformed entries are skipped (values are never logged)", name
                )  # fmt: skip
        with sanitized_export_diagnostics():
            return OTLPSpanExporter()
    return None


def _headers_well_formed(raw: str) -> bool:
    """Whether ``raw`` is OTLP env header syntax (the form :func:`otlp_signal_settings` accepts)."""
    items = filter(None, re.split(r"[ \t]*,[ \t]*", raw.strip()))
    return all(_HEADER_RE.fullmatch(item) for item in items)


def install_default_provider(
    *,
    service_name: str | None = None,
    exporter: SpanExporter | None = None,
    resource_attributes: dict[str, Any] | None = None,
    meter_provider: metrics.MeterProvider | None = None,
    capture_content: bool | None = None,
) -> TracerProvider:
    """Install a :class:`TracerProvider` on the global OTel API.

    Intended for tests, examples, and small agents without their own
    OTel wiring. Production deployments should configure OTel at the
    process level and let the SDK reuse the global provider.

    Returns the newly-installed provider. Its managed exporter receives a
    metadata-only projection by default: content/events/status text are removed,
    string identifiers are hashed, names/scope are fixed, and numeric/boolean
    metadata is type-checked. Trace/span/parent IDs and timings are retained.
    Projection counts are available through ``trace_export_protection_status``
    and on each exported span. Source spans are not mutated.

    ``capture_content=True`` (or ``FABRIC_CAPTURE_LLM_CONTENT=true`` when this
    argument is omitted) explicitly bypasses protection on this route. This can
    export prompts, credentials and exception text. Upstream instrumentation
    requires its separate content opt-in too. Any exporters/processors added
    later by the host are outside this protection boundary.

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
    replace it. An existing non-SDK provider raises a fixed setup error rather
    than returning an unused provider that appears protected. Concurrent
    installation is also detected. Call this before starting request producers.
    """
    if capture_content is not None and type(capture_content) is not bool:
        raise ValueError("capture_content must be a boolean or None")
    existing = trace.get_tracer_provider()
    if isinstance(existing, TracerProvider):
        _LOG.warning(
            "fabric.tracing: TracerProvider already installed; "
            "ignoring install_default_provider() request and returning the "
            "existing provider. Its host-owned exporters are not modified or "
            "protected by this call. Configure OTel once at process startup."
        )
        return existing
    if type(existing) is not trace.ProxyTracerProvider:
        raise RuntimeError(
            "fabric.tracing: a host-owned non-SDK TracerProvider is already installed; "
            "its exporters are unchanged and protection is unverified. "
            "Configure protection in the host provider before starting requests."
        )
    if capture_content is None:
        capture_content = os.environ.get("FABRIC_CAPTURE_LLM_CONTENT", "false").strip().lower() in (
            "1",
            "true",
            "yes",
            "on",
        )
    resolved_exporter = _resolve_default_exporter(exporter)
    attrs: dict[str, Any] = {
        "service.name": service_name or os.environ.get("OTEL_SERVICE_NAME", FABRIC_SDK_NAME),
        "fabric.sdk.version": __version__,
    }
    if resource_attributes:
        attrs.update(resource_attributes)
    provider = TracerProvider(
        resource=Resource.create(attrs),
        span_limits=SpanLimits(max_span_attribute_length=_MAX_ATTR_VALUE_LEN),
    )
    trace.set_tracer_provider(provider)
    if trace.get_tracer_provider() is not provider:
        # No processor is attached yet: this cannot shut down a supplied
        # exporter that another host route may share. Never return an unused
        # provider whose status could falsely imply active protection.
        provider.shutdown()
        raise RuntimeError(
            "fabric.tracing: global TracerProvider installation was not accepted; "
            "the actual host provider is unchanged and protection is unverified."
        )
    if resolved_exporter is not None:
        provider.add_span_processor(
            BatchSpanProcessor(
                MetadataOnlySpanExporter(resolved_exporter, capture_content=capture_content)
            )
        )
    else:
        _LOG.warning(
            "fabric.tracing: install_default_provider() called without an "
            "exporter; the provider has no span processor and every Fabric "
            "span will be recorded then dropped. Pass exporter=..., set "
            "OTEL_EXPORTER_OTLP_ENDPOINT (with the [otlp] extra), or wire "
            "your own TracerProvider."
        )
    if meter_provider is not None:
        metrics.set_meter_provider(meter_provider)
    # Latch the noop warning only when the install actually ships spans.
    # A zero-processor provider still loses every span silently, so leave
    # the latch unset and let _warn_if_noop_provider flag that shape too.
    global _NOOP_PROVIDER_WARNED  # noqa: PLW0603
    _NOOP_PROVIDER_WARNED = resolved_exporter is not None
    return provider


def trace_export_protection_status(provider: object | None = None) -> dict[str, Any]:
    """Describe observed managed routes, including any unprotected host routes.

    This is route/configuration evidence, not proof of backend delivery. Counts
    include projections attempted, even if the destination later rejects them.
    """
    provider = provider if provider is not None else trace.get_tracer_provider()
    processor = getattr(provider, "_active_span_processor", None)
    processors = getattr(processor, "_span_processors", None)
    if not isinstance(processors, tuple):
        return {
            "status": "UNKNOWN",
            "reason": "host_provider_not_inspectable",
            "basis": "current_process",
        }
    protected = opt_in = host_owned = 0
    counts: dict[str, int] = {}
    for item in processors:
        exporter = getattr(item, "span_exporter", None)
        if isinstance(exporter, MetadataOnlySpanExporter):
            if exporter.capture_content:
                opt_in += 1
            else:
                protected += 1
            for key, value in exporter.snapshot().items():
                counts[key] = counts.get(key, 0) + value
        else:
            host_owned += 1
    if host_owned:
        status, reason = "UNPROTECTED_HOST_ROUTES", "host_exporters_not_modified"
    elif opt_in:
        status, reason = "CONTENT_OPT_IN", "raw_content_explicitly_enabled"
    elif protected:
        status, reason = "PROTECTED_METADATA_ONLY", "fabric_managed_projection"
    else:
        status, reason = "NO_EXPORTER", "no_export_routes_configured"
    return {
        "status": status,
        "reason": reason,
        "basis": "current_process",
        "protected_routes": protected,
        "content_opt_in_routes": opt_in,
        "unprotected_host_routes": host_owned,
        "counts": counts,
    }


def has_protected_route(provider: object) -> bool:
    """Whether ``provider`` has a Fabric-managed projection route (the metadata-only
    projection of :func:`install_default_provider`, content opt-in included).

    Capture records (wire exchange spans, loss and heartbeat markers) must never travel
    such a route: the projection renames them and hashes or drops their identifiers. A
    provider that cannot be inspected has no Fabric-managed route."""
    processor = getattr(provider, "_active_span_processor", None)
    processors = getattr(processor, "_span_processors", None)
    if not isinstance(processors, tuple):
        return False
    return any(
        isinstance(getattr(item, "span_exporter", None), MetadataOnlySpanExporter)
        for item in processors
    )


def otlp_endpoint_configured() -> bool:
    """Whether the standard env names an OTLP traces endpoint."""
    names = ("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT")
    return any(os.environ.get(name) for name in names)


_OTLP_COMPRESSIONS = frozenset({"gzip", "deflate", "none"})


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
    """Resolve ``OTEL_EXPORTER_OTLP_<SIGNAL>_*`` > ``OTEL_EXPORTER_OTLP_*`` (048 §3);
    ``ValueError`` naming only the variable for an endpoint with userinfo, query or fragment
    (047 E8), malformed headers, an unreadable TLS file, a lone key/cert or a bad timeout."""

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
        if not _headers_well_formed(raw[1]):
            raise ValueError(f"{raw[0]} must be k=v pairs separated by commas")
        for item in filter(None, re.split(r"[ \t]*,[ \t]*", raw[1])):
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
    # Validated here, not left to the exporter: some OTel releases reject a bad value while
    # newer ones log it and fall back to no compression.
    compression = pick("COMPRESSION")
    if compression is not None and compression[1].lower() not in _OTLP_COMPRESSIONS:
        raise ValueError(f"{compression[0]} must be gzip, deflate or none")
    path = {k: v[1] if v else None for k, v in files.items()}
    return OtlpSettings(
        endpoint[1] if endpoint else None, headers, path["CERTIFICATE"],
        path["CLIENT_CERTIFICATE"], path["CLIENT_KEY"], timeout_s,
        (pick("PROTOCOL") or ("", "http/protobuf"))[1],
    )  # fmt: skip


def check_endpoint_url(name: str, value: str) -> None:
    """Reject a URL with userinfo, a query or a fragment; the error never echoes it (047 E8)."""
    try:
        parts = urlsplit(value.strip())
        _ = parts.port  # an invalid port raises here, not later inside the exporter
    except ValueError:
        raise ValueError(f"{name} is not a valid URL") from None
    if "@" in parts.netloc or parts.query or parts.fragment or "?" in value or "#" in value:
        raise ValueError(f"{name} must not carry credentials, a query or a fragment")


_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def check_content_endpoint_url(name: str, value: str) -> None:
    """:func:`check_endpoint_url`, plus the content transport rule shared with metadata
    delivery: verified HTTPS, or plain HTTP only to a loopback host (content bytes never
    cross a network unencrypted). The error never echoes the URL."""
    check_endpoint_url(name, value)
    parts = urlsplit(value.strip())
    scheme, host = parts.scheme.lower(), (parts.hostname or "")
    if (
        not host
        or scheme not in ("http", "https")
        or (scheme == "http" and host not in _LOOPBACK_HOSTS)
    ):
        raise ValueError(f"{name} requires verified HTTPS or loopback HTTP")


def _read_tls_file(name: str, path: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError:
        raise ValueError(f"the file named by {name} is not readable") from None


def _refuse_redirect(response: Any, *args: Any, **kwargs: Any) -> Any:
    """Response hook: any 3xx is a delivery failure, raised before requests could follow it
    (no body or header is ever re-sent elsewhere). Fixed text: no URL or location."""
    if 300 <= int(getattr(response, "status_code", 0)) < 400:  # noqa: PLR2004
        # requests ships inline types only from 2.34; older releases need the ignore.
        import requests  # type: ignore[import-untyped, unused-ignore]  # noqa: PLC0415

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


def exporter_session(exporter: object) -> Any:
    """The ``requests`` session an OTLP/HTTP span exporter delivers through, or ``None``.

    Older ``opentelemetry-exporter-otlp-proto-http`` releases keep it on the exporter
    (``_session``); newer ones keep it on a pluggable transport
    (``_client._transport._session``). The ``>=1.41`` floor admits both layouts."""
    session = getattr(exporter, "_session", None)
    if session is None:
        transport = getattr(getattr(exporter, "_client", None), "_transport", None)
        session = getattr(transport, "_session", None)
    return session


def _harden_exporter_session(exporter: object) -> None:
    """Make the OTLP/HTTP exporter's ``requests`` session refuse redirects (H1); a session
    that cannot be found fails construction rather than delivering with redirects on."""
    session = exporter_session(exporter)
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
    """The capture-path span exporter (spec 048 §8): the OTLP exporter the env selects
    (047 D3), every export, flush and shutdown under sanitized diagnostics, exceptions as
    ``FAILURE``. ``ValueError`` (fixed text) when none can be built."""
    exporter = _otlp_exporter()
    if exporter is None:
        raise ValueError("Fabric capture needs an OTLP traces endpoint")
    return guarded_exporter(exporter)


def is_private_provider(provider: object) -> bool:
    """Whether ``provider`` was built by :func:`build_private_provider` (Fabric shuts it down)."""
    return isinstance(provider, TracerProvider) and provider in _PRIVATE_PROVIDERS


def build_private_provider(
    *, exporter: SpanExporter | None = None, service_name: str | None = None
) -> TracerProvider:
    """A :class:`TracerProvider` for Fabric's direct capture path, never installed globally.

    The exporter is ``exporter``, else the OTLP exporter of
    :func:`build_capture_span_exporter` when an OTLP endpoint is set (otherwise none, with
    a WARN); either is guarded (sanitized diagnostics, exceptions as ``FAILURE``). The
    resource is only ``service.name`` (``service_name``, else :func:`capture_service_name`:
    pseudonymous by default); sampling is ``ALWAYS_ON``. Spans a failed or evicted export loses
    stay sequence gaps the verifier reports (spec 047 §6); the spool (spec 048) closes
    them. No exit handler of its own: ``fabric.wire`` shuts it down within its budget.
    """
    resolved = exporter if exporter is not None else _otlp_exporter()
    provider = TracerProvider(
        sampler=ALWAYS_ON,
        resource=Resource({"service.name": service_name or capture_service_name()}),
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


def capture_service_name(
    environ: Mapping[str, str] | None = None, *, id_key: bytes | None = None,
    clear: bool | None = None,
) -> str:  # fmt: skip
    """The capture ``service.name``: ``OTEL_SERVICE_NAME`` when it is a safe name, else
    ``fabric-wire`` (047 D3), exported as ``svc-`` + 32 hex of HMAC-SHA256(``id_key``, name)
    (SHA-256 without a key) unless ``clear`` (J1). ``id_key``/``clear`` default to
    ``FABRIC_WIRE_ID_KEY`` and ``FABRIC_WIRE_LABELS=clear``."""
    env = os.environ if environ is None else environ
    name = env.get("OTEL_SERVICE_NAME", "")
    name = name if _SERVICE_NAME_RE.fullmatch(name) else "fabric-wire"
    if clear if clear is not None else (env.get(LABELS_ENV) or "").strip() == "clear":
        return name
    return label_pseudonym("svc-", name, id_key if id_key is not None else id_key_from_env(env))
