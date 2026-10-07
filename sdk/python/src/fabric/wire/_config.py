# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Wire-capture configuration and environment parsing (spec 042 §2-§3)."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote, urlsplit

from .._sequence import OPAQUE_ID_RE
from ._model import EndpointMatcher

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import TracerProvider

    from ..content_store.base import ByteEvidenceStore

__all__ = [
    "DEFAULT_ENDPOINTS",
    "MAX_BODY_BYTES_CAP",
    "WireConfig",
    "config_from_env",
    "parse_endpoints",
    "validate_endpoint",
]

ENDPOINT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
PROVIDER_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.:\[\]_-]{1,253}$")
MAX_BODY_BYTES_CAP = 64 * 1024 * 1024
_QUEUE_CAP = 65536
_SHUTDOWN_CAP_S = 300

DEFAULT_ENDPOINTS: tuple[EndpointMatcher, ...] = (
    EndpointMatcher(
        endpoint_id="openai",
        dialect="openai",
        hosts=frozenset({"api.openai.com"}),
        provider_name="openai",
    ),
    EndpointMatcher(
        endpoint_id="anthropic",
        dialect="anthropic",
        hosts=frozenset({"api.anthropic.com"}),
        provider_name="anthropic",
    ),
    EndpointMatcher(
        endpoint_id="azure-openai",
        dialect="openai",
        host_suffixes=frozenset({".openai.azure.com"}),
        provider_name="azure.ai.openai",
    ),
)


def _bounded_int(name: str, value: Any, low: int, high: int | None = None) -> None:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < low
        or (high is not None and value > high)
    ):
        bound = f"between {low} and {high}" if high is not None else f">= {low}"
        raise ValueError(f"{name} must be an integer {bound}")


def validate_endpoint(matcher: EndpointMatcher) -> None:
    """Raise ``ValueError`` when ``matcher`` is not a usable endpoint."""
    if not isinstance(matcher, EndpointMatcher):
        raise ValueError("endpoints must be EndpointMatcher values")
    if not isinstance(matcher.endpoint_id, str) or not ENDPOINT_ID_RE.match(matcher.endpoint_id):
        raise ValueError("endpoint_id must match ^[a-z0-9][a-z0-9._-]{0,63}$")
    if matcher.dialect not in ("openai", "anthropic"):
        raise ValueError("dialect must be 'openai' or 'anthropic'")
    if not isinstance(matcher.provider_name, str) or not PROVIDER_NAME_RE.match(
        matcher.provider_name
    ):
        raise ValueError("provider_name must match ^[a-z0-9][a-z0-9._-]{0,63}$")
    if not matcher.hosts and not matcher.host_suffixes:
        raise ValueError("an endpoint needs at least one host or host suffix")
    for host in (*matcher.hosts, *matcher.host_suffixes):
        if not isinstance(host, str) or not _HOST_RE.match(host):
            raise ValueError("hosts and host_suffixes must be host names")
    if not matcher.schemes or not set(matcher.schemes) <= {"http", "https"}:
        raise ValueError("schemes must be a non-empty subset of {'http', 'https'}")
    if matcher.ports is not None:
        for port in matcher.ports:
            _bounded_int("ports", port, 1, 65535)
    if not isinstance(matcher.path_prefix, str) or (
        matcher.path_prefix and not matcher.path_prefix.startswith("/")
    ):
        raise ValueError("path_prefix must be empty or start with '/'")


@dataclass(frozen=True, slots=True)
class WireConfig:
    """Configuration of the in-process wire tee.

    ``store`` is the customer-controlled content-v2 byte store; ``None``
    runs metadata-only (digests and spans, no stored bodies).
    """

    store: ByteEvidenceStore | None = None
    endpoints: tuple[EndpointMatcher, ...] = DEFAULT_ENDPOINTS
    extra_endpoints: tuple[EndpointMatcher, ...] = ()
    tracer_provider: TracerProvider | None = None
    source_id: str | None = None
    max_body_bytes: int = 8 * 1024 * 1024
    max_inflight_bytes: int = 256 * 1024 * 1024
    queue_max_items: int = 256
    store_retry_attempts: int = 3
    otlp_message_hashes: bool = True
    patch_httpx: bool = True
    shutdown_timeout_s: float = 2.0

    def __post_init__(self) -> None:
        _bounded_int("max_body_bytes", self.max_body_bytes, 1, MAX_BODY_BYTES_CAP)
        _bounded_int("max_inflight_bytes", self.max_inflight_bytes, 1)
        _bounded_int("queue_max_items", self.queue_max_items, 1, _QUEUE_CAP)
        _bounded_int("store_retry_attempts", self.store_retry_attempts, 1, 10)
        if (
            not isinstance(self.shutdown_timeout_s, (int, float))
            or isinstance(self.shutdown_timeout_s, bool)
            or not 0 <= self.shutdown_timeout_s <= _SHUTDOWN_CAP_S
        ):
            raise ValueError("shutdown_timeout_s must be between 0 and 300 seconds")
        for flag in ("otlp_message_hashes", "patch_httpx"):
            if not isinstance(getattr(self, flag), bool):
                raise ValueError(f"{flag} must be a bool")
        if self.source_id is not None and (
            not isinstance(self.source_id, str) or not OPAQUE_ID_RE.match(self.source_id)
        ):
            raise ValueError("source_id must match ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
        if not isinstance(self.endpoints, tuple) or not isinstance(self.extra_endpoints, tuple):
            raise ValueError("endpoints and extra_endpoints must be tuples")
        seen: set[str] = set()
        for matcher in (*self.endpoints, *self.extra_endpoints):
            validate_endpoint(matcher)
            if matcher.endpoint_id in seen:
                raise ValueError(f"duplicate endpoint_id {matcher.endpoint_id!r}")
            seen.add(matcher.endpoint_id)
        if self.store is not None:
            for attribute in ("tenant_id", "evidence_ref_for", "put_bytes_object"):
                if not hasattr(self.store, attribute):
                    raise ValueError("store must implement ByteEvidenceStore")
            tenant = self.store.tenant_id
            if not isinstance(tenant, str) or not OPAQUE_ID_RE.match(tenant):
                raise ValueError("store must be tenant-scoped (tenant_id set)")

    @property
    def all_endpoints(self) -> tuple[EndpointMatcher, ...]:
        """Configured endpoints followed by extras."""
        return self.endpoints + self.extra_endpoints


def _string_set(value: Any, name: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"{name} must be a list of strings")
    return frozenset(value)


def parse_endpoints(text: str) -> tuple[EndpointMatcher, ...]:
    """Parse ``FABRIC_WIRE_ENDPOINTS`` (a JSON array of matcher objects)."""
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise ValueError("FABRIC_WIRE_ENDPOINTS is not valid JSON") from exc
    if not isinstance(raw, list):
        raise ValueError("FABRIC_WIRE_ENDPOINTS must be a JSON array")
    allowed = {
        "endpoint_id",
        "dialect",
        "hosts",
        "host_suffixes",
        "ports",
        "path_prefix",
        "provider_name",
        "schemes",
    }
    matchers: list[EndpointMatcher] = []
    for entry in raw:
        if not isinstance(entry, dict) or set(entry) - allowed:
            raise ValueError("FABRIC_WIRE_ENDPOINTS entries must be matcher objects")
        ports = entry.get("ports")
        if ports is not None and (
            not isinstance(ports, list)
            or not all(isinstance(p, int) and not isinstance(p, bool) for p in ports)
        ):
            raise ValueError("ports must be a list of integers")
        schemes = _string_set(entry.get("schemes"), "schemes") or frozenset({"https"})
        matcher = EndpointMatcher(
            endpoint_id=entry.get("endpoint_id"),  # type: ignore[arg-type]
            dialect=entry.get("dialect"),  # type: ignore[arg-type]
            hosts=_string_set(entry.get("hosts"), "hosts"),
            host_suffixes=_string_set(entry.get("host_suffixes"), "host_suffixes"),
            ports=frozenset(ports) if ports is not None else None,
            path_prefix=entry.get("path_prefix", ""),
            provider_name=entry.get("provider_name", "openai"),
            schemes=schemes,
        )
        validate_endpoint(matcher)
        matchers.append(matcher)
    return tuple(matchers)


def _env_int(environ: Mapping[str, str], name: str) -> int | None:
    value = environ.get(name)
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _env_bool(environ: Mapping[str, str], name: str, default: bool) -> bool:
    value = environ.get(name)
    if value is None or value == "":
        return default
    lowered = value.strip().lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"{name} must be a boolean")


def build_store(uri: str, tenant_id: str | None) -> ByteEvidenceStore:
    """Build the byte store named by ``FABRIC_WIRE_STORE``."""
    if not tenant_id:
        raise ValueError("FABRIC_WIRE_STORE requires FABRIC_TENANT_ID")
    parsed = urlsplit(uri)
    if parsed.scheme == "file":
        if parsed.netloc not in ("", "localhost") or parsed.query or parsed.fragment:
            raise ValueError("FABRIC_WIRE_STORE file URI must be file:///absolute/dir")
        path = unquote(parsed.path)
        if not path.startswith("/"):
            raise ValueError("FABRIC_WIRE_STORE file URI must be absolute")
        from ..content_store.local import LocalFilesystemContentStore  # noqa: PLC0415

        return LocalFilesystemContentStore(root=path, tenant_id=tenant_id)
    if parsed.scheme == "s3":
        if not parsed.netloc or parsed.query or parsed.fragment or "@" in parsed.netloc:
            raise ValueError("FABRIC_WIRE_STORE s3 URI must be s3://bucket/prefix")
        from ..content_store.s3 import S3ContentStore  # noqa: PLC0415

        prefix = parsed.path.lstrip("/")
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        if prefix:
            return S3ContentStore(bucket=parsed.netloc, prefix=prefix, tenant_id=tenant_id)
        return S3ContentStore(bucket=parsed.netloc, tenant_id=tenant_id)
    raise ValueError("FABRIC_WIRE_STORE must be a file:// or s3:// URI")


def config_from_env(environ: Mapping[str, str]) -> tuple[WireConfig, str]:
    """Build a :class:`WireConfig` from environment variables.

    Returns the config (without a tracer provider) and the requested tracer
    mode (``private`` or ``global``). Raises ``ValueError`` on any invalid
    value; the caller logs one warning and installs nothing.
    """
    tenant_id = environ.get("FABRIC_TENANT_ID") or None
    store_uri = environ.get("FABRIC_WIRE_STORE") or None
    store = build_store(store_uri, tenant_id) if store_uri else None
    tracer_mode = (environ.get("FABRIC_WIRE_TRACER") or "private").strip().lower()
    if tracer_mode not in ("private", "global"):
        raise ValueError("FABRIC_WIRE_TRACER must be 'private' or 'global'")
    source_id = environ.get("FABRIC_SOURCE_ID") or None
    run_id = environ.get("FABRIC_RUN_ID")
    if run_id and not OPAQUE_ID_RE.match(run_id):
        raise ValueError("FABRIC_RUN_ID must match ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    kwargs: dict[str, Any] = {"store": store, "source_id": source_id}
    endpoints = environ.get("FABRIC_WIRE_ENDPOINTS")
    if endpoints:
        kwargs["extra_endpoints"] = parse_endpoints(endpoints)
    for env_name, field_name in (
        ("FABRIC_WIRE_MAX_BODY_BYTES", "max_body_bytes"),
        ("FABRIC_WIRE_QUEUE_MAX_ITEMS", "queue_max_items"),
    ):
        number = _env_int(environ, env_name)
        if number is not None:
            kwargs[field_name] = number
    kwargs["otlp_message_hashes"] = _env_bool(environ, "FABRIC_WIRE_OTLP_MESSAGE_HASHES", True)
    return WireConfig(**kwargs), tracer_mode
