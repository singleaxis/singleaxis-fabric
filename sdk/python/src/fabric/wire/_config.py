# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Wire-capture configuration and environment parsing (spec 042 §2-§3)."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, cast
from urllib.parse import unquote, urlsplit

from .._sequence import OPAQUE_ID_RE
from ._model import EndpointMatcher

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import TracerProvider

    from ..content_store.base import ByteEvidenceStore

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.:\[\]_-]{1,253}$")
_MATCHER_KEYS = frozenset(EndpointMatcher.__dataclass_fields__)
_SET_KEYS = ("hosts", "host_suffixes", "schemes", "ports")
MAX_BODY_BYTES_CAP = 64 * 1024 * 1024

DEFAULT_ENDPOINTS: tuple[EndpointMatcher, ...] = (
    EndpointMatcher("openai", "openai", hosts=frozenset({"api.openai.com"})),
    EndpointMatcher("anthropic", "anthropic", hosts=frozenset({"api.anthropic.com"}),
                    provider_name="anthropic"),
    EndpointMatcher("azure-openai", "openai", host_suffixes=frozenset({".openai.azure.com"}),
                    provider_name="azure.ai.openai"),
)  # fmt: skip


def _int(name: str, value: Any, low: int, high: int = 1 << 62) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{name} must be an integer between {low} and {high}")


def validate_endpoint(matcher: EndpointMatcher) -> None:
    """Raise ``ValueError`` unless ``matcher`` is a usable endpoint (spec 042 §2)."""
    m = matcher
    valid = (
        isinstance(m, EndpointMatcher)
        and all(
            isinstance(v, str) and _NAME_RE.fullmatch(v) for v in (m.endpoint_id, m.provider_name)
        )
        and m.dialect in ("openai", "anthropic")
        and bool(hosts := [*m.hosts, *m.host_suffixes])
        and all(isinstance(h, str) and _HOST_RE.fullmatch(h) for h in hosts)
        and bool(m.schemes)
        and set(m.schemes) <= {"http", "https"}
        and all(type(p) is int and 0 < p < 65536 for p in m.ports or ())  # noqa: PLR2004
        and isinstance(m.path_prefix, str)
        and m.path_prefix[:1] in ("", "/")
    )
    if not valid:
        raise ValueError(f"invalid endpoint matcher {getattr(m, 'endpoint_id', m)!r}")


@dataclass(frozen=True, slots=True)
class WireConfig:
    """In-process tee configuration; ``store=None`` runs metadata-only."""

    store: ByteEvidenceStore | None = None
    endpoints: tuple[EndpointMatcher, ...] = DEFAULT_ENDPOINTS
    extra_endpoints: tuple[EndpointMatcher, ...] = ()
    tracer_provider: TracerProvider | None = None
    source_id: str | None = None
    max_body_bytes: int = 8 * 1024 * 1024
    max_inflight_bytes: int = 256 * 1024 * 1024
    queue_max_items: int = 256
    patch_httpx: bool = True
    shutdown_timeout_s: float = 2.0

    def __post_init__(self) -> None:
        _int("max_body_bytes", self.max_body_bytes, 1, MAX_BODY_BYTES_CAP)
        _int("max_inflight_bytes", self.max_inflight_bytes, 1)
        _int("queue_max_items", self.queue_max_items, 1, 65536)
        timeout = self.shutdown_timeout_s
        if not isinstance(timeout, (int, float)) or not 0 <= timeout <= 300:  # noqa: PLR2004
            raise ValueError("shutdown_timeout_s must be between 0 and 300 seconds")
        if self.source_id is not None and not OPAQUE_ID_RE.fullmatch(str(self.source_id)):
            raise ValueError("source_id must match ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
        for matcher in self.all_endpoints:
            validate_endpoint(matcher)
        if len({m.endpoint_id for m in self.all_endpoints}) != len(self.all_endpoints):
            raise ValueError("endpoint_id values must be unique")

    @property
    def all_endpoints(self) -> tuple[EndpointMatcher, ...]:
        return self.endpoints + self.extra_endpoints


def _frozen(value: Any) -> frozenset[Any]:
    if not isinstance(value, list):
        raise TypeError("expected a JSON array")
    return frozenset(value)


def parse_endpoints(text: str) -> tuple[EndpointMatcher, ...]:
    """Parse ``FABRIC_WIRE_ENDPOINTS`` (a JSON array of matcher objects)."""
    raw = json.loads(text)  # JSONDecodeError is a ValueError
    if not isinstance(raw, list):
        raise ValueError("FABRIC_WIRE_ENDPOINTS must be a JSON array")
    matchers: list[EndpointMatcher] = []
    for entry in raw:
        try:
            if not isinstance(entry, dict) or set(entry) - _MATCHER_KEYS:
                raise TypeError("unknown field")
            fields: dict[str, Any] = {
                k: _frozen(v) if k in _SET_KEYS else v for k, v in entry.items()
            }
            matcher = EndpointMatcher(**{"schemes": frozenset({"https"}), **fields})
        except TypeError as exc:
            raise ValueError("FABRIC_WIRE_ENDPOINTS entries must be matcher objects") from exc
        validate_endpoint(matcher)
        matchers.append(matcher)
    return tuple(matchers)


def build_store(
    uri: str, tenant_id: str | None, *, sse: str | None = None, kms_key_id: str | None = None
) -> ByteEvidenceStore:
    """Build the byte store named by ``file:///abs/dir`` or ``s3://bucket/prefix``.

    ``sse`` (``AES256``/``aws:kms``) and ``kms_key_id`` (``aws:kms`` only) apply to S3.
    """
    if sse not in (None, "AES256", "aws:kms") or (kms_key_id and sse != "aws:kms"):
        raise ValueError("FABRIC_WIRE_STORE_SSE must be AES256 or aws:kms (KMS key: aws:kms)")
    if (sse or kms_key_id) and not uri.startswith("s3://"):
        raise ValueError("FABRIC_WIRE_STORE_SSE applies to s3:// stores only")
    if not tenant_id:
        raise ValueError("FABRIC_WIRE_STORE requires FABRIC_TENANT_ID")
    parsed = urlsplit(uri)
    if parsed.query or parsed.fragment:
        raise ValueError("FABRIC_WIRE_STORE must not carry a query or fragment")
    if parsed.scheme == "file":
        path = unquote(parsed.path)
        if parsed.netloc not in ("", "localhost") or not path.startswith("/"):
            raise ValueError("FABRIC_WIRE_STORE file URI must be file:///absolute/dir")
        from ..content_store.local import LocalFilesystemContentStore  # noqa: PLC0415

        return LocalFilesystemContentStore(root=path, tenant_id=tenant_id)
    if parsed.scheme == "s3":
        if not parsed.netloc or "@" in parsed.netloc:
            raise ValueError("FABRIC_WIRE_STORE s3 URI must be s3://bucket/prefix")
        from ..content_store.s3 import S3ContentStore  # noqa: PLC0415

        prefix = parsed.path.strip("/")
        extra = {"prefix": prefix + "/"} if prefix else {}
        return S3ContentStore(
            bucket=parsed.netloc, tenant_id=tenant_id, sse_algorithm=sse,
            sse_kms_key_id=kms_key_id, **extra,
        )  # fmt: skip
    raise ValueError("FABRIC_WIRE_STORE must be a file:// or s3:// URI")


def config_from_env(
    environ: Mapping[str, str],
) -> tuple[WireConfig, Literal["private", "global"]]:
    """Build a config (without tracer provider) and the tracer mode; ``ValueError`` if invalid."""
    store_uri = environ.get("FABRIC_WIRE_STORE")
    tracer_mode = (environ.get("FABRIC_WIRE_TRACER") or "private").strip().lower()
    if tracer_mode not in ("private", "global"):
        raise ValueError("FABRIC_WIRE_TRACER must be 'private' or 'global'")
    sse = environ.get("FABRIC_WIRE_STORE_SSE") or None
    kms = environ.get("FABRIC_WIRE_STORE_KMS_KEY_ID") or None
    if (sse or kms) and not store_uri:
        raise ValueError("FABRIC_WIRE_STORE_SSE needs an s3:// FABRIC_WIRE_STORE")
    tenant = environ.get("FABRIC_TENANT_ID")
    store = build_store(store_uri, tenant, sse=sse, kms_key_id=kms) if store_uri else None
    kwargs: dict[str, Any] = {"store": store, "source_id": environ.get("FABRIC_SOURCE_ID") or None}
    if environ.get("FABRIC_WIRE_ENDPOINTS"):
        kwargs["extra_endpoints"] = parse_endpoints(environ["FABRIC_WIRE_ENDPOINTS"])
    for name, field in (
        ("MAX_BODY_BYTES", "max_body_bytes"),
        ("QUEUE_MAX_ITEMS", "queue_max_items"),
    ):
        if value := environ.get(f"FABRIC_WIRE_{name}"):
            kwargs[field] = int(value)  # ValueError when not an integer
    return WireConfig(**kwargs), cast(Literal["private", "global"], tracer_mode)
