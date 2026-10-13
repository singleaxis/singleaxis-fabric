# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Wire-capture configuration and environment parsing (spec 042 §2-§3, 043 §1)."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, cast
from urllib.parse import unquote, urlsplit

from .._model_names import parse_model_allowlist
from .._sequence import OPAQUE_ID_RE, Labels, check_id_key, id_key_from_env, labels_from_env
from ..content_store.s3 import S3ContentStore  # boto3 stays lazy
from ..tracing import check_endpoint_url
from ._model import EndpointMatcher

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import TracerProvider

    from ..content_store.base import ByteEvidenceStore

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.:\[\]_-]{1,253}$")
_MATCHER_KEYS = frozenset(EndpointMatcher.__dataclass_fields__)
_SET_KEYS = ("hosts", "host_suffixes", "schemes", "ports")
_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
MAX_BODY_BYTES_CAP, NODE_MAX_BODY_BYTES = 64 * 1024 * 1024, 63 * 1024 * 1024
SPOOL_RESERVE_BYTES = 1024 * 1024

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
    tenant_id: str | None = None
    content_endpoint: str | None = None  # node mode: bodies go to the Fabric Node (spec 043)
    spool_dir: str | None = None
    spool_max_bytes: int = 1 << 30
    model_allowlist: tuple[str, ...] = ()
    # Run-id pseudonym key (H3; FABRIC_WIRE_ID_KEY): a secret, so never in repr or logs.
    id_key: bytes | None = field(default=None, repr=False)
    # J1: source id and service.name pseudonymous (default) or "clear" (FABRIC_WIRE_LABELS);
    # None = from the environment at install.
    labels: Labels | None = None

    def __post_init__(self) -> None:
        _int("max_body_bytes", self.max_body_bytes, 1, MAX_BODY_BYTES_CAP)
        check_id_key(self.id_key)
        if self.labels not in (None, "pseudonymous", "clear"):
            raise ValueError("labels must be 'pseudonymous' or 'clear'")
        self._check_delivery()
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

    def _check_delivery(self) -> None:
        """Spec 043 §1: node mode, spool and model-allowlist rules; never echoes a value."""
        if isinstance(self.store, S3ContentStore):
            raise ValueError("s3 content is written by the Fabric Node (spec 043)")
        if self.tenant_id is not None and not _TENANT_RE.fullmatch(str(self.tenant_id)):
            raise ValueError("tenant_id must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
        if parse_model_allowlist(",".join(self.model_allowlist)) != tuple(self.model_allowlist):
            raise ValueError("model_allowlist entries must be stripped names or prefix*")
        if self.spool_dir is not None:
            if not isinstance(self.spool_dir, str) or not self.spool_dir.startswith("/"):
                raise ValueError("spool_dir must be an absolute directory")
            if self.tracer_provider is not None:
                raise ValueError("spool delivery uses Fabric's exporter, not a tracer provider")
            low = 2 * self.max_body_bytes + SPOOL_RESERVE_BYTES
            _int("spool_max_bytes", self.spool_max_bytes, low)
        if self.content_endpoint is None:
            return
        check_endpoint_url("FABRIC_WIRE_CONTENT_ENDPOINT", str(self.content_endpoint))
        if self.store is not None or not self.tenant_id or self.spool_dir is None:
            raise ValueError("node mode needs FABRIC_TENANT_ID, FABRIC_WIRE_SPOOL_DIR, no store")
        _int("max_body_bytes", self.max_body_bytes, 1, NODE_MAX_BODY_BYTES)

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


def build_store(uri: str, tenant_id: str | None) -> ByteEvidenceStore:
    """The direct local store named by ``file:///abs/dir`` (spec 043 F1: no ``s3://``)."""
    if uri.startswith("s3:"):
        raise ValueError("s3 content is written by the Fabric Node (spec 043)")
    parsed, path = urlsplit(uri), unquote(urlsplit(uri).path)
    if parsed.scheme != "file" or parsed.netloc not in ("", "localhost") or parsed.query or (
            parsed.fragment or not path.startswith("/") or not tenant_id):  # fmt: skip
        raise ValueError("FABRIC_WIRE_STORE must be 'node' or file:///absolute/dir (+ tenant)")
    from ..content_store.local import LocalFilesystemContentStore  # noqa: PLC0415

    return LocalFilesystemContentStore(root=path, tenant_id=tenant_id)


def config_from_env(
    environ: Mapping[str, str],
) -> tuple[WireConfig, Literal["private", "global"]]:
    """Build a config (without tracer provider) and the tracer mode; ``ValueError`` if invalid."""
    tracer_mode = (environ.get("FABRIC_WIRE_TRACER") or "private").strip().lower()
    if tracer_mode not in ("private", "global"):
        raise ValueError("FABRIC_WIRE_TRACER must be 'private' or 'global'")
    if environ.get("FABRIC_WIRE_STORE_SSE") or environ.get("FABRIC_WIRE_STORE_KMS_KEY_ID"):
        raise ValueError("encryption is configured on the Fabric Node")
    store_uri = (environ.get("FABRIC_WIRE_STORE") or "").strip()
    endpoint = (environ.get("FABRIC_WIRE_CONTENT_ENDPOINT") or "").strip() or None
    tenant = environ.get("FABRIC_TENANT_ID") or None
    node = store_uri == "node" or (not store_uri and endpoint is not None)
    if node and endpoint is None:
        raise ValueError("node mode needs FABRIC_WIRE_CONTENT_ENDPOINT")
    if (node or environ.get("FABRIC_WIRE_SPOOL_DIR")) and tracer_mode != "private":
        raise ValueError("node mode and the spool need FABRIC_WIRE_TRACER=private")
    if store_uri and not node and endpoint is not None:
        raise ValueError("FABRIC_WIRE_CONTENT_ENDPOINT is for node mode only")
    kwargs: dict[str, Any] = {
        "store": build_store(store_uri, tenant) if store_uri and not node else None,
        "source_id": environ.get("FABRIC_SOURCE_ID") or None, "tenant_id": tenant,
        "content_endpoint": endpoint if node else None,
        "spool_dir": environ.get("FABRIC_WIRE_SPOOL_DIR") or None,
        "model_allowlist": parse_model_allowlist(environ.get("FABRIC_WIRE_MODEL_ALLOWLIST")),
        "id_key": id_key_from_env(environ), "labels": labels_from_env(environ),
    }  # fmt: skip
    if environ.get("FABRIC_WIRE_ENDPOINTS"):
        kwargs["extra_endpoints"] = parse_endpoints(environ["FABRIC_WIRE_ENDPOINTS"])
    for name in ("MAX_BODY_BYTES", "QUEUE_MAX_ITEMS", "SPOOL_MAX_BYTES"):
        if value := environ.get(f"FABRIC_WIRE_{name}"):
            try:
                kwargs[name.lower()] = int(value)
            except ValueError:
                raise ValueError(f"FABRIC_WIRE_{name} must be an integer") from None
    return WireConfig(**kwargs), cast(Literal["private", "global"], tracer_mode)
