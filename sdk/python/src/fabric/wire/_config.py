# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Wire-capture configuration and environment parsing (spec 047 §2-§3, 048 §1)."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, cast
from urllib.parse import unquote, urlsplit

from .._model_names import parse_model_allowlist
from .._sequence import OPAQUE_ID_RE, Labels, check_id_key, id_key_from_env, labels_from_env
from ..content_store.s3 import S3ContentStore  # boto3 stays lazy
from ..deployment_policy import DeploymentPolicy
from ..redaction import RedactionService, Transformation
from ..tracing import check_content_endpoint_url
from ._keys import SPOOL_KEY_BYTES, TOKEN_KEY_MIN_BYTES, key_from_env
from ._model import EndpointMatcher
from ._policy import policy_from_env
from ._protect import (
    DEFAULT_MAX_RETAIN_BYTES,
    DEFAULT_PART_MIN_BYTES,
    check_transformations,
)

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
# Default capture-queue entry cap (agent matrix D3: 256 entries overflowed on an asyncio
# fan-out of 408 calls while the host's busy thread starved the capture worker).
QUEUE_MAX_ITEMS = 16384

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
    """Raise ``ValueError`` unless ``matcher`` is a usable endpoint (spec 047 §2)."""
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
    max_body_bytes: int = 32 * 1024 * 1024  # 049 §7.4 (was 8 MiB)
    # Most one side may retain for the worker (049 §7.4); beyond it a side is truncated.
    max_retain_bytes: int = DEFAULT_MAX_RETAIN_BYTES
    part_min_bytes: int = DEFAULT_PART_MIN_BYTES  # smallest inline part worth extracting
    # The capture queue is bounded by bytes: every queued exchange keeps its retained
    # bodies charged to max_inflight_bytes until the worker has written it (past the
    # budget a side is truncated, inflight_budget). queue_max_items only caps the
    # per-entry overhead; a full queue drops with queue_full (049 §7.1 rule 5).
    max_inflight_bytes: int = 256 * 1024 * 1024
    queue_max_items: int = QUEUE_MAX_ITEMS
    patch_httpx: bool = True
    # wire.py.aiohttp (049 §2.8): tee aiohttp client requests too (FABRIC_WIRE_AIOHTTP=0: off).
    patch_aiohttp: bool = True
    shutdown_timeout_s: float = 2.0
    tenant_id: str | None = None
    content_endpoint: str | None = None  # node mode: bodies go to the Fabric Node (spec 048)
    spool_dir: str | None = None
    spool_max_bytes: int = 1 << 30
    # Delivery receipts kept for other writer processes (spec 048 §2), oldest expire first.
    spool_max_receipts: int = 4096
    # Optional provisioned durable boundary for the spool's directory barrier (spec 048
    # §2; FABRIC_WIRE_SPOOL_DURABLE_BOUNDARY): spool_dir or one of its ancestors, treated
    # like a mount point (fsync'd, never its parent).
    spool_durable_boundary: str | None = None
    model_allowlist: tuple[str, ...] = ()
    # Run-id pseudonym key (H3; FABRIC_WIRE_ID_KEY): a secret, so never in repr or logs.
    id_key: bytes | None = field(default=None, repr=False)
    # J1: source id and service.name pseudonymous (default) or "clear" (FABRIC_WIRE_LABELS);
    # None = from the environment at install.
    labels: Labels | None = None
    # 049 §2.7/§7.3: the capture policy (FABRIC_CAPTURE_POLICY, deployment-policy/v1);
    # None = from the environment at install, else fabric.local-default (local profile).
    capture_policy: DeploymentPolicy | None = None
    # 049 §7.7: customer transformations for redact / masked_only / review copies, by role,
    # performed by the customer-run redaction service (contracts/redaction/v1).
    transformations: Mapping[str, Transformation] = field(
        default_factory=lambda: MappingProxyType({}), repr=False
    )
    # The redaction service (FABRIC_REDACTION_ENDPOINT[, _TOKEN_FILE]); None = from the
    # environment at install. Needed when ``transformations`` is set.
    redaction: RedactionService | None = None
    # Tenant-scoped tokenization key (FABRIC_TOKENIZATION_KEY[_FILE]); a secret.
    tokenization_key: bytes | None = field(default=None, repr=False)
    # AES-256-GCM spool envelope key (049 §7.8; FABRIC_WIRE_SPOOL_KEY[_FILE]); a secret.
    spool_key: bytes | None = field(default=None, repr=False)
    # 049 §7.8: seal plaintext records left from before ``spool_key`` was set, in place
    # (FABRIC_WIRE_SPOOL_MIGRATE_PLAINTEXT=1). An explicit opt-in for the local profile;
    # ignored (and logged) in the production profile, where such records are quarantined.
    spool_migrate_plaintext: bool = False

    def __post_init__(self) -> None:
        _int("max_body_bytes", self.max_body_bytes, 1, MAX_BODY_BYTES_CAP)
        _int("max_retain_bytes", self.max_retain_bytes, self.max_body_bytes, MAX_BODY_BYTES_CAP)
        _int("part_min_bytes", self.part_min_bytes, 1, MAX_BODY_BYTES_CAP)
        if not isinstance(self.spool_migrate_plaintext, bool):
            raise ValueError("spool_migrate_plaintext must be a boolean")
        self._check_protection()
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

    def _check_protection(self) -> None:
        """049 §7.3/§7.7/§7.8 settings; fixed text, never a value or a key."""
        policy = self.capture_policy
        if policy is not None and not isinstance(policy, DeploymentPolicy):
            raise ValueError("capture_policy must be a validated DeploymentPolicy")
        if policy is not None and self.tenant_id is not None and (
            policy.tenant_id != self.tenant_id
        ):  # fmt: skip
            raise ValueError("the capture policy belongs to another tenant")
        check_transformations(self.transformations)
        if self.redaction is not None and not isinstance(self.redaction, RedactionService):
            raise ValueError("redaction must be a RedactionService")
        key = self.tokenization_key
        if key is not None and (not isinstance(key, bytes) or len(key) < TOKEN_KEY_MIN_BYTES):
            raise ValueError(f"tokenization_key must be at least {TOKEN_KEY_MIN_BYTES} bytes")
        if self.spool_key is not None and (
            not isinstance(self.spool_key, bytes) or len(self.spool_key) != SPOOL_KEY_BYTES
        ):  # fmt: skip
            raise ValueError(f"spool_key must be exactly {SPOOL_KEY_BYTES} bytes")

    def _check_delivery(self) -> None:
        """Spec 048 §1: node mode, spool and model-allowlist rules; never echoes a value."""
        if isinstance(self.store, S3ContentStore):
            raise ValueError("s3 content is written by the Fabric Node (spec 048)")
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
            _int("spool_max_receipts", self.spool_max_receipts, 1, 1 << 20)
            if (boundary := self.spool_durable_boundary) is not None:
                spool = self.spool_dir.rstrip("/") or "/"
                if (not isinstance(boundary, str) or not boundary.startswith("/")
                        or os.path.normpath(boundary) != boundary
                        or not (spool == boundary
                                or spool.startswith(boundary.rstrip("/") + "/"))):  # fmt: skip
                    raise ValueError("spool_durable_boundary must be spool_dir or an ancestor")
        elif self.spool_durable_boundary is not None:
            raise ValueError("spool_durable_boundary needs spool_dir")
        if self.content_endpoint is None:
            return
        check_content_endpoint_url("FABRIC_WIRE_CONTENT_ENDPOINT", str(self.content_endpoint))
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
    """The direct local store named by ``file:///abs/dir`` (spec 048 F1: no ``s3://``)."""
    if uri.startswith("s3:"):
        raise ValueError("s3 content is written by the Fabric Node (spec 048)")
    parsed, path = urlsplit(uri), unquote(urlsplit(uri).path)
    if parsed.scheme != "file" or parsed.netloc not in ("", "localhost") or parsed.query or (
            parsed.fragment or not path.startswith("/") or not tenant_id):  # fmt: skip
        raise ValueError("FABRIC_WIRE_STORE must be 'node' or file:///absolute/dir (+ tenant)")
    from ..content_store.local import LocalFilesystemContentStore  # noqa: PLC0415

    return LocalFilesystemContentStore(root=path, tenant_id=tenant_id)


MIGRATE_PLAINTEXT_ENV = "FABRIC_WIRE_SPOOL_MIGRATE_PLAINTEXT"
# FABRIC_WIRE_SPOOL_DIR=off: local file mode exports spans directly, without the spool.
SPOOL_OFF = "off"
FILE_SPOOL_DIR = ".fabric-wire-spool"


def aiohttp_from_env(environ: Mapping[str, str]) -> bool:
    """``FABRIC_WIRE_AIOHTTP`` (default on): whether to tee aiohttp client requests."""
    value = (environ.get("FABRIC_WIRE_AIOHTTP") or "1").strip().lower()
    if value not in ("1", "true", "yes", "on", "0", "false", "no", "off"):
        raise ValueError("FABRIC_WIRE_AIOHTTP must be 1 or 0")
    return value in ("1", "true", "yes", "on")


def default_file_spool(
    store_uri: str, tenant: str | None, tracer_mode: str, environ: Mapping[str, str]
) -> str | None:
    """Local file mode's spool (agent matrix D1/D6): ``<store root>/.fabric-wire-spool/
    <tenant>``, so an exchange record is durable once the capture worker has written it
    (fsync'd), whatever happens to the process afterwards, and any later process capturing
    to the same store delivers what an earlier one left. Only where the spool can deliver:
    a private tracer, an OTLP traces endpoint, POSIX ``fcntl``; else ``None`` (the direct
    export path, as before). ``.`` never starts a tenant id, so the store never reads it."""
    if tracer_mode != "private" or not tenant or not _TENANT_RE.fullmatch(tenant):
        return None
    try:
        import fcntl  # noqa: F401, PLC0415
    except ImportError:
        return None
    if not (environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
            or environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")):  # fmt: skip
        return None
    parsed = urlsplit(store_uri)
    root = unquote(parsed.path)
    if parsed.scheme != "file" or not root.startswith("/"):
        return None
    return os.path.join(os.path.normpath(root), FILE_SPOOL_DIR, tenant)


def migrate_plaintext_from_env(environ: Mapping[str, str]) -> bool:
    """The explicit spool migration opt-in (049 §7.8): ``1``/``true``/``yes``/``on``."""
    return (environ.get(MIGRATE_PLAINTEXT_ENV) or "").strip().lower() in ("1", "true", "yes", "on")


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
    spool_dir = environ.get("FABRIC_WIRE_SPOOL_DIR") or None
    if spool_dir is None and store_uri and not node:
        spool_dir = default_file_spool(store_uri, tenant, tracer_mode, environ)
    kwargs: dict[str, Any] = {
        "store": build_store(store_uri, tenant) if store_uri and not node else None,
        "source_id": environ.get("FABRIC_SOURCE_ID") or None, "tenant_id": tenant,
        "content_endpoint": endpoint if node else None,
        "spool_dir": None if spool_dir == SPOOL_OFF else spool_dir,
        "spool_durable_boundary": environ.get("FABRIC_WIRE_SPOOL_DURABLE_BOUNDARY") or None,
        "model_allowlist": parse_model_allowlist(environ.get("FABRIC_WIRE_MODEL_ALLOWLIST")),
        "id_key": id_key_from_env(environ), "labels": labels_from_env(environ),
        "capture_policy": policy_from_env(environ),
        "tokenization_key": key_from_env(environ, "FABRIC_TOKENIZATION_KEY",
                                         minimum=TOKEN_KEY_MIN_BYTES),
        "spool_key": key_from_env(environ, "FABRIC_WIRE_SPOOL_KEY", exact=SPOOL_KEY_BYTES),
        "spool_migrate_plaintext": migrate_plaintext_from_env(environ),
        "redaction": RedactionService.from_env(environ),
    }  # fmt: skip
    kwargs["patch_aiohttp"] = aiohttp_from_env(environ)
    if environ.get("FABRIC_WIRE_ENDPOINTS"):
        kwargs["extra_endpoints"] = parse_endpoints(environ["FABRIC_WIRE_ENDPOINTS"])
    for name in ("MAX_BODY_BYTES", "MAX_RETAIN_BYTES", "PART_MIN_BYTES", "QUEUE_MAX_ITEMS",
                 "SPOOL_MAX_BYTES", "SPOOL_MAX_RECEIPTS"):  # fmt: skip
        if value := environ.get(f"FABRIC_WIRE_{name}"):
            try:
                kwargs[name.lower()] = int(value)
            except ValueError:
                raise ValueError(f"FABRIC_WIRE_{name} must be an integer") from None
    return WireConfig(**kwargs), cast(Literal["private", "global"], tracer_mode)
