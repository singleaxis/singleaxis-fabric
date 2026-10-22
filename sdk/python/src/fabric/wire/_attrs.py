# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Wire exchange enrichment (spec 050 §3.9): the P1 keys merged into every exchange span by
:func:`fabric.wire._pipeline.exchange_attributes`.

Everything a key needs is fixed either per install (:class:`WireEnrichment`: the capture
point versions, the emitted endpoint ids, the X05 identity block, the C40 opt-in and key) or
per exchange on the host thread at no more than a field store each (:class:`WireJob`: the
event id minted at allocation, the segment of the allocation, the first-chunk offset, the
one provider request id header value when opted in). :func:`p1_attributes` builds the keys
on the capture worker, so the only per-exchange hashing (C40) never runs on the host's
thread.

Only ids, enums and labels are emitted, never content or a hostname. Every value is checked
against the Node's admission check for the exchange class before it is emitted
(``contracts/coverage/v1/registry/telemetry-keys-v1.json``): a value the Node would strip
would break seal parity (050 §3.14, T3), so it is omitted instead.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from .._capture_types import SEGMENT_ID_RE, UUID4_RE
from .._sequence import label_pseudonym, operator_label, pseudonym_v2
from ._model import CaptureJob

if TYPE_CHECKING:
    from opentelemetry.util.types import AttributeValue

    from ._config import WireConfig
    from ._model import EndpointMatcher, ResponseState

_LOG = logging.getLogger("fabric.wire")

CAPTURE_INPUT = "wire"
CAPTURE_SOURCE = "observed"
ACTOR_TYPE = "agent"  # S03: the SDK stamps ``agent`` on every step it emits
PROVIDER_REQUEST_ID_ENV = "FABRIC_WIRE_PROVIDER_REQUEST_ID"  # C40 opt-in, default off
POINT_HTTPX, POINT_AIOHTTP = "wire.py.httpx", "wire.py.aiohttp"
# C40: the one response header Fabric may read, per dialect (OpenAI and Azure OpenAI use
# ``x-request-id``, Anthropic ``request-id``). Never the header block.
PROVIDER_REQUEST_ID_HEADERS: Mapping[str, str] = MappingProxyType({
    "openai": "x-request-id", "anthropic": "request-id",
})  # fmt: skip
MAX_PROVIDER_REQUEST_ID_CHARS = 256  # a longer value is not a request id: not kept
# X05 (049 §2.9; 050 §3.9): the deployment identity block, from the environment, emitted on
# capture spans as operator labels (``lbl-`` + 32 hex; clear under FABRIC_WIRE_LABELS=clear).
# ``workload_id`` has no telemetry key placed on exchanges, so it is not emitted.
IDENTITY_ENV: Mapping[str, str] = MappingProxyType({
    "fabric.agent_id": "FABRIC_AGENT_ID", "fabric.system_id": "FABRIC_SYSTEM_ID",
    "fabric.deployment_id": "FABRIC_DEPLOYMENT_ID", "fabric.release_id": "FABRIC_RELEASE_ID",
    "fabric.environment": "FABRIC_ENVIRONMENT",
})  # fmt: skip
_TRUTHY = frozenset({"1", "true", "yes", "on"})
_HTTP_OK, _HTTP_REDIRECT, _HTTP_CLIENT_ERROR, _HTTP_END = 200, 300, 400, 600

# The Node's checks of the keys emitted here (telemetry-keys-v1.json, exchange class).
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")  # X05 capture_check
_POINT_RE = re.compile(r"^[a-z][a-z0-9_.]{0,63}@[0-9A-Za-z.+-]{1,32}$")  # X26
_ENDPOINT_RE = re.compile(r"^(?:[a-z][a-z0-9_]{0,31}\.default|lbl-[0-9a-f]{32})$")  # C35
_NOT_NAME_RE = re.compile(r"[^a-z0-9_]")


class P1Attr:
    """The exchange-span keys this module adds (050 §3.9)."""

    EVENT_ID, CAPTURE_INPUT = "fabric.event_id", "fabric.capture.input"
    CAPTURE_POINT, CAPTURE_SOURCE = "fabric.capture.point", "fabric.capture.source"
    SEGMENT_ID, STEP_KIND = "fabric.run.segment_id", "fabric.step.kind"
    ACTOR_TYPE, LIFECYCLE = "fabric.actor.type", "fabric.step.lifecycle_state"
    STEP_STATUS, ERROR_DOMAIN = "fabric.step.status", "fabric.error.domain"
    FIRST_CHUNK = "fabric.wire.first_chunk_offset_ns"
    ENDPOINT_ID = "fabric.wire.endpoint_id"
    PROVIDER_REQUEST_ID = "fabric.wire.provider_request_id"


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in _TRUTHY


def endpoint_label(matcher: EndpointMatcher, *, builtin: bool, key: bytes | None) -> str:
    """C35 as emitted: a built-in endpoint is ``<name>.default`` (not sensitive); a
    configured one ``lbl-`` + the keyed v1 label of its configured name. Never a hostname.

    Under ``FABRIC_WIRE_LABELS=clear`` a configured endpoint still gets its ``lbl-`` label:
    the Node's C35 check admits no clear name, and a value the Node strips breaks seal
    parity (050 §3.14)."""
    if builtin:
        name = _NOT_NAME_RE.sub("_", matcher.endpoint_id.lower()) + ".default"
        if _ENDPOINT_RE.fullmatch(name):
            return name
    return label_pseudonym("lbl-", matcher.endpoint_id, key)


def identity_block(environ: Mapping[str, str], key: bytes | None, *, clear: bool) -> dict[str, str]:
    """X05 from ``FABRIC_*``: each set value as an operator label (``lbl-`` + 32 hex, keyed
    when ``key`` is set), clear only when ``clear``. A value that is not an operator label
    (049 §4.2, validated like ``service.name``) is omitted with one class-only warning that
    names the variable, never the value."""
    block: dict[str, str] = {}
    for attr, name in IDENTITY_ENV.items():
        raw = (environ.get(name) or "").strip()
        if not raw:
            continue
        if not _LABEL_RE.fullmatch(raw):
            _LOG.warning("fabric.wire: %s is not an operator label; not on wire spans", name)
            continue
        block[attr] = operator_label(raw, key, clear=clear)
    return block


def _empty() -> Mapping[str, str]:
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class WireEnrichment:
    """Per-install P1 enrichment, resolved once at install (no I/O on the request path)."""

    points: Mapping[str, str] = field(default_factory=_empty)
    endpoint_ids: Mapping[str, str] = field(default_factory=_empty)
    identity: Mapping[str, str] = field(default_factory=_empty)
    # C40: the id key, set only when the opt-in is on and a key exists (otherwise the value
    # would be omitted, so the header is never read). A secret: never in a repr or log.
    request_id_key: bytes | None = field(default=None, repr=False)

    @property
    def reads_provider_request_id(self) -> bool:
        return self.request_id_key is not None

    @classmethod
    def build(cls, config: WireConfig, environ: Mapping[str, str] | None = None) -> WireEnrichment:
        """From the install's configuration and environment (``os.environ`` by default)."""
        from .._manifest import point_version  # noqa: PLC0415 - _manifest imports fabric.wire
        from ._config import DEFAULT_ENDPOINTS  # noqa: PLC0415 - keeps this module light

        env = os.environ if environ is None else environ
        key, clear = config.id_key, config.labels == "clear"
        points = {}
        for point in (POINT_HTTPX, POINT_AIOHTTP):
            if _POINT_RE.fullmatch(value := f"{point}@{point_version(point)}"):
                points[point] = value
        endpoints = {
            m.endpoint_id: endpoint_label(m, builtin=m in DEFAULT_ENDPOINTS, key=key)
            for m in config.all_endpoints
        }  # fmt: skip
        opted_in = _truthy(env.get(PROVIDER_REQUEST_ID_ENV))
        return cls(
            points=MappingProxyType(points), endpoint_ids=MappingProxyType(endpoints),
            identity=MappingProxyType(identity_block(env, key, clear=clear)),
            request_id_key=key if opted_in else None,
        )  # fmt: skip


@dataclass(frozen=True, slots=True)
class WireJob(CaptureJob):
    """A :class:`CaptureJob` with what P1 adds per exchange (050 §3.9). The tee builds these;
    :func:`p1_attributes` reads every field with a default, so a plain ``CaptureJob`` still
    gets the keys derivable from it alone. (``segment_id`` and ``event_id`` are the names
    WP-12 gives the same fields on ``CaptureJob``; redefining them here is harmless.)"""

    segment_id: str | None = None
    event_id: str | None = None  # uuid4, minted at allocation (WireTee.begin / adopt)
    capture_point: str | None = None  # POINT_HTTPX or POINT_AIOHTTP
    endpoint_id: str | None = None  # the matcher's configured id; mapped on the worker
    first_chunk_offset_ns: int | None = None
    # C40: the one header value, read at response start only when opted in and keyed;
    # mapped to ``p-`` on the worker and never emitted, logged or spooled as is.
    provider_request_id: str | None = field(default=None, repr=False)
    enrichment: WireEnrichment | None = field(default=None, repr=False)


def step_status(state: ResponseState, http_status: int | None) -> str:
    """S08 by the 049 §2.3 legacy mapping: ``complete`` + HTTP 2xx -> ``ok`` (HTTP >= 400
    -> ``error``; any other status, or none, -> ``unknown``); ``error`` -> ``error``;
    ``closed_early`` -> ``cancelled``; ``abandoned`` -> ``unknown``."""
    if state == "complete":
        if http_status is None:
            return "unknown"
        if _HTTP_OK <= http_status < _HTTP_REDIRECT:
            return "ok"
        return "error" if _HTTP_CLIENT_ERROR <= http_status < _HTTP_END else "unknown"
    return {"error": "error", "closed_early": "cancelled"}.get(state, "unknown")


def error_domain(http_status: int | None) -> str:
    """S09 of an ``error`` step: ``provider`` for HTTP >= 400, else ``transport`` (an
    exception with no HTTP status, or one raised while the body was read)."""
    provider = http_status is not None and _HTTP_CLIENT_ERROR <= http_status < _HTTP_END
    return "provider" if provider else "transport"


def p1_attributes(job: CaptureJob) -> dict[str, AttributeValue]:
    """The P1 attributes of ``job``'s exchange span: ids, enums and labels only, never
    content or a hostname; each value passes the Node's exchange-class check or is
    omitted. Runs on the capture worker; never raises (the caller also guards it)."""
    extra: Any = job  # the WireJob fields, read with defaults
    state, http_status = job.response_state, job.http_status_code
    status = step_status(state, http_status)
    attrs: dict[str, AttributeValue] = {
        P1Attr.CAPTURE_INPUT: CAPTURE_INPUT,
        P1Attr.CAPTURE_SOURCE: CAPTURE_SOURCE,
        P1Attr.STEP_KIND: "embedding" if job.api == "openai.embeddings" else "model_call",
        P1Attr.ACTOR_TYPE: ACTOR_TYPE,
        P1Attr.LIFECYCLE: "cancelled" if state == "closed_early" else "completed",
        P1Attr.STEP_STATUS: status,
    }
    if status == "error":
        attrs[P1Attr.ERROR_DOMAIN] = error_domain(http_status)
    event_id = getattr(extra, "event_id", None)
    if isinstance(event_id, str) and UUID4_RE.fullmatch(event_id):
        attrs[P1Attr.EVENT_ID] = event_id
    segment = getattr(extra, "segment_id", None)
    if isinstance(segment, str) and SEGMENT_ID_RE.fullmatch(segment):
        attrs[P1Attr.SEGMENT_ID] = segment
    offset = getattr(extra, "first_chunk_offset_ns", None)
    if type(offset) is int and 0 <= offset < 1 << 63:
        attrs[P1Attr.FIRST_CHUNK] = offset
    enrichment = getattr(extra, "enrichment", None)
    if isinstance(enrichment, WireEnrichment):
        point = enrichment.points.get(getattr(extra, "capture_point", None) or "")
        if point is not None:
            attrs[P1Attr.CAPTURE_POINT] = point
        endpoint = enrichment.endpoint_ids.get(getattr(extra, "endpoint_id", None) or "")
        if endpoint is not None:
            attrs[P1Attr.ENDPOINT_ID] = endpoint
        request_id = getattr(extra, "provider_request_id", None)
        if isinstance(request_id, str) and (
            mapped := pseudonym_v2("p", request_id, enrichment.request_id_key)
        ):  # ``None`` without a key: omitted
            attrs[P1Attr.PROVIDER_REQUEST_ID] = mapped
        attrs.update(enrichment.identity)
    return attrs


def read_provider_request_id(
    enrichment: WireEnrichment | None, dialect: str, headers: Any
) -> str | None:  # fmt: skip
    """C40 at response start: the value of the one named header, or ``None``. Reads nothing
    unless the install opted in with a key; never iterates or copies the header block."""
    if enrichment is None or enrichment.request_id_key is None:
        return None
    name = PROVIDER_REQUEST_ID_HEADERS.get(dialect)
    if name is None:
        return None
    value = headers.get(name)
    if isinstance(value, str) and 0 < len(value) <= MAX_PROVIDER_REQUEST_ID_CHARS:
        return value
    return None


__all__ = [
    "ACTOR_TYPE", "CAPTURE_INPUT", "CAPTURE_SOURCE", "IDENTITY_ENV", "POINT_AIOHTTP",
    "POINT_HTTPX", "PROVIDER_REQUEST_ID_ENV", "PROVIDER_REQUEST_ID_HEADERS", "P1Attr",
    "WireEnrichment", "WireJob", "endpoint_label", "error_domain", "identity_block",
    "p1_attributes", "read_provider_request_id", "step_status",
]  # fmt: skip
