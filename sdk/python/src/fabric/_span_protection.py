# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed metadata projection for exporters installed by Fabric.

Never mutate the SDK's source spans: another processor may be owned by the host.
Names, scope metadata, resources and exception text are not trusted merely
because an upstream instrumentor calls them metadata. Content opt-in explicitly
bypasses this projection; it is not a PII detector or credential scrubber.
"""

from __future__ import annotations

import hashlib
import logging
import math
import threading
from collections.abc import Mapping, Sequence
from typing import Any

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.sdk.util.instrumentation import InstrumentationScope
from opentelemetry.trace import Link, SpanContext, SpanKind, Status, StatusCode

_LOG = logging.getLogger("fabric.tracing")
_MAX_STRING_CHARS = 4096
_MAX_ARRAY_ITEMS = 32

# Exact keys, never namespace wildcards. String metadata is hashed unless it
# belongs to the enumerated semantic vocabulary below. This deliberately
# sacrifices readable customer/model/tool identifiers for a raw-content-suppressed
# default. Hashes remain correlatable/guessable.
_STRING_KEYS = frozenset(
    [
        "service.name",
        "service.namespace",
        "service.version",
        "service.instance.id",
        "telemetry.sdk.name",
        "telemetry.sdk.language",
        "telemetry.sdk.version",
        "fabric.sdk.version",
        "deployment.environment",
        "deployment.environment.name",
        "fabric.tenant_id",
        "fabric.system_id",
        "fabric.agent_id",
        "fabric.deployment_id",
        "fabric.environment",
        "fabric.release_id",
        "fabric.execution_id",
        "fabric.decision_id",
        "fabric.request_id",
        "fabric.session_id",
        "fabric.workflow_id",
        "fabric.source_id",
        "fabric.execution.attempt_id",
        "fabric.execution.retry.previous_attempt_id",
        "fabric.step.id",
        "fabric.step.attempt_id",
        "fabric.step.retry.previous_attempt_id",
        "fabric.parent_agent_id",
        "fabric.parent_decision_id",
        "fabric.schema_version",
        "fabric.component.version",
        "fabric.producer.name",
        "fabric.producer.version",
        "fabric.capture.source",
        "fabric.content_mode",
        "fabric.observed_status",
        "fabric.outcome",
        "fabric.source.timestamp",
        "fabric.event_id",
        "fabric.event_type",
        "fabric.event_class",
        "fabric.llm.request.model",
        "fabric.llm.response.model",
        "fabric.llm.response.finish_reasons",
        "fabric.tool.name",
        "fabric.tool.kind",
        "fabric.tool.call.id",
        "fabric.tool.arguments_hash",
        "fabric.tool.result_hash",
        "fabric.tool.error_category",
        "fabric.tool.idempotency_key",
        "fabric.retrieval.source",
        "fabric.retrieval.query_hash",
        "fabric.retrieval.result_hashes",
        "fabric.retrieval.source_document_ids",
        "fabric.retrieval_sources",
        "fabric.checkpoint.checkpoint_id",
        "fabric.checkpoint.state_hash",
        "fabric.checkpoint.step_name",
        "fabric.content.ref",
        "fabric.content.request_ref",
        "fabric.content.result_ref",
        "fabric.content.manifest_ref",
        "fabric.memory.content_hash",
        "fabric.memory.kind",
        "fabric.memory.direction",
        "fabric.memory.source",
        "fabric.memory.tenant_scope",
        "fabric.file.path_hash",
        "fabric.file.content_hash",
        "fabric.file.operation",
        "fabric.interaction.kind",
        "fabric.interaction.metadata_hash",
        "fabric.interaction.payload_hash",
        "fabric.interaction.target_hash",
        "fabric.execution.status",
        "fabric.step.type",
        "fabric.signature.key_id",
        "fabric.signature.scheme",
        "fabric.side_effect.request_hash",
        "fabric.side_effect.result_hash",
        "fabric.side_effect.side_effect_id",
        "fabric.side_effect.type",
        "fabric.side_effect.target_system",
        "fabric.side_effect.idempotency_key",
        "fabric.mcp.server",
        "fabric.mcp.transport",
        "fabric.mcp.tools_hash",
        "fabric.skill.name",
        "fabric.skill.version",
        "fabric.skill.source",
        "fabric.skill.manifest_hash",
        "fabric.hook.phase",
        "fabric.hook.name",
        "fabric.hook.input_hash",
        "fabric.hook.output_hash",
        "fabric.coverage.kind",
        "fabric.coverage.reason",
        "fabric.baseline.name",
        "fabric.baseline.status",
        "fabric.llm.system",
        "gen_ai.system",
        "gen_ai.provider.name",
        "gen_ai.operation.name",
        "gen_ai.request.model",
        "gen_ai.response.model",
        "gen_ai.response.id",
        "gen_ai.response.finish_reasons",
        "gen_ai.tool.name",
        "gen_ai.tool.type",
        "gen_ai.tool.call.id",
        "gen_ai.conversation.id",
        "gen_ai.agent.id",
        "gen_ai.agent.name",
        "gen_ai.agent.version",
        "gen_ai.workflow.name",
        "gen_ai.prompt.name",
        "gen_ai.prompt.version",
        "gen_ai.output.type",
        "gen_ai.request.reasoning.level",
        "gen_ai.request.previous_response.id",
        "gen_ai.request.encoding_formats",
        "gen_ai.data_source.id",
        "error.type",
        "http.request.method",
        "rpc.system",
        "rpc.service",
        "rpc.method",
        "db.system",
        "db.namespace",
        "db.operation.name",
    ]
)
_NUMBER_KEYS = frozenset(
    [
        "gen_ai.request.max_tokens",
        "gen_ai.request.temperature",
        "gen_ai.request.top_p",
        "gen_ai.request.top_k",
        "gen_ai.usage.input_tokens",
        "gen_ai.usage.output_tokens",
        "gen_ai.usage.reasoning.output_tokens",
        "gen_ai.usage.cache_read.input_tokens",
        "gen_ai.usage.cache_creation.input_tokens",
        "gen_ai.usage.cache_read_input_tokens",
        "gen_ai.usage.cache_creation_input_tokens",
        "gen_ai.embeddings.dimension.count",
        "gen_ai.retrieval.top_k",
        "gen_ai.response.time_to_first_chunk",
        "fabric.llm.request.max_tokens",
        "fabric.llm.request.temperature",
        "fabric.llm.request.top_p",
        "fabric.llm.usage.input_tokens",
        "fabric.llm.usage.output_tokens",
        "fabric.llm.usage.cache_creation_tokens",
        "fabric.llm.usage.cache_read_tokens",
        "fabric.llm.retry.count",
        "fabric.llm.streaming.chunk_count",
        "fabric.llm.streaming.ttft_ms",
        "fabric.tool.result_count",
        "fabric.tool.retry.count",
        "fabric.retrieval.result_count",
        "fabric.retrieval.latency_ms",
        "fabric.delegation_count",
        "fabric.checkpoint_count",
        "fabric.mcp.tool_count",
        "fabric.mcp.prompt_count",
        "fabric.mcp.resource_count",
        "fabric.skill_count",
        "fabric.hook_count",
        "fabric.interaction_count",
        "fabric.file_access_count",
        "fabric.memory.ttl_seconds",
        "fabric.memory_erase_count",
        "fabric.file.size_bytes",
        "fabric.execution.attempt",
        "fabric.step.attempt",
        "fabric.source.sequence",
        "fabric.cost_usd",
        "fabric.latency_ms",
        "fabric.input_length",
        "fabric.output_length",
        "fabric.retrieval_count",
        "fabric.memory_read_count",
        "fabric.memory_write_count",
        "fabric.side_effect_count",
        "http.response.status_code",
        "http.status_code",
        "rpc.grpc.status_code",
    ]
)
_BOOL_KEYS = frozenset(
    [
        "gen_ai.request.stream",
        "gen_ai.conversation.compacted",
        "fabric.tool.idempotent",
        "fabric.file.path_redacted",
        "fabric.interaction.target_redacted",
        "fabric.skill.signed",
        "fabric.hook.modified",
        "fabric.signature.verified",
        "fabric.side_effect.committed",
        "fabric.side_effect.approval_required",
        "fabric.side_effect.rollback_supported",
    ]
)
_ENUMS = {
    "gen_ai.operation.name": frozenset(
        {
            "chat",
            "text_completion",
            "generate_content",
            "embeddings",
            "embedding",
            "execute_tool",
            "create_agent",
            "invoke_agent",
            "invoke_workflow",
            "rerank",
        }
    ),
    "gen_ai.provider.name": frozenset(
        {
            "openai",
            "anthropic",
            "aws.bedrock",
            "azure.ai.openai",
            "cohere",
            "gcp.vertex_ai",
            "gcp.gemini",
            "mistral_ai",
            "ollama",
        }
    ),
    "gen_ai.system": frozenset({"openai", "anthropic", "bedrock", "cohere"}),
    "http.request.method": frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}),
    "telemetry.sdk.language": frozenset({"python"}),
}


def _hash(value: str) -> str:
    if len(value) > _MAX_STRING_CHARS:
        raise ValueError("oversize hash input")
    return "sha256:" + hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _number(value: Any) -> bool:
    return (type(value) is int and -(2**63) <= value < 2**63) or (
        type(value) is float and math.isfinite(value)
    )


def _attributes(source: Mapping[str, Any] | None) -> tuple[dict[str, Any], int, int, int]:
    kept: dict[str, Any] = {}
    dropped = hashed = oversized = 0
    for key, value in (source or {}).items():
        if (key in _NUMBER_KEYS and _number(value)) or (key in _BOOL_KEYS and type(value) is bool):
            kept[key] = value
        elif key in _STRING_KEYS and isinstance(value, str):
            if len(value) > _MAX_STRING_CHARS:
                dropped += 1
                oversized += 1
                continue
            if value in _ENUMS.get(key, ()):
                kept[key] = value
            else:
                kept[key] = _hash(value)
                hashed += 1
        elif key in _STRING_KEYS and isinstance(value, (tuple, list)):
            if len(value) > _MAX_ARRAY_ITEMS or any(
                isinstance(item, str) and len(item) > _MAX_STRING_CHARS for item in value
            ):
                dropped += 1
                oversized += 1
            elif all(isinstance(item, str) for item in value):
                kept[key] = tuple(_hash(item) for item in value)
                hashed += 1
            else:
                dropped += 1
        else:
            dropped += 1
    return kept, dropped, hashed, oversized


def _context(source: SpanContext | None) -> SpanContext | None:
    if source is None:
        return None
    if (
        type(source.trace_id) is not int
        or not 0 <= source.trace_id < 2**128
        or type(source.span_id) is not int
        or not 0 <= source.span_id < 2**64
        or type(source.is_remote) is not bool
        or not isinstance(source.trace_flags, int)
        or not 0 <= source.trace_flags < 2**8
    ):
        raise ValueError("invalid span context")
    # Tracestate may contain customer/vendor content. Causal IDs/flags survive.
    return SpanContext(source.trace_id, source.span_id, source.is_remote, source.trace_flags)


def _project(span: ReadableSpan) -> tuple[ReadableSpan, dict[str, int]]:
    if type(span.kind) is not SpanKind or type(span.status.status_code) is not StatusCode:
        raise ValueError("invalid span enum")
    if any(
        value is not None and (type(value) is not int or not 0 <= value < 2**64)
        for value in (span.start_time, span.end_time)
    ):
        raise ValueError("invalid span timestamp")
    attributes, removed, hashed, oversized = _attributes(span.attributes)
    resource, resource_removed, resource_hashed, resource_oversized = _attributes(
        span.resource.attributes
    )
    links = []
    link_removed = link_hashed = link_oversized = 0
    for link in span.links:
        safe, dropped, hashed_count, oversized_count = _attributes(link.attributes)
        link_removed += dropped
        link_hashed += hashed_count
        link_oversized += oversized_count
        context = _context(link.context)
        if context is not None:
            links.append(Link(context, safe))
    counts = {
        "dropped_attributes": removed + resource_removed + link_removed,
        "dropped_oversize_attributes": oversized + resource_oversized + link_oversized,
        "dropped_events": len(span.events),
        "dropped_status_descriptions": int(bool(span.status.description)),
        "hashed_attributes": hashed + resource_hashed + link_hashed,
        "dropped_scope_attributes": len(span.instrumentation_scope.attributes or {})
        if span.instrumentation_scope
        else 0,
        "upstream_dropped_attributes": span.dropped_attributes,
        "upstream_dropped_events": span.dropped_events,
        "upstream_dropped_links": span.dropped_links,
    }
    counts["dropped_oversize_names"] = 0
    if len(span.name) <= _MAX_STRING_CHARS:
        attributes["fabric.protection.span_name_hash"] = _hash(span.name)
    else:
        counts["dropped_oversize_names"] += 1
    scope = span.instrumentation_scope
    if scope:
        if len(scope.name) <= _MAX_STRING_CHARS:
            attributes["fabric.protection.scope_name_hash"] = _hash(scope.name)
        else:
            counts["dropped_oversize_names"] += 1
    attributes.update({f"fabric.protection.{key}": value for key, value in counts.items()})
    attributes["fabric.protection.mode"] = "metadata_only"
    projected = ReadableSpan(
        name="fabric.capture.span",
        context=_context(span.context),
        parent=_context(span.parent),
        resource=Resource(resource),  # Do not run environment resource detectors again.
        attributes=attributes,
        events=(),
        links=links,
        kind=span.kind,
        status=Status(span.status.status_code),
        start_time=span.start_time,
        end_time=span.end_time,
        instrumentation_scope=InstrumentationScope("fabric.protected"),
    )
    return projected, counts


class MetadataOnlySpanExporter(SpanExporter):
    """Protect only this explicitly managed export route, never host exporters."""

    def __init__(self, exporter: SpanExporter, *, capture_content: bool = False) -> None:
        if type(capture_content) is not bool:
            raise ValueError("capture_content must be a boolean")
        self.wrapped_exporter = exporter
        self.capture_content = capture_content
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {"projected_spans": 0, "failed_closed_spans": 0}

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        if self.capture_content:
            return self._export(spans)
        safe = []
        counts: dict[str, int] = {}
        for span in spans:
            try:
                projected, changes = _project(span)
            except Exception:
                # A malformed/custom span cannot cause a raw fallback or leak
                # exception text through diagnostics. Drop just that span.
                counts["failed_closed_spans"] = counts.get("failed_closed_spans", 0) + 1
                _LOG.warning("fabric.tracing: span projection failed; span dropped before export")
                continue
            safe.append(projected)
            counts["projected_spans"] = counts.get("projected_spans", 0) + 1
            for key, value in changes.items():
                counts[key] = counts.get(key, 0) + value
        with self._lock:
            for key, value in counts.items():
                self._counts[key] = self._counts.get(key, 0) + value
        if not safe:
            return SpanExportResult.FAILURE if spans else SpanExportResult.SUCCESS
        result = self._export(tuple(safe))
        return SpanExportResult.FAILURE if counts.get("failed_closed_spans") else result

    def _failure(self, operation: str) -> None:
        with self._lock:
            key = f"{operation}_failures"
            self._counts[key] = self._counts.get(key, 0) + 1
        _LOG.warning("fabric.tracing: managed exporter %s failed", operation)

    def _export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        try:
            result = self.wrapped_exporter.export(spans)
        except Exception:
            self._failure("export")
            return SpanExportResult.FAILURE
        if result is not SpanExportResult.SUCCESS:
            self._failure("export")
            return SpanExportResult.FAILURE
        return result

    def shutdown(self) -> None:
        try:
            self.wrapped_exporter.shutdown()
        except Exception:
            self._failure("shutdown")

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        try:
            return self.wrapped_exporter.force_flush(timeout_millis)
        except Exception:
            self._failure("flush")
            return False
