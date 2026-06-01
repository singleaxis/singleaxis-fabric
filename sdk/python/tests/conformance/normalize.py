# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Normalization of captured spans into stable, comparable dicts.

The goal is a representation that is byte-identical across runs and
machines for a fixed scenario input. We therefore drop or zero the
non-deterministic fields (ids, timestamps, durations, latencies, and
generated UUIDs) while keeping everything that is part of the wire
contract — span name, kind, status, the ``fabric.*`` / ``gen_ai.*``
attribute keys + values, and the ordered list of span events.

Hashes are deterministic for a fixed input and are therefore KEPT:
they are part of the contract a downstream consumer must reproduce.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from opentelemetry.sdk.trace import ReadableSpan
    from opentelemetry.util.types import AttributeValue

# Placeholder substituted for any normalized-away volatile value.
PLACEHOLDER = "<normalized>"

# Attribute keys whose values are generated UUIDs. Stable across the
# contract by key, volatile by value — replace with the placeholder.
_UUID_ATTR_KEYS = frozenset(
    {
        "fabric.decision_id",
        "fabric.checkpoint.checkpoint_id",
        "fabric.eval.eval_id",
        "fabric.policy.evaluation_id",
        "fabric.judge.request_id",
    }
)

# Attribute keys carrying wall-clock-dependent latencies. The key is
# part of the contract; the value is not reproducible.
_LATENCY_ATTR_KEYS = frozenset(
    {
        "fabric.guardrail.latency_ms",
        "fabric.policy.latency_ms",
        "fabric.retrieval.latency_ms",
    }
)


def _normalize_attr_value(value: AttributeValue) -> Any:
    """Convert an OTel attribute value to a JSON-stable form.

    Tuples/lists (OTel sequence attributes) become lists; scalars pass
    through unchanged.
    """
    if isinstance(value, (tuple, list)):
        return [_normalize_attr_value(v) for v in value]
    return value


def normalize_attributes(attributes: Mapping[str, AttributeValue] | None) -> dict[str, Any]:
    """Return a sorted-by-key dict with volatile values placeheld.

    UUID-bearing and latency-bearing keys keep their key (so the
    contract still asserts the key is present) but get the stable
    placeholder value.
    """
    if not attributes:
        return {}
    out: dict[str, Any] = {}
    for key in sorted(attributes):
        if key in _UUID_ATTR_KEYS or key in _LATENCY_ATTR_KEYS:
            out[key] = PLACEHOLDER
        else:
            out[key] = _normalize_attr_value(attributes[key])
    return out


def _normalize_event(event: Any) -> dict[str, Any]:
    """Normalize one span event into ``{name, attributes}``.

    The event timestamp is dropped entirely (ordering is preserved by
    list position, which is the contract-relevant signal).
    """
    return {
        "name": event.name,
        "attributes": normalize_attributes(event.attributes),
    }


def normalize_span(span: ReadableSpan) -> dict[str, Any]:
    """Normalize one span into a stable, comparable dict.

    Dropped: trace_id, span_id, parent id, start/end timestamps,
    duration. Kept (normalized): name, kind, status code + description,
    attributes, ordered ``fabric.*`` / ``gen_ai.*`` events.

    The OTel-internal ``exception`` event (emitted by
    ``span.record_exception`` on fail-closed paths) is dropped: its
    ``exception.stacktrace`` carries machine-dependent file paths and
    line numbers and is not part of the Fabric wire contract.
    """
    status = span.status
    events = [_normalize_event(e) for e in span.events if e.name != "exception"]
    return {
        "name": span.name,
        "kind": span.kind.name,
        "status": {
            "code": status.status_code.name,
            "description": status.description,
        },
        "attributes": normalize_attributes(span.attributes),
        "events": events,
    }


def normalize_spans(spans: Sequence[ReadableSpan]) -> list[dict[str, Any]]:
    """Normalize a captured span list, ordering deterministically.

    Spans are emitted in finish order, which for a single decision is
    children-before-parent. To make the golden independent of timing we
    sort: child spans (``fabric.llm_call`` / ``fabric.tool_call``)
    first by name, then the parent ``fabric.decision``. Within a
    scenario each span name is unique, so name ordering is total.
    """
    normalized = [normalize_span(s) for s in spans]
    normalized.sort(key=lambda s: s["name"])
    return normalized
