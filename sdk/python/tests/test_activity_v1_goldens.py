# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Reproduce the activity v1 goldens whose example values were neutralized in v0.9.

The full conformance suite that ran every activity v1 scenario was retired with
the passive-capture release qualification. The ``hook`` and
``interaction_tagged`` goldens were re-valued (neutral hook name and tags), so
this test proves the current SDK still emits them byte for byte after the same
normalization the retired suite used. ``sdk/typescript/test/activity-v1-goldens.test.ts``
is the TypeScript twin.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from fabric import Baseline, BaselineCheck, Fabric, FabricConfig, SignatureCheck
from fabric.decision import Decision, reset_coverage_registry

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import ReadableSpan
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

CONTRACT_DIR = Path(__file__).resolve().parents[3] / "contracts" / "activity" / "v1"
PLACEHOLDER = "<normalized>"
# Keys whose values are minted per run; the retired normalizer kept the key and
# replaced the value. Only the ones these scenarios can emit are listed.
_VOLATILE_KEYS = frozenset({"fabric.decision_id"})
# Standard gen_ai.* keys follow the separately versioned OpenTelemetry schema;
# activity v1 pins only these (the retired normalizer's allowlist).
_V1_GEN_AI_KEYS = frozenset(
    {
        "gen_ai.system",
        "gen_ai.request.model",
        "gen_ai.request.temperature",
        "gen_ai.request.top_p",
        "gen_ai.request.max_tokens",
        "gen_ai.response.model",
        "gen_ai.response.finish_reasons",
        "gen_ai.usage.input_tokens",
        "gen_ai.usage.output_tokens",
        "gen_ai.usage.cache_creation_input_tokens",
        "gen_ai.usage.cache_read_input_tokens",
        "gen_ai.tool.name",
        "gen_ai.tool.call.id",
    }
)
_SIG_SECRET = "conformance-shared-secret"  # noqa: S105 - a test HMAC secret


def _normalize_attributes(attributes: Mapping[str, Any] | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in sorted(attributes or {}):
        if key.startswith("gen_ai.") and key not in _V1_GEN_AI_KEYS:
            continue
        value = (attributes or {})[key]
        if key in _VOLATILE_KEYS:
            out[key] = PLACEHOLDER
        elif isinstance(value, (tuple, list)):
            out[key] = list(value)
        else:
            out[key] = value
    return out


def _normalize(spans: Sequence[ReadableSpan]) -> list[dict[str, Any]]:
    normalized = [
        {
            "name": span.name,
            "kind": span.kind.name,
            "status": {
                "code": span.status.status_code.name,
                "description": span.status.description,
            },
            "attributes": _normalize_attributes(span.attributes),
            "events": [
                {"name": event.name, "attributes": _normalize_attributes(event.attributes)}
                for event in span.events
                if event.name != "exception" and not event.name.startswith("gen_ai.")
            ],
        }
        for span in spans
    ]
    normalized.sort(key=lambda span: str(span["name"]))
    return normalized


def _decision() -> Decision:
    client = Fabric(
        FabricConfig(
            tenant_id="tenant-conformance", agent_id="agent-conformance", profile="permissive-dev"
        )
    )
    return client.decision(
        session_id="session-0001", request_id="request-0001", user_id="user-0001"
    )


def _hook() -> None:
    with _decision() as d:
        d.record_hook(
            "example-redactor",
            "pre_model",
            modified=True,
            input_hash="a" * 64,
            output_hash="b" * 64,
        )


def _interaction_tagged() -> None:
    reset_coverage_registry()
    payload_hash = "b" * 64
    baseline = Baseline.load({"db.query": payload_hash})
    signature = hmac.new(
        _SIG_SECRET.encode("utf-8"), payload_hash.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    with _decision() as d:
        d.record_interaction(
            "db.query",
            "orders",
            direction="internal",
            payload_hash=payload_hash,
            # The golden predates hashed-by-default targets.
            redact_target=False,
            tags=["example:category", "example:label", "myco:risk-high"],
            baseline=BaselineCheck(baseline, "db.query", payload_hash),
            signature=SignatureCheck(
                artifact_hash=payload_hash,
                signature=signature,
                public_key=_SIG_SECRET,
                scheme="hmac-sha256",
                key_id="conformance-key-1",
            ),
        )


SCENARIOS: dict[str, Callable[[], None]] = {
    "hook": _hook,
    "interaction_tagged": _interaction_tagged,
}


def _manifest_entry(name: str) -> dict[str, Any]:
    manifest = json.loads((CONTRACT_DIR / "manifest.json").read_text(encoding="utf-8"))
    (entry,) = [item for item in manifest["scenarios"] if item["name"] == name]
    return dict(entry)


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_current_sdk_reproduces_neutralized_golden(
    name: str, span_exporter: InMemorySpanExporter
) -> None:
    entry = _manifest_entry(name)
    assert "python" in entry["support"]
    fixture = CONTRACT_DIR / entry["fixture"]
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == entry["sha256"]

    span_exporter.clear()
    SCENARIOS[name]()
    got = _normalize(span_exporter.get_finished_spans())

    assert got == json.loads(fixture.read_text(encoding="utf-8"))
