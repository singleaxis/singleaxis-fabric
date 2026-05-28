# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for CedarAdapter using a faked cedarpy module.

cedarpy is not a dev dependency; tests inject a fake module via
``monkeypatch.setitem(sys.modules, "cedarpy", ...)``. The fake exposes
``is_authorized(request, policies, entities)`` returning a
``SimpleNamespace`` with ``decision`` and ``annotations`` attributes,
matching the small call boundary the adapter relies on.
"""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import (
    CedarAdapter,
    Fabric,
    FabricConfig,
    PolicyAdapterError,
    PolicyEngine,
    PolicyEvaluation,
)

_POLICIES = "permit(principal, action, resource);"
_INPUT: dict[str, object] = {
    "principal": 'User::"alice"',
    "action": 'Action::"read"',
    "resource": 'Doc::"42"',
    "context": {},
}


def _fake_cedarpy(
    *, decision: str, annotations: dict[str, str] | None = None, raise_exc: Exception | None = None
) -> ModuleType:
    """Build a fake cedarpy module with a stubbed is_authorized()."""
    module = ModuleType("cedarpy")

    def is_authorized(request: Any, policies: Any, entities: Any) -> SimpleNamespace:
        if raise_exc is not None:
            raise raise_exc
        return SimpleNamespace(decision=decision, annotations=annotations or {})

    module.is_authorized = is_authorized  # type: ignore[attr-defined]
    return module


@pytest.fixture
def install_cedarpy(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Return a helper that installs a fake cedarpy and returns an adapter."""

    def _install(
        *,
        decision: str,
        annotations: dict[str, str] | None = None,
        raise_exc: Exception | None = None,
    ) -> CedarAdapter:
        fake = _fake_cedarpy(decision=decision, annotations=annotations, raise_exc=raise_exc)
        monkeypatch.setitem(sys.modules, "cedarpy", fake)
        return CedarAdapter(policies=_POLICIES)

    return _install


def test_allow_no_annotations_maps_to_allow(install_cedarpy: Any) -> None:
    adapter = install_cedarpy(decision="Allow")
    verdict = adapter.evaluate(policy_id="p", input=_INPUT, timeout_seconds=2.0)
    assert verdict.decision == "allow"
    assert verdict.reason is None


def test_allow_with_redact_annotation_maps_to_redact(install_cedarpy: Any) -> None:
    adapter = install_cedarpy(decision="Allow", annotations={"redact": "true"})
    verdict = adapter.evaluate(policy_id="p", input=_INPUT, timeout_seconds=2.0)
    assert verdict.decision == "redact"
    assert verdict.reason is not None


def test_allow_with_warn_annotation_maps_to_warn(install_cedarpy: Any) -> None:
    adapter = install_cedarpy(decision="Allow", annotations={"warn": "true"})
    verdict = adapter.evaluate(policy_id="p", input=_INPUT, timeout_seconds=2.0)
    assert verdict.decision == "warn"
    assert verdict.reason is not None


def test_deny_with_escalate_annotation_maps_to_escalate(install_cedarpy: Any) -> None:
    adapter = install_cedarpy(decision="Deny", annotations={"escalate": "true"})
    verdict = adapter.evaluate(policy_id="p", input=_INPUT, timeout_seconds=2.0)
    assert verdict.decision == "escalate"
    assert verdict.reason is not None


def test_deny_no_annotations_maps_to_deny(install_cedarpy: Any) -> None:
    adapter = install_cedarpy(decision="Deny")
    verdict = adapter.evaluate(policy_id="finance.refund", input=_INPUT, timeout_seconds=2.0)
    assert verdict.decision == "deny"
    assert verdict.reason is not None
    assert "finance.refund" in verdict.reason


def test_redact_takes_precedence_over_warn(install_cedarpy: Any) -> None:
    """Both annotations present on an Allow: redact wins over warn."""
    adapter = install_cedarpy(decision="Allow", annotations={"redact": "true", "warn": "true"})
    verdict = adapter.evaluate(policy_id="p", input=_INPUT, timeout_seconds=2.0)
    assert verdict.decision == "redact"


def test_escalate_annotation_ignored_on_allow(install_cedarpy: Any) -> None:
    """An escalate annotation only matters on a Deny decision."""
    adapter = install_cedarpy(decision="Allow", annotations={"escalate": "true"})
    verdict = adapter.evaluate(policy_id="p", input=_INPUT, timeout_seconds=2.0)
    assert verdict.decision == "allow"


def test_cedarpy_raising_becomes_policy_adapter_error(install_cedarpy: Any) -> None:
    adapter = install_cedarpy(decision="Allow", raise_exc=RuntimeError("boom"))
    with pytest.raises(PolicyAdapterError, match="cedar evaluation failed"):
        adapter.evaluate(policy_id="p", input=_INPUT, timeout_seconds=2.0)


def test_missing_cedarpy_raises_import_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing without cedarpy installed raises ImportError."""
    monkeypatch.setitem(sys.modules, "cedarpy", None)
    with pytest.raises(ImportError, match=r"singleaxis-fabric\[cedar\]"):
        CedarAdapter(policies=_POLICIES)


def test_satisfies_policy_engine_protocol(install_cedarpy: Any) -> None:
    adapter = install_cedarpy(decision="Allow")
    assert isinstance(adapter, PolicyEngine)
    assert adapter.engine_name == "cedar"


def test_close_is_noop(install_cedarpy: Any) -> None:
    adapter = install_cedarpy(decision="Allow")
    adapter.close()  # must not raise


def test_truthy_annotation_variants(install_cedarpy: Any) -> None:
    """Annotation values "1" and "yes" are also treated as truthy."""
    adapter = install_cedarpy(decision="Allow", annotations={"warn": "yes"})
    assert adapter.evaluate(policy_id="p", input=_INPUT, timeout_seconds=2.0).decision == "warn"
    adapter2 = install_cedarpy(decision="Allow", annotations={"redact": "1"})
    assert adapter2.evaluate(policy_id="p", input=_INPUT, timeout_seconds=2.0).decision == "redact"


def test_non_dict_annotations_treated_as_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """A result whose annotations attr is not a dict yields no annotations."""
    fake = ModuleType("cedarpy")

    def is_authorized(request: Any, policies: Any, entities: Any) -> SimpleNamespace:
        return SimpleNamespace(decision="Allow", annotations=["not", "a", "dict"])

    fake.is_authorized = is_authorized  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "cedarpy", fake)
    adapter = CedarAdapter(policies=_POLICIES)
    verdict = adapter.evaluate(policy_id="p", input=_INPUT, timeout_seconds=2.0)
    assert verdict.decision == "allow"


def test_end_to_end_emits_evaluation_event(
    install_cedarpy: Any, span_exporter: InMemorySpanExporter
) -> None:
    """Full path: decision.evaluate_policy() emits a mapped event."""
    adapter = install_cedarpy(decision="Deny", annotations={"escalate": "true"})
    fabric = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))
    with fabric.decision(session_id="s", request_id="r") as d:
        evaluation = d.evaluate_policy(adapter, policy_id="finance.refund.cap", input=_INPUT)
    assert isinstance(evaluation, PolicyEvaluation)
    assert evaluation.decision == "escalate"
    span = span_exporter.get_finished_spans()[0]
    event = next(e for e in span.events if e.name == "fabric.policy.evaluation")
    attrs = dict(event.attributes or {})
    assert attrs["fabric.policy.engine"] == "cedar"
    assert attrs["fabric.policy.policy_id"] == "finance.refund.cap"
    assert attrs["fabric.policy.decision"] == "escalate"
