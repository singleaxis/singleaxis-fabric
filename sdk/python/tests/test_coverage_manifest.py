# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Installed, active, versioned and qualified are deliberately separate facts."""

from __future__ import annotations

import builtins
import sys
import types
from typing import Any

import pytest

from fabric.auto_instrument import enable_auto_instrumentation_with_manifest
from fabric.coverage_manifest import inspect_integrations


def _fake(monkeypatch: Any, *, active: bool | None = True, raises: bool = False) -> None:
    class Fake:
        is_instrumented_by_opentelemetry = active

        def instrument(self) -> None:
            if raises:
                raise RuntimeError("secret provider error")

    module = types.ModuleType("opentelemetry.instrumentation.openai_v2")
    module.OpenAIInstrumentor = Fake  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr("fabric.coverage_manifest._version", lambda _: "fixture-version")


def _openai(manifest: Any) -> Any:
    return next(row for row in manifest.integrations if row.name == "openai")


def test_versioned_registration_is_still_unqualified(monkeypatch: Any) -> None:
    _fake(monkeypatch)
    manifest = enable_auto_instrumentation_with_manifest(required=["openai"], only=[])
    row = _openai(manifest)
    assert row.status == "ACTIVE" and row.installed is True and row.active is True
    assert row.instrumentor_version == row.target_version == "fixture-version"
    assert row.qualification == "UNVERIFIED"
    assert manifest.to_dict()["production_qualified"] is False


@pytest.mark.parametrize("active,status", [(False, "FAILED"), (None, "UNKNOWN")])
def test_instrument_return_without_active_hook_cannot_pass(
    monkeypatch: Any, active: Any, status: str
) -> None:
    _fake(monkeypatch, active=active)
    manifest = enable_auto_instrumentation_with_manifest(required=["openai"], only=[])
    assert _openai(manifest).status == status
    assert manifest.required_active is False


def test_distribution_version_unavailable_remains_unknown(monkeypatch: Any) -> None:
    _fake(monkeypatch)
    monkeypatch.setattr("fabric.coverage_manifest._version", lambda _: None)
    manifest = inspect_integrations(required=["openai"], only=[])
    assert _openai(manifest).status == "UNKNOWN"
    assert _openai(manifest).reason == "distribution_version_unavailable"


def test_version_drift_is_failed(monkeypatch: Any) -> None:
    _fake(monkeypatch)
    manifest = inspect_integrations(
        required=["openai"],
        only=[],
        expected_versions={"openai": {"target_version": "different"}},
    )
    assert _openai(manifest).status == "FAILED"
    assert _openai(manifest).reason == "version_mismatch"


def test_registration_failure_is_content_free(monkeypatch: Any) -> None:
    _fake(monkeypatch, raises=True)
    manifest = enable_auto_instrumentation_with_manifest(required=["openai"], only=[])
    assert _openai(manifest).status == "FAILED"
    assert "secret" not in str(manifest.to_dict())


def test_missing_required_extra_retained(monkeypatch: Any) -> None:
    original = builtins.__import__

    def unavailable(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "opentelemetry.instrumentation.openai_v2":
            raise ImportError
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", unavailable)
    # Missing extras have neither an importable module nor installed metadata.
    monkeypatch.setattr("fabric.coverage_manifest._version", lambda _: None)
    manifest = inspect_integrations(required=["openai"], only=[])
    row = _openai(manifest)
    assert row.required is True and row.status == "MISSING"
    assert manifest.required_active is False


def test_unknown_required_and_scope_limits_are_explicit() -> None:
    manifest = inspect_integrations(required=["custom"], only=[])
    row = next(row for row in manifest.integrations if row.name == "custom")
    assert row.status == "UNKNOWN" and row.required is True
    scope = manifest.to_dict()["scope"]
    assert scope["qualified_source_epochs"] == [0]
    assert scope["distributed_closure_supported"] is False
    assert scope["qualified_run_max_projected_records"] == 4096
    assert scope["explicit_batching_available"] is True


def test_invalid_version_pin_rejected() -> None:
    with pytest.raises(ValueError):
        inspect_integrations(only=["openai"], expected_versions={"openai": {"version": "1"}})


def test_installed_but_broken_dependency_is_failed_not_missing(monkeypatch: Any) -> None:
    original = builtins.__import__

    def broken(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "opentelemetry.instrumentation.openai_v2":
            raise ImportError("SYNTHETIC-PRIVATE-CANARY")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", broken)
    monkeypatch.setattr("fabric.coverage_manifest._version", lambda _: "installed-version")
    manifest = inspect_integrations(required=["openai"], only=[])
    row = _openai(manifest)
    assert row.status == "FAILED" and row.installed is True and row.active is False
    assert row.reason == "instrumentor_dependency_import_failed"
    assert "SYNTHETIC-PRIVATE-CANARY" not in str(manifest.to_dict())
