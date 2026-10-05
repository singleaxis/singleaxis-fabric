# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for fabric.auto_instrument lazy-detect-and-enable logic.

The upstream `opentelemetry-instrumentation-*` packages aren't dev
deps (they pull heavy LLM SDK transitives), so these tests stub the
import + Instrumentor surface via monkeypatch rather than actually
installing them.
"""

from __future__ import annotations

import builtins
import importlib
import os
import sys
import types
from typing import Any

import pytest

from fabric import Fabric, FabricConfig
from fabric.auto_instrument import (
    _CONTENT_CAPTURE_ENV_VARS,
    enable_auto_instrumentation,
    known_instrumentor_names,
)


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))


def _block_instrumentor_imports(
    monkeypatch: pytest.MonkeyPatch, *, allowed: tuple[str, ...] = ()
) -> None:
    """Model absent extras independently of packages installed in the test environment."""
    original = builtins.__import__

    def unavailable(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("opentelemetry.instrumentation.") and name not in allowed:
            raise ImportError("instrumentor absent in fixture")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", unavailable)


def _install_fake_instrumentor(
    monkeypatch: pytest.MonkeyPatch,
    module_name: str,
    class_name: str,
    *,
    raise_on_instrument: bool = False,
    drop_class: bool = False,
) -> dict[str, int]:
    """Inject a fake Instrumentor module into sys.modules.

    Returns a counter dict the test reads to assert ``.instrument()``
    was called.
    """
    counters: dict[str, int] = {"instrumented": 0}

    class FakeInstrumentor:
        is_instrumented_by_opentelemetry = True

        def instrument(self) -> None:
            if raise_on_instrument:
                raise RuntimeError("upstream broke")
            counters["instrumented"] += 1

    fake_module = types.ModuleType(module_name)
    if not drop_class:
        setattr(fake_module, class_name, FakeInstrumentor)
    monkeypatch.setitem(sys.modules, module_name, fake_module)
    return counters


# ---------- known names ----------


def test_known_instrumentor_names_returns_canonical_set() -> None:
    names = known_instrumentor_names()
    # Don't pin the exact set — these will grow — but verify the
    # current minimum is present and there are no duplicates.
    assert len(names) == len(set(names))
    assert "openai" in names
    assert "anthropic" in names


# ---------- lazy detection ----------


def test_no_extras_installed_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force ImportError for every known instrumentor module.
    real_import = builtins.__import__

    def faux_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("opentelemetry.instrumentation."):
            raise ImportError(f"no module named {name!r}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", faux_import)
    enabled = enable_auto_instrumentation()
    assert enabled == ()


def test_one_extra_installed_enables_only_that(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Stub openai and explicitly model every other extra as unavailable.
    _block_instrumentor_imports(monkeypatch, allowed=("opentelemetry.instrumentation.openai_v2",))
    counters = _install_fake_instrumentor(
        monkeypatch,
        "opentelemetry.instrumentation.openai_v2",
        "OpenAIInstrumentor",
    )

    enabled = enable_auto_instrumentation()
    assert "openai" in enabled
    assert counters["instrumented"] == 1
    # The other names that weren't stubbed are absent.
    assert "anthropic" not in enabled


def test_only_filter_restricts_to_subset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    openai_counters = _install_fake_instrumentor(
        monkeypatch,
        "opentelemetry.instrumentation.openai_v2",
        "OpenAIInstrumentor",
    )
    anthropic_counters = _install_fake_instrumentor(
        monkeypatch,
        "opentelemetry.instrumentation.anthropic",
        "AnthropicInstrumentor",
    )

    # Only request openai; anthropic stays uninstrumented even though
    # the package is "installed" (stubbed).
    enabled = enable_auto_instrumentation(only=["openai"])
    assert enabled == ("openai",)
    assert openai_counters["instrumented"] == 1
    assert anthropic_counters["instrumented"] == 0


def test_only_filter_warns_on_unknown_name(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _block_instrumentor_imports(monkeypatch)
    with caplog.at_level("WARNING", logger="fabric.auto_instrument"):
        enabled = enable_auto_instrumentation(only=["openai", "made-up-thing"])
    assert "made-up-thing" in caplog.text
    # The fixture explicitly makes openai unavailable, even if installed.
    assert "openai" not in enabled


def test_instrument_method_failure_logs_warning_and_skips(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _install_fake_instrumentor(
        monkeypatch,
        "opentelemetry.instrumentation.openai_v2",
        "OpenAIInstrumentor",
        raise_on_instrument=True,
    )

    with caplog.at_level("WARNING", logger="fabric.auto_instrument"):
        enabled = enable_auto_instrumentation(only=["openai"])
    assert enabled == ()  # failed instrument() means not enabled
    assert "raised on init/instrument" in caplog.text


def test_instrumentor_constructor_failure_logs_warning_and_skips(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Some upstream Instrumentors check peer-dep imports in __init__
    # rather than .instrument(). Make sure we catch __init__ failures
    # too — silently skipping a broken Instrumentor is the right
    # posture; crashing agent startup over a third-party bug is not.
    fake_module = types.ModuleType("opentelemetry.instrumentation.openai_v2")

    class BrokenInit:
        def __init__(self) -> None:
            raise ImportError("openai package missing")

        def instrument(self) -> None:  # pragma: no cover — never reached
            pass

    fake_module.OpenAIInstrumentor = BrokenInit  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "opentelemetry.instrumentation.openai_v2", fake_module)

    with caplog.at_level("WARNING", logger="fabric.auto_instrument"):
        enabled = enable_auto_instrumentation(only=["openai"])
    assert enabled == ()
    assert "raised on init/instrument" in caplog.text


def test_module_imports_but_class_missing_logs_warning(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Module exists but lacks the expected Instrumentor class — e.g.
    # upstream renamed it. We want a warning, not a crash.
    _install_fake_instrumentor(
        monkeypatch,
        "opentelemetry.instrumentation.openai_v2",
        "OpenAIInstrumentor",
        drop_class=True,
    )

    with caplog.at_level("WARNING", logger="fabric.auto_instrument"):
        enabled = enable_auto_instrumentation(only=["openai"])
    assert enabled == ()
    assert "may have renamed its Instrumentor" in caplog.text


# ---------- content capture posture ----------


def test_content_capture_default_off(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _CONTENT_CAPTURE_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.delenv("FABRIC_CAPTURE_LLM_CONTENT", raising=False)
    enable_auto_instrumentation(only=[])
    for var in _CONTENT_CAPTURE_ENV_VARS:
        assert os.environ.get(var) == "false"


def test_content_capture_explicit_arg_true(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _CONTENT_CAPTURE_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    enable_auto_instrumentation(only=[], capture_content=True)
    for var in _CONTENT_CAPTURE_ENV_VARS:
        assert os.environ.get(var) == "true"


def test_content_capture_via_env_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _CONTENT_CAPTURE_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("FABRIC_CAPTURE_LLM_CONTENT", "true")
    enable_auto_instrumentation(only=[])
    for var in _CONTENT_CAPTURE_ENV_VARS:
        assert os.environ.get(var) == "true"


def test_content_capture_false_overrides_upstream_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_CONTENT_CAPTURE_ENV_VARS[0], "operator-set-value")
    enable_auto_instrumentation(only=[])
    assert os.environ[_CONTENT_CAPTURE_ENV_VARS[0]] == "false"


# ---------- Fabric.enable_auto_instrumentation passthrough ----------


def test_fabric_enable_auto_instrumentation_delegates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    counters = _install_fake_instrumentor(
        monkeypatch,
        "opentelemetry.instrumentation.openai_v2",
        "OpenAIInstrumentor",
    )
    fabric = _client()
    enabled = fabric.enable_auto_instrumentation(only=["openai"])
    assert enabled == ("openai",)
    assert counters["instrumented"] == 1


# Force-reimport of auto_instrument to clear any cached state between
# tests (the env-var setdefault writes are persistent across tests
# otherwise).
@pytest.fixture(autouse=True)
def _reimport_auto_instrument() -> None:
    importlib.reload(sys.modules["fabric.auto_instrument"])


@pytest.mark.parametrize("error", [ImportError, RuntimeError])
def test_import_diagnostics_do_not_include_third_party_error_content(
    monkeypatch: Any, caplog: Any, error: Any
) -> None:
    original = builtins.__import__

    def broken(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "opentelemetry.instrumentation.openai_v2":
            raise error("SYNTHETIC-PRIVATE-CANARY")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", broken)
    with caplog.at_level("DEBUG", logger="fabric.auto_instrument"):
        assert enable_auto_instrumentation(only=["openai"]) == ()
    assert "SYNTHETIC-PRIVATE-CANARY" not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.parametrize("stage", ["constructor", "instrument"])
def test_registration_diagnostics_do_not_include_third_party_error_content(
    monkeypatch: Any, caplog: Any, stage: str
) -> None:
    class Broken:
        def __init__(self) -> None:
            if stage == "constructor":
                raise RuntimeError("SYNTHETIC-PRIVATE-CANARY")

        def instrument(self) -> None:
            raise RuntimeError("SYNTHETIC-PRIVATE-CANARY")

    module = types.ModuleType("opentelemetry.instrumentation.openai_v2")
    module.OpenAIInstrumentor = Broken  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, module.__name__, module)
    assert enable_auto_instrumentation(only=["openai"]) == ()
    assert "SYNTHETIC-PRIVATE-CANARY" not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.parametrize("active", [False, None])
def test_tuple_does_not_report_unverified_or_noop_activation(monkeypatch: Any, active: Any) -> None:
    class Noop:
        is_instrumented_by_opentelemetry = active

        def instrument(self) -> None:
            pass

    module = types.ModuleType("opentelemetry.instrumentation.openai_v2")
    module.OpenAIInstrumentor = Noop  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, module.__name__, module)
    assert enable_auto_instrumentation(only=["openai"]) == ()


@pytest.mark.parametrize("value", ["false", "true", 0, 1])
def test_upstream_content_opt_in_requires_actual_boolean(value: Any) -> None:
    with pytest.raises(ValueError, match="capture_content"):
        enable_auto_instrumentation(only=[], capture_content=value)
