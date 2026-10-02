# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Cold public imports keep optional instrumentation lazy and aliases available."""

from __future__ import annotations

import importlib
import multiprocessing
import sys
from importlib.abc import MetaPathFinder
from importlib.machinery import ModuleSpec
from multiprocessing.connection import Connection
from types import ModuleType
from typing import Any

import pytest


class _RejectOptionalInstrumentors(MetaPathFinder):
    def find_spec(
        self,
        fullname: str,
        path: Any = None,
        target: ModuleType | None = None,
    ) -> ModuleSpec | None:
        if fullname.startswith("opentelemetry.instrumentation."):
            raise AssertionError("optional instrumentor imported during SDK import")
        return None


def _check_public_import(first: str, result: Connection) -> None:
    try:
        # The package initializer determines internal import order. These are
        # two public entry imports, not a claim about isolated submodule order.
        assert "fabric" not in sys.modules
        sys.meta_path.insert(0, _RejectOptionalInstrumentors())
        importlib.import_module("fabric." + first)
        registry = importlib.import_module("fabric._instrumentation_registry")
        auto = importlib.import_module("fabric.auto_instrument")
        coverage = importlib.import_module("fabric.coverage_manifest")
        assert auto._KNOWN_INSTRUMENTORS is registry._KNOWN_INSTRUMENTORS
        assert coverage._KNOWN_INSTRUMENTORS is registry._KNOWN_INSTRUMENTORS
        assert auto._set_content_capture_default is registry._set_content_capture_default
        assert auto._CONTENT_CAPTURE_ENV_VARS is registry._CONTENT_CAPTURE_ENV_VARS
        assert auto.known_instrumentor_names() == (
            "openai",
            "anthropic",
            "bedrock",
            "langchain",
            "cohere",
        )
        result.send(None)
    except BaseException as exc:
        result.send(repr(exc))
        raise
    finally:
        result.close()


@pytest.mark.parametrize("first", ["auto_instrument", "coverage_manifest"])
def test_cold_public_imports_keep_optional_instrumentors_lazy(first: str) -> None:
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=_check_public_import, args=(first, send))
    try:
        process.start()
        send.close()
        ready = receive.poll(20)
        assert ready, "cold import did not finish"
        result = receive.recv()
        assert result is None
        process.join(20)
        assert process.exitcode == 0
    finally:
        if process.is_alive():
            process.terminate()
            process.join(5)
        receive.close()
        send.close()
