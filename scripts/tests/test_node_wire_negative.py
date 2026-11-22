# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 055 §9.3 negative rows, unit 055-t17: where wire capture is not qualified, the
preload reports why and the agent runs unchanged.

From the packed tarball (``_node_package.py``), an unmodified tool-loop script over global
``fetch`` (``clients/fetch.mjs``) is started with and without the preload on:

- **Node 22 and Node 24.0.0** (no undici body-chunk publications): the status file names
  ``wire.ts.undici`` ``unsupported(unsupported_version)`` and FW-026, nothing is spooled;
  ``FABRIC_TEST_NODE_UNSUPPORTED`` lists the binaries (``os.pathsep``-separated; the
  ``ts-wire-matrix`` CI job installs Node 22.23.5 and 24.0.0);
- **Bun and Deno** (each through its own preload flag, since neither reads
  ``NODE_OPTIONS``): capture never starts (``unsupported_runtime``, FW-026); their
  binaries come from ``FABRIC_TEST_BUN`` and ``FABRIC_TEST_DENO``
  (``qualification/node-wire/runtimes/``, pinned).

In every case the application's output, exit code and stderr, and the bytes the provider
received, are identical with the preload on and off. The other negative rows (an
unqualified external undici, an HTTP/2 dispatcher, unsupported endpoints, a custom fetch
over ``node:http``) are rows of ``test_node_wire_matrix.py``; a missing native prebuild is
``sdk/typescript/test/package-artifact.node.mjs``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(
    0,
    str(
        Path(__file__).resolve().parents[2] / "qualification" / "node-wire" / "harness"
    ),
)

from provider import ScriptedProvider  # noqa: E402

import _node_package  # noqa: E402

_MISSING = _node_package.missing()
_REQUIRED = os.environ.get("FABRIC_REQUIRE_NODE_E2E") == "1"
pytestmark = pytest.mark.skipif(
    _MISSING is not None and not _REQUIRED, reason=_MISSING or ""
)


def _binaries(variable: str) -> list[str]:
    return [p for p in os.environ.get(variable, "").split(os.pathsep) if p]


@pytest.fixture(scope="module")
def app(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if _MISSING is not None:
        pytest.fail(f"FABRIC_REQUIRE_NODE_E2E=1 but this machine {_MISSING}")
    directory = tmp_path_factory.mktemp("f055-t17-negative")
    _node_package.install_app(directory)
    return directory


@pytest.fixture
def provider() -> Iterator[ScriptedProvider]:
    server = ScriptedProvider()
    yield server
    server.close()


def _env(root: Path, provider: ScriptedProvider) -> dict[str, str]:
    base = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("FABRIC_", "OTEL_", "NODE_"))
    }
    endpoint = {
        "endpoint_id": "negative", "dialect": "openai", "hosts": ["127.0.0.1"],
        "ports": [provider.port], "schemes": ["http"],
    }  # fmt: skip
    return {
        **base,
        "FABRIC_WIRE_AUTOLOAD": "1",
        "FABRIC_TENANT_ID": "tenant-negative",
        "FABRIC_WIRE_SPOOL_DIR": str(root / "spool"),
        "FABRIC_WIRE_ENDPOINTS": json.dumps([endpoint]),
        "FABRIC_WIRE_STORE": f"file://{root / 'store'}",
        "FABRIC_OTLP_ENDPOINT": "http://127.0.0.1:9",
        "FABRIC_WIRE_STATUS_FILE": str(root / "fabric-status.json"),
        "MODEL_BASE_URL": f"{provider.base}/ok",
    }


def _run(app: Path, command: list[str], env: dict[str, str]) -> tuple[str, str, int]:
    done = subprocess.run(  # noqa: S603
        command, cwd=app, env=env, capture_output=True, text=True, timeout=180,
        check=False,
    )  # fmt: skip
    return done.stdout, done.stderr, done.returncode


def _on_off(
    app: Path,
    root: Path,
    provider: ScriptedProvider,
    on: list[str],
    off: list[str],
    extra: dict[str, str],
) -> dict[str, object]:
    env = _env(root, provider)
    plain = {k: v for k, v in env.items() if not k.startswith("FABRIC_")}
    without = _run(app, off, plain)
    received_off = sorted(provider.received)
    provider.received.clear()
    with_preload = _run(app, on, {**env, **extra})
    assert with_preload == without
    assert without[2] == 0, without[1]
    assert json.loads(without[0].strip().splitlines()[-1])["tool"] == "get_weather"
    assert sorted(provider.received) == received_off and len(received_off) == 2
    # Nothing was captured, so nothing was spooled.
    spool = root / "spool"
    assert not spool.exists() or not list(spool.glob("*.rec"))
    status: dict[str, object] = json.loads((root / "fabric-status.json").read_text())
    return status


@pytest.mark.parametrize("node", _binaries("FABRIC_TEST_NODE_UNSUPPORTED") or [None])
def test_node_22_and_node_24_0_report_unsupported_and_run_unchanged(
    tmp_path: Path, app: Path, provider: ScriptedProvider, node: str | None
) -> None:
    if node is None:
        if _REQUIRED and os.environ.get("CI"):
            pytest.fail(
                "set FABRIC_TEST_NODE_UNSUPPORTED to the Node 22 and 24.0.0 binaries"
            )
        pytest.skip("FABRIC_TEST_NODE_UNSUPPORTED names no Node 22 or 24.0 binary")
    preload = ["--import=@singleaxis/fabric/register"]
    status = _on_off(
        app, tmp_path, provider, [node, *preload, "fetch.mjs"], [node, "fetch.mjs"], {}
    )
    assert status["capture"] == "disabled", status
    detail = status["status"]
    assert isinstance(detail, dict)
    assert detail["capture_points"]["wire.ts.undici"] == "unsupported", detail
    assert detail["capture_point_reasons"]["wire.ts.undici"] == "unsupported_version"
    assert "FW-026" in status["warning_ids"]  # type: ignore[operator]


@pytest.mark.parametrize("runtime", ["bun", "deno"])
def test_bun_and_deno_never_install_capture(
    tmp_path: Path, app: Path, provider: ScriptedProvider, runtime: str
) -> None:
    binary = os.environ.get(f"FABRIC_TEST_{runtime.upper()}")
    if not binary:
        if _REQUIRED and os.environ.get("CI"):
            pytest.fail(
                f"set FABRIC_TEST_{runtime.upper()} (qualification/node-wire/runtimes)"
            )
        pytest.skip(f"FABRIC_TEST_{runtime.upper()} is not set")
    register = "./node_modules/@singleaxis/fabric/dist/register.js"
    if runtime == "bun":
        on = [binary, "--preload", register, "fetch.mjs"]
        off = [binary, "fetch.mjs"]
    else:
        flags = ["run", "--allow-all", "--quiet"]
        on = [binary, *flags, "--preload", register, "fetch.mjs"]
        off = [binary, *flags, "fetch.mjs"]
    status = _on_off(app, tmp_path, provider, on, off, {})
    assert status["capture"] == "disabled", status
    assert status["status"]["capture_reason"] == "unsupported_runtime", status  # type: ignore[index]
    assert "FW-026" in status["warning_ids"]  # type: ignore[operator]
