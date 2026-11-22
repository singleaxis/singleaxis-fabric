# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 055 §9.5, unit 055-t17: a Node.js agent through a real, production-shaped Fabric
Node, read back from the Node's own store.

The same stack ``test_wire_capture_node_e2e.py`` drives for Python agents (the custom
Collector image in node mode with the production and content overlays, TLS and an
ingress bearer token, the Node bound to the agents' source, fsync sink behind it) records
an unmodified-by-Fabric Node agent instead: ``clients/node-e2e.mjs`` uses the official
``openai`` client inside one run, started from the packed tarball with only
``NODE_OPTIONS=--import=@singleaxis/fabric/register`` and environment variables, in the
production profile (capture policy, id key, sealed spool). Against the running stack:

- every span arrives through the Node, which stamps it ``fabric.source.authenticated``;
- the Node, not the agent, wrote every body, sealed at rest under the Node's key, and
  the bytes read back from that store are the bytes the provider received and sent;
- ``python -m fabric.reconstruct`` over the sink (trusted readback, production profile)
  and the Node's store reports the run ``complete_for_observed_scopes`` and
  ``terminated`` with every check passed;
- no prompt, tool result, completion, API key or ingress token appears in the sink, the
  Node's logs or its telemetry queue volume.

Opt-in: skips without Docker Compose or the packed tarball, unless
``FABRIC_REQUIRE_NODE_E2E=1`` (the ``ts-wire-node-e2e`` CI job). ``FABRIC_NODE_IMAGE``
reuses a prebuilt Node image.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import quote

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
from _wire_capture_common import build_image, compose_available, volume_grep  # noqa: E402
from test_wire_capture_node_e2e import (  # noqa: E402
    ID_KEY,
    INGRESS_TOKEN,
    MARK,
    TENANT,
    Stack,
    source_of,
)

_MISSING = _node_package.missing() or (
    None if compose_available() else "needs Docker Compose (the Fabric Node image)"
)
_REQUIRED = os.environ.get("FABRIC_REQUIRE_NODE_E2E") == "1"
pytestmark = pytest.mark.skipif(
    _MISSING is not None and not _REQUIRED, reason=_MISSING or ""
)
PROMPT = f"{MARK}_nodeprompt What is the weather in Paris?"
TOOL_RESULT = f"{MARK}_nodetool"
API_KEY = f"sk-{MARK}_nodekey"
RUN_ID = "node-e2e-run"


@pytest.fixture(scope="module")
def app(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if _MISSING is not None:
        pytest.fail(f"FABRIC_REQUIRE_NODE_E2E=1 but this machine {_MISSING}")
    directory = tmp_path_factory.mktemp("f055-t17-node-e2e-app")
    _node_package.install_app(directory)
    return directory


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    stack = Stack(tmp_path_factory.mktemp("f055-t17-node-e2e"))
    try:
        if not os.environ.get("FABRIC_NODE_IMAGE"):
            build_image(stack.image)
        stack.sink.start()
        stack.compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "90")
        stack.wait_health()
        yield stack
    finally:
        stack.compose("down", "-v", "--remove-orphans", check=False)
        stack.sink.stop()
        stack.model.close()


def node_env(stack: Stack, provider: ScriptedProvider, spool: Path) -> dict[str, str]:
    """A production Node agent's environment: only the preload and settings."""
    base = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("FABRIC_", "OTEL_", "OPENAI_", "NODE_"))
    }
    endpoint = {
        "endpoint_id": "node-e2e", "dialect": "openai", "hosts": ["127.0.0.1"],
        "ports": [provider.port], "schemes": ["http"],
    }  # fmt: skip
    return {
        **base,
        "NODE_OPTIONS": "--import=@singleaxis/fabric/register",
        "FABRIC_WIRE_AUTOLOAD": "1",
        "FABRIC_TENANT_ID": TENANT,
        "FABRIC_WIRE_CONTENT_ENDPOINT": (
            f"https://127.0.0.1:{stack.ports['otlp_content']}/v1/logs"
        ),
        "FABRIC_WIRE_SPOOL_DIR": str(spool),
        "FABRIC_WIRE_ENDPOINTS": json.dumps([endpoint]),
        "FABRIC_WIRE_ID_KEY": ID_KEY,
        **stack.protection,
        "FABRIC_SOURCE_ID": source_of(""),
        "FABRIC_WIRE_DRAIN_ON_EXIT_S": "30",
        "FABRIC_WIRE_STATUS_FILE": str(spool.parent / "fabric-status.json"),
        "OTEL_SERVICE_NAME": "node-e2e-agent",
        "OTEL_EXPORTER_OTLP_ENDPOINT": f"https://127.0.0.1:{stack.ports['otlp_http']}",
        "OTEL_EXPORTER_OTLP_HEADERS": "Authorization="
        + quote(f"Bearer {INGRESS_TOKEN}"),
        "OTEL_EXPORTER_OTLP_CERTIFICATE": str(stack.tls / "ca.crt"),
        "OPENAI_BASE_URL": f"{provider.base}/ok/v1",
        "OPENAI_API_KEY": API_KEY,
        "E2E_RUN_ID": RUN_ID,
        "E2E_PROMPT": PROMPT,
        "E2E_TOOL_RESULT": TOOL_RESULT,
    }


def test_a_node_agent_through_the_production_node_reads_back_complete(
    stack: Stack, app: Path, tmp_path: Path
) -> None:
    provider = ScriptedProvider()
    try:
        spool = tmp_path / "spool"
        node = _node_package.node_binary()
        assert node is not None
        done = subprocess.run(  # noqa: S603
            [node, "node-e2e.mjs"], cwd=app, env=node_env(stack, provider, spool),
            capture_output=True, text=True, timeout=240, check=False,
        )  # fmt: skip
    finally:
        provider.close()
    assert done.returncode == 0, done.stderr
    lines = [json.loads(line) for line in done.stdout.strip().splitlines()]
    assert lines[0]["tool"] == "get_weather" and lines[-1]["ended"] == "ended", lines
    assert "fabric" not in done.stderr.lower(), done.stderr
    status = json.loads((tmp_path / "fabric-status.json").read_text())
    assert status["delivered"] is True and status["stats"]["backlog"] == 0, status
    assert not list(spool.glob("*.rec"))
    received = [b for _, b in provider.received]
    sent = [b for _, b in provider.sent]
    assert len(received) == 3

    # Every span came through the Node, which stamped the bound source authenticated.
    spans = stack.spans_of("node-e2e-agent")
    exchanges = [s for s in spans if s["name"] == "fabric.model_call"]
    assert len(exchanges) == 3, [s["name"] for s in spans]
    assert all(
        s["attributes"].get("fabric.source.authenticated") is True for s in spans
    )
    assert all(
        s["attributes"]["fabric.capture.point"].startswith("wire.ts.undici@")
        for s in exchanges
    )

    # The Node wrote every body, sealed at rest; the reader reads that store.
    objects = {
        s["attributes"][key]
        for s in exchanges
        for key in ("fabric.content.request_ref", "fabric.content.result_ref")
        if key in s["attributes"]
    }
    assert len(objects) == 6
    store = stack.wait_content(objects)
    code, report = stack.reconstruct(store)
    (run,) = [r for r in report["runs"] if r["exchanges"]]
    assert code == 0, (run["verdict"], run["gaps"])
    assert run["verdict"] == "complete_for_observed_scopes", run["gaps"]
    assert run.get("run_state") == "terminated"
    assert set(run["checks"].values()) <= {"passed", "skipped"}, run["checks"]
    assert run["checks"]["sequence"] == "passed" and run["checks"]["bytes"] == "passed"
    evidence = store / TENANT / "evidence"
    ordered = sorted(run["exchanges"], key=lambda e: e["source_sequence"])
    for side, expected in (("request", received), ("response", sent)):
        stored = [
            (evidence / e["objects"][side]["object_id"]).read_bytes() for e in ordered
        ]
        assert stored == expected, side

    # Spec 055 §9.2 canary scan, the Node half (C0A-2): no content or secret leaves the
    # customer boundary except sealed into the Node's store. Scanned: the decoded sink
    # output, the delivered OTLP bytes, the Node's logs, the reader's report, the Node's
    # telemetry queue, and its content queue and file store at rest (sealed with the
    # Node key, spec 049 §7.8, so neither holds a body or a credential in clear).
    markers = [f"{MARK}_nodeprompt", TOOL_RESULT, API_KEY, INGRESS_TOKEN, ID_KEY]
    # J1 (pseudonymous by default): no clear label reaches the sink, the logs or a report.
    labels = [TENANT, "node-e2e-agent", source_of(""), RUN_ID]
    sink_text = stack.records.read_text("utf-8")
    raw = stack.sink.raw_bytes()
    logs = stack.node_logs()
    reports = "\n".join(stack.reports)
    assert sink_text and reports and "fabric-node" in logs, (
        "a leak scan would be vacuous"
    )
    assert b"fabric.wire.exchange_id" in raw  # the raw bytes are the delivered spans
    for marker in markers + labels:
        assert marker not in sink_text, f"{marker} reached the decoded sink output"
        assert marker.encode() not in raw, f"{marker} reached the delivered OTLP bytes"
        assert marker not in logs, f"{marker} appeared in the Node logs"
        assert marker not in reports, f"{marker} appeared in the reader's report"
    for marker in markers:
        for volume in ("fabric-queue", "fabric-content-queue", "fabric-content"):
            assert volume_grep(f"{stack.project}_{volume}", marker) == "", (
                f"{marker} persisted in clear in the Node's {volume} volume"
            )
