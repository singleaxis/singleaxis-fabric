# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for HTTPPolicyAdapter against a local stdlib HTTP server."""

from __future__ import annotations

import json
import threading
from collections.abc import Generator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from fabric import HTTPPolicyAdapter, PolicyAdapterError


@pytest.fixture
def http_policy_server() -> Generator[tuple[str, dict[str, Any]], None, None]:
    """Spin up an in-process policy server. The fixture returns the
    base URL and a mutable dict the test populates with the response
    body to return on the next request.
    """
    state: dict[str, Any] = {"response": {"decision": "allow"}, "status": 200}

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", "0"))
            self.rfile.read(length)
            self.send_response(state["status"])
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(state["response"]).encode())

        def log_message(self, *_: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/evaluate", state
    server.shutdown()
    thread.join(timeout=2)


def test_http_adapter_returns_allow(
    http_policy_server: tuple[str, dict[str, Any]],
) -> None:
    url, state = http_policy_server
    state["response"] = {"decision": "allow"}
    adapter = HTTPPolicyAdapter(endpoint=url)
    verdict = adapter.evaluate(policy_id="p", input={"x": 1}, timeout_seconds=2.0)
    assert verdict.decision == "allow"


def test_http_adapter_returns_deny_with_reason(
    http_policy_server: tuple[str, dict[str, Any]],
) -> None:
    url, state = http_policy_server
    state["response"] = {
        "decision": "deny",
        "reason": "blocked by tenant policy",
        "policy_version": "2026-04-12",
    }
    adapter = HTTPPolicyAdapter(endpoint=url)
    verdict = adapter.evaluate(policy_id="p", input={}, timeout_seconds=2.0)
    assert verdict.decision == "deny"
    assert verdict.reason == "blocked by tenant policy"
    assert verdict.policy_version == "2026-04-12"


def test_http_adapter_rejects_unrecognized_decision(
    http_policy_server: tuple[str, dict[str, Any]],
) -> None:
    url, state = http_policy_server
    state["response"] = {"decision": "maybe"}
    adapter = HTTPPolicyAdapter(endpoint=url)
    with pytest.raises(PolicyAdapterError, match="unrecognized decision"):
        adapter.evaluate(policy_id="p", input={}, timeout_seconds=2.0)
