# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for HTTPGuardrailChecker against a local stdlib HTTP server."""

from __future__ import annotations

import json
import threading
from collections.abc import Generator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from fabric import HTTPGuardrailChecker
from fabric.guardrails import GuardrailChecker


@pytest.fixture
def http_guardrail_server() -> Generator[tuple[str, dict[str, Any]], None, None]:
    """Spin up an in-process guardrail server. The fixture returns the
    base URL and a mutable dict the test populates with the response
    body (or a raw, non-JSON body) to return on the next request.
    """
    state: dict[str, Any] = {"response": {"action": "allow"}, "status": 200, "raw": None}

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", "0"))
            self.rfile.read(length)
            self.send_response(state["status"])
            self.send_header("content-type", "application/json")
            self.end_headers()
            if state["raw"] is not None:
                self.wfile.write(state["raw"].encode())
            else:
                self.wfile.write(json.dumps(state["response"]).encode())

        def log_message(self, *_: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/check", state
    server.shutdown()
    thread.join(timeout=2)


def test_allow_response(http_guardrail_server: tuple[str, dict[str, Any]]) -> None:
    url, state = http_guardrail_server
    state["response"] = {"action": "allow"}
    checker = HTTPGuardrailChecker(endpoint=url)
    verdict = checker.check("input", "input", "hello")
    assert verdict.action == "allow"
    assert verdict.rail == "custom:http"


def test_block_response_with_reason(http_guardrail_server: tuple[str, dict[str, Any]]) -> None:
    url, state = http_guardrail_server
    state["response"] = {"action": "block", "reason": "tenant policy", "rail": "custom:tox"}
    checker = HTTPGuardrailChecker(endpoint=url)
    verdict = checker.check("input", "input", "bad")
    assert verdict.action == "block"
    assert verdict.reason == "tenant policy"
    assert verdict.rail == "custom:tox"


def test_redact_response_with_modified_value(
    http_guardrail_server: tuple[str, dict[str, Any]],
) -> None:
    url, state = http_guardrail_server
    state["response"] = {"action": "redact", "modified_value": "<REDACTED>"}
    checker = HTTPGuardrailChecker(endpoint=url)
    verdict = checker.check("output_final", "output", "ssn 123-45-6789")
    assert verdict.action == "redact"
    assert verdict.modified_value == "<REDACTED>"


@pytest.mark.parametrize("action", ["warn", "escalate"])
def test_warn_and_escalate_pass_through(
    http_guardrail_server: tuple[str, dict[str, Any]], action: str
) -> None:
    url, state = http_guardrail_server
    state["response"] = {"action": action, "reason": f"{action} hit"}
    checker = HTTPGuardrailChecker(endpoint=url)
    verdict = checker.check("input", "input", "edge case")
    assert verdict.action == action
    assert verdict.reason == f"{action} hit"


def test_unrecognized_action_fails_closed(
    http_guardrail_server: tuple[str, dict[str, Any]],
) -> None:
    url, state = http_guardrail_server
    state["response"] = {"action": "maybe"}
    checker = HTTPGuardrailChecker(endpoint=url)
    verdict = checker.check("input", "input", "x")
    assert verdict.action == "block"
    assert verdict.reason is not None
    assert "unrecognized action" in verdict.reason


def test_non_object_response_blocks(http_guardrail_server: tuple[str, dict[str, Any]]) -> None:
    url, state = http_guardrail_server
    state["raw"] = "[1, 2, 3]"
    checker = HTTPGuardrailChecker(endpoint=url)
    verdict = checker.check("input", "input", "x")
    assert verdict.action == "block"
    assert verdict.reason == "response not an object"


def test_non_str_modified_value_blocks(http_guardrail_server: tuple[str, dict[str, Any]]) -> None:
    url, state = http_guardrail_server
    state["response"] = {"action": "redact", "modified_value": 42}
    checker = HTTPGuardrailChecker(endpoint=url)
    verdict = checker.check("input", "input", "x")
    assert verdict.action == "block"
    assert verdict.reason == "modified_value must be str or absent"


def test_non_json_response_blocks(http_guardrail_server: tuple[str, dict[str, Any]]) -> None:
    url, state = http_guardrail_server
    state["raw"] = "this is not json"
    checker = HTTPGuardrailChecker(endpoint=url)
    verdict = checker.check("input", "input", "x")
    assert verdict.action == "block"
    assert verdict.reason is not None
    assert "non-JSON response" in verdict.reason


def test_transport_error_fails_closed_by_default() -> None:
    # Point at a closed port (nothing listening) to force a URLError.
    checker = HTTPGuardrailChecker(endpoint="http://127.0.0.1:1/check", timeout_seconds=1.0)
    verdict = checker.check("input", "input", "x")
    assert verdict.action == "block"
    assert verdict.reason is not None
    assert "fail-closed" in verdict.reason


def test_transport_error_fail_open_allows() -> None:
    checker = HTTPGuardrailChecker(
        endpoint="http://127.0.0.1:1/check", timeout_seconds=1.0, fail_open=True
    )
    verdict = checker.check("input", "input", "x")
    assert verdict.action == "allow"
    assert verdict.reason is not None
    assert "fail-open" in verdict.reason


def test_satisfies_guardrail_checker_protocol() -> None:
    checker = HTTPGuardrailChecker(endpoint="http://127.0.0.1:1/check")
    assert isinstance(checker, GuardrailChecker)


def test_close_is_noop() -> None:
    checker = HTTPGuardrailChecker(endpoint="http://127.0.0.1:1/check")
    assert checker.close() is None
