# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Prove the conformance kit works against the SDK's own reference impls.

These concrete ``Test*`` subclasses are the kit's self-validation: each
points a contract mixin at a real reference adapter (or the SDK's
existing deterministic test stub where a real impl needs network / heavy
deps), so the inherited contract tests both run as part of CI *and*
demonstrate the kit catches conformance.

Reference / stub subjects validated here:
- GuardrailChecker  -> deterministic stub checker + HTTPGuardrailChecker
                       (against an in-process stdlib HTTP server)
- JudgeWorker       -> SimpleLLMJudge with a stub chat client
- QueueTransport    -> LocalQueueTransport
- DrainableTransport-> LocalQueueTransport
- PolicyEngine      -> deterministic stub policy engine
- ContentStore      -> LocalFilesystemContentStore + in-memory stub store
- ToolAuthorizer    -> simple allow / deny test authorizers
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any

import pytest

from fabric import (
    CheckerVerdict,
    EngineVerdict,
    HTTPGuardrailChecker,
    LocalFilesystemContentStore,
    LocalQueueTransport,
    SimpleLLMJudge,
    ToolAuthorization,
)

from .contracts import (
    ContentStoreContract,
    DrainableTransportContract,
    GuardrailCheckerContract,
    JudgeWorkerContract,
    PolicyEngineContract,
    QueueTransportContract,
    ToolAuthorizerContract,
)

if TYPE_CHECKING:
    from collections.abc import Generator

    from fabric.content_store.base import ContentStore
    from fabric.guardrails import GuardrailChecker
    from fabric.judge import DrainableTransport, JudgeWorker, QueueTransport
    from fabric.policy import PolicyEngine
    from fabric.tool_auth import ToolAuthorizer


# --- local deterministic subjects (mirroring tests/ stub patterns) --------


@dataclass(slots=True)
class _AllowingChecker:
    """Minimal GuardrailChecker stub that always allows."""

    name: str = "stub-allow"

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        """Return a fixed allow verdict regardless of input."""
        return CheckerVerdict(action="allow", rail=self.name)

    def close(self) -> None:
        """No resources to release."""


@dataclass(slots=True)
class _StubPolicyEngine:
    """PolicyEngine stub returning a fixed allow verdict."""

    engine_name: str = "stub-policy"

    def evaluate(
        self,
        *,
        policy_id: str,
        input: dict[str, object],
        timeout_seconds: float,
    ) -> EngineVerdict:
        """Return a fixed allow verdict regardless of input."""
        return EngineVerdict(decision="allow")

    def close(self) -> None:
        """No resources to release."""


@dataclass(slots=True)
class _AllowAuthorizer:
    """ToolAuthorizer stub that always allows."""

    def authorize(self, *, tool_name: str, arguments_hash: str | None) -> ToolAuthorization:
        """Return a fixed allow authorization regardless of input."""
        return ToolAuthorization(decision="allow")


@dataclass(slots=True)
class _DenyAuthorizer:
    """ToolAuthorizer stub that always denies (exercises raise_for_denied)."""

    def authorize(self, *, tool_name: str, arguments_hash: str | None) -> ToolAuthorization:
        """Return a fixed deny authorization regardless of input."""
        return ToolAuthorization(decision="deny", reason="stub deny")


class _StubLLM:
    """Duck-typed chat client returning a fixed parseable score."""

    def complete(self, prompt: str) -> str:
        """Return a fixed score string SimpleLLMJudge can parse."""
        return "score: 0.7"


# --- GuardrailChecker -----------------------------------------------------


class TestStubChecker(GuardrailCheckerContract):
    """Kit run against an always-allow stub checker."""

    def make_checker(self) -> GuardrailChecker:
        return _AllowingChecker()


@pytest.fixture
def http_guardrail_server() -> Generator[str, None, None]:
    """In-process stdlib guardrail server returning a fixed allow body."""

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", "0"))
            self.rfile.read(length)
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"action": "allow"}).encode())

        def log_message(self, *_: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/check"
    server.shutdown()
    thread.join(timeout=2)


class TestHTTPGuardrailChecker(GuardrailCheckerContract):
    """Kit run against HTTPGuardrailChecker pointed at a fake endpoint."""

    @pytest.fixture(autouse=True)
    def _endpoint(self, http_guardrail_server: str) -> None:
        self._url = http_guardrail_server

    def make_checker(self) -> GuardrailChecker:
        return HTTPGuardrailChecker(endpoint=self._url, timeout_seconds=2.0)


# --- JudgeWorker ----------------------------------------------------------


class TestSimpleLLMJudge(JudgeWorkerContract):
    """Kit run against SimpleLLMJudge with a stub chat client."""

    def make_worker(self) -> JudgeWorker:
        return SimpleLLMJudge(llm=_StubLLM(), prompt_template="rate 0-1: {user_input}")


# --- QueueTransport / DrainableTransport ----------------------------------


class TestLocalQueueTransport(QueueTransportContract):
    """Kit run against LocalQueueTransport as a producer transport."""

    def make_transport(self) -> QueueTransport:
        return LocalQueueTransport()


class TestLocalQueueDrainable(DrainableTransportContract):
    """Kit run against LocalQueueTransport as a drainable transport."""

    def make_drainable(self) -> DrainableTransport:
        return LocalQueueTransport()


# --- PolicyEngine ---------------------------------------------------------


class TestStubPolicyEngine(PolicyEngineContract):
    """Kit run against a deterministic stub policy engine."""

    def make_engine(self) -> PolicyEngine:
        return _StubPolicyEngine()


# --- ContentStore ---------------------------------------------------------


class TestLocalFilesystemContentStore(ContentStoreContract):
    """Kit run against the local-filesystem reference content store."""

    @pytest.fixture(autouse=True)
    def _root(self, tmp_path_factory: pytest.TempPathFactory) -> None:
        self._root = str(tmp_path_factory.mktemp("content-store"))

    def make_store(self) -> ContentStore:
        return LocalFilesystemContentStore(root=self._root)


# --- ToolAuthorizer -------------------------------------------------------


class TestAllowAuthorizer(ToolAuthorizerContract):
    """Kit run against an always-allow tool authorizer."""

    def make_authorizer(self) -> ToolAuthorizer:
        return _AllowAuthorizer()


class TestDenyAuthorizer(ToolAuthorizerContract):
    """Kit run against an always-deny tool authorizer (raise_for_denied)."""

    def make_authorizer(self) -> ToolAuthorizer:
        return _DenyAuthorizer()
