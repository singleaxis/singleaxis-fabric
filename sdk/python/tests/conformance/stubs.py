# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Deterministic stub rails for the conformance scenarios.

No real Presidio/NeMo/LLM/OPA is used. Each stub has fixed, seeded
behaviour so the emitted telemetry is byte-stable across runs and
machines. The stubs satisfy the SDK's structural protocols
(``GuardrailChecker``, ``PolicyEngine``, ``ToolAuthorizer``,
``ContentStore``).
"""

from __future__ import annotations

from dataclasses import dataclass

from fabric import (
    CheckerVerdict,
    ContentRef,
    EngineVerdict,
    ToolAuthorization,
)
from fabric.content_store.base import content_hash


@dataclass(slots=True)
class RedactingChecker:
    """Guardrail checker that always redacts to a fixed replacement.

    Emits a deterministic ``redact`` verdict so the ``fabric.guardrail``
    event carries a stable ``policies`` entry and the chain reports a
    rewritten value.
    """

    name: str = "stub-redactor"
    replacement: str = "[REDACTED]"

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        """Return a fixed redact verdict regardless of input."""
        return CheckerVerdict(
            action="redact",
            modified_value=self.replacement,
            reason="stub redaction",
            rail="pii",
        )

    def close(self) -> None:
        """No resources to release."""


@dataclass(slots=True)
class BlockingChecker:
    """Guardrail checker that always blocks with a fixed response."""

    name: str = "stub-blocker"
    block_response: str = "request blocked by stub policy"

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        """Return a fixed block verdict regardless of input."""
        return CheckerVerdict(
            action="block",
            reason=self.block_response,
            rail="jailbreak",
        )

    def close(self) -> None:
        """No resources to release."""


@dataclass(slots=True)
class StubPolicyEngine:
    """Policy engine returning a fixed configured verdict."""

    verdict: EngineVerdict
    engine_name: str = "stub-policy"

    def evaluate(
        self,
        *,
        policy_id: str,
        input: dict[str, object],
        timeout_seconds: float,
    ) -> EngineVerdict:
        """Return the configured verdict regardless of input."""
        return self.verdict

    def close(self) -> None:
        """No resources to release."""


@dataclass(slots=True)
class StubToolAuthorizer:
    """Tool authorizer returning a fixed allow/deny verdict."""

    authorization: ToolAuthorization

    def authorize(
        self,
        *,
        tool_name: str,
        arguments_hash: str | None,
    ) -> ToolAuthorization:
        """Return the configured authorization regardless of input."""
        return self.authorization


@dataclass(slots=True)
class DeterministicContentStore:
    """In-memory content store with a content-addressed, stable ref.

    The ``mem://<hash>`` URI is a pure function of the content, so a
    fixed scenario input yields a fixed stamped ``content_ref``.
    """

    def put(self, content: str, *, key_hint: str | None = None) -> ContentRef:
        """Return a deterministic content-addressed ref for ``content``."""
        digest = content_hash(content)
        return ContentRef(uri=f"mem://{digest}", content_hash=digest)

    def close(self) -> None:
        """No resources to release."""
