# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Internal guardrail chain that composes the configured rails into
the spec-005 ``GuardrailResult`` shape.

Current rails (in pipeline order):

1. **Presidio** — redacts PII. Never blocks.
2. **NeMo Colang** — dialog / jailbreak / refusal rails. May block.

Presidio runs first so NeMo's (potentially LLM-backed) check never
sees raw PII. Each rail is optional — the chain works with any
subset, and ``has_rails`` is true if at least one is wired.

This module is ``_chain`` (leading underscore) — not part of the
public API. Hosts configure the chain implicitly via
:class:`fabric.Fabric` and interact with it only through
:class:`fabric.Decision`.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING
from uuid import uuid4

from .guardrails import EntitySummary, GuardrailPhase, GuardrailResult

if TYPE_CHECKING:
    from .nemo import NemoClient
    from .presidio import PresidioClient


class GuardrailChain:
    """Applies the configured rails to a single phase of a decision."""

    def __init__(
        self,
        *,
        presidio: PresidioClient | None = None,
        nemo: NemoClient | None = None,
    ) -> None:
        self._presidio = presidio
        self._nemo = nemo

    @property
    def has_rails(self) -> bool:
        return self._presidio is not None or self._nemo is not None

    def check(self, *, phase: GuardrailPhase, path: str, value: str) -> GuardrailResult:
        start = time.monotonic()
        entities: list[EntitySummary] = []
        policies: list[str] = []
        content = value
        blocked = False
        block_response: str | None = None

        if self._presidio is not None:
            presidio_result = self._presidio.redact(path, value)
            content = presidio_result.value
            if presidio_result.hashed:
                entities.append(EntitySummary(category=presidio_result.pii_category, count=1))
                policies.append(f"presidio:{presidio_result.pii_category}")

        if self._nemo is not None:
            nemo_result = self._nemo.check(phase, path, content)
            # NeMo may rewrite the content (e.g. refusal redirect).
            content = nemo_result.modified_value
            if nemo_result.action != "allow":
                policies.append(f"nemo:{nemo_result.rail}")
                entities.append(EntitySummary(category=nemo_result.rail, count=1))
            if nemo_result.action == "block":
                blocked = True
                block_response = nemo_result.block_response

        latency_ms = (time.monotonic() - start) * 1000.0
        return GuardrailResult(
            event_id=uuid4(),
            blocked=blocked,
            block_response=block_response,
            redacted_content=content,
            entities_detected=entities,
            policies_fired=policies,
            latency_ms=latency_ms,
        )

    def close(self) -> None:
        if self._presidio is not None:
            self._presidio.close()
        if self._nemo is not None:
            self._nemo.close()
