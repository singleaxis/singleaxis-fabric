# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Deterministic standard inputs shared by the adapter contract mixins.

These are plain helper builders, not pytest fixtures, so a contract
mixin can call them inline without depending on fixture wiring in the
implementer's test module. Everything is deterministic: a fixed phase /
path / value, a fixed JudgeRequest, a fixed policy input, fixed content.
"""

from __future__ import annotations

from typing import Final
from uuid import UUID

from fabric import JudgeContext, JudgeRequest

# --- GuardrailChecker -----------------------------------------------------
SAMPLE_PHASE: Final = "input"
SAMPLE_PATH: Final = "input"
SAMPLE_VALUE: Final = "my SSN is 123-45-6789, email a@b.com"

# --- PolicyEngine ---------------------------------------------------------
SAMPLE_POLICY_ID: Final = "conformance/sample"
SAMPLE_POLICY_INPUT: Final[dict[str, object]] = {
    "action": "read",
    "resource": "doc-1",
    "principal": "user-1",
}
SAMPLE_TIMEOUT_SECONDS: Final = 3.0

# --- ContentStore ---------------------------------------------------------
SAMPLE_CONTENT: Final = "the quick brown fox jumps over the lazy dog"

# --- ToolAuthorizer -------------------------------------------------------
SAMPLE_TOOL_NAME: Final = "get_weather"
SAMPLE_ARGUMENTS_HASH: Final = "a" * 64  # fixed 64-hex-char placeholder

# --- JudgeWorker / transports ---------------------------------------------
_FIXED_REQUEST_ID: Final = UUID("00000000-0000-0000-0000-000000000001")


def make_judge_request(*, request_id: UUID | None = None) -> JudgeRequest:
    """Build a deterministic JudgeRequest with a populated context.

    A distinct ``request_id`` can be supplied so transport-ordering
    tests can enqueue several distinguishable requests.
    """
    return JudgeRequest(
        request_id=request_id if request_id is not None else _FIXED_REQUEST_ID,
        decision_id="decision-1",
        rubric_id="conformance-rubric",
        dimensions=("overall",),
        context=JudgeContext(
            user_input="What is the capital of France?",
            agent_response="Paris.",
        ),
        payload_ref=None,
    )
