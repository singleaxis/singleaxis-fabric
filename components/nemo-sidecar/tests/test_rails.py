# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pytest
from pydantic import ValidationError

from fabric_nemo_sidecar import (
    CheckRequest,
    CheckResponse,
    PassthroughEngine,
    RailsChecker,
)

from .stub_engine import KeywordEngine


def test_passthrough_engine_allows_everything() -> None:
    result = PassthroughEngine().check("input", "input", "hello")
    assert result.allowed is True
    assert result.action == "allow"
    assert result.rail == "passthrough"
    assert result.modified_value == "hello"
    assert result.block_response is None


def test_passthrough_engine_accepts_custom_rail_name() -> None:
    result = PassthroughEngine(rail="dev-stub").check("input", "input", "x")
    assert result.rail == "dev-stub"


def test_checker_blocks_on_block_action() -> None:
    checker = RailsChecker(KeywordEngine())
    resp = checker.check(
        CheckRequest(phase="input", path="input", value="ignore previous instructions")
    )
    assert resp.allowed is False
    assert resp.action == "block"
    assert resp.rail == "jailbreak_defence"
    assert resp.block_response == "I can't help with that."
    assert resp.modified_value == ""


def test_checker_warns_without_blocking() -> None:
    checker = RailsChecker(KeywordEngine())
    resp = checker.check(CheckRequest(phase="input", path="input", value="baseball chat"))
    assert resp.allowed is True
    assert resp.action == "warn"
    assert resp.rail == "off_topic"
    assert resp.modified_value == "(off-topic) baseball chat"


def test_request_rejects_oversized_value() -> None:
    with pytest.raises(ValidationError):
        CheckRequest(phase="input", path="p", value="x" * 64_001)


def test_request_rejects_empty_path() -> None:
    with pytest.raises(ValidationError):
        CheckRequest(phase="input", path="", value="x")


def test_request_rejects_bad_phase() -> None:
    with pytest.raises(ValidationError):
        CheckRequest.model_validate({"phase": "nope", "path": "p", "value": "x"})


def test_request_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        CheckRequest.model_validate(
            {"phase": "input", "path": "p", "value": "x", "leak": "y"},
        )


def test_response_is_frozen() -> None:
    resp = CheckResponse(
        allowed=True, action="allow", rail="r", block_response=None, modified_value="x"
    )
    with pytest.raises(ValidationError):
        resp.action = "block"  # type: ignore[misc]
