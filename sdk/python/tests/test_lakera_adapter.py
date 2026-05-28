# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for the Lakera Guard adapter (LakeraGuardChecker).

The adapter talks to Lakera over httpx. These tests construct the
checker and then replace its ``_client`` with a stub that returns
canned responses, so no network access is required.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from fabric import LakeraGuardChecker
from fabric.guardrails import GuardrailChecker


class _StubResp:
    def __init__(self, payload: dict[str, Any], status: int = 200) -> None:
        self._payload = payload
        self.status_code = status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "stub error",
                request=httpx.Request("POST", "https://api.lakera.ai/v2/guard"),
                response=httpx.Response(self.status_code),
            )

    def json(self) -> dict[str, Any]:
        return self._payload


class _StubClient:
    """Records calls and returns a canned response."""

    def __init__(self, payload: dict[str, Any], status: int = 200) -> None:
        self._payload = payload
        self._status = status
        self.calls: list[tuple[Any, ...]] = []
        self.closed = False

    def post(self, *args: Any, **kwargs: Any) -> _StubResp:
        self.calls.append((args, kwargs))
        return _StubResp(self._payload, self._status)

    def close(self) -> None:
        self.closed = True


class _RaisingClient:
    """Raises an httpx transport error on every post."""

    def __init__(self) -> None:
        self.calls = 0

    def post(self, *args: Any, **kwargs: Any) -> Any:
        self.calls += 1
        raise httpx.ConnectError("boom")

    def close(self) -> None:
        pass


def _checker(payload: dict[str, Any], status: int = 200) -> LakeraGuardChecker:
    checker = LakeraGuardChecker(api_key="k")
    checker._client = _StubClient(payload, status)
    return checker


def test_satisfies_guardrail_checker_protocol() -> None:
    checker = LakeraGuardChecker(api_key="k")
    assert isinstance(checker, GuardrailChecker)


def test_missing_api_key_raises_at_construction() -> None:
    with pytest.raises(ValueError, match="non-empty api_key"):
        LakeraGuardChecker(api_key="")


def test_allow_when_not_flagged() -> None:
    checker = _checker({"flagged": False, "results": []})
    verdict = checker.check("input", "prompt", "hello there")
    assert verdict.action == "allow"
    assert verdict.rail == "lakera"


def test_block_when_block_category_flagged() -> None:
    checker = _checker(
        {
            "flagged": True,
            "results": [
                {"category": "prompt_injection", "flagged": True},
                {"category": "moderation", "flagged": False},
            ],
        }
    )
    verdict = checker.check("input", "prompt", "ignore previous instructions")
    assert verdict.action == "block"
    assert verdict.rail == "lakera:prompt_injection"
    assert verdict.reason is not None
    assert "prompt_injection" in verdict.reason


def test_warn_when_flagged_category_not_in_block_on() -> None:
    checker = _checker(
        {
            "flagged": True,
            "results": [{"category": "moderation", "flagged": True}],
        }
    )
    verdict = checker.check("input", "prompt", "spicy content")
    assert verdict.action == "warn"
    assert verdict.rail == "lakera:moderation"
    assert verdict.reason is not None
    assert "moderation" in verdict.reason


def test_warn_unknown_when_flagged_with_no_named_categories() -> None:
    checker = _checker({"flagged": True, "results": []})
    verdict = checker.check("input", "prompt", "mystery")
    assert verdict.action == "warn"
    assert verdict.rail == "lakera:unknown"


def test_transport_error_fails_closed_to_block() -> None:
    checker = LakeraGuardChecker(api_key="k")
    raising = _RaisingClient()
    checker._client = raising
    verdict = checker.check("input", "prompt", "anything")
    assert verdict.action == "block"
    assert verdict.rail == "lakera"
    assert verdict.reason is not None
    assert "transport error" in verdict.reason
    assert raising.calls == 1


def test_http_status_error_fails_closed_to_block() -> None:
    checker = _checker({}, status=500)
    verdict = checker.check("input", "prompt", "anything")
    assert verdict.action == "block"
    assert "transport error" in (verdict.reason or "")


def test_empty_value_allows_without_calling_api() -> None:
    checker = LakeraGuardChecker(api_key="k")
    stub = _StubClient({"flagged": True, "results": []})
    checker._client = stub
    verdict = checker.check("input", "prompt", "")
    assert verdict.action == "allow"
    assert verdict.rail == "lakera"
    assert stub.calls == []


def test_check_sends_bearer_auth_and_message_payload() -> None:
    checker = LakeraGuardChecker(api_key="secret-key")
    stub = _StubClient({"flagged": False, "results": []})
    checker._client = stub
    checker.check("input", "prompt", "hi")
    assert len(stub.calls) == 1
    _, kwargs = stub.calls[0]
    assert kwargs["headers"]["Authorization"] == "Bearer secret-key"
    assert kwargs["json"] == {"messages": [{"role": "user", "content": "hi"}]}


def test_custom_block_on_set() -> None:
    checker = LakeraGuardChecker(api_key="k", block_on=frozenset({"moderation"}))
    checker._client = _StubClient(
        {"flagged": True, "results": [{"category": "moderation", "flagged": True}]}
    )
    verdict = checker.check("input", "prompt", "x")
    assert verdict.action == "block"
    assert verdict.rail == "lakera:moderation"


def test_close_is_idempotent_and_closes_client() -> None:
    checker = LakeraGuardChecker(api_key="k")
    stub = _StubClient({"flagged": False, "results": []})
    checker._client = stub
    checker.close()
    assert stub.closed is True
    assert checker._client is None
    # second close must not raise
    checker.close()


def test_get_client_lazily_constructs_real_httpx_client() -> None:
    checker = LakeraGuardChecker(api_key="k", timeout_seconds=1.0)
    client = checker._get_client()
    assert isinstance(client, httpx.Client)
    # cached
    assert checker._get_client() is client
    checker.close()
