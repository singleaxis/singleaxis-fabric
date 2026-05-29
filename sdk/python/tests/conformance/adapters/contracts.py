# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Behavioral-contract mixins for the Fabric extension Protocols.

Each mixin drives the contract of one Protocol through an abstract
factory method the subclass supplies (Pattern A). An implementer writes::

    class TestMyChecker(GuardrailCheckerContract):
        def make_checker(self) -> GuardrailChecker:
            return MyChecker(...)

and pytest runs every inherited ``test_*`` against that instance.

Mixins are deliberately named ``*Contract`` (no ``Test`` prefix) so
pytest does not collect the bare mixin — only the implementer's concrete
``Test*`` subclass is collected. The factory methods raise
``NotImplementedError`` (never a bare ``...``) to satisfy CodeQL.

Tolerant where behavior legitimately varies (a checker may allow OR
block a given input — the harness asserts the verdict is *structurally*
valid), strict where the contract is fixed (content-hash integrity,
FIFO ordering, dequeue-empty -> None, ``raise_for_denied`` semantics).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, get_args
from uuid import UUID

import pytest

from fabric.content_store.base import ContentRef, content_hash
from fabric.guardrails import CheckerVerdict, GuardrailAction
from fabric.policy import EngineVerdict, PolicyDecision
from fabric.tool_auth import (
    ToolAuthorization,
    ToolAuthorizationDecision,
    ToolCallDenied,
)

from ._fixtures import (
    SAMPLE_ARGUMENTS_HASH,
    SAMPLE_CONTENT,
    SAMPLE_PATH,
    SAMPLE_PHASE,
    SAMPLE_POLICY_ID,
    SAMPLE_POLICY_INPUT,
    SAMPLE_TIMEOUT_SECONDS,
    SAMPLE_TOOL_NAME,
    SAMPLE_VALUE,
    make_judge_request,
)

if TYPE_CHECKING:
    from fabric.content_store.base import ContentStore
    from fabric.guardrails import GuardrailChecker
    from fabric.judge import DrainableTransport, JudgeWorker, QueueTransport
    from fabric.policy import PolicyEngine
    from fabric.tool_auth import ToolAuthorizer

_GUARDRAIL_ACTIONS: frozenset[str] = frozenset(get_args(GuardrailAction))
_POLICY_DECISIONS: frozenset[str] = frozenset(get_args(PolicyDecision))
_TOOL_DECISIONS: frozenset[str] = frozenset(get_args(ToolAuthorizationDecision))


class GuardrailCheckerContract:
    """Contract mixin for :class:`fabric.guardrails.GuardrailChecker`.

    Subclass and implement :meth:`make_checker`.
    """

    def make_checker(self) -> GuardrailChecker:
        """Return a fresh adapter instance under test. Subclass-provided."""
        raise NotImplementedError("subclass must implement make_checker()")

    def test_check_returns_valid_verdict(self) -> None:
        checker = self.make_checker()
        verdict = checker.check(SAMPLE_PHASE, SAMPLE_PATH, SAMPLE_VALUE)
        assert isinstance(verdict, CheckerVerdict)
        assert verdict.action in _GUARDRAIL_ACTIONS
        assert verdict.modified_value is None or isinstance(verdict.modified_value, str)
        assert verdict.reason is None or isinstance(verdict.reason, str)
        assert verdict.rail is None or isinstance(verdict.rail, str)

    def test_name_is_nonempty_str(self) -> None:
        checker = self.make_checker()
        name = checker.name
        assert isinstance(name, str)
        assert name != ""

    def test_close_is_idempotent(self) -> None:
        checker = self.make_checker()
        checker.close()
        checker.close()  # second call must not raise


class JudgeWorkerContract:
    """Contract mixin for :class:`fabric.judge.JudgeWorker`.

    Subclass and implement :meth:`make_worker`.
    """

    def make_worker(self) -> JudgeWorker:
        """Return a fresh JudgeWorker under test. Subclass-provided."""
        raise NotImplementedError("subclass must implement make_worker()")

    def test_score_returns_non_none(self) -> None:
        worker = self.make_worker()
        result = worker.score(make_judge_request())
        # The protocol declares an opaque return; the contract is only
        # that a valid request yields *some* score object (not None).
        assert result is not None


class QueueTransportContract:
    """Contract mixin for :class:`fabric.judge.QueueTransport`.

    Subclass and implement :meth:`make_transport`.
    """

    def make_transport(self) -> QueueTransport:
        """Return a fresh QueueTransport under test. Subclass-provided."""
        raise NotImplementedError("subclass must implement make_transport()")

    def test_enqueue_accepts_request(self) -> None:
        transport = self.make_transport()
        # enqueue is fire-and-forget; the contract is that a valid
        # request is accepted without raising.
        transport.enqueue(make_judge_request())

    def test_close_is_idempotent(self) -> None:
        transport = self.make_transport()
        transport.close()
        transport.close()  # second call must not raise


class DrainableTransportContract:
    """Contract mixin for :class:`fabric.judge.DrainableTransport`.

    Subclass and implement :meth:`make_drainable`. The factory MUST
    return an empty, ready-to-use transport so the FIFO and
    empty-dequeue invariants hold.
    """

    def make_drainable(self) -> DrainableTransport:
        """Return a fresh, empty DrainableTransport. Subclass-provided.

        Must also satisfy ``QueueTransport`` (expose ``enqueue``) so the
        round-trip can be driven; the SDK's reference transports do.
        """
        raise NotImplementedError("subclass must implement make_drainable()")

    def test_dequeue_empty_returns_none(self) -> None:
        transport = self.make_drainable()
        assert transport.dequeue() is None

    def test_round_trip_is_fifo(self) -> None:
        transport = self.make_drainable()
        ids = [
            UUID("00000000-0000-0000-0000-00000000000a"),
            UUID("00000000-0000-0000-0000-00000000000b"),
            UUID("00000000-0000-0000-0000-00000000000c"),
        ]
        # enqueue is on QueueTransport; a DrainableTransport used for a
        # round-trip is expected to also be enqueue-able.
        enqueue = transport.enqueue  # type: ignore[attr-defined]
        for request_id in ids:
            enqueue(make_judge_request(request_id=request_id))
        drained = [transport.dequeue() for _ in ids]
        assert all(item is not None for item in drained)
        observed = [item.request_id for item in drained if item is not None]
        assert observed == ids

    def test_dequeue_returns_none_after_drained(self) -> None:
        transport = self.make_drainable()
        enqueue = transport.enqueue  # type: ignore[attr-defined]
        enqueue(make_judge_request())
        first = transport.dequeue()
        assert first is not None
        assert transport.dequeue() is None


class PolicyEngineContract:
    """Contract mixin for :class:`fabric.policy.PolicyEngine`.

    Subclass and implement :meth:`make_engine`.
    """

    def make_engine(self) -> PolicyEngine:
        """Return a fresh PolicyEngine under test. Subclass-provided."""
        raise NotImplementedError("subclass must implement make_engine()")

    def test_evaluate_returns_valid_verdict(self) -> None:
        engine = self.make_engine()
        verdict = engine.evaluate(
            policy_id=SAMPLE_POLICY_ID,
            input=SAMPLE_POLICY_INPUT,
            timeout_seconds=SAMPLE_TIMEOUT_SECONDS,
        )
        assert isinstance(verdict, EngineVerdict)
        assert verdict.decision in _POLICY_DECISIONS
        assert verdict.reason is None or isinstance(verdict.reason, str)
        assert verdict.policy_version is None or isinstance(verdict.policy_version, str)

    def test_engine_name_is_nonempty_str(self) -> None:
        engine = self.make_engine()
        name = engine.engine_name
        assert isinstance(name, str)
        assert name != ""

    def test_close_is_idempotent(self) -> None:
        engine = self.make_engine()
        engine.close()
        engine.close()  # second call must not raise


class ContentStoreContract:
    """Contract mixin for :class:`fabric.content_store.base.ContentStore`.

    Subclass and implement :meth:`make_store`.
    """

    def make_store(self) -> ContentStore:
        """Return a fresh ContentStore under test. Subclass-provided."""
        raise NotImplementedError("subclass must implement make_store()")

    def test_put_returns_ref_with_integrity_hash(self) -> None:
        store = self.make_store()
        ref = store.put(SAMPLE_CONTENT)
        assert isinstance(ref, ContentRef)
        assert ref.uri != ""
        # Strict integrity invariant: the ref's hash MUST equal the
        # canonical content hash of the stored bytes.
        assert ref.content_hash == content_hash(SAMPLE_CONTENT)

    def test_put_is_content_addressed_stable(self) -> None:
        store = self.make_store()
        first = store.put(SAMPLE_CONTENT)
        second = store.put(SAMPLE_CONTENT)
        # Same content -> same hash (content-addressed). URIs may carry
        # the hash, so they are expected to match too.
        assert first.content_hash == second.content_hash
        assert first.uri == second.uri

    def test_distinct_content_distinct_hash(self) -> None:
        store = self.make_store()
        a = store.put(SAMPLE_CONTENT)
        b = store.put(SAMPLE_CONTENT + " (variant)")
        assert a.content_hash != b.content_hash

    def test_close_is_idempotent(self) -> None:
        store = self.make_store()
        store.close()
        store.close()  # second call must not raise


class ToolAuthorizerContract:
    """Contract mixin for :class:`fabric.tool_auth.ToolAuthorizer`.

    Subclass and implement :meth:`make_authorizer`.
    """

    def make_authorizer(self) -> ToolAuthorizer:
        """Return a fresh ToolAuthorizer under test. Subclass-provided."""
        raise NotImplementedError("subclass must implement make_authorizer()")

    def test_authorize_returns_valid_verdict(self) -> None:
        authorizer = self.make_authorizer()
        authorization = authorizer.authorize(
            tool_name=SAMPLE_TOOL_NAME,
            arguments_hash=SAMPLE_ARGUMENTS_HASH,
        )
        assert isinstance(authorization, ToolAuthorization)
        assert authorization.decision in _TOOL_DECISIONS
        assert authorization.reason is None or isinstance(authorization.reason, str)
        # `allowed` must agree with the decision string.
        assert authorization.allowed == (authorization.decision == "allow")

    def test_raise_for_denied_matches_decision(self) -> None:
        authorizer = self.make_authorizer()
        authorization = authorizer.authorize(
            tool_name=SAMPLE_TOOL_NAME,
            arguments_hash=SAMPLE_ARGUMENTS_HASH,
        )
        if authorization.decision == "deny":
            with pytest.raises(ToolCallDenied):
                authorization.raise_for_denied()
        else:
            authorization.raise_for_denied()  # allow -> must not raise

    def test_accepts_none_arguments_hash(self) -> None:
        authorizer = self.make_authorizer()
        authorization = authorizer.authorize(tool_name=SAMPLE_TOOL_NAME, arguments_hash=None)
        assert authorization.decision in _TOOL_DECISIONS
