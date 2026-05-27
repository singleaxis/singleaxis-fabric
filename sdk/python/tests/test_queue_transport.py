# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for LocalQueueTransport."""

from __future__ import annotations

from uuid import uuid4

import pytest

from fabric import JudgeContext, JudgeRequest, LocalQueueTransport


def _req(rubric: str = "r") -> JudgeRequest:
    return JudgeRequest(
        request_id=uuid4(),
        decision_id="d",
        rubric_id=rubric,
        dimensions=("dim",),
        context=JudgeContext(),
        payload_ref=None,
    )


def test_enqueue_dequeue_fifo() -> None:
    t = LocalQueueTransport()
    t.enqueue(_req("first"))
    t.enqueue(_req("second"))
    assert len(t) == 2
    a = t.dequeue()
    b = t.dequeue()
    assert a is not None
    assert a.rubric_id == "first"
    assert b is not None
    assert b.rubric_id == "second"
    assert t.dequeue() is None


def test_close_rejects_further_enqueues() -> None:
    t = LocalQueueTransport()
    t.enqueue(_req())
    t.close()
    with pytest.raises(RuntimeError, match="closed"):
        t.enqueue(_req())


def test_close_clears_pending() -> None:
    t = LocalQueueTransport()
    t.enqueue(_req())
    t.enqueue(_req())
    t.close()
    assert len(t) == 0
