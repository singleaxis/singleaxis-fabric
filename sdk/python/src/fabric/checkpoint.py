# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Checkpoint span event for replay-engine consumption.

Spec 012 §Replayability. The SDK emits checkpoints as breadcrumbs;
the replay engine (commercial) consumes them. This module ships the
schema only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Self
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class CheckpointEvent:
    """One save-point on the decision timeline."""

    checkpoint_id: UUID
    step_name: str
    state_hash: str | None = None

    @classmethod
    def create(
        cls,
        *,
        step_name: str,
        state_hash: str | None = None,
        checkpoint_id: UUID | None = None,
    ) -> Self:
        """Build a CheckpointEvent. Auto-generates checkpoint_id if absent.

        Args:
            step_name: human-readable label. Must be non-empty.
            state_hash: optional fingerprint of agent state.
            checkpoint_id: optional pre-supplied ID; uuid4 otherwise.

        Raises:
            ValueError: if step_name is empty or whitespace-only.
        """
        if not step_name or not step_name.strip():
            raise ValueError("step_name must be non-empty")
        return cls(
            checkpoint_id=checkpoint_id or uuid4(),
            step_name=step_name.strip(),
            state_hash=state_hash,
        )
