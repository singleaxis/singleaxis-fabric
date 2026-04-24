# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tiny deterministic rails engine used in tests."""

from __future__ import annotations

from fabric_nemo_sidecar.rails import EngineResult


class KeywordEngine:
    """Flag a small set of trigger keywords. Used to prove the wire
    contract end-to-end without pulling NeMo."""

    def check(self, phase: str, path: str, value: str) -> EngineResult:
        lowered = value.lower()
        if "ignore previous instructions" in lowered:
            return EngineResult(
                allowed=False,
                action="block",
                rail="jailbreak_defence",
                block_response="I can't help with that.",
                modified_value="",
            )
        if "baseball" in lowered:
            return EngineResult(
                allowed=True,
                action="warn",
                rail="off_topic",
                block_response=None,
                modified_value="(off-topic) " + value,
            )
        return EngineResult(
            allowed=True,
            action="allow",
            rail="on_topic",
            block_response=None,
            modified_value=value,
        )
