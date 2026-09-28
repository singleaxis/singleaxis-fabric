# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Opt-in byte-call adapter for testing an existing Python agent boundary.

This is not automatic interception. The caller must place it at the final
observable byte boundary and independently establish that no route bypasses
the adapter. See spec 042 before using it for a coverage claim.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import suppress
from inspect import isawaitable
from typing import TypeVar

from fabric.adapters.synthetic_evidence import SyntheticCaptureSession

_T = TypeVar("_T")
_ROLES = {
    "model": ("provider_bound", "model.request.messages", "model.output.messages"),
    "tool": ("tool", "tool.call.arguments", "tool.call.result"),
}


class ByteBoundaryAdapter:
    """Observe a synchronous byte-oriented call without replacing its delegate.

    ``context=None`` means absent; ``context=b""`` is a present zero-byte
    object. A non-byte payload or result is passed through unchanged but
    labelled unsupported, never serialized by a guessed representation.
    """

    def __init__(
        self,
        session: SyntheticCaptureSession,
        *,
        kind: str,
        source_id: str,
    ) -> None:
        if kind not in _ROLES:
            raise ValueError("kind must be model or tool")
        if not source_id or not source_id.isascii() or not source_id.replace("-", "").isalnum():
            raise ValueError("source_id must be a simple non-empty ASCII identifier")
        self.session = session
        self.source_id = source_id
        self.boundary, self.input_role, self.output_role = _ROLES[kind]

    def _capture_or_gap(
        self,
        value: object,
        *,
        role: str,
        operation_id: str,
        attempt_id: str,
    ) -> None:
        try:
            if isinstance(value, bytes):
                self.session.capture(
                    value,
                    source_id=self.source_id,
                    boundary=self.boundary,
                    role=role,
                    operation_id=operation_id,
                    attempt_id=attempt_id,
                )
            else:
                self.session.gap(
                    source_id=self.source_id,
                    boundary=self.boundary,
                    role=role,
                    operation_id=operation_id,
                    attempt_id=attempt_id,
                    status="unsupported",
                    reason="not_exact_bytes",
                )
        except Exception:
            # Recording cannot change the monitored call. The fallback gap
            # is best effort; independent truth must expose a total failure.
            with suppress(Exception):
                self.session.gap(
                    source_id=self.source_id,
                    boundary=self.boundary,
                    role=role,
                    operation_id=operation_id,
                    attempt_id=attempt_id,
                    status="failed",
                    reason="recording_handler_failed",
                )

    def _outcome(self, operation_id: str, attempt_id: str, status: str) -> None:
        try:
            self.session.outcome(
                source_id=self.source_id,
                boundary=self.boundary,
                operation_id=operation_id,
                attempt_id=attempt_id,
                result_status=status,
            )
        except Exception:
            with suppress(Exception):
                self.session.gap(
                    source_id=self.source_id,
                    boundary=self.boundary,
                    role=self.output_role,
                    operation_id=operation_id,
                    attempt_id=attempt_id,
                    status="failed",
                    reason="outcome_recording_failed",
                )

    def call(
        self,
        payload: bytes,
        delegate: Callable[[bytes], _T],
        *,
        operation_id: str,
        attempt_id: str,
        context: bytes | None = None,
    ) -> _T:
        """Call ``delegate`` exactly once and preserve its result or exception."""
        if context is not None:
            self._capture_or_gap(
                context,
                role="interaction.payload",
                operation_id=operation_id,
                attempt_id=attempt_id,
            )
        self._capture_or_gap(
            payload,
            role=self.input_role,
            operation_id=operation_id,
            attempt_id=attempt_id,
        )
        try:
            result = delegate(payload)
        except BaseException as exc:
            with suppress(Exception):
                self.session.gap(
                    source_id=self.source_id,
                    boundary=self.boundary,
                    role=self.output_role,
                    operation_id=operation_id,
                    attempt_id=attempt_id,
                    status="failed",
                    reason="delegate_raised",
                )
            self._outcome(
                operation_id,
                attempt_id,
                "cancelled" if isinstance(exc, KeyboardInterrupt) else "error",
            )
            raise
        self._capture_or_gap(
            result,
            role=self.output_role,
            operation_id=operation_id,
            attempt_id=attempt_id,
        )
        if isawaitable(result) or isinstance(result, Iterator):
            self._outcome(operation_id, attempt_id, "deferred")
        else:
            self._outcome(operation_id, attempt_id, "ok")
        return result
