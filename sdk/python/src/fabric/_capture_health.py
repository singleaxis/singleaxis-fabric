# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Local decision-span loss visibility; never an end-to-end capture proof."""

from __future__ import annotations

import logging
from typing import Literal, TypedDict


class DecisionCaptureHealth(TypedDict):
    """Local metadata only. Unknown counters stay null; healthy stays unverified."""

    status: Literal["unverified", "disabled", "partial"]
    scope: Literal["decision_span_only"]
    recording_at_start: bool | None
    dropped_events: int | None
    dropped_attributes: int | None


_LOG = logging.getLogger("fabric.capture_health")
_WARNED: set[str] = set()


def recording_state(span: object) -> bool | None:
    try:
        value = span.is_recording()  # type: ignore[attr-defined]  # host-owned OTel span
    except Exception:
        return None
    return value if isinstance(value, bool) else None


def _counter(span: object | None, name: str) -> int | None:
    try:
        value = getattr(span, name, None)
    except Exception:
        return None
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def capture_health(span: object | None, recording: bool | None) -> DecisionCaptureHealth:
    events = _counter(span, "dropped_events")
    attributes = _counter(span, "dropped_attributes")
    status: Literal["unverified", "disabled", "partial"] = "unverified"
    if recording is False:
        status = "disabled"
    elif (events is not None and events > 0) or (attributes is not None and attributes > 0):
        status = "partial"
    return {
        "status": status,
        "scope": "decision_span_only",
        "recording_at_start": recording,
        "dropped_events": events,
        "dropped_attributes": attributes,
    }


def warn_capture_health(health: DecisionCaptureHealth) -> None:
    """One fixed warning per process/reason; logging cannot change agent results."""
    status = health["status"]
    if status == "unverified" or status in _WARNED:
        return
    _WARNED.add(status)
    try:
        if status == "disabled":
            _LOG.warning(
                "Fabric decision span is not recording; local capture is disabled. "
                "Inspect Decision.capture_health and host sampling/provider configuration."
            )
        else:
            _LOG.warning(
                "Fabric decision span has dropped events or attributes; local capture is partial. "
                "Inspect Decision.capture_health; this is not an exporter delivery assessment."
            )
    except Exception:  # noqa: S110 - logging failure must not change agent behavior
        # Host logging handlers must not turn observation into enforcement.
        pass
