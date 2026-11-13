# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``--latest`` (spec 058 §13.4, F16): report only the run that started last.

A run starts at its first exchange; a run without one has no start and is never the
latest. The choice is made on a first reading of the same inputs with the same id key,
profile and trust, so the selected run id is exactly as the full report names it; the
report is then built for that run alone (``--run``), so every output (summary,
``--json``, ``--out``, ``--projection``, the action view) describes the same run."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

_STAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$")


def _ns(value: Any) -> int | None:
    match = _STAMP.match(value) if isinstance(value, str) else None
    if match is None:
        return None
    seconds = datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC).timestamp()
    return int(seconds) * 1_000_000_000 + int((match[2] or "0").ljust(9, "0"))


def stamp_ns(value: Any) -> int | None:
    """A report time (RFC 3339 UTC, ``...Z``, up to nanoseconds) in nanoseconds."""
    return _ns(value)


def run_start_ns(run: Mapping[str, Any]) -> int | None:
    """When a reported run started: its first exchange (``None`` without one)."""
    starts = [_ns(exchange.get("started_at")) for exchange in run.get("exchanges") or []]
    known = [start for start in starts if start is not None]
    return min(known) if known else None


def latest_run_id(document: Mapping[str, Any]) -> str | None:
    """The run id of the run that started last; ties go to the greater run id, so the
    choice never depends on input order."""
    dated = [(start, str(run["run_id"])) for run in document.get("runs") or []
             if (start := run_start_ns(run)) is not None]  # fmt: skip
    return max(dated)[1] if dated else None
