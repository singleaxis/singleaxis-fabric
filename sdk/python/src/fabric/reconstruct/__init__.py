# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline run reconstruction verifier (spec 042 §9).

``python -m fabric.reconstruct`` reads exchange, loss and heartbeat spans
(sink JSONL or OTLP/JSON) plus the customer content store holding the exact
exchange bytes, and writes a ``fabric.run-reconstruction/v1`` document:
per-run exchanges, threads, gaps and an **integrity** verdict per
``fabric.wire.run()`` scope and per run (a scoped run is at best
``complete_for_observed_scopes``; see ``COMPLETE_VERDICTS``). It is the only
component that parses messages (stitching happens here, from stored bytes,
never at capture time). It is read-only, carries no content, and never
evaluates the agent's behaviour.
"""

from __future__ import annotations

from fabric.reconstruct._ids import run_id_pseudonym
from fabric.reconstruct._inputs import ReconstructInputError, SpanRecord, read_span_file
from fabric.reconstruct._report import COMPLETE_VERDICTS
from fabric.reconstruct._verify import reconstruct

__all__ = [
    "COMPLETE_VERDICTS",
    "ReconstructInputError",
    "SpanRecord",
    "read_span_file",
    "reconstruct",
    "run_id_pseudonym",
]
