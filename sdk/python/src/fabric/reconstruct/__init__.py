# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline run reconstruction verifier (spec 042 §10).

``python -m fabric.reconstruct`` reads exchange and loss/watermark spans
(sink JSONL or OTLP/JSON) plus an optional customer content store and
writes a ``fabric.run-reconstruction/v1`` document: per-run exchanges,
threads, gaps and an **integrity** verdict for a declared scope. It is
read-only, carries no content, and never evaluates the agent's behaviour.
"""

from __future__ import annotations

from fabric.reconstruct._inputs import ReconstructInputError, SpanRecord, read_span_file
from fabric.reconstruct._verify import reconstruct

__all__ = ["ReconstructInputError", "SpanRecord", "read_span_file", "reconstruct"]
