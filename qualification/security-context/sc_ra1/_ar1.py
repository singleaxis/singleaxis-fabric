# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The AR-1 destination, reused: the loopback OTLP/HTTP sink that decodes what the agent
delivers into the sink JSONL the reader reads, and a free-port helper
(``qualification/action-record/ar1``)."""

from __future__ import annotations

import sys
from pathlib import Path

_AR1 = Path(__file__).resolve().parents[2] / "action-record"
if str(_AR1) not in sys.path:
    sys.path.insert(0, str(_AR1))

from ar1.node import free_port  # noqa: E402
from ar1.sink import Sink  # noqa: E402

__all__ = ["Sink", "free_port"]
