# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The AR-1 destination and Node, reused (``qualification/action-record/ar1``): the
loopback OTLP/HTTP sink that decodes what the Node delivers into the sink JSONL the
reader reads, the local-profile Node run from a built ``dist/``, and a free-port helper."""

from __future__ import annotations

import sys
from pathlib import Path

_AR1 = Path(__file__).resolve().parents[2] / "action-record"
if str(_AR1) not in sys.path:
    sys.path.insert(0, str(_AR1))

from ar1.node import Node, free_port, node_dist  # noqa: E402
from ar1.sink import Sink  # noqa: E402

__all__ = ["Node", "Sink", "free_port", "node_dist"]
