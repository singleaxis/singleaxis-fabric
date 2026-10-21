# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A customer transformation module whose import never finishes (Sol P0-A round 3 #4)."""

from __future__ import annotations

import time

time.sleep(3600)


def fn(data: bytes) -> bytes:  # pragma: no cover - never reached
    return data
