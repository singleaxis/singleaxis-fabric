# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A customer transformation module whose import holds the GIL indefinitely (a
catastrophic regex): no thread of its interpreter runs meanwhile (Sol P0-A round 3 #4)."""

from __future__ import annotations

import re

re.sub(rb"(a+)+$", b"x", b"a" * 48 + b"!")


def fn(data: bytes) -> bytes:  # pragma: no cover - never reached
    return data
