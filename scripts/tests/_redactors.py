# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Customer transformations for these tests, loaded by reference (``_redactors:name``) in
a child process (spec 049 §7.7): this directory is on ``sys.path`` under pytest."""

from __future__ import annotations


def redacted(_data: bytes) -> bytes:
    return b"[redacted]"
