# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Scoped raw file descriptors for the descriptor-relative (``dir_fd``) readers."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager


@contextmanager
def open_descriptor(path: str, flags: int, *, dir_fd: int | None = None) -> Iterator[int]:
    """``os.open`` whose descriptor is closed when the block exits, however it exits.

    Errors from ``os.open`` itself (for example ``FileNotFoundError``) propagate
    unchanged and leave nothing to close.
    """
    descriptor = os.open(path, flags, dir_fd=dir_fd)
    try:
        yield descriptor
    finally:
        os.close(descriptor)
