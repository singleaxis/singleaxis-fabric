# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Fail-open, class-only recorder diagnostics (spec 049 §7.1, §7.6).

A recorder diagnostic never carries an exception message, a traceback, a value, an id
or a path (any of them can hold payload text), and a log handler that raises never
reaches the application: the diagnostic is dropped instead."""

from __future__ import annotations

import contextlib
import logging


def safe_log(logger: logging.Logger, level: int, message: str, *args: object) -> None:
    """``logger.log(level, message, *args)`` that never raises. ``args`` must be
    class names, enums or counts: never a value from the application."""
    with contextlib.suppress(Exception):  # a failing handler must not change the app
        logger.log(level, message, *args)


def exc_class(exc: BaseException) -> str:
    """The exception's class name: the only part of an exception a diagnostic carries."""
    return type(exc).__name__
