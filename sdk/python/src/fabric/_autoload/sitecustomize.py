# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Env-gated wire-capture bootstrap (spec 047 §3), only from ``PYTHONPATH``: with
``FABRIC_WIRE_AUTOLOAD=1``/``true`` it calls ``fabric.wire.install_from_env()``, swallowing
every failure but ``KeyboardInterrupt``/``SystemExit`` (one warning naming the class), then
runs the next ``sitecustomize`` on ``sys.path`` so an existing one keeps working."""

from __future__ import annotations

import contextlib
import importlib.machinery
import importlib.util
import logging
import os
import sys


def _install() -> None:
    if os.environ.get("FABRIC_WIRE_AUTOLOAD", "").strip().lower() not in ("1", "true"):
        return
    try:
        from fabric.wire import install_from_env  # noqa: PLC0415

        install_from_env()
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:
        with contextlib.suppress(Exception):
            logging.getLogger("fabric.wire").warning(
                "fabric.wire: autoload failed (%s); capture is not installed", type(exc).__name__
            )


def _same_dir(path: str, here_real: str) -> bool:
    """Whether ``path`` is this directory under any spelling (symlinks included)."""
    try:
        if os.path.realpath(path) == here_real:
            return True
        return os.path.isdir(path) and os.path.samefile(path, here_real)
    except (OSError, TypeError, ValueError):
        return False


def _chain() -> None:
    here_real = os.path.realpath(os.path.dirname(os.path.abspath(__file__)))
    search: list[str] = []
    for entry in sys.path:
        try:
            if not _same_dir(os.path.abspath(entry or os.getcwd()), here_real):
                search.append(entry)
        except (OSError, TypeError, ValueError):
            continue
    spec = importlib.machinery.PathFinder.find_spec("sitecustomize", search)
    if spec is None or spec.loader is None:
        return
    origin = spec.origin
    if origin is not None and _same_dir(os.path.dirname(os.path.abspath(origin)), here_real):
        return
    module = importlib.util.module_from_spec(spec)
    sys.modules["sitecustomize"] = module  # as if it had been imported first
    spec.loader.exec_module(module)


# Once per interpreter, even if reached again under another spelling of this
# directory (a symlinked venv, /var vs /private/var): no re-install, no recursion.
if not getattr(sys, "_fabric_wire_autoload_ran", False):
    sys._fabric_wire_autoload_ran = True  # type: ignore[attr-defined]
    _install()
    _chain()
