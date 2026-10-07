# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Env-gated wire-capture bootstrap (spec 042 §3).

Runs only when this directory is on ``PYTHONPATH``. It:

1. does nothing unless ``FABRIC_WIRE_AUTOLOAD`` is ``1`` or ``true``;
2. calls ``fabric.wire.install_from_env()``, swallowing every failure except
   ``KeyboardInterrupt``/``SystemExit`` and logging at most one warning;
3. then executes the next ``sitecustomize`` on ``sys.path`` (excluding this
   directory) so an existing site customization keeps working.
"""

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
                "fabric.wire: autoload failed (%s); capture is not installed",
                type(exc).__name__,
            )


_SENTINEL = "_fabric_wire_autoload_ran"


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
            resolved = os.path.abspath(entry or os.getcwd())
        except (OSError, TypeError, ValueError):
            continue
        if not _same_dir(resolved, here_real):
            search.append(entry)
    spec = importlib.machinery.PathFinder.find_spec("sitecustomize", search)
    if spec is None or spec.loader is None:
        return
    origin = spec.origin
    if origin is not None and _same_dir(os.path.dirname(os.path.abspath(origin)), here_real):
        return
    module = importlib.util.module_from_spec(spec)
    # The chained module replaces this one under the canonical name, exactly
    # as if it had been imported first.
    sys.modules["sitecustomize"] = module
    spec.loader.exec_module(module)


# Run once per interpreter even if this file is reached again under another
# spelling of its directory (a symlinked venv, /var vs /private/var): a second
# execution would otherwise re-install and chain into itself recursively.
if not getattr(sys, _SENTINEL, False):
    setattr(sys, _SENTINEL, True)
    _install()
    _chain()
