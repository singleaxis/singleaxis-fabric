# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Env-gated wire-capture bootstrap (spec 047 §3), only from ``PYTHONPATH``: with
``FABRIC_WIRE_AUTOLOAD=1``/``true`` it calls ``fabric.wire.install_from_env()``, swallowing
every failure but ``KeyboardInterrupt``/``SystemExit`` (one warning naming the class), then
runs the next ``sitecustomize`` on ``sys.path`` so an existing one keeps working.

Every process that inherits this environment loads it, including each Python child an
agent's tool starts, and that child's stdout and stderr are what the model reads. So
Fabric's diagnostics (configuration warnings above all) never reach the process's own
output: the ``fabric`` logger gets a ``NullHandler`` and stops propagating, which keeps
them off Python's last-resort stderr handler and out of any handler the application
installs. ``FABRIC_WIRE_DIAGNOSTICS=stderr`` prints them to stderr (in every autoloaded
process); ``python -m fabric.wire status`` reports the configuration diagnostics without
running an agent."""

from __future__ import annotations

import contextlib
import importlib.machinery
import importlib.util
import logging
import os
import sys


def _is_fabric_tool() -> bool:
    """``python -m fabric.wire drain`` or ``status``: the spool drainer and the status
    command run with the agent's own environment (autoload included) but must never capture
    themselves, which would add an epoch of their own to the agent's spool."""
    argv = list(getattr(sys, "orig_argv", ()))
    for index, arg in enumerate(argv[:-2]):
        if (
            arg == "-m"
            and argv[index + 1] == "fabric.wire"
            and argv[index + 2] in ("drain", "status")
        ):
            return True
    return False


def _quiet_diagnostics() -> None:
    """Keep Fabric's log records off this process's stdout and stderr (see the module
    docstring), unless ``FABRIC_WIRE_DIAGNOSTICS=stderr`` asks for them there."""
    logger = logging.getLogger("fabric")
    logger.propagate = False
    if not any(isinstance(h, logging.NullHandler) for h in logger.handlers):
        logger.addHandler(logging.NullHandler())
    wanted = os.environ.get("FABRIC_WIRE_DIAGNOSTICS", "").strip().lower() == "stderr"
    if wanted and not any(getattr(h, "_fabric_diagnostics", False) for h in logger.handlers):
        handler = logging.StreamHandler(sys.stderr)  # "%(message)s", as the last resort
        handler.setLevel(logging.WARNING)
        handler._fabric_diagnostics = True  # type: ignore[attr-defined]
        logger.addHandler(handler)


def _install() -> None:
    if os.environ.get("FABRIC_WIRE_AUTOLOAD", "").strip().lower() not in ("1", "true"):
        return
    if _is_fabric_tool():
        return
    with contextlib.suppress(Exception):
        _quiet_diagnostics()
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
