# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Run one agent script inside a framework venv, outside that venv.

    <venv>/bin/python -I harness/launch.py agents/<framework>.py [args...]

``python -I`` ignores ``PYTHONPATH`` (it implies ``-E``), so the documented zero-code
autoload (``PYTHONPATH=$(python -m fabric.wire --print-autoload-path)`` plus
``FABRIC_WIRE_AUTOLOAD=1``) cannot reach an isolated interpreter. This launcher puts
the autoload directory first on ``sys.path`` and imports ``sitecustomize`` from it,
which is exactly what ``PYTHONPATH`` would have done at startup, before any agent or
framework module is imported. It contains no capture code of its own: whether
anything is captured is decided by the same ``FABRIC_*`` variables autoload reads.

``MATRIX_LAUNCH=pythonpath`` skips the emulation (the interpreter was started with
``-s -P`` and a real ``PYTHONPATH``: the documented mechanism, used as a cross-check).

``MATRIX_TRANSFORM`` (privacy runs only) installs capture with a customer
transformation instead of autoload: ``redact``/``masked_only``/``original_plus_masked``
need a ``Transformation`` object and there is no environment variable for one. This is
a configuration hook, not agent code, and the report flags those runs as such.
"""

from __future__ import annotations

import importlib
import os
import sys
import types


def _emulate_pythonpath_autoload() -> None:
    directory = os.environ.get("MATRIX_AUTOLOAD_DIR")
    if not directory or os.environ.get("MATRIX_LAUNCH") == "pythonpath":
        return
    sys.path.insert(0, directory)
    if "sitecustomize" in sys.modules:  # site already ran one from site-packages
        sys.stderr.write("matrix-launch: a sitecustomize was already imported\n")
        del sys.modules["sitecustomize"]
    importlib.import_module("sitecustomize")


def _transform_install() -> None:
    mode = os.environ.get("MATRIX_TRANSFORM")
    if not mode:
        return
    from fabric.wire import Transformation, install  # noqa: PLC0415
    from fabric.wire._config import config_from_env  # noqa: PLC0415

    secret = os.environ.get("MATRIX_SECRET", "")

    def mask(data: bytes) -> bytes:
        if mode == "fail":
            raise RuntimeError(f"transformation failed on {secret}")
        return data.replace(secret.encode(), b"[masked]") if secret else data

    roles = ("model.exchange.request", "model.exchange.response", "model.exchange.part")
    t = Transformation("matrix-mask", "v1", mask)
    config, _ = config_from_env(os.environ)
    install(config, transformations=dict.fromkeys(roles, t))


def main() -> None:
    if len(sys.argv) < 2:
        sys.stderr.write("usage: launch.py AGENT.py [args...]\n")
        raise SystemExit(2)
    _emulate_pythonpath_autoload()
    _transform_install()
    agent = os.path.abspath(sys.argv[1])
    sys.path.append(os.path.dirname(agent))  # the harness's own agents/_common.py
    sys.argv = [agent, *sys.argv[2:]]
    # A real __main__ module so multiprocessing (spawn) re-imports the agent, not us.
    module = types.ModuleType("__main__")
    module.__file__ = agent
    module.__builtins__ = __builtins__
    sys.modules["__main__"] = module
    with open(agent, "rb") as handle:
        code = compile(handle.read(), agent, "exec")
    exec(code, module.__dict__)  # noqa: S102


if __name__ == "__main__":
    main()
