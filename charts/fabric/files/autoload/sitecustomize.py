# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Fabric's autoload shim for injected pods (spec 058 section 10.4).

The pod injector mounts this file from a ConfigMap and puts its directory first on
PYTHONPATH. It uses the standard library only and never installs anything. It finds the
Fabric SDK in the image's own Python and hands over to the SDK's autoload, which installs
capture when FABRIC_WIRE_AUTOLOAD=1 and then runs the image's own sitecustomize, if any.
Without the SDK it runs the image's sitecustomize itself and records why capture is off
in autoload-status.json beside the spool directory, never on the process's output. Its
own failures never raise: the program starts as it would without Fabric.
"""

import importlib.machinery
import importlib.util
import json
import os
import sys


def _same(path, here):
    try:
        if os.path.realpath(path) == here:
            return True
        return os.path.isdir(path) and os.path.samefile(path, here)
    except (OSError, TypeError, ValueError):
        return False


def _record(state):
    """Beside the spool the injector mounts (/var/lib/fabric/autoload-status.json)."""
    try:
        spool = os.environ.get("FABRIC_WIRE_SPOOL_DIR", "").strip()
        if not spool or not os.path.isabs(spool):
            return
        path = os.path.join(os.path.dirname(spool.rstrip("/")), "autoload-status.json")
        with open(path, "w") as handle:
            json.dump(
                {
                    "state": state,
                    "python": sys.version.split()[0],
                    "executable": sys.executable,
                    "pid": os.getpid(),
                },
                handle,
            )
    except Exception:  # noqa: BLE001, S110 - recording is best effort
        pass


def _exec(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return
    spec.loader.exec_module(importlib.util.module_from_spec(spec))


def _chain(search):
    spec = importlib.machinery.PathFinder.find_spec("sitecustomize", search)
    if spec is None or spec.loader is None or not spec.origin:
        return
    module = importlib.util.module_from_spec(spec)
    sys.modules["sitecustomize"] = module
    spec.loader.exec_module(module)


_UNEXPANDED = "$(PYTHONPATH)"


def _drop_unexpanded():
    """For a container with envFrom the injector writes PYTHONPATH as
    "<this directory>:$(PYTHONPATH)", so a value one of those sources sets is kept.
    When none sets it, Kubernetes leaves the reference as written: take that text out
    of sys.path and of PYTHONPATH, so neither this program nor one it starts looks
    for modules in a directory of that name."""
    sys.path[:] = [entry for entry in sys.path if os.path.basename(entry) != _UNEXPANDED]
    parts = os.environ.get("PYTHONPATH", "").split(os.pathsep)
    if _UNEXPANDED in parts:
        os.environ["PYTHONPATH"] = os.pathsep.join(p for p in parts if p != _UNEXPANDED)


def _find_autoload():
    """Take this directory off sys.path and return the SDK's autoload file, or None.
    This directory has done its job once Python imported this file: removing it means
    nothing else is looked up here and the SDK's own chaining finds the image's
    sitecustomize, not this shim."""
    here = os.path.realpath(os.path.dirname(os.path.abspath(__file__)))
    sys.path[:] = [
        entry for entry in sys.path if not _same(os.path.abspath(entry or "."), here)
    ]
    spec = importlib.machinery.PathFinder.find_spec("fabric", sys.path)
    for location in (spec.submodule_search_locations or []) if spec is not None else []:
        candidate = os.path.join(location, "_autoload", "sitecustomize.py")
        if os.path.isfile(candidate):
            return candidate
    return None


def _run():
    if getattr(sys, "_fabric_autoload_shim_ran", False):
        return
    sys._fabric_autoload_shim_ran = True
    try:
        _drop_unexpanded()
        autoload = _find_autoload()
    except Exception:  # noqa: BLE001 - never stop the program
        _record("shim_failed")
        autoload = None
    if autoload is None:
        if os.environ.get("FABRIC_WIRE_AUTOLOAD", "").strip().lower() in ("1", "true"):
            _record("sdk_not_found")
        # The image's own sitecustomize runs as it would without Fabric, its errors included.
        _chain(sys.path)
        return
    # The SDK's autoload never raises for its own failures, and then chains to the image's
    # sitecustomize, whose errors Python reports as it would without Fabric.
    _exec(autoload, "_fabric_sdk_autoload")


_run()
