# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The Kubernetes TTFR agent pod's command: one agent process per run, a pause between.

A run is one agent process, so each one ends and is delivered. The pause is taken in
this process rather than by a shell's ``sleep``: a process the pod starts right after an
agent exits falls inside that run's window (widened by the clocks' uncertainty) and the
host sensor would see it as a process no record explains. Run with ``python -S`` so this
supervisor is not itself captured (the autoload shim is a ``sitecustomize``); the agent
it starts gets the pod's environment unchanged."""

import os
import subprocess
import sys
import time

AGENT = os.environ.get("AGENT_SCRIPT", "/agent/agent_command_tool.py")
PAUSE_S = float(os.environ.get("AGENT_PAUSE_S", "5"))


def main() -> int:
    while True:
        subprocess.run([sys.executable, AGENT], check=False)  # noqa: S603 - the fixture agent
        sys.stdout.flush()
        time.sleep(PAUSE_S)


if __name__ == "__main__":
    sys.exit(main())
