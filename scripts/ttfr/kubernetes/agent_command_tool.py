# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The Kubernetes TTFR's agent: the httpx tool-calling agent of the laptop TTFR, whose
tool gets its reading by running a command, as an agent's tools often do. It knows
nothing of Fabric.

The command is what lets the host sensor's evidence be joined to this run (spec 056
§4.3): the sensor sees the agent's process by its pid in the pod's own pid namespace,
and the agent's run names that pid and namespace only through a subprocess it started
(``FABRIC_WIRE_EXEC``, on with the chart's host sensor). An agent that runs no command
has its model calls recorded and verified, but its connections stay unexplained."""

import json
import subprocess
import sys

import httpx_tool_loop


def get_weather(city: str) -> dict:
    reading = subprocess.run(  # noqa: S603 - a fixed command of the fixture
        ["/bin/echo", "18.5"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    return {"city": city, "celsius": json.loads(reading.stdout)}


if __name__ == "__main__":
    httpx_tool_loop.get_weather = get_weather
    sys.exit(httpx_tool_loop.main())
