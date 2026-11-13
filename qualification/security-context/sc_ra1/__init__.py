# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""SC-RA-1, the spec 057 §10.2 P1 real-agent acceptance run: harness modules.

``agent.py`` holds the agents under test and imports nothing from here (nor from
Fabric); ``mcp_server.py`` is the fixture MCP servers (run by the harness over Streamable
HTTP, launched by the agent over stdio). Every other module is the harness around them:
the replaying fixture model (``model.py``, ``cassette.json``), the runner
(``harness.py``), the independent ground truth (``truth.py``) and the checks
(``check.py``). ``run_sc_ra1.py`` one level up is the entry point.
"""
