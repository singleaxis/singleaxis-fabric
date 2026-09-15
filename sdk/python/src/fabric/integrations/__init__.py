# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Passive protocol integrations that wrap Fabric capture primitives.

The MCP integration duck-types the MCP client session via a local Protocol,
so the module is always importable. The ``[mcp]`` extra only installs the real
``mcp`` package for users connecting to a live server.

- ``traced_call_tool`` / ``InstrumentedMCPSession`` ([mcp] extra):
  wrap MCP ``ClientSession.call_tool`` so each invocation emits a
  tool-named ``execute_tool`` child span (kind="mcp") under the active
  ``fabric.decision`` without altering or authorizing the invocation.
"""

from fabric.integrations.mcp import (
    FABRIC_MCP_SERVER,
    FABRIC_MCP_TRANSPORT,
    InstrumentedMCPSession,
    MCPSessionLike,
    traced_call_tool,
)

__all__ = [
    "FABRIC_MCP_SERVER",
    "FABRIC_MCP_TRANSPORT",
    "InstrumentedMCPSession",
    "MCPSessionLike",
    "traced_call_tool",
]
