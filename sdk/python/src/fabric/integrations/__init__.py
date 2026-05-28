# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Framework / protocol integrations that wrap Fabric primitives.

These modules adapt external agent runtimes and tool protocols onto
Fabric's decision-span tracing and control hooks. Unlike the
``judge_adapters`` (which depend on a heavy optional package and ship
behind an import guard), the MCP integration duck-types the MCP client
session via a local Protocol, so the module is always importable — the
``[mcp]`` extra only pulls the real ``mcp`` package in for users.

- ``traced_call_tool`` / ``InstrumentedMCPSession`` ([mcp] extra):
  wrap MCP ``ClientSession.call_tool`` so each invocation emits a
  ``fabric.tool_call`` child span (kind="mcp") under the active
  ``fabric.decision`` and optionally runs through a pre-execution
  tool authorizer.
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
