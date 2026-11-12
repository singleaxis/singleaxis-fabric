# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline derivation rules over stored model-wire bytes (spec 057 §4.1, P1).

Each module reads one exchange's verified request or response document, as the reader
already holds it, and returns plain values; nothing here runs in the agent's request path
(B2), opens a file, calls a model or interprets free text (§3.8).

- :mod:`.offered_grant` (``wire.offered_grant``, WP7-4): the tools, tool choice and
  instructions digest one request offered the model, as a ``basis=offered`` grant document.
- :mod:`.safety_map` (``wire.safety_map``, WP7-5): the provider safety-signal map, one row
  per literal response field of a dialect the wire parser supports.
- :mod:`.tool_result` (``wire.tool_result_flag`` and ``wire.tool_result_marker``, WP7-6):
  the tool results a request fed back, their structured error flag, and the customer's
  exact denial markers.
- :mod:`.jsonrpc2` (053 §5.4, frozen) and :mod:`.mcp` (``mcp.jsonrpc``, WP7-7, WP7-8):
  JSON-RPC 2.0 structure, and the MCP method layer over it, for the MCP messages of
  ``http.nonmodel`` and ``mcp.client`` records.

Supported dialects are the ones the wire parser already reads (``openai.chat_completions``,
``openai.responses``, ``anthropic.messages``; ``openai.completions`` and
``openai.embeddings`` offer no tools). Another dialect yields nothing.
"""

from __future__ import annotations

#: The derivation rules of this package, as the capture manifest names them (§6.4).
OFFERED_GRANT = "wire.offered_grant"
SAFETY_MAP = "wire.safety_map"
TOOL_RESULT_FLAG = "wire.tool_result_flag"
TOOL_RESULT_MARKER = "wire.tool_result_marker"
MCP_JSONRPC = "mcp.jsonrpc"
RULES = (OFFERED_GRANT, SAFETY_MAP, TOOL_RESULT_FLAG, TOOL_RESULT_MARKER, MCP_JSONRPC)

__all__ = [
    "MCP_JSONRPC", "OFFERED_GRANT", "RULES", "SAFETY_MAP", "TOOL_RESULT_FLAG",
    "TOOL_RESULT_MARKER",
]  # fmt: skip
