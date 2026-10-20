# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Frameworks and scenarios of the agent matrix."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
VENVS = ROOT / ".work" / "venvs"

ALL = ("simple", "stream", "parallel", "retry429", "disconnect", "multimodal", "long50", "node")

# Scenario-specific capture settings. The multimodal request carries two ~103 KiB base64
# images, far below the 32 MiB default body cap, so the cap is lowered to 160 KiB: the
# side (~207 KiB) then exceeds it and typed extraction splits it into a skeleton plus two
# model.exchange.part objects that each fit the cap (spec 049 §7.4).
SCENARIOS: dict[str, dict[str, Any]] = {
    "simple": {}, "stream": {}, "parallel": {}, "retry429": {}, "disconnect": {},
    "multimodal": {"env": {"FABRIC_WIRE_MAX_BODY_BYTES": "163840",
                           "FABRIC_WIRE_PART_MIN_BYTES": "1024"}},
    "long50": {}, "node": {}, "error400": {},
}  # fmt: skip


@dataclass(frozen=True)
class Framework:
    name: str
    venv: str
    agent: str
    variant: str = ""
    scenarios: tuple[str, ...] = ALL
    # scenario -> why it does not apply to this framework (reported, never a pass)
    not_applicable: dict[str, str] = field(default_factory=dict)
    note: str = ""
    env: dict[str, str] = field(default_factory=dict)  # framework settings, never FABRIC_*
    # "isolated": python -I + harness/launch.py (autoload emulated); "pythonpath": the
    # documented PYTHONPATH autoload with python -s -P (spawned children inherit it).
    launch: str = "isolated"

    @property
    def python(self) -> Path:
        return VENVS / self.venv / "bin" / "python"


NO_TOOLS = "the pipeline has no tool calls"
FRAMEWORKS: dict[str, Framework] = {f.name: f for f in (
    Framework("openai", "openai", "openai_plain.py", note="chat completions, hand-written loop"),
    Framework("openai-responses", "openai", "openai_plain.py", variant="responses",
              note="Responses API, hand-written loop"),
    Framework("anthropic", "anthropic", "anthropic_plain.py", note="Messages API, tool loop"),
    Framework("openai-agents", "openai-agents", "openai_agents_sdk.py",
              note="Runner + function tools, Responses model"),
    Framework("openai-agents-chat", "openai-agents", "openai_agents_sdk.py", variant="chat",
              note="Runner + function tools, Chat Completions model"),
    Framework("langgraph", "langgraph", "langgraph_agent.py",
              note="create_react_agent + langchain-openai ChatOpenAI"),
    Framework("llamaindex", "llamaindex", "llamaindex_agent.py",
              note="FunctionAgent + OpenAILike"),
    Framework("pydantic-ai", "pydantic-ai", "pydantic_ai_agent.py", note="OpenAIChatModel"),
    Framework("pydantic-ai-anthropic", "pydantic-ai", "pydantic_ai_agent.py",
              variant="anthropic", note="AnthropicModel"),
    Framework("smolagents", "smolagents", "smolagents_agent.py",
              note="ToolCallingAgent + OpenAIServerModel"),
    Framework("autogen", "autogen", "autogen_agent.py",
              note="AgentChat AssistantAgent + OpenAIChatCompletionClient"),
    Framework("ag2", "ag2", "ag2_agent.py", note="two ConversableAgents + register_function"),
    Framework("crewai", "crewai", "crewai_agent.py", note="Agent/Task/Crew + crewai.LLM"),
    Framework("dspy", "dspy", "dspy_agent.py", note="dspy.ReAct + dspy.LM (LiteLLM)"),
    Framework("dspy-httpx", "dspy", "dspy_agent.py",
              note="as dspy, LiteLLM async on httpx (DISABLE_AIOHTTP_TRANSPORT=True)",
              env={"DISABLE_AIOHTTP_TRANSPORT": "True"}),
    # Patterns
    Framework("handoff", "openai-agents", "openai_agents_sdk.py", variant="handoff",
              note="multi-agent handoff: triage -> specialist (OpenAI Agents SDK)"),
    Framework("rag", "llamaindex", "llamaindex_agent.py", variant="rag",
              note="RAG: VectorStoreIndex, OpenAI-compatible embeddings + chat (LlamaIndex)",
              not_applicable={"parallel": NO_TOOLS, "multimodal": "text-only retrieval"}),
    Framework("gather", "openai", "openai_gather.py",
              note="asyncio.gather fan-out of 8 tool loops on one AsyncOpenAI client"),
    Framework("pool-spawn", "openai", "openai_pool.py", launch="pythonpath",
              note="multiprocessing Pool(4), spawn start method (macOS default); "
                   "documented PYTHONPATH autoload, since python -I children cannot inherit it"),
    Framework("pool-fork", "openai", "openai_pool.py", variant="fork",
              note="multiprocessing Pool(4), fork start method (Linux default)"),
    Framework("pool-spawn-join", "openai", "openai_pool.py", variant="spawn-join",
              launch="pythonpath",
              note="as pool-spawn, but pool.close(); pool.join() instead of the with block"),
    Framework("pool-fork-join", "openai", "openai_pool.py", variant="fork-join",
              note="as pool-fork, but pool.close(); pool.join() instead of the with block"),
    # Probe only (not in the matrix): openai SDK + requests + aiohttp in one process.
    Framework("mixed-clients", "llamaindex", "mixed_clients.py", scenarios=("simple",),
              note="probe: three HTTP clients in one process"),
)}  # fmt: skip
