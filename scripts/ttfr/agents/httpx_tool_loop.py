# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A plain tool-calling agent on httpx, no provider SDK: the second "own agent" of the
TTFR test (spec 058 §3.3). It knows nothing of Fabric and imports nothing from this
repository. It finds its model in OPENAI_BASE_URL, else its own AGENT_MODEL_URL."""

import json
import os
import sys

import httpx


def get_weather(city: str) -> dict:
    return {"city": city, "celsius": 18.5}


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Current weather for a city",
            "parameters": {
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"],
            },
        },
    }
]


def main() -> int:
    base_url = (
        os.environ.get("OPENAI_BASE_URL") or os.environ["AGENT_MODEL_URL"]
    ).rstrip("/")
    headers = {"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}"}
    messages = [{"role": "user", "content": "What is the weather in Lisbon?"}]
    with httpx.Client(timeout=60) as client:
        for _ in range(4):
            response = client.post(
                f"{base_url}/chat/completions",
                headers=headers,
                json={
                    "model": os.environ.get("AGENT_MODEL", "fixture-model"),
                    "messages": messages,
                    "tools": TOOLS,
                },
            )
            response.raise_for_status()
            reply = response.json()["choices"][0]["message"]
            if not reply.get("tool_calls"):
                print(json.dumps({"answer": reply.get("content")}))
                return 0
            messages.append(reply)
            for call in reply["tool_calls"]:
                result = get_weather(**json.loads(call["function"]["arguments"]))
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call["id"],
                        "content": json.dumps(result),
                    }
                )
    print("no answer after 4 turns", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
