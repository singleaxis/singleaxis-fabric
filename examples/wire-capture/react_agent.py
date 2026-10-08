# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Wire capture of a ReAct loop, then offline reconstruction (spec 042).

A tiny ReAct agent talks to an OpenAI-compatible chat-completions endpoint
through a plain ``httpx`` client. The "model" is an ``httpx.MockTransport``
handler, so the example runs fully offline. ``fabric.wire`` tees the exact
request and response bytes of every model call into a local content store;
spans (ids, digests and metadata only) go to a JSONL file. Afterwards
``python -m fabric.reconstruct`` reads the stored bytes, stitches the run
offline from them and states an integrity verdict.

Run from the repository root::

    sdk/python/.venv/bin/python examples/wire-capture/react_agent.py

Nothing here is framework-specific: any agent that sends its model calls
through httpx (the OpenAI and Anthropic SDKs, LiteLLM, hand-written clients)
is captured the same way.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import httpx
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult

from fabric import wire
from fabric.content_store import LocalFilesystemContentStore

TENANT = "demo-tenant"
RUN_ID = "react-demo-1"
MODEL_URL = "http://model.local/v1/chat/completions"

# An OpenAI-compatible endpoint that is not in DEFAULT_ENDPOINTS (vLLM,
# Ollama, an internal proxy...). Plain http must be listed explicitly.
FAKE_MODEL_ENDPOINT = wire.EndpointMatcher(
    endpoint_id="fake-model",
    dialect="openai",
    hosts=frozenset({"model.local"}),
    provider_name="openai",
    schemes=frozenset({"http"}),
)

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Current temperature for a city, in Celsius.",
            "parameters": {
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "c_to_f",
            "description": "Convert Celsius to Fahrenheit.",
            "parameters": {
                "type": "object",
                "properties": {"celsius": {"type": "number"}},
                "required": ["celsius"],
            },
        },
    },
]


# --------------------------------------------------------------------------
# Span sink: one JSON row per finished span (the demo sink JSONL format)
# --------------------------------------------------------------------------


class JsonlSpanExporter(SpanExporter):
    """Write each span as ``{"kind": "span", ...}``: ids, digests, metadata."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        rows = [json.dumps(_row(span), sort_keys=True) for span in spans]
        with self._lock, self._path.open("a", encoding="utf-8") as handle:
            for row in rows:
                handle.write(row + "\n")
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


def _plain(value: Any) -> Any:
    return list(value) if isinstance(value, tuple) else value


def _row(span: ReadableSpan) -> dict[str, Any]:
    context = span.get_span_context()
    parent = span.parent
    return {
        "kind": "span",
        "trace_id": f"{context.trace_id:032x}" if context else None,
        "span_id": f"{context.span_id:016x}" if context else None,
        "parent_span_id": f"{parent.span_id:016x}" if parent else None,
        "name": span.name,
        "start_ns": span.start_time,
        "end_ns": span.end_time,
        "resource": {k: _plain(v) for k, v in span.resource.attributes.items()},
        "attributes": {k: _plain(v) for k, v in (span.attributes or {}).items()},
    }


# --------------------------------------------------------------------------
# The fake model: an OpenAI-compatible chat-completions responder
# --------------------------------------------------------------------------


def fake_model(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    messages = body["messages"]
    tool_results = [m for m in messages if m.get("role") == "tool"]
    step = len(tool_results)
    if step == 0:
        message: dict[str, Any] = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_weather_1",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": '{"city": "Paris"}'},
                }
            ],
        }
        finish = "tool_calls"
    elif step == 1:
        celsius = json.loads(tool_results[0]["content"])["celsius"]
        message = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_convert_1",
                    "type": "function",
                    "function": {"name": "c_to_f", "arguments": json.dumps({"celsius": celsius})},
                }
            ],
        }
        finish = "tool_calls"
    else:
        fahrenheit = json.loads(tool_results[-1]["content"])["fahrenheit"]
        message = {"role": "assistant", "content": f"It is {fahrenheit:.1f} F in Paris."}
        finish = "stop"
    return httpx.Response(
        200,
        headers={"x-request-id": f"req_demo_{step}"},
        json={
            "id": f"chatcmpl-demo-{step}",
            "object": "chat.completion",
            "model": body["model"],
            "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": {"prompt_tokens": 40 + 20 * step, "completion_tokens": 12},
        },
    )


# --------------------------------------------------------------------------
# The agent: a plain ReAct loop over an httpx client
# --------------------------------------------------------------------------


def get_weather(city: str) -> dict[str, Any]:
    return {"city": city, "celsius": 18.5}


def c_to_f(celsius: float) -> dict[str, Any]:
    return {"fahrenheit": celsius * 9 / 5 + 32}


TOOL_IMPLS: dict[str, Callable[..., dict[str, Any]]] = {
    "get_weather": get_weather,
    "c_to_f": c_to_f,
}


def react(client: httpx.Client, question: str, *, max_steps: int = 5) -> str:
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": "You are a helpful assistant. Use tools."},
        {"role": "user", "content": question},
    ]
    for _ in range(max_steps):
        response = client.post(
            MODEL_URL,
            headers={"authorization": "Bearer demo-not-a-real-key"},
            json={"model": "demo-model", "messages": messages, "tools": TOOLS},
        )
        response.raise_for_status()
        message = response.json()["choices"][0]["message"]
        messages.append(message)  # re-send the assistant turn exactly as received
        calls = message.get("tool_calls") or []
        if not calls:
            return str(message.get("content"))
        for call in calls:
            args = json.loads(call["function"]["arguments"])
            result = TOOL_IMPLS[call["function"]["name"]](**args)
            messages.append(
                {"role": "tool", "tool_call_id": call["id"], "content": json.dumps(result)}
            )
    raise RuntimeError("agent did not finish")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def capture(out_dir: Path) -> tuple[Path, Path, str]:
    spans_path = out_dir / "spans.jsonl"
    store_root = out_dir / "store"
    provider = TracerProvider(resource=Resource.create({"service.name": "wire-capture-demo"}))
    provider.add_span_processor(SimpleSpanProcessor(JsonlSpanExporter(spans_path)))
    store = LocalFilesystemContentStore(root=str(store_root), tenant_id=TENANT)

    handle = wire.install(
        store=store,
        tracer_provider=provider,
        extra_endpoints=(FAKE_MODEL_ENDPOINT,),
        # The explicit WireTransport below does the capture; leave the
        # process-wide httpx transports untouched.
        patch_httpx=False,
    )
    try:
        client = httpx.Client(transport=wire.WireTransport(httpx.MockTransport(fake_model)))
        with client, wire.run(RUN_ID):
            answer = react(client, "What is the temperature in Paris in Fahrenheit?")
        if not handle.flush(10.0):
            raise RuntimeError("capture pipeline did not drain")
    finally:
        handle.close()
        provider.shutdown()
    return spans_path, store_root, answer


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "output",
        help="where to write spans.jsonl, store/ and report.json (recreated)",
    )
    args = parser.parse_args(argv)
    out_dir: Path = args.out_dir.resolve()
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True)

    spans_path, store_root, answer = capture(out_dir)
    print(f"agent answer: {answer}")
    print(f"spans:        {spans_path}")
    print(f"store:        {store_root}", flush=True)

    report_path = out_dir / "report.json"
    command = [
        sys.executable,
        "-m",
        "fabric.reconstruct",
        "--spans",
        str(spans_path),
        "--store-root",
        str(store_root),
        "--tenant",
        TENANT,
        "--out",
        str(report_path),
    ]
    print("$ python -m fabric.reconstruct " + " ".join(command[3:]), flush=True)
    code = subprocess.run(command, check=False).returncode  # noqa: S603
    report = json.loads(report_path.read_text("utf-8"))
    for run in report["runs"]:
        print(f"run {run['run_id']}: verdict={run['verdict']}")
        for thread in run.get("threads", []):
            print(f"  {thread.get('thread_id')}: exchanges={thread.get('exchange_ids')}")
        for gap in run.get("gaps", []):
            print(f"  gap {gap['gap_type']} ({gap['effect']}): {gap.get('reason')}")
    print(f"reconstruct exit code: {code}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
