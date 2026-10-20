# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Deterministic fake OpenAI-compatible model for the chaos harness (loopback only).

Run as a process: ``python fakemodel.py --port P --log PATH``. ``POST /v1/chat/completions``
answers deterministically from the request bytes, so an application can check that the
result it received is exactly the result it would get without Fabric (I1):

    answer = "ans-" + sha256(request body)[:24]

The request may carry a ``chaos`` object (ignored by real models) that shapes the reply:

- ``stream`` (top-level, OpenAI's own flag): SSE ``chat.completion.chunk`` events;
- ``sse_events``: number of content events in a stream (default 4);
- ``resp_bytes``: pad the non-streamed answer's content to about this many bytes;
- ``encoding``: ``gzip`` or ``br`` (Content-Encoding of the response body);
- ``invalid_utf8``: put invalid UTF-8 bytes in the response (non-streamed, raw);
- ``nested``: depth of a nested JSON array in the response;
- ``delay_ms``: wait before answering; ``chunk_delay_ms``: wait between SSE events;
- ``kill_pid`` + ``kill_after_events``: SIGKILL that pid after sending that many SSE
  events (a kill exactly mid-stream);
- ``status``: reply with this HTTP status (error path);
- ``nonce``, ``run``, ``call``: logged, never interpreted.

Every request is logged as one JSON line (fsync'd): nonce, run, call, request digest and
length, response status, answer. The log is the harness's ground truth of what the model
served.
"""

from __future__ import annotations

import argparse
import asyncio
import gzip
import hashlib
import json
import os
import signal
import threading
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

_LOG_LOCK = threading.Lock()
_LOG_FD: int | None = None
_FSYNC = True


def _log(row: dict[str, Any]) -> None:
    if _LOG_FD is None:
        return
    data = (json.dumps(row, sort_keys=True) + "\n").encode()
    with _LOG_LOCK:
        os.write(_LOG_FD, data)
        if _FSYNC:
            os.fsync(_LOG_FD)


def answer_for(body: bytes) -> str:
    return "ans-" + hashlib.sha256(body).hexdigest()[:24]


def _encode(data: bytes, encoding: str | None) -> tuple[bytes, dict[str, str]]:
    if encoding == "gzip":
        return gzip.compress(data, mtime=0), {"content-encoding": "gzip"}
    if encoding == "br":
        import brotli  # noqa: PLC0415

        return brotli.compress(data), {"content-encoding": "br"}
    return data, {}


async def completions(request: Request) -> Response:
    body = await request.body()
    try:
        doc = json.loads(body) if body else {}
    except (ValueError, RecursionError):
        doc = {}
    if not isinstance(doc, dict):
        doc = {}
    chaos = doc.get("chaos") if isinstance(doc.get("chaos"), dict) else {}
    answer = answer_for(body)
    row = {
        "nonce": chaos.get("nonce"), "run": chaos.get("run"), "call": chaos.get("call"),
        "req_sha256": hashlib.sha256(body).hexdigest(), "req_len": len(body),
        "stream": bool(doc.get("stream")), "answer": answer, "pid": chaos.get("pid"),
    }  # fmt: skip
    if delay := chaos.get("delay_ms"):
        await asyncio.sleep(float(delay) / 1000)
    status = int(chaos.get("status") or 200)
    row["status"] = status
    _log(row)
    if status != 200:  # noqa: PLR2004
        return JSONResponse({"error": {"message": "chaos error", "code": status}}, status)
    model = "gpt-4o-mini-2024-07-18"
    if doc.get("stream"):
        events = int(chaos.get("sse_events") or 4)
        gap = float(chaos.get("chunk_delay_ms") or 0) / 1000
        kill_pid, kill_after = chaos.get("kill_pid"), chaos.get("kill_after_events")
        step = max(1, -(-len(answer) // events))
        pieces = [answer[i * step : (i + 1) * step] for i in range(events)]

        async def gen():  # noqa: ANN202
            base = {"id": "chatcmpl-chaos", "object": "chat.completion.chunk", "model": model}
            for i in range(events):
                piece = pieces[i] if i < len(pieces) else ""
                chunk = {**base, "choices": [{"index": 0, "delta": {"content": piece}}]}
                yield f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n".encode()
                if kill_pid and kill_after is not None and i + 1 == int(kill_after):
                    try:
                        os.kill(int(kill_pid), signal.SIGKILL)
                    except OSError:
                        pass
                if gap:
                    await asyncio.sleep(gap)
            last = {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
            yield f"data: {json.dumps(last)}\n\ndata: [DONE]\n\n".encode()

        return StreamingResponse(gen(), media_type="text/event-stream")
    content: Any = answer
    if pad := int(chaos.get("resp_bytes") or 0):
        content = answer + " " + ("z" * max(0, pad - len(answer) - 200))
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if depth := int(chaos.get("nested") or 0):
        message["nested_note"] = "nested"
    out = {
        "id": "chatcmpl-chaos", "object": "chat.completion", "model": model,
        "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": len(body) % 1000, "completion_tokens": 7},
    }  # fmt: skip
    data = json.dumps(out, separators=(",", ":")).encode()
    if depth:
        nested = b"[" * depth + b"]" * depth
        data = data[:-1] + b',"deep":' + nested + b"}"
    if chaos.get("invalid_utf8"):
        data = data[:-1] + b',"bad":"\xff\xfe\xc3\x28"}'
    data, headers = _encode(data, chaos.get("encoding"))
    return Response(data, 200, headers=headers, media_type="application/json")


async def health(_: Request) -> Response:
    return Response(b"ok")


def _raise_nofile() -> None:
    import resource  # noqa: PLC0415

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = 65536 if hard == resource.RLIM_INFINITY else min(hard, 65536)
    for target in (want, 10240, 4096):
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, target), hard))
            return
        except (ValueError, OSError):
            continue

def main() -> None:
    _raise_nofile()
    global _LOG_FD, _FSYNC  # noqa: PLW0603
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--no-fsync", action="store_true")
    args = parser.parse_args()
    _FSYNC = not args.no_fsync
    _LOG_FD = os.open(args.log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    app = Starlette(routes=[Route("/v1/chat/completions", completions, methods=["POST"]),
                            Route("/health", health)])  # fmt: skip
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="error", access_log=False,
                backlog=4096, limit_concurrency=None, timeout_keep_alive=30, h11_max_incomplete_event_size=128 * 1024 * 1024)  # fmt: skip


if __name__ == "__main__":
    main()
