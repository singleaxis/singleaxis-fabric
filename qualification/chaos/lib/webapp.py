# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A web service that calls the model per request, for scenario 2c (server workers).

``wsgi_app``: a plain WSGI app (gunicorn sync/gthread workers, ``--preload`` forks the
workers after the master installed capture). ``asgi_app``: a Starlette app using
``httpx.AsyncClient`` (``uvicorn --workers N``, spawned workers). Each request
``POST /ask?run=<id>&n=<k>&stream=0|1`` makes one model call inside
``fabric.wire.run(<id>)`` and returns ``{"ok": bool, "pid": ...}`` (``ok`` = the model's
deterministic answer was received intact). Capture comes from the autoload only.
"""

from __future__ import annotations

import hashlib
import json
import os
from urllib.parse import parse_qs

import httpx

MODEL_URL = os.environ["CHAOS_MODEL_URL"]
CANARY = os.environ["CHAOS_CANARY"]
_CLIENT: httpx.Client | None = None
_CLIENT_PID = 0


def _body(run: str, n: str, stream: bool) -> bytes:
    nonce = f"{run}-{n}"
    return json.dumps({"model": "gpt-4o-mini", "stream": stream,
                       "messages": [{"role": "user", "content": f"{CANARY} {nonce}"}],
                       "chaos": {"nonce": nonce, "run": run, "call": n,
                                 "pid": os.getpid()}}).encode()  # fmt: skip


def _text(data: bytes) -> str:
    return "".join(
        (json.loads(x[5:]).get("choices") or [{}])[0].get("delta", {}).get("content") or ""
        for x in data.decode().splitlines()
        if x.startswith("data:") and x[5:].strip() not in ("", "[DONE]"))  # fmt: skip


def _client() -> httpx.Client:
    global _CLIENT, _CLIENT_PID  # noqa: PLW0603
    if _CLIENT is None or _CLIENT_PID != os.getpid():
        _CLIENT, _CLIENT_PID = httpx.Client(timeout=60), os.getpid()
    return _CLIENT


def _scope(run: str):  # noqa: ANN202
    try:
        from fabric import wire  # noqa: PLC0415

        return wire.run(run)
    except Exception:  # noqa: BLE001
        import contextlib  # noqa: PLC0415

        return contextlib.nullcontext()


def wsgi_app(environ, start_response):  # noqa: ANN001, ANN201
    q = parse_qs(environ.get("QUERY_STRING", ""))
    run, n, stream = q["run"][0], q["n"][0], q.get("stream", ["0"])[0] == "1"
    body = _body(run, n, stream)
    expected = "ans-" + hashlib.sha256(body).hexdigest()[:24]
    ok = False
    with _scope(run):
        if stream:
            with _client().stream("POST", MODEL_URL, content=body,
                                  headers={"content-type": "application/json"}) as r:
                ok = _text(b"".join(r.iter_bytes())) == expected
        else:
            r = _client().post(MODEL_URL, content=body, headers={"content-type": "application/json"})
            ok = r.status_code == 200 and expected.encode() in r.content  # noqa: PLR2004
    out = json.dumps({"ok": ok, "pid": os.getpid(),
                      "req_sha256": hashlib.sha256(body).hexdigest()}).encode()
    start_response("200 OK", [("Content-Type", "application/json"),
                              ("Content-Length", str(len(out)))])
    return [out]


def _asgi():  # noqa: ANN202
    from starlette.applications import Starlette  # noqa: PLC0415
    from starlette.requests import Request  # noqa: PLC0415
    from starlette.responses import JSONResponse  # noqa: PLC0415
    from starlette.routing import Route  # noqa: PLC0415

    state: dict[str, httpx.AsyncClient] = {}

    async def ask(request: Request) -> JSONResponse:
        run, n = request.query_params["run"], request.query_params["n"]
        stream = request.query_params.get("stream") == "1"
        body = _body(run, n, stream)
        expected = "ans-" + hashlib.sha256(body).hexdigest()[:24]
        client = state.get("c") or state.setdefault("c", httpx.AsyncClient(timeout=60))
        with _scope(run):
            if stream:
                async with client.stream("POST", MODEL_URL, content=body,
                                         headers={"content-type": "application/json"}) as r:
                    ok = _text(b"".join([c async for c in r.aiter_bytes()])) == expected
            else:
                r = await client.post(MODEL_URL, content=body,
                                      headers={"content-type": "application/json"})
                ok = r.status_code == 200 and expected.encode() in r.content  # noqa: PLR2004
        return JSONResponse({"ok": ok, "pid": os.getpid(),
                             "req_sha256": hashlib.sha256(body).hexdigest()})

    return Starlette(routes=[Route("/ask", ask, methods=["POST"])])


asgi_app = _asgi()
