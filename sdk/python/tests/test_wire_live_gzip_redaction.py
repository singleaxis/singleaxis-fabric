# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""0.11.1 acceptance B1, live: a real child interpreter talks to a loopback
OpenAI-compatible server that gzips every response (JSON and SSE), with a redaction
policy and a customer redaction service on a Unix socket. The local content store must
hold no canary, in clear or behind a coding, and no object may claim ``redacted`` over
bytes that are not plaintext.

Two installs: zero-code (the autoload on ``PYTHONPATH``; it cannot name a transformation,
so ``redact`` withholds) and the documented explicit install that names one."""

from __future__ import annotations

import contextlib
import gzip
import json
import textwrap
import zlib
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

import pytest

from ._wire_live import (
    FakeModel,
    OtlpSink,
    capture_env,
    run_agent,
    wait_for,
)
from .redaction_server import RedactionServer

CANARY = b"sk-live-CANARY-6f2a91c4d0b7e3aa"
AGENT = textwrap.dedent(
    """
    import json, os
    if os.environ.get("LIVE_EXPLICIT"):  # the explicit install that names a transformation
        import dataclasses
        from fabric import wire
        from fabric.wire import Transformation
        from fabric.wire._config import config_from_env
        cfg, _ = config_from_env(os.environ)
        mask = Transformation("live-mask", "1")
        roles = ("model.exchange.request", "model.exchange.response")
        wire.install(dataclasses.replace(cfg, transformations={r: mask for r in roles}))
    from openai import OpenAI
    client = OpenAI(base_url=os.environ["LIVE_MODEL_BASE"], api_key="sk-live-fake")
    ask = [{"role": "user", "content": "what is the deploy key?"}]
    out = [client.chat.completions.create(model="m", messages=ask).choices[0].message.content]
    stream = client.chat.completions.create(model="m", messages=ask, stream=True)
    out.append("".join(c.choices[0].delta.content or "" for c in stream if c.choices))
    print("RESULT", json.dumps(out))
    """
)


def _chat(stream: bool) -> tuple[bytes, str]:
    text = "the deploy key is " + CANARY.decode()
    if not stream:
        return json.dumps({
            "id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "m",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }).encode(), "application/json"  # fmt: skip
    events = [
        {"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
         "choices": [{"index": 0, "delta": {"role": "assistant", "content": piece},
                      "finish_reason": None}]}
        for piece in (text[:9], text[9:])
    ] + [{"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
          "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}]  # fmt: skip
    body = b"".join(b"data: " + json.dumps(e).encode() + b"\n\n" for e in events)
    return body + b"data: [DONE]\n\n", "text/event-stream"


class GzipModel(FakeModel):
    """Chat Completions whose every response is ``Content-Encoding: gzip`` and carries the
    canary; the SSE body is written in several small chunks."""

    def _handler(self) -> type[BaseHTTPRequestHandler]:  # replaces FakeModel's handler
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                plain, media = _chat(bool(json.loads(raw or b"{}").get("stream")))
                data = gzip.compress(plain)
                self.send_response(200)
                self.send_header("Content-Type", media)
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                for i in range(0, len(data), 40):
                    self.wfile.write(data[i : i + 40])
                    self.wfile.flush()

        return Handler


def _policy(path: Path) -> Path:
    path.write_text(json.dumps({
        "schema_version": "fabric.deployment-policy/v1", "policy_id": "live-gzip",
        "policy_version": 1, "tenant_id": "live-tenant", "workload_id": "live-agent",
        "privacy": {"model.exchange.request": "redact", "model.exchange.response": "redact",
                    "model.exchange.part": "omit"},
        "storage": {"backend": "local", "region": "local", "key_id": "live-key"},
        "retention": {"days": 1}, "required_integrations": [],
        "deployment": {"profile": "local", "image_digest": "sha256:" + "0" * 64,
                       "tls_required": False, "encrypted_store_required": False},
    }))  # fmt: skip
    return path


def _scan_store(store: Path) -> dict[str, Any]:
    """Every file of the store, in clear and behind any coding we can undo; and every
    descriptor that claims ``redacted``."""
    leaks, mislabelled, redacted, objects = [], [], 0, 0
    for path in store.rglob("*"):
        if not path.is_file():
            continue
        objects += 1
        data = path.read_bytes()
        views = [data]
        for decode in (gzip.decompress, zlib.decompress):
            with contextlib.suppress(OSError, zlib.error, EOFError):
                views.append(decode(data))
        if any(CANARY in v for v in views):
            leaks.append(str(path.relative_to(store)))
        if path.suffix == ".json" and b'"protection_status": "redacted"' in data.replace(
            b'":"', b'": "'
        ):  # fmt: skip
            redacted += 1
            if b'"content_encoding": "identity"' not in data.replace(b'":"', b'": "'):
                mislabelled.append(str(path.relative_to(store)))
    return {"leaks": leaks, "mislabelled": mislabelled, "redacted": redacted, "objects": objects}


@pytest.mark.parametrize("install", ["zero_code", "explicit"])
def test_gzip_responses_never_leave_a_canary_in_the_store(tmp_path: Path, install: str) -> None:
    model, sink = GzipModel(), OtlpSink(tmp_path / "otlp")
    (store := tmp_path / "store").mkdir()
    (script := tmp_path / "agent.py").write_text(AGENT, encoding="utf-8")
    with RedactionServer() as service:
        service.behaviours |= {"live-mask": lambda d: d.replace(CANARY, b"[masked:key]")}
        try:
            extra = {"FABRIC_CAPTURE_POLICY": str(_policy(tmp_path / "policy.json")),
                     "FABRIC_REDACTION_ENDPOINT": service.endpoint}  # fmt: skip
            env = capture_env(model, sink, store, **extra)
            if install == "explicit":
                env.pop("FABRIC_WIRE_AUTOLOAD")
                env["LIVE_EXPLICIT"] = "1"
            done = run_agent(script, env)
            assert done["returncode"] == 0 and not done["hung"], done["stderr"][-2000:]
            expected = "the deploy key is " + CANARY.decode()
            assert done["stdout"].strip().endswith(json.dumps([expected, expected]))
            assert wait_for(lambda: len(sink.exchanges()) == 2)
            found = _scan_store(store)
            assert found["objects"], found
            assert found["leaks"] == [], found
            assert found["mislabelled"] == [], found  # redacted needs plaintext
            exchanges = sink.exchanges()
            assert CANARY.decode() not in json.dumps(exchanges)
            reasons = {x.get("fabric.wire.store_reason") for x in exchanges}
            if install == "explicit":  # redaction ran over the plaintext
                assert found["redacted"] >= 4, found  # two requests, two responses
                assert all(not body.startswith(b"\x1f\x8b") for _, body in service.requests)
                assert reasons == {None}, reasons
            else:  # zero-code names no transformation: withheld, never redacted
                assert found["redacted"] == 0 and service.requests == []
                assert reasons == {"protection_failed"}, reasons
        finally:
            model.close()
            sink.close()
