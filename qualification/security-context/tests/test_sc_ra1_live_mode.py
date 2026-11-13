# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""SC-RA-1's live mode, end to end, against a loopback stand-in for the model endpoint.

The real endpoint needs a key CI does not hold, so this exercises everything the live mode
does around the model: the key read from ``SC_RA1_MODEL_KEY_FILE`` and sent only in the
request headers, no replay session header, the live endpoint's own ``FABRIC_WIRE_ENDPOINTS``
row, the capture-off twin replaying exactly what the capture-on run received, and
``--record-cassette`` writing those bytes without the endpoint's URL. The key never
appears in anything the run writes.
"""

from __future__ import annotations

import base64
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

import run_sc_ra1
from sc_ra1 import model
from sc_ra1.agent import SESSION_HEADER
from sc_ra1.harness import KEY_ENV

# A fresh value per run; the stand-in refuses any other.
KEY = "stand-in-" + os.urandom(8).hex()


class StandIn:
    """Answers Chat Completions with one session's recorded replies, in order, and only
    for the right bearer key (401 otherwise, as the real endpoint does)."""

    def __init__(self, replies: list[model.Reply]) -> None:
        self.replies = replies
        self.requests: list[dict[str, Any]] = []
        stand_in = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:
                return

            def do_POST(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                stand_in.requests.append(
                    {
                        "path": self.path,
                        "authorized": self.headers.get("authorization") == f"Bearer {KEY}",
                        "session_header": self.headers.get(SESSION_HEADER),
                    }
                )
                served = sum(1 for r in stand_in.requests if r["authorized"]) - 1
                if not stand_in.requests[-1]["authorized"]:
                    reply = model.Reply(401, "application/json", b'{"error":"unauthorized"}')
                else:
                    reply = stand_in.replies[served]
                self.send_response(reply.status)
                self.send_header("Content-Type", reply.content_type)
                self.send_header("Content-Length", str(len(reply.body)))
                self.end_headers()
                self.wfile.write(reply.body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def test_live_mode_end_to_end_against_a_stand_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    replies = model.load()["loop-openai"]
    stand_in = StandIn(replies)
    key_file = tmp_path / "key"
    key_file.write_text(KEY + "\n")
    monkeypatch.delenv(KEY_ENV, raising=False)  # _load_key sets it; monkeypatch restores
    monkeypatch.setenv("SC_RA1_MODEL_KEY_FILE", str(key_file))
    out, cassette = tmp_path / "out", tmp_path / "cassette.json"
    try:
        code = run_sc_ra1.main(
            [
                "--mode", "live", "--sessions", "loop-openai", "--base-url", stand_in.base_url,
                "--out", str(out), "--no-latency-gate", "--record-cassette", str(cassette),
            ]
        )  # fmt: skip
    finally:
        stand_in.close()
    result = json.loads((out / "sc-ra1-result.json").read_text())
    failed = [c for c in result["checks"] if not c["ok"]]
    assert code == 0 and not failed, failed
    # only the capture-on run reached the endpoint, with the key and no replay header
    assert len(stand_in.requests) == len(replies)
    assert all(r["authorized"] and r["session_header"] is None for r in stand_in.requests)
    assert {r["path"] for r in stand_in.requests} == {"/v1/chat/completions"}
    # the capture-off twin answered from what the live run received: same requests made
    on = [json.loads(x) for x in (out / "on/loop-openai/ledger.jsonl").read_text().splitlines()]
    off = [json.loads(x) for x in (out / "off/loop-openai/ledger.jsonl").read_text().splitlines()]
    assert [r["sha256"] for r in on if r["event"] == "model_request"] == [
        r["sha256"] for r in off if r["event"] == "model_request"
    ]
    # the recorded cassette holds the received bytes, and not the endpoint's URL
    doc = json.loads(cassette.read_text())
    entry = doc["sessions"]["loop-openai"]
    assert [base64.b64decode(r["body_b64"]) for r in entry["responses"]] == [
        r.body for r in replies
    ]
    assert stand_in.base_url.split("/v1")[0] not in cassette.read_text()
    assert "run_sc_ra1.py --mode live" in entry["provenance"]
    # the replay-only sessions are carried over unchanged
    assert (
        doc["sessions"]["safety-openai"]
        == json.loads(model.CASSETTE.read_text())["sessions"]["safety-openai"]
    )
    # the key is in nothing the run wrote
    for path in [cassette, *out.rglob("*")]:
        if path.is_file():
            assert KEY.encode() not in path.read_bytes(), path
