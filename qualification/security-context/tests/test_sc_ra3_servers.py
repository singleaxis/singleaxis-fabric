# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The SC-RA-3 fixture servers bind without a reverse DNS lookup.

``http.server.HTTPServer`` looks its own name up with ``socket.getfqdn`` when it binds.
On a host with slow DNS (the macOS CI runners) that blocked the approval service for
longer than the harness waits, so SC-RA-3 could not start there. These tests fail if a
fixture server calls ``getfqdn`` again.
"""

from __future__ import annotations

import http.client
import json
import socket
from http.server import BaseHTTPRequestHandler

import pytest

from sc_ra3 import model as fixture
from sc_ra3.approval_service import LoopbackHTTPServer


@pytest.fixture
def no_name_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(name: str = "") -> str:
        raise AssertionError(f"socket.getfqdn({name!r}) called while binding a fixture server")

    monkeypatch.setattr(socket, "getfqdn", refuse)


@pytest.mark.usefixtures("no_name_lookup")
def test_the_loopback_server_binds_without_looking_its_name_up() -> None:
    server = LoopbackHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    try:
        assert server.server_name == "127.0.0.1"
        assert server.server_port == server.server_address[1] != 0
        assert server.daemon_threads
    finally:
        server.server_close()


@pytest.mark.usefixtures("no_name_lookup")
def test_the_model_stand_in_starts_and_answers_without_a_name_lookup() -> None:
    model = fixture.FixtureModel(fixture.scripted(["done"])).start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", model.port, timeout=10)
        connection.request(
            "POST",
            "/v1/chat/completions",
            body=json.dumps({"model": fixture.MODEL, "messages": []}),
            headers={"Content-Type": "application/json"},
        )
        reply = connection.getresponse()
        assert reply.status == 200
        assert json.loads(reply.read())["choices"][0]["message"]["content"] == "done"
        connection.close()
    finally:
        model.close()
