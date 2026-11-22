# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 055 §9.5, unit 055-t18 (milestone M4): ``fabric run -- node agent.mjs`` records
and verifies a Node.js agent with no code change (spec 055 §13.1, spec 058 §5.5, G2).

The local profile, as a person runs it: ``fabric init`` writes ``fabric.yaml`` and every
secret; the packed ``@singleaxis/fabric`` tarball is installed in the agent's own project
(``_node_package.py``); ``fabric run -- node agent.mjs`` starts an unmodified plain
``fetch`` tool loop against a model host in neither the endpoint table nor the agent's
code (``OPENAI_BASE_URL``, 058 §8.3); ``fabric verify`` finds the run and the reader's
verdict on it. The local-dir sink on loopback stands in for the Node, as in the Python
CLI tests (``sdk/python/tests/test_cli_verify.py``): ``fabric verify`` is given a Node
that answers, then runs its Python canary and reads the Node.js agent's run.

Nothing Fabric-specific is in the agent or its command line: ``fabric run`` decides from
the installed package's qualification table and this Node build to append
``--import=@singleaxis/fabric/register`` to ``NODE_OPTIONS`` and set
``FABRIC_WIRE_AUTOLOAD=1``. The ``ts-wire-package`` CI job runs it on Node 24.4.0, a
build the shipped table qualifies, with ``FABRIC_REQUIRE_NODE_E2E=1``; elsewhere it is
skipped without the tarball, and on a developer's machine the installed table gains this
build's tuple (``_node_package.activate_here``)."""

from __future__ import annotations

import http.server
import json
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _node_package  # noqa: E402

_MISSING = _node_package.missing()
_REQUIRED = os.environ.get("FABRIC_REQUIRE_NODE_E2E") == "1"
pytestmark = pytest.mark.skipif(_MISSING is not None and not _REQUIRED, reason=_MISSING or "")
PRELOAD = "--import=@singleaxis/fabric/register"
#: G1's targets with `node` in place of `python` (spec 058 §3.2): one install, at most
#: three commands (`up` is replaced here by the loopback sink), no hand-made item.
BUDGET_S = 300.0

#: A plain fetch tool loop against OPENAI_BASE_URL: one tool call, one answer. It knows
#: nothing about Fabric and prints what it saw of the two variables `fabric run` added.
AGENT = """
const base = process.env.OPENAI_BASE_URL.replace(/\\/$/, "");
const messages = [{ role: "user", content: "What time is it in UTC?" }];
for (let turn = 0; turn < 4; turn += 1) {
  const response = await fetch(`${base}/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "fake-model", messages }),
  });
  const reply = (await response.json()).choices[0].message;
  messages.push(reply);
  if (!reply.tool_calls) break;
  for (const call of reply.tool_calls) {
    messages.push({ role: "tool", tool_call_id: call.id, content: JSON.stringify({ time: "12:00" }) });
  }
}
process.stdout.write(JSON.stringify({
  answer: messages.at(-1).content,
  node_options: process.env.NODE_OPTIONS ?? null,
  autoload: process.env.FABRIC_WIRE_AUTOLOAD ?? null,
}) + "\\n");
"""


@pytest.fixture(autouse=True)
def _prerequisites() -> None:
    if _MISSING is not None:
        pytest.fail(f"FABRIC_REQUIRE_NODE_E2E=1 but this machine {_MISSING}")


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self) -> None:  # no resolver call for this machine's name
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "localhost", int(self.server_address[1])


class FakeModel:
    """OpenAI Chat Completions on loopback: a ``get_time`` tool call, then the answer."""

    def __init__(self) -> None:
        self.received = 0
        model = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

            def do_POST(self) -> None:  # noqa: N802
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                model.received += 1
                answered = any(m.get("role") == "tool" for m in payload["messages"])
                message: dict[str, Any] = (
                    {"role": "assistant", "content": "It is noon in UTC."}
                    if answered
                    else {"role": "assistant", "content": None, "tool_calls": [{
                        "id": "call_time_1", "type": "function",
                        "function": {"name": "get_time", "arguments": '{"zone": "UTC"}'}}]}
                )  # fmt: skip
                body = json.dumps({
                    "id": f"chatcmpl-{model.received}", "object": "chat.completion",
                    "model": "fake-model",
                    "choices": [{"index": 0, "message": message,
                                 "finish_reason": "stop" if answered else "tool_calls"}],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 3},
                }).encode()  # fmt: skip
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = _Server(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@pytest.fixture(scope="module")
def app(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The agent's own project with the packed tarball installed (`npm i`)."""
    directory = tmp_path_factory.mktemp("f055-t18-agent") / "agent-project"
    _node_package.install_app(directory)
    (directory / "agent.mjs").write_text(AGENT)
    return directory


@pytest.fixture
def lab(app: Path, tmp_path: Path) -> Iterator[dict[str, Any]]:
    from fabric.cli import _localsink

    node = _node_package.node_binary()
    assert node is not None
    env = {
        "PATH": f"{Path(node).parent}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
        "HOME": str(tmp_path / "home"),
        "XDG_STATE_HOME": str(tmp_path / "xdg"),
        "LANG": "C.UTF-8",
    }
    for name in ("fabric.yaml", ".fabric", "fabric-data"):  # a fresh project each test
        subprocess.run(["rm", "-rf", str(app / name)], check=True)  # noqa: S603, S607
    (app / "fabric.yaml").write_text(
        f"schema: fabric.config/v1\nnode:\n  endpoint: https://localhost:{_free_port()}\n"
    )
    sink = _localsink.serve(app / "fabric-data", "127.0.0.1", 0)
    threading.Thread(target=sink.serve_forever, daemon=True).start()
    model = FakeModel()
    shell = {
        **env,
        # The sink stands in for the Node (a variable already set wins, 058 §6.2).
        "FABRIC_OTLP_ENDPOINT": f"http://127.0.0.1:{sink.server_address[1]}",
        "OPENAI_BASE_URL": model.url,
    }
    try:
        yield {"app": app, "env": env, "shell": shell, "model": model}
    finally:
        sink.shutdown()
        sink.server_close()
        model.close()


def _fabric(lab: dict[str, Any], *args: str, env: dict[str, str] | None = None) -> Any:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "fabric.cli", *args],
        cwd=lab["app"],
        env=env or lab["shell"],
        capture_output=True,
        text=True,
        timeout=240,
        check=False,
    )


def _verify(lab: dict[str, Any]) -> tuple[int, dict[str, Any], list[str]]:
    """`fabric verify` with a Node that answers (the sink stands in for it)."""
    from fabric.cli import _verify, build_parser

    options = build_parser().parse_args(["verify", "--wait", "30"])
    report, lines = _verify.run(options, lab["shell"], lab["app"], node_ok=lambda *_: True)
    return report.exit_code, report.to_json(), lines


def test_fabric_run_records_and_verifies_an_unmodified_node_agent(lab: dict[str, Any]) -> None:
    started = time.monotonic()
    init = _fabric(lab, "init", "--quiet", env=lab["env"])
    assert init.returncode == 0, init.stdout + init.stderr
    run = _fabric(lab, "run", "--run", "node-agent", "--", "node", "agent.mjs")
    assert run.returncode == 0, run.stdout + run.stderr
    assert run.stderr == "", run.stderr  # not a terminal: nothing on the agent's stderr
    seen = json.loads(run.stdout.strip().splitlines()[-1])
    assert seen == {"answer": "It is noon in UTC.", "node_options": PRELOAD, "autoload": "1"}
    assert lab["model"].received == 2

    code, report, lines = _verify(lab)
    elapsed = time.monotonic() - started
    assert code == 0, (lines, report["findings"])
    data = report["data"]["run"]
    assert (data["label"], data["capture"]) == ("node-agent", "on"), data
    (process,) = data["runs"]  # the canary's own run is never taken for the agent's
    assert process["exchanges"] == 2, process
    assert process["chains"]["decisions"] == "complete", process
    rows = {row["row"]: (row["state"], row["note"]) for row in data["coverage"]}
    assert rows["model calls (requests and responses)"] == ("recorded", "2 exchange(s)")
    assert rows["tool calls and results"][0] == "recorded"
    # G1 with `node` in place of `python`: init, run, verify; no hand-made item.
    assert elapsed < BUDGET_S, elapsed


def test_an_unqualified_node_build_runs_unchanged_and_verify_says_why(
    lab: dict[str, Any],
) -> None:
    """Spec 055 §13.1: with a table that does not list this build, `fabric run` adds no
    preload, the agent runs as it would bare, and `verify` names the reason with the
    qualified builds instead of passing."""
    table_path = lab["app"] / "node_modules" / "@singleaxis" / "fabric" / "dist"
    table_path = table_path / "wire-qualification.json"
    original = table_path.read_text()
    table = json.loads(original)
    for entry in table["tuples"]:
        entry["node"] = "24.999.0"
    table_path.write_text(json.dumps(table))
    try:
        assert _fabric(lab, "init", "--quiet", env=lab["env"]).returncode == 0
        run = _fabric(lab, "run", "--run", "bare-node", "--", "node", "agent.mjs")
        assert run.returncode == 0 and run.stderr == "", run.stderr
        seen = json.loads(run.stdout.strip().splitlines()[-1])
        assert seen == {"answer": "It is noon in UTC.", "node_options": None, "autoload": None}
        code, report, _ = _verify(lab)
        rows = {r["row"]: (r["state"], r["note"]) for r in report["data"]["run"]["coverage"]}
        state, note = rows["model calls (requests and responses)"]
        assert state == "invisible" and note.startswith("unsupported_version: Node "), note
        assert "qualified: Node 24.999.0" in note and "(FC-100)" in note
        # Never a false pass: the run was started without capture (FC-070, an error) and
        # the detail names the recorded reason, which `fabric doctor` shows with its fix.
        (why,) = [f for f in report["findings"] if f["id"] == "FC-070"]
        assert code == 1 and "bare-node: FC-100" in why["detail"], why
    finally:
        table_path.write_text(original)
