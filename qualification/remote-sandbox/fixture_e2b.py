# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A fixture E2B service for the ``remote.sandbox`` qualification (spec 056 §4.4.1, §7.3.2
WP6-09b; AR-1 production, §6.2).

It answers the calls the pinned E2B Python SDK (``pins.json``: ``e2b`` 2.62.x and
``e2b-code-interpreter`` 2.11.x) makes for what the hook observes, on one plain-HTTP
listener at a configurable address (default ``127.0.0.1``, any free port; IPv6 when the
host has a colon). Point the SDK at it with :meth:`FixtureE2B.env` (``E2B_API_URL``,
``E2B_SANDBOX_URL`` and the API key)::

    with FixtureE2B(api_key=KEY) as fixture:
        fixture.script("echo hi", Script(stdout="hi\\n"))
        os.environ.update(fixture.env())
        sandbox = e2b.Sandbox.create()
        sandbox.commands.run("echo hi")

The three planes, told apart by path:

- **control plane** (the REST API, through ``pyqwest``'s httpx transport): ``POST
  /v2/sandboxes`` mints a sandbox, ``DELETE /sandboxes/<id>`` kills it;
- **envd** (Connect RPC with envd's JSON codec, over ``pyqwest``):
  ``/process.Process/Start`` runs a command, served by the SDK's own generated Connect
  server stub, so the wire format is the SDK's; ``GET /health`` answers the SDK's probe;
- **code interpreter** (``POST /execute``, the newline-delimited JSON stream
  ``run_code`` reads).

A command or a piece of code does what its :class:`Script` says (registered with
:meth:`FixtureE2B.script`); an unscripted ``echo WORDS`` prints its words, anything else
exits 127. A script can also fail the call itself (``fail=True``): envd answers the
command with a Connect ``deadline_exceeded`` error and the code interpreter with HTTP
502, which the SDK raises as ``e2b.exceptions.TimeoutException``.

**The ledger** (:attr:`FixtureE2B.ledger`) is one :class:`Entry` per request received,
in order: its plane and call, the fixture-minted sandbox id, the *names* of the
environment variables the request carried, and canary booleans (did the API key header,
or an environment value, equal the canary the test configured). It never holds a value:
not a command, code, output, header or environment value. Comparisons with canaries use
``hmac.compare_digest``; nothing received is logged.
"""

from __future__ import annotations

import hmac
import io
import itertools
import json
import socket
import socketserver
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, cast
from wsgiref.simple_server import ServerHandler, WSGIRequestHandler, WSGIServer

HERE = Path(__file__).resolve().parent
PINS: dict[str, Any] = json.loads((HERE / "pins.json").read_text(encoding="utf-8"))
ENVD_VERSION: str = PINS["providers"]["e2b"]["envd_version"]
SANDBOX_ID_PREFIX = "ifx"  # fixture-minted ids: never a real E2B sandbox id
TEMPLATE_ID = "fixture-template"

StartResponse = Callable[..., Any]
WsgiEnviron = dict[str, Any]


@dataclass(frozen=True)
class Script:
    """What a command or a piece of code does on the fixture. ``results`` are
    ``run_code`` results (``e2b_code_interpreter.Result`` fields, such as
    ``{"text": "4"}``); ``error`` is a ``run_code`` error ``(name, value, traceback)``;
    ``fail`` fails the call itself (no output at all)."""

    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    results: tuple[Mapping[str, Any], ...] = ()
    error: tuple[str, str, str] | None = None
    fail: bool = False


@dataclass(frozen=True)
class Entry:
    """One request as the ledger keeps it: names and canary booleans, never values."""

    plane: str  # control | envd | interpreter
    call: str  # sandboxes.create | sandboxes.kill | process.start | health | execute
    sandbox: str | None = None  # the fixture's own id for it
    env_names: tuple[str, ...] = ()
    canaries: Mapping[str, bool] = field(default_factory=dict)

    def as_json(self) -> dict[str, Any]:
        return {"plane": self.plane, "call": self.call, "sandbox": self.sandbox,
                "env_names": list(self.env_names), "canaries": dict(self.canaries)}  # fmt: skip


def _equal(received: object, canary: str | None) -> bool:
    if canary is None or not isinstance(received, str):
        return False
    return hmac.compare_digest(received.encode("utf-8", "surrogatepass"),
                               canary.encode("utf-8"))  # fmt: skip


MAX_BODY = 8 << 20  # a request body the fixture reads at most


def _read_chunked(stream: Any) -> bytes:
    """An HTTP/1.1 chunked request body (the envd client streams its request)."""
    body = bytearray()
    while True:
        size = int(stream.readline(1024).split(b";", 1)[0].strip() or b"0", 16)
        if size == 0:
            while stream.readline(1024).strip():  # trailers
                pass
            return bytes(body)
        body.extend(stream.read(size))
        stream.readline(8)  # the chunk's CRLF
        if len(body) > MAX_BODY:
            raise ValueError("request body over the fixture's bound")


class _Handler(WSGIRequestHandler):
    """wsgiref's handler, silent (it would log request lines and client addresses), that
    also reads a chunked request body (wsgiref only reads ``Content-Length`` bodies)."""

    def handle(self) -> None:
        self.raw_requestline = self.rfile.readline(65537)
        if len(self.raw_requestline) > 65536:  # noqa: PLR2004 - wsgiref's own bound
            self.send_error(414)
            return
        if not self.parse_request():
            return
        stdin: Any = self.rfile
        if (self.headers.get("Transfer-Encoding") or "").lower() == "chunked":
            body = _read_chunked(self.rfile)
            del self.headers["Transfer-Encoding"]
            self.headers["Content-Length"] = str(len(body))
            stdin = io.BytesIO(body)
        handler = ServerHandler(stdin, cast("IO[bytes]", self.wfile), self.get_stderr(),
                                self.get_environ(), multithread=True)  # fmt: skip
        handler.request_handler = self  # type: ignore[attr-defined]
        handler.run(self.server.get_app())  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        return


class _Server(socketserver.ThreadingMixIn, WSGIServer):
    daemon_threads = True
    allow_reuse_address = True


class _Server6(_Server):
    address_family = socket.AF_INET6


class FixtureE2B:
    """The fixture service (a context manager; :meth:`start` and :meth:`close` too)."""

    def __init__(
        self, *, api_key: str, host: str = "127.0.0.1", port: int = 0,
        env_canary: str | None = None, sandbox_ids: Iterable[str] = (),
    ) -> None:  # fmt: skip
        """``sandbox_ids`` are the ids the first creates are given (then ``ifx`` and a
        counter)."""
        self.api_key, self.host, self.requested_port = api_key, host, port
        self.env_canary = env_canary
        self._preset = list(sandbox_ids)
        self._minted = itertools.count(1)
        self.ledger: list[Entry] = []
        self.sandboxes: list[str] = []
        self._scripts: dict[str, Script] = {}
        self._lock = threading.Lock()
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None
        self._envd = self._envd_app()

    # -- lifecycle --------------------------------------------------------------------

    def start(self) -> FixtureE2B:
        server_class = _Server6 if ":" in self.host else _Server
        server = server_class((self.host, self.requested_port), _Handler)
        server.set_app(self._app)
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, name="fixture-e2b",
                                        kwargs={"poll_interval": 0.05}, daemon=True)  # fmt: skip
        self._thread.start()
        return self

    def close(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.shutdown()
            server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> FixtureE2B:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("the fixture E2B server is not started")
        return int(self._server.server_address[1])

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}"

    def env(self) -> dict[str, str]:
        """The SDK's configuration for this fixture (``E2B_API_URL``, ``E2B_SANDBOX_URL``,
        ``E2B_API_KEY``)."""
        return {"E2B_API_URL": self.url, "E2B_SANDBOX_URL": self.url,
                "E2B_API_KEY": self.api_key}  # fmt: skip

    # -- scripting and the ledger -----------------------------------------------------

    def script(self, text: str, script: Script) -> None:
        """What the command or code ``text`` (exactly) does."""
        with self._lock:
            self._scripts[text] = script

    def _lookup(self, text: str) -> Script:
        with self._lock:
            found = self._scripts.get(text)
        if found is not None:
            return found
        if text.startswith("echo "):
            return Script(stdout=text[len("echo ") :] + "\n")
        return Script(stderr=f"bash: {text.split(' ', 1)[0]}: command not found\n",
                      exit_code=127)  # fmt: skip

    def _note(self, entry: Entry) -> None:
        with self._lock:
            self.ledger.append(entry)

    def reset(self) -> None:
        """Forget the ledger and the scripts (between tests)."""
        with self._lock:
            self.ledger.clear()
            self._scripts.clear()

    def calls(self) -> list[tuple[str, str]]:
        """The ledger as ``(plane, call)`` pairs, in order."""
        with self._lock:
            return [(entry.plane, entry.call) for entry in self.ledger]

    def ledger_json(self) -> list[dict[str, Any]]:
        with self._lock:
            return [entry.as_json() for entry in self.ledger]

    def _env_entry(self, envs: object) -> tuple[tuple[str, ...], bool]:
        if not isinstance(envs, Mapping):
            return (), False
        names = tuple(sorted(str(name) for name in envs))
        return names, any(_equal(value, self.env_canary) for value in envs.values())

    # -- the WSGI application ---------------------------------------------------------

    def _app(self, environ: WsgiEnviron, start_response: StartResponse) -> Iterable[bytes]:
        path = environ.get("PATH_INFO", "")
        method = environ.get("REQUEST_METHOD", "GET")
        sandbox = environ.get("HTTP_E2B_SANDBOX_ID")
        if path.startswith("/process.Process/"):
            return self._envd(environ, start_response)
        if method == "POST" and path == "/v2/sandboxes":
            return self._create(environ, start_response)
        if method == "DELETE" and path.startswith("/sandboxes/"):
            killed = path[len("/sandboxes/") :]
            self._note(Entry("control", "sandboxes.kill", killed,
                             canaries={"api_key": _equal(environ.get("HTTP_X_API_KEY"),
                                                         self.api_key)}))  # fmt: skip
            start_response("204 No Content", [])
            return [b""]
        if method == "GET" and path == "/health":
            self._note(Entry("envd", "health", sandbox))
            start_response("204 No Content", [])
            return [b""]
        if method == "POST" and path == "/execute":
            return self._execute(environ, start_response, sandbox)
        self._note(Entry("unknown", method))  # never the path: it may carry a value
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"not served by the fixture\n"]

    @staticmethod
    def _body(environ: WsgiEnviron) -> bytes:
        length = int(environ.get("CONTENT_LENGTH") or 0)
        return bytes(environ["wsgi.input"].read(length)) if length > 0 else b""

    def _create(self, environ: WsgiEnviron, start_response: StartResponse) -> Iterable[bytes]:
        request = json.loads(self._body(environ) or b"{}")
        names, env_canary = self._env_entry(request.get("envVars"))
        with self._lock:
            preset = self._preset.pop(0) if self._preset else None
            sandbox = preset or f"{SANDBOX_ID_PREFIX}{next(self._minted):017d}"
            self.sandboxes.append(sandbox)
        self._note(Entry("control", "sandboxes.create", sandbox, names, {
            "api_key": _equal(environ.get("HTTP_X_API_KEY"), self.api_key),
            "env_value": env_canary,
        }))  # fmt: skip
        body = json.dumps({
            "templateID": TEMPLATE_ID, "sandboxID": sandbox, "clientID": "fixture",
            "envdVersion": ENVD_VERSION, "domain": None,
        }).encode()  # fmt: skip
        start_response("201 Created", [("Content-Type", "application/json"),
                                       ("Content-Length", str(len(body)))])  # fmt: skip
        return [body]

    def _execute(self, environ: WsgiEnviron, start_response: StartResponse,
                 sandbox: str | None) -> Iterable[bytes]:  # fmt: skip
        request = json.loads(self._body(environ) or b"{}")
        names, env_canary = self._env_entry(request.get("env_vars"))
        self._note(Entry("interpreter", "execute", sandbox, names,
                         {"env_value": env_canary}))  # fmt: skip
        code = request.get("code")
        script = self._lookup(code if isinstance(code, str) else "")
        if script.fail:
            start_response("502 Bad Gateway", [("Content-Type", "text/plain")])
            return [b"fixture: the sandbox did not answer"]
        lines: list[dict[str, Any]] = [{"type": "number_of_executions", "execution_count": 1}]
        stamp = time.time_ns() // 1000
        if script.stdout:
            lines.append({"type": "stdout", "text": script.stdout, "timestamp": stamp})
        if script.stderr:
            lines.append({"type": "stderr", "text": script.stderr, "timestamp": stamp})
        lines.extend({"type": "result", **result} for result in script.results)
        if script.error is not None:
            name, value, traceback = script.error
            lines.append({"type": "error", "name": name, "value": value,
                          "traceback": traceback})  # fmt: skip
        body = b"".join(json.dumps(line).encode() + b"\n" for line in lines)
        start_response("200 OK", [("Content-Type", "application/x-ndjson"),
                                  ("Content-Length", str(len(body)))])  # fmt: skip
        return [body]

    def _envd_app(self) -> Callable[[WsgiEnviron, StartResponse], Iterable[bytes]]:
        """envd's process service on the SDK's own generated Connect server stub."""
        from connectrpc.code import Code  # noqa: PLC0415 - the SDK's dependencies
        from connectrpc.errors import ConnectError  # noqa: PLC0415
        from e2b.envd.process import process_connect, process_pb  # noqa: PLC0415
        from protobuf import Oneof  # noqa: PLC0415

        fixture = self
        pids = itertools.count(1000)
        events: Any = process_pb.ProcessEvent  # the generated messages, built loosely

        def event(payload: Any) -> Any:
            return process_pb.StartResponse(event=events(event=payload))

        class Process(process_connect.ProcessSync):
            def start(self, request: Any, ctx: Any) -> Iterator[Any]:
                headers = ctx.request_headers
                config = request.process
                names, env_canary = fixture._env_entry(dict(config.envs) if config else {})
                fixture._note(Entry("envd", "process.start", headers.get("e2b-sandbox-id"),
                                    names, {"env_value": env_canary}))  # fmt: skip
                args = list(config.args) if config else []
                script = fixture._lookup(args[2] if len(args) == 3 else "")  # noqa: PLR2004
                if script.fail:
                    raise ConnectError(Code.DEADLINE_EXCEEDED, "fixture: the command timed out")
                yield event(Oneof("start", events.StartEvent(pid=next(pids))))
                if script.stdout:
                    out = events.DataEvent(output=Oneof("stdout", script.stdout.encode()))
                    yield event(Oneof("data", out))
                if script.stderr:
                    err = events.DataEvent(output=Oneof("stderr", script.stderr.encode()))
                    yield event(Oneof("data", err))
                end = events.EndEvent(exit_code=script.exit_code, exited=True,
                                      status=f"exit status {script.exit_code}")  # fmt: skip
                yield event(Oneof("end", end))

        app: Callable[[WsgiEnviron, StartResponse], Iterable[bytes]]
        app = process_connect.ProcessWSGIApplication(Process())
        return app
