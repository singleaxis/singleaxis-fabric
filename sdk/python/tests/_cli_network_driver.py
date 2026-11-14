# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Driver of the I4 (no phone-home) tests for every E1 command: ``init``, ``up``, ``run``,
``verify``, ``show``, ``doctor`` and ``down``.

Runs the commands in this process with every socket use recorded by an audit hook,
against a fake ``docker`` command and a fake Fabric Node (a loopback TLS server with the
certificate ``init`` generated, which writes what it receives into the project's data
directory as the Node and the local-dir sink do). Prints one JSON line: exit codes, every connection
attempt, every name lookup, and the ``docker`` commands issued.

``--netns``: the caller started this process in a fresh network namespace, whose only
interface is loopback (brought up here). Nothing outside the machine is reachable, so a
command that needed anything else would fail."""

from __future__ import annotations

import fcntl
import gzip
import http.server
import json
import os
import socket
import socketserver
import ssl
import stat
import struct
import sys
import threading
from pathlib import Path
from typing import Any

_FAKE_DOCKER = """#!{python}
import json, sys
args = sys.argv[1:]
with open({log!r}, "a") as handle:
    handle.write(json.dumps(args) + "\\n")
if args[:1] == ["info"]:
    print(json.dumps({{"OperatingSystem": "Docker Desktop", "KernelVersion": "6.12.0",
                      "CgroupVersion": "2", "SecurityOptions": []}}))
elif args[:1] == ["ps"]:
    pass
elif "ps" in args:
    print(json.dumps({{"Service": args[-1]}}))
"""
_SIOCGIFFLAGS, _SIOCSIFFLAGS, _IFF_UP = 0x8913, 0x8914, 0x1


def _interfaces_up() -> list[str]:
    """The interfaces that are up. A fresh namespace also lists the kernel's idle fallback
    tunnel devices (``gre0``, ``sit0``, ...); they are down and route nothing."""
    up = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _, name in socket.if_nameindex():
            request = struct.pack("16sH14s", name.encode()[:15], 0, b"")
            flags = struct.unpack("16sH14s", fcntl.ioctl(sock, _SIOCGIFFLAGS, request))[1]
            if flags & _IFF_UP:
                up.append(name)
    return sorted(up)


def _loopback_up() -> None:
    """Bring ``lo`` up in a fresh network namespace (no iproute2 needed)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        request = struct.pack("16sH14s", b"lo", 0, b"")
        flags = struct.unpack("16sH14s", fcntl.ioctl(sock, _SIOCGIFFLAGS, request))[1]
        fcntl.ioctl(sock, _SIOCSIFFLAGS, struct.pack("16sH14s", b"lo", flags | _IFF_UP, b""))


class _FakeNode(http.server.ThreadingHTTPServer):
    """The fake Node. ``HTTPServer.server_bind`` asks the resolver for this machine's name;
    that lookup would be the test's own, so it is skipped."""

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "localhost", self.server_address[1]


def _node_handler(data_dir: Path) -> type[http.server.BaseHTTPRequestHandler]:
    from fabric.cli import _localsink  # noqa: PLC0415

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            if self.headers.get("Content-Encoding") == "gzip":
                body = gzip.decompress(body)
            if self.path in _localsink.ROUTES:
                _localsink.store(data_dir, self.path, body)
            self.send_response(200)
            self.send_header("Content-Type", "application/x-protobuf")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def main(argv: list[str]) -> int:  # noqa: PLR0915 - one statement per command it drives
    work = Path(argv[0])
    netns = "--netns" in argv
    if netns:
        _loopback_up()
    if "--drop" in argv:  # started by sudo: back to the invoking user before anything runs
        uid, gid = (int(v) for v in argv[argv.index("--drop") + 1 :][:2])
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
    project = work / "agent"
    project.mkdir(parents=True)
    docker_log = work / "docker.log"
    bin_dir = work / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(_FAKE_DOCKER.format(python=sys.executable, log=str(docker_log)))
    docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
    for name in [n for n in os.environ if n.startswith(("FABRIC_", "OTEL_", "DOCKER_"))]:
        del os.environ[name]
    os.environ.update(PATH=f"{bin_dir}{os.pathsep}/usr/bin:/bin", HOME=str(work / "home"),
                      XDG_STATE_HOME=str(work / "xdg"))  # fmt: skip
    os.chdir(project)
    port = _free_port()
    (project / "fabric.yaml").write_text(
        f"schema: fabric.config/v1\nnode:\n  endpoint: https://localhost:{port}\n"
    )

    attempts: dict[str, list[Any]] = {"connect": [], "lookup": [], "send": []}

    def record(event: str, args: tuple[Any, ...]) -> None:
        if event == "socket.connect":
            attempts["connect"].append(list(args[1]) if isinstance(args[1], tuple) else args[1])
        elif event in ("socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr",
                       "socket.gethostbyname_ex"):  # fmt: skip
            attempts["lookup"].append(str(args[0]))
        elif event in ("socket.sendto", "socket.sendmsg"):
            attempts["send"].append(str(args[1]))

    sys.addaudithook(record)
    from fabric.cli import main as fabric  # noqa: PLC0415

    codes = {"init": fabric(["init", "--quiet"])}
    (secrets,) = (work / "xdg" / "fabric").iterdir()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(secrets / "secrets" / "node.crt", secrets / "secrets" / "node.key")
    server = _FakeNode(("127.0.0.1", port), _node_handler(project / "fabric-data"))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    codes["up"] = fabric(["up", "--quiet", "--wait", "20"])
    codes["up again"] = fabric(["up", "--quiet", "--wait", "20"])
    # The agent is a child (--no-exec keeps this process for the remaining commands); its
    # own connections are the SDK's, to the configured Node.
    codes["run"] = fabric(["run", "--no-exec", "--quiet", "--", sys.executable, "-c", "pass"])
    codes["verify --canary-only"] = fabric(["verify", "--canary-only", "--quiet", "--wait",
                                            "30"])  # fmt: skip
    codes["show --list"] = fabric(["show", "--list", "--quiet"])
    codes["doctor"] = fabric(["doctor", "--quiet"])
    codes["down"] = fabric(["down", "--quiet"])
    codes["down --purge"] = fabric(["down", "--purge", "--quiet"])
    server.shutdown()
    interfaces = _interfaces_up() if netns else []
    commands = [json.loads(line) for line in docker_log.read_text().splitlines()]
    sys.stdout.write(json.dumps({"codes": codes, "port": port, "attempts": attempts,
                                 "docker": commands, "interfaces": interfaces}) + "\n")  # fmt: skip
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
