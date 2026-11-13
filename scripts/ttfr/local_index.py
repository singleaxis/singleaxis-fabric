#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A package index for the TTFR test (spec 058 §3.3): ``pip install
"singleaxis-fabric[cli]"``, run verbatim from the Get started page, must install the
build under test, not the release on PyPI. This index serves the wheels of
``--wheel-dir`` for ``singleaxis-fabric`` and redirects every other project to PyPI, so
the dependencies are the ones a user downloads. Release candidates run without it
(``ttfr.py --published``). Standard library only; loopback only.

    python3 local_index.py --wheel-dir sdk/python/dist --ready-file index.json
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote

PROJECT = "singleaxis-fabric"
PYPI = "https://pypi.org/simple/"


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def handler(wheels: Path) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

        def do_GET(self) -> None:  # noqa: N802
            parts = [p for p in self.path.split("?")[0].split("/") if p]
            if (
                len(parts) == 2
                and parts[0] == "simple"
                and normalize(parts[1]) == PROJECT
            ):
                links = "".join(
                    f'<a href="/files/{quote(w.name)}">{html.escape(w.name)}</a>\n'
                    for w in sorted(wheels.glob("singleaxis_fabric-*.whl"))
                )
                self._send(
                    200,
                    "text/html",
                    f"<!DOCTYPE html><html><body>\n{links}</body></html>",
                )
            elif len(parts) == 2 and parts[0] == "simple":
                self.send_response(302)
                self.send_header("Location", f"{PYPI}{normalize(parts[1])}/")
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif (
                len(parts) == 2
                and parts[0] == "files"
                and (wheels / parts[1]).is_file()
            ):
                data = (wheels / parts[1]).read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self._send(404, "text/plain", "not found")

        def _send(self, status: int, kind: str, text: str) -> None:
            data = text.encode()
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    options = parser.parse_args(argv)
    if not list(options.wheel_dir.glob("singleaxis_fabric-*.whl")):
        print(
            f"local_index: no singleaxis_fabric wheel in {options.wheel_dir}",
            file=sys.stderr,
        )
        return 2
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler(options.wheel_dir))
    options.ready_file.write_text(json.dumps({"port": server.server_address[1]}))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
