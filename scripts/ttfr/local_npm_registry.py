#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A loopback npm registry for the Node.js TTFR test (spec 058 §3.3): the page's verbatim
``npm install @singleaxis/fabric ...`` resolves ``@singleaxis/fabric`` to the tarball under
test, and every other package to the public registry (its metadata is fetched from there
and served unchanged, so its tarballs come from there too). The npm counterpart of
``local_index.py``. Standard library only.

    python3 local_npm_registry.py --tarball singleaxis-fabric-0.12.1.tgz --ready-file r.json
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import sys
import tarfile
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote

PACKAGE = "@singleaxis/fabric"
UPSTREAM = "https://registry.npmjs.org"
_FIELDS = ("name", "version", "description", "license", "type", "main", "module", "types",
           "exports", "bin", "engines", "dependencies", "peerDependencies",
           "peerDependenciesMeta", "optionalDependencies")  # fmt: skip


def packument(tarball: bytes, base: str) -> dict[str, Any]:
    """The registry document of the one version in ``tarball``."""
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as archive:
        member = archive.extractfile("package/package.json")
        if member is None:
            raise ValueError("the tarball has no package/package.json")
        manifest = json.loads(member.read())
    if manifest.get("name") != PACKAGE:
        raise ValueError(f"the tarball is {manifest.get('name')!r}, not {PACKAGE}")
    version = manifest["version"]
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()
    entry = {k: manifest[k] for k in _FIELDS if k in manifest}
    entry["dist"] = {"tarball": f"{base}/-/fabric-{version}.tgz", "integrity": integrity,
                     "shasum": hashlib.sha1(tarball).hexdigest()}  # noqa: S324 - npm's field
    return {"name": PACKAGE, "dist-tags": {"latest": version}, "versions": {version: entry}}


def handler(tarball: bytes, base: str) -> type[BaseHTTPRequestHandler]:
    document = json.dumps(packument(tarball, base)).encode()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

        def do_GET(self) -> None:  # noqa: N802
            path = unquote(self.path.split("?", 1)[0])
            if path.rstrip("/") == f"/{PACKAGE}":
                self._send(200, document, "application/json")
            elif path.startswith("/-/fabric-") and path.endswith(".tgz"):
                self._send(200, tarball, "application/octet-stream")
            else:
                self._proxy()

        def _proxy(self) -> None:
            request = urllib.request.Request(  # noqa: S310 - the public registry, fixed
                UPSTREAM + self.path,
                headers={"Accept": self.headers.get("Accept", "application/json")},
            )
            try:
                with urllib.request.urlopen(request, timeout=60) as answer:  # noqa: S310
                    self._send(answer.status, answer.read(),
                               answer.headers.get("Content-Type", "application/json"))  # fmt: skip
            except urllib.error.HTTPError as exc:
                self._send(exc.code, exc.read(), "application/json")
            except OSError:
                self._send(502, b'{"error":"upstream unreachable"}', "application/json")

        def _send(self, status: int, body: bytes, kind: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tarball", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--ready-file", type=Path, required=True)
    options = parser.parse_args(argv)
    tarball = options.tarball.read_bytes()
    server = ThreadingHTTPServer((options.host, options.port), BaseHTTPRequestHandler)
    port = server.server_address[1]
    server.RequestHandlerClass = handler(tarball, f"http://{options.host}:{port}")
    options.ready_file.write_text(json.dumps({"port": port}), encoding="utf-8")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
