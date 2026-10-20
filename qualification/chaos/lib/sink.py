# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The e2e HTTPS sink (``scripts/tests/_wire_capture_sink.py``) made fault-tolerant for
chaos: same arguments, same handler, same records.

The e2e sink wraps its listening socket with ``do_handshake_on_connect=True``, so the TLS
handshake runs inside ``accept()`` on the server's only accept thread with no timeout. One
connection whose handshake stalls (``netem corrupt``/``loss`` on the Node's egress) wedges
the sink for good, and every later delivery hangs: a destination fault, not a Node fault.
Here the handshake is deferred to the per-connection handler thread and every connection
gets a socket timeout, so one bad connection costs one thread for at most ``TIMEOUT_S``.
"""

from __future__ import annotations

import runpy
import ssl
import sys
from http.server import ThreadingHTTPServer
from pathlib import Path

TIMEOUT_S = 30
E2E_SINK = Path(__file__).resolve().parents[3] / "scripts" / "tests" / "_wire_capture_sink.py"


def main() -> None:
    sink = runpy.run_path(str(E2E_SINK), run_name="_wire_capture_sink")
    handler = sink["Handler"]
    handler.timeout = TIMEOUT_S  # StreamRequestHandler: settimeout() on each connection
    sink["RAW"].mkdir(parents=True, exist_ok=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(sink["CERT"], sink["KEY"])
    server = ThreadingHTTPServer((sink["BIND"], sink["PORT"]), handler)
    server.daemon_threads = True
    server.socket = context.wrap_socket(server.socket, server_side=True,
                                        do_handshake_on_connect=False)  # fmt: skip
    print(f"chaos sink ready on {sink['BIND']}:{sink['PORT']}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
