# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The SC-RA-3 fixture approval service: another service, in its own process, that decides
whether a refund may go ahead and reports each decision as OpenTelemetry, under its own
attribute names (spec 057 §10.4 P3 acceptance).

It knows nothing of Fabric. It uses the OpenTelemetry SDK and its OTLP/HTTP exporter, as
any service does, and sends its spans to the Fabric Node, where the customer's mapping
profile (``approval-service.profile.json``) rewrites them into control decision records.

- ``POST /approvals`` with ``{"ticket", "order_id", "amount"}`` answers ``202`` with
  ``{"status": "pending"}`` and decides about 100 ms later: ``approved`` up to
  ``LIMIT``, ``rejected`` above it. Each decision is one span ``approvals.decide`` in a
  trace of its own (the service is not told the agent's trace or run).
- ``GET /approvals/<ticket>`` answers the decision so far.

What a real service also puts on its spans travels with each decision: the requester's
email, a free-text reviewer note, a span event and an organisation id on the resource.
They are the harness's privacy canaries; the profile maps none of them, so none may
leave the Node.

Every decision is written to the ledger (``--ledger``, one JSON object per line), the
harness's ground truth. Without ``--otlp`` (the capture-off runs) the service decides the
same way and sends nothing.
"""

from __future__ import annotations

import argparse
import json
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import FrameType
from typing import Any

LIMIT = 100.0
DECIDE_AFTER_S = 0.1
POLICY = "refund-limits"
RELEASE = "2026.11.1"


class Service:
    def __init__(self, ledger: Path, otlp: str, email: str, note: str, org: str) -> None:
        self.ledger = ledger
        self.email = email
        self.note = note
        self.decisions: dict[str, str] = {}
        self.lock = threading.Lock()
        self.tracer: Any = None
        self.provider: Any = None
        if otlp:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # noqa: PLC0415
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.resources import Resource  # noqa: PLC0415
            from opentelemetry.sdk.trace import TracerProvider  # noqa: PLC0415
            from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: PLC0415

            resource = Resource.create({"service.name": "refund-approvals", "tenant.org_id": org})
            self.provider = TracerProvider(resource=resource)
            exporter = OTLPSpanExporter(endpoint=otlp.rstrip("/") + "/v1/traces", timeout=10)
            self.provider.add_span_processor(SimpleSpanProcessor(exporter))
            self.tracer = self.provider.get_tracer("refund-approvals")

    def submit(self, ticket: str, amount: float) -> None:
        with self.lock:
            self.decisions.setdefault(ticket, "pending")
        threading.Thread(target=self._decide, args=(ticket, amount), daemon=True).start()

    def status(self, ticket: str) -> str | None:
        with self.lock:
            return self.decisions.get(ticket)

    def _decide(self, ticket: str, amount: float) -> None:
        started = time.monotonic()
        time.sleep(DECIDE_AFTER_S)
        result = "approved" if amount <= LIMIT else "rejected"
        reason = "amount.within_limit" if result == "approved" else "amount.over_limit"
        took_ms = round((time.monotonic() - started) * 1000)
        trace_id = span_id = ""
        if self.tracer is not None:
            with self.tracer.start_as_current_span("approvals.decide") as span:
                span.set_attribute("approvals.ticket", ticket)
                span.set_attribute("approvals.result", result)
                span.set_attribute("approvals.policy_name", POLICY)
                span.set_attribute("approvals.policy_release", RELEASE)
                span.set_attribute("approvals.reason", reason)
                span.set_attribute("approvals.took_ms", took_ms)
                span.set_attribute("approvals.amount", amount)
                # What a real service also records; the profile maps none of it.
                span.set_attribute("enduser.email", self.email)
                span.set_attribute("approvals.note", self.note)
                span.add_event("reviewer.comment", {"comment.text": self.note})
                context = span.get_span_context()
                trace_id, span_id = f"{context.trace_id:032x}", f"{context.span_id:016x}"
        with self.lock:
            self.decisions[ticket] = result
            with self.ledger.open("a", encoding="utf-8") as out:
                out.write(
                    json.dumps(
                        {
                            "ticket": ticket,
                            "result": result,
                            "reason": reason,
                            "trace_id": trace_id,
                            "span_id": span_id,
                            "decided_at_ns": time.time_ns(),
                        }
                    )
                    + "\n"
                )

    def close(self) -> None:
        if self.provider is not None:
            self.provider.shutdown()


def serve(service: Service, port_file: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:
            return

        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if self.path != "/approvals":
                self._reply(404, {"error": "not found"})
                return
            try:
                request = json.loads(body)
                ticket, amount = str(request["ticket"]), float(request["amount"])
            except (ValueError, KeyError, TypeError):
                self._reply(400, {"error": "ticket and amount are required"})
                return
            service.submit(ticket, amount)
            self._reply(202, {"ticket": ticket, "status": "pending"})

        def do_GET(self) -> None:
            ticket = self.path.removeprefix("/approvals/")
            found = service.status(ticket) if self.path.startswith("/approvals/") else None
            if found is None:
                self._reply(404, {"error": "unknown ticket"})
                return
            self._reply(200, {"ticket": ticket, "status": found})

        def _reply(self, status: int, payload: dict[str, Any]) -> None:
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True

    def stop(signum: int, frame: FrameType | None) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    port_file.write_text(str(server.server_address[1]))
    try:
        server.serve_forever()
    finally:
        server.server_close()
        service.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port-file", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--otlp", default="", help="the Node's OTLP/HTTP base URL; empty: off")
    parser.add_argument("--email", required=True)
    parser.add_argument("--note", required=True)
    parser.add_argument("--org", required=True)
    args = parser.parse_args()
    serve(Service(args.ledger, args.otlp, args.email, args.note, args.org), args.port_file)


if __name__ == "__main__":
    main()
