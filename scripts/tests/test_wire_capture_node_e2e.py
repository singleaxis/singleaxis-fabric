# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""LLM wire capture through a real, production-shaped Fabric Node (specs 047, 048).

This drives the whole recorder path in node mode with real processes and
real sockets:

    ReAct agent over plain httpx and over the real OpenAI SDK (httpx2)
        (zero-code autoload, no Fabric import, no cloud credentials)
        -> fake OpenAI-compatible model (http.server, real TCP)
        -> wire tee -> durable agent spool (FABRIC_WIRE_SPOOL_DIR)
        -> sender: bodies as OTLP/HTTP log records to the Node's content
           port (4319), then the span over OTLP/HTTP (4318); TLS + bearer
    Fabric Node (the custom Collector image, fabric-gate entrypoint,
    collector-production.yaml plus the opt-in content path,
    docker-compose.content.yml / collector-content.yaml, with their documented
    TLS stanzas enabled):
        traces/logs: memory_limiter + fabricguard -> persistent queue
            -> OTLP/HTTP over TLS (private CA) + egress Authorization
            -> fsync sink -> decoded JSONL
        logs/content: memory_limiter -> fabriccontent (file backend)
            -> the Node's content volume (SDK store layout)
    ``python -m fabric.reconstruct --spans <sink> --store-root <content>``

and proves, against the running stack:

- every model call (non-streamed, streamed SSE, tool-call round trip)
  arrives as a ``fabric.model_call`` span, with heartbeats, and the agent's
  spool is empty afterwards (every record delivered and deleted);
- the Node, not the agent, wrote every body and descriptor; capture spans
  carry only the spec 047 §8 keys and their digests/refs agree with the
  Node-written store;
- no prompt, completion, tool argument/result, model API key or bearer
  token appears in the sink output, the raw delivered bytes, the Node logs
  or the Node's telemetry queue volume (while the content store does hold
  the content);
- by default (spec 048 J1) the agents' clear source ids, service names and
  the tenant id appear in none of the sink output, the delivered bytes, the
  Node logs or the reconstruction reports: only their s-/svc-/t- pseudonyms;
- the run reconstructs ``complete_for_declared_scope`` with zero gaps;
- spans accepted while the destination is down survive a Node restart in
  the persistent queue and arrive afterwards, still reconstructing cleanly;
- a wrong ingress token is rejected on the telemetry and content ports, the
  agent is unaffected and keeps its undelivered records on disk.

Opt-in by environment: the module skips when Docker Compose is unavailable.
``FABRIC_NODE_IMAGE`` reuses a prebuilt Node image instead of building one.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from _wire_capture_common import (
    AGENT,
    COMPOSE_DIR,
    DEFAULT_NODE_IMAGE,
    FakeModel,
    Sink,
    autoload_path,
    build_image,
    compose_available,
    free_port,
    content_config_with_tls,
    production_config_with_tls,
    pseudonym,
    spool_header,
    spool_records,
    volume_grep,
    wait_until,
    write_tls,
)

TENANT = "wire-e2e-tenant"
NODE_CONTENT_DIR = "/var/lib/fabric-node/content"

# Unique per session: content and credentials that must never leave the
# agent process except as bytes in the customer's own store.
MARK = f"WIREE2E{uuid.uuid4().hex[:12]}"
PROMPT = f"{MARK}_prompt What is the temperature in Paris in Fahrenheit?"
CITY = f"{MARK}_city"
TOOL_RESULT = f"{MARK}_toolresult"
COMPLETION = f"{MARK}_completion"
API_KEY = f"sk-{MARK}_apikey"
INGRESS_TOKEN = f"{MARK}_ingress_token"
WRONG_TOKEN = f"{MARK}_wrong_token"
EGRESS_AUTH = f"Bearer {MARK}_egress_token"
# Set by the agent as its ambient W3C trace state (spec 047 §8, decision E7).
TRACE_STATE = f"{MARK}_tracestate"
CONTENT_MARKERS = [f"{MARK}_prompt", CITY, TOOL_RESULT, COMPLETION]
# The run-id pseudonym key (spec 048 §6, H3): a secret the agent never emits.
ID_KEY = f"{MARK}_idkey"
SECRET_MARKERS = [
    API_KEY, INGRESS_TOKEN, WRONG_TOKEN, f"{MARK}_egress_token", TRACE_STATE, ID_KEY
]  # fmt: skip


def source_of(service: str) -> str:
    """The clear FABRIC_SOURCE_ID each agent is given: identifying on purpose (J1)."""
    return f"{MARK}-src-{service}"


# Spec 047 §8: the fifteen capture keys, plus spec 048's run scope id, plus
# the reused, already allowlisted keys a capture span may carry. Anything
# else is a leak channel.
CAPTURE_KEYS = frozenset(
    {
        "fabric.source.epoch", "fabric.run.id", "fabric.wire.exchange_id", "fabric.wire.api",
        "fabric.wire.request_sha256", "fabric.wire.response_sha256",
        "fabric.wire.response_state", "fabric.wire.truncated", "fabric.wire.store_status",
        "fabric.loss.reason", "fabric.loss.count", "fabric.loss.first_sequence",
        "fabric.loss.last_sequence", "fabric.heartbeat.last_sequence",
        "fabric.heartbeat.kind", "fabric.run.scope_id",
    }
)  # fmt: skip
REUSED_KEYS = frozenset(
    {
        "fabric.source_id", "fabric.source.sequence", "fabric.content.request_ref",
        "fabric.content.result_ref", "gen_ai.operation.name", "gen_ai.provider.name",
        "http.request.method", "http.response.status_code", "error.type",
        "gen_ai.response.model", "gen_ai.response.finish_reasons",
        "gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens",
    }
)  # fmt: skip
assert len(CAPTURE_KEYS) == 16
HEARTBEAT_KINDS = frozenset({"periodic", "run_start", "run_end", "final"})
# Content refs on spans are bare uuid4 object ids (spec 047 §8, decision D2).
OBJECT_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
# Spec 048 F7: "e2e-model-2026" is not on the model allowlist.
HASHED_MODEL = re.compile(r"m-[0-9a-f]{16}")
EXCHANGE_REQUIRED = frozenset(
    {
        "fabric.wire.exchange_id", "fabric.run.id", "fabric.source_id",
        "fabric.source.sequence", "fabric.source.epoch", "fabric.wire.api",
        "fabric.wire.request_sha256", "fabric.wire.response_sha256",
        "fabric.wire.response_state", "fabric.wire.truncated", "fabric.wire.store_status",
        "fabric.content.request_ref", "fabric.content.result_ref", "gen_ai.operation.name",
        "gen_ai.provider.name", "http.request.method", "http.response.status_code",
    }
)  # fmt: skip
# Extracted only from a complete, plain-JSON response (spec 047 §5): never
# from the streamed call.
EXCHANGE_METADATA = frozenset(
    {
        "gen_ai.response.model", "gen_ai.response.finish_reasons",
        "gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens",
    }
)  # fmt: skip
CAPTURE_SPAN_NAMES = {
    "fabric.model_call",
    "fabric.capture_heartbeat",
    "fabric.capture_loss",
}
SPAN_KIND_CLIENT = 3


pytestmark = pytest.mark.skipif(
    not compose_available(), reason="docker compose unavailable — env-dependent gate"
)


# --------------------------------------------------------------------------
# The stack: Node (compose, production overlay) + host sink + fake model
# --------------------------------------------------------------------------


@dataclass
class AgentRun:
    service: str
    spool: Path
    result: subprocess.CompletedProcess[str]
    model_requests: int
    info: dict[str, Any] = field(default_factory=dict)
    # The Node-written content store snapshot holding this run's objects.
    store: Path = Path()


class Stack:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.project = f"fabric-wire-e2e-{uuid.uuid4().hex[:12]}"
        self.tls = root / "tls"
        self.ports = {
            name: free_port()
            for name in ("otlp_http", "otlp_grpc", "otlp_content", "health", "metrics")
        }
        self.image = os.environ.get("FABRIC_NODE_IMAGE") or DEFAULT_NODE_IMAGE
        self.model = FakeModel(api_key=API_KEY, city=CITY, completion=COMPLETION)
        token_file = root / "secrets" / "ingress.token"
        token_file.parent.mkdir()
        # No trailing newline (fabric-gate rule); nonroot in the container
        # reads it through a bind mount.
        token_file.write_text(INGRESS_TOKEN, "utf-8")
        token_file.chmod(0o644)
        write_tls(self.tls)
        self.sink = Sink(root / "sink", self.tls, EGRESS_AUTH, id_key=ID_KEY)
        # Clear labels the agents were given, and every report: the J1 leak scan.
        self.services: set[str] = set()
        self.reports: list[str] = []
        self.config = root / "collector-production.yaml"
        production_config_with_tls(self.config)
        self.content_config = root / "collector-content.yaml"
        content_config_with_tls(self.content_config)
        self.override = root / "compose.override.yml"
        self.override.write_text(
            "services:\n"
            "  fabric-node:\n"
            "    pull_policy: never\n"
            "    volumes:\n"
            f"      - {self.config}:/etc/fabric-node/collector-production.yaml:ro\n"
            f"      - {self.content_config}:/etc/fabric-node/collector-content.yaml:ro\n"
            "    extra_hosts:\n"
            '      - "host.docker.internal:host-gateway"\n',
            "utf-8",
        )
        (root / "empty.env").write_text("", "utf-8")
        self.env = {
            **{k: v for k, v in os.environ.items() if not k.startswith("FABRIC_")},
            "FABRIC_NODE_IMAGE": self.image,
            "FABRIC_BIND_ADDR": "127.0.0.1",
            "FABRIC_OTLP_HTTP_PORT": str(self.ports["otlp_http"]),
            "FABRIC_OTLP_GRPC_PORT": str(self.ports["otlp_grpc"]),
            "FABRIC_OTLP_CONTENT_PORT": str(self.ports["otlp_content"]),
            "FABRIC_HEALTH_PORT": str(self.ports["health"]),
            "FABRIC_METRICS_PORT": str(self.ports["metrics"]),
            "FABRIC_INGRESS_TOKEN_FILE": str(token_file),
            "FABRIC_INGRESS_TLS_DIR": str(self.tls),
            "FABRIC_EXPORT_ENDPOINT": self.sink.endpoint,
            "FABRIC_EXPORT_AUTH_HEADER": EGRESS_AUTH,
            # The only tenant the Node's fabriccontent exporter writes.
            "FABRIC_TENANT_ID": TENANT,
        }
        self._autoload = autoload_path()

    # -- compose -------------------------------------------------------------

    def compose(
        self, *args: str, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        command = [
            "docker", "compose", "-p", self.project, "--project-directory", str(COMPOSE_DIR),
            "--env-file", str(self.root / "empty.env"),
            "-f", str(COMPOSE_DIR / "docker-compose.yml"),
            "-f", str(COMPOSE_DIR / "docker-compose.production.yml"),
            # The opt-in production content path (FABRIC_CONTENT_BACKEND=file).
            "-f", str(COMPOSE_DIR / "docker-compose.content.yml"),
            "-f", str(self.override), *args,
        ]  # fmt: skip
        return subprocess.run(
            command, cwd=COMPOSE_DIR, env=self.env, check=check, capture_output=True,
            text=True, timeout=900,
        )  # fmt: skip

    def node_logs(self) -> str:
        result = self.compose("logs", "--no-color", "fabric-node", check=False)
        return result.stdout + result.stderr

    def wait_health(self, timeout_s: float = 60.0) -> None:
        def healthy() -> bool:
            try:
                url = f"http://127.0.0.1:{self.ports['health']}/"
                with urllib.request.urlopen(url, timeout=2) as response:
                    return bool(response.status == 200)
            except (OSError, ValueError):
                return False

        wait_until(
            healthy, timeout_s,
            lambda: f"Fabric Node never became healthy:\n{self.node_logs()[-4000:]}",
        )  # fmt: skip

    def queue_size(self, exporter: str = "otlp_http/fabric") -> float:
        url = f"http://127.0.0.1:{self.ports['metrics']}/metrics"
        with urllib.request.urlopen(url, timeout=5) as response:
            text = response.read().decode()
        sizes = [
            float(line.rsplit(" ", 1)[1])
            for line in text.splitlines()
            if line.startswith("otelcol_exporter_queue_size{")
            and f'exporter="{exporter}"' in line
        ]
        return max(sizes, default=0.0)

    # -- sink ----------------------------------------------------------------

    @property
    def records(self) -> Path:
        return self.sink.records

    def spans_of(self, service: str) -> list[dict[str, Any]]:
        return self.sink.spans_of(service)

    def wait_for_run(
        self, service: str, calls: int, timeout_s: float = 90.0
    ) -> list[dict[str, Any]]:
        """Until every exchange span and the clean-exit final heartbeat of ``service`` arrived."""
        found: list[dict[str, Any]] = []

        def arrived() -> bool:
            found[:] = self.spans_of(service)
            exchanges = {
                s["attributes"].get("fabric.wire.exchange_id")
                for s in found if s["name"] == "fabric.model_call"
            }  # fmt: skip
            tail = [
                s for s in found
                if s["attributes"].get("fabric.heartbeat.kind") == "final"
            ]  # fmt: skip
            return len(exchanges) >= calls and bool(tail)

        wait_until(
            arrived, timeout_s,
            lambda: f"{service}: {len(found)} spans after {timeout_s}s, expected {calls} "
            f"exchanges and a final heartbeat\n{self.node_logs()[-4000:]}",
        )  # fmt: skip
        return found

    # -- Node-written content --------------------------------------------------

    def content_snapshot(self) -> Path:
        """A host copy of the Node's content volume (file backend)."""
        target = self.root / f"content-{uuid.uuid4().hex[:8]}"
        self.compose("cp", f"fabric-node:{NODE_CONTENT_DIR}", str(target))
        return target

    def wait_content(self, object_ids: set[str], timeout_s: float = 60.0) -> Path:
        """Snapshot once every object and descriptor in ``object_ids`` is on the Node."""
        snapshot: list[Path] = []

        def written() -> bool:
            store = self.content_snapshot()
            snapshot[:] = [store]
            evidence = store / TENANT / "evidence"
            return all(
                (evidence / oid).is_file()
                and (evidence / "meta" / f"{oid}.json").is_file()
                for oid in object_ids
            )

        wait_until(
            written, timeout_s,
            lambda: f"the Node did not write {len(object_ids)} objects\n"
            f"{self.node_logs()[-4000:]}",
        )  # fmt: skip
        return snapshot[0]

    # -- agent ---------------------------------------------------------------

    def agent_env(self, service: str, spool: Path, token: str) -> dict[str, str]:
        self.services.add(service)
        base = {
            k: v for k, v in os.environ.items()
            if not k.startswith(("FABRIC_", "OTEL_", "AWS_")) and k != "PYTHONPATH"
        }  # fmt: skip
        return {
            **base,
            "PYTHONPATH": self._autoload,
            "FABRIC_WIRE_AUTOLOAD": "1",
            "FABRIC_TENANT_ID": TENANT,
            # Node mode (spec 048): no FABRIC_WIRE_STORE, no store credentials.
            "FABRIC_WIRE_CONTENT_ENDPOINT": (
                f"https://127.0.0.1:{self.ports['otlp_content']}/v1/logs"
            ),
            "FABRIC_WIRE_SPOOL_DIR": str(spool),
            "FABRIC_WIRE_ENDPOINTS": self.model.endpoints_json(),
            "FABRIC_WIRE_ID_KEY": ID_KEY,
            # Default labels (no FABRIC_WIRE_LABELS): leave only as s-/svc- (J1).
            "FABRIC_SOURCE_ID": source_of(service),
            "OTEL_SERVICE_NAME": service,
            "OTEL_EXPORTER_OTLP_ENDPOINT": f"https://127.0.0.1:{self.ports['otlp_http']}",
            "OTEL_EXPORTER_OTLP_HEADERS": "Authorization=" + quote(f"Bearer {token}"),
            "OTEL_EXPORTER_OTLP_CERTIFICATE": str(self.tls / "ca.crt"),
            "E2E_MODEL_API_KEY": API_KEY,
            "E2E_TOOL_RESULT_MARK": TOOL_RESULT,
            "E2E_TRACE_STATE": TRACE_STATE,
        }

    def run_agent(
        self,
        service: str,
        *,
        token: str = INGRESS_TOKEN,
        spool: Path | None = None,
        client: str = "httpx",
    ) -> AgentRun:
        spool = spool or self.root / "spool" / service
        before = self.model.requests
        result = subprocess.run(  # noqa: S603
            [sys.executable, str(AGENT), "--model-url", self.model.url, "--question", PROMPT,
             "--client", client],
            env=self.agent_env(service, spool, token), cwd=self.root, capture_output=True,
            text=True, timeout=180, check=False,
        )  # fmt: skip
        run = AgentRun(service, spool, result, self.model.requests - before)
        assert result.returncode == 0, (
            f"agent failed:\n{result.stdout}\n{result.stderr}"
        )
        run.info = json.loads(result.stdout.strip().splitlines()[-1])
        assert run.info["capture_active"], (
            f"zero-code capture did not install:\n{result.stderr}"
        )
        assert "capture not installed" not in result.stderr
        assert "autoload failed" not in result.stderr, result.stderr
        assert ID_KEY not in result.stdout + result.stderr, "the id key was echoed"
        assert run.info["answer"].startswith(COMPLETION), run.info
        assert run.model_requests == 3 and self.model.unauthorized == 0
        # Spec 048 F1: the agent holds no store credentials and loads no cloud SDK.
        assert run.info["aws_env"] == [] and run.info["cloud_sdk_imported"] == [], (
            run.info
        )
        return run

    # -- verification --------------------------------------------------------

    def reconstruct(self, store: Path) -> tuple[int, dict[str, Any]]:
        out = self.root / f"report-{uuid.uuid4().hex[:8]}.json"
        result = subprocess.run(
            [sys.executable, "-m", "fabric.reconstruct", "--spans", str(self.records),
             "--store-root", str(store), "--tenant", TENANT, "--out", str(out)],
            env={**os.environ, "FABRIC_WIRE_ID_KEY": ID_KEY},
            capture_output=True, text=True, timeout=300, check=False,
        )  # fmt: skip
        assert result.returncode in (0, 1), f"reconstruct usage error:\n{result.stderr}"
        text = out.read_text("utf-8")
        self.reports.append(text + result.stdout + result.stderr)
        report: dict[str, Any] = json.loads(text)
        _assert_report_labels(report, text)
        return result.returncode, report


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    stack = Stack(tmp_path_factory.mktemp("wire-node"))
    try:
        if not os.environ.get("FABRIC_NODE_IMAGE"):
            build_image(stack.image)
        stack.sink.start()
        stack.compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "90")
        stack.wait_health()
        yield stack
    finally:
        stack.compose("down", "-v", "--remove-orphans", check=False)
        stack.sink.stop()
        stack.model.close()


# --------------------------------------------------------------------------
# Assertions shared by the tests
# --------------------------------------------------------------------------


def _store_descriptors(store: Path) -> dict[str, dict[str, Any]]:
    """Descriptor per stored object id, from the self-describing store."""
    return {
        path.stem: json.loads(path.read_text("utf-8"))
        for path in store.glob(f"{TENANT}/evidence/meta/*.json")
    }


def _assert_report_labels(report: dict[str, Any], text: str) -> None:
    """J1: the report names the tenant only as t-, sources only as s-."""
    assert report["inputs"]["store"]["tenant_id"] == pseudonym("t-", TENANT, ID_KEY)
    assert TENANT not in text, "the clear tenant id appeared in a report"
    sources = set(_values_of(report, "source_id"))
    assert sources and all(re.fullmatch(r"s-[0-9a-f]{32}", s) for s in sources), sources


def _values_of(node: Any, key: str) -> Iterator[Any]:
    """Every value stored under ``key`` anywhere in a JSON document."""
    if isinstance(node, dict):
        for name, value in node.items():
            if name == key:
                yield value
            yield from _values_of(value, key)
    elif isinstance(node, list):
        for item in node:
            yield from _values_of(item, key)


def _label_markers(stack: Stack) -> list[str]:
    """Clear labels that must never leave an agent by default (J1), plus the tenant."""
    return sorted(
        {TENANT} | stack.services | {source_of(service) for service in stack.services}
    )


def _assert_no_leak(stack: Stack) -> None:
    sink_text = stack.records.read_text("utf-8")
    raw = stack.sink.raw_bytes()
    logs = stack.node_logs()
    assert sink_text and raw and "fabric-node" in logs, "a leak scan would be vacuous"
    assert b"fabric.wire.exchange_id" in raw  # the raw bytes are the delivered spans
    for marker in CONTENT_MARKERS + SECRET_MARKERS:
        assert marker not in sink_text, f"{marker} reached the decoded sink output"
        assert marker.encode() not in raw, f"{marker} reached the delivered OTLP bytes"
        assert marker not in logs, f"{marker} appeared in the Node logs"
    # J1: pseudonymous labels by default. The scan is not vacuous: some agent's
    # svc-/s- pseudonyms reached the sink.
    assert any(
        pseudonym("svc-", service, ID_KEY) in sink_text
        and pseudonym("s-", source_of(service), ID_KEY) in sink_text
        for service in stack.services
    ), "a label leak scan would be vacuous"
    reports = "\n".join(stack.reports)
    for marker in _label_markers(stack):
        assert marker not in sink_text, f"clear label {marker} reached the sink"
        assert marker.encode() not in raw, (
            f"clear label {marker} reached the OTLP bytes"
        )
        assert marker not in logs, f"clear label {marker} appeared in the Node logs"
        assert marker not in reports, f"clear label {marker} appeared in a report"
    assert volume_grep(f"{stack.project}_fabric-queue", MARK) == "", (
        "a marker persisted in the Node's telemetry queue volume"
    )
    # The content queue carries bodies by design, never a credential.
    for secret in SECRET_MARKERS:
        assert volume_grep(f"{stack.project}_fabric-content-queue", secret) == "", (
            f"{secret} persisted in the Node's content queue volume"
        )


def _delivered(
    stack: Stack, run: AgentRun, calls: int = 3, timeout_s: float = 90.0
) -> list[dict[str, Any]]:
    """Wait for the run's spans and its Node-written objects; the spool is drained."""
    spans = stack.wait_for_run(run.service, calls=calls, timeout_s=timeout_s)
    refs = {
        s["attributes"][key]
        for s in spans if s["name"] == "fabric.model_call"
        for key in ("fabric.content.request_ref", "fabric.content.result_ref")
    }  # fmt: skip
    run.store = stack.wait_content(refs)
    # Every record was delivered (content, then span) before it was deleted.
    assert spool_records(run.spool) == [], [p.name for p in spool_records(run.spool)]
    assert not list(run.spool.glob("*.corrupt"))
    return spans


def _assert_capture_spans(
    spans: list[dict[str, Any]],
    run: AgentRun,
    *,
    streamed_states: frozenset[str] = frozenset({"complete"}),
) -> list[dict[str, Any]]:
    """Shape of one agent's capture spans after the Node; returns the exchanges.

    ``streamed_states``: the OpenAI SDK (>=3) stops reading at ``[DONE]`` and
    closes the response before end-of-stream, which is recorded as
    ``closed_early`` with every byte the client read (spec 047 §4.6).
    """
    store = run.store
    assert {s["name"] for s in spans} <= CAPTURE_SPAN_NAMES, {s["name"] for s in spans}
    for span in spans:
        extra = set(span["attributes"]) - CAPTURE_KEYS - REUSED_KEYS
        assert not extra, f"{span['name']} carries non-allowlisted keys {extra}"
        assert span["scope"] == "", (
            "fabricguard must clear the instrumentation scope name"
        )
        # Decision E7: the host's trace state never leaves with a capture span.
        assert span["trace_state"] == "", (span["name"], span["trace_state"])
    by_id: dict[str, dict[str, Any]] = {}
    for span in spans:
        if span["name"] == "fabric.model_call":
            by_id.setdefault(span["attributes"]["fabric.wire.exchange_id"], span)
    exchanges = sorted(
        by_id.values(), key=lambda s: s["attributes"]["fabric.source.sequence"]
    )
    assert [s["attributes"]["fabric.source.sequence"] for s in exchanges] == [0, 1, 2]
    assert len({s["attributes"]["fabric.source.epoch"] for s in exchanges}) == 1
    assert len({s["attributes"]["fabric.run.id"] for s in exchanges}) == 1
    descriptors = _store_descriptors(store)
    for index, span in enumerate(exchanges):
        attrs = span["attributes"]
        missing = EXCHANGE_REQUIRED - set(attrs)
        assert not missing, f"the Node dropped exchange keys {missing}"
        assert span["span_kind"] == SPAN_KIND_CLIENT
        # Correlation is kept: the exchange is a child of the host's ambient span.
        assert (span["trace_id"], span["parent_span_id"]) == (
            run.info["trace_id"],
            run.info["span_id"],
        )
        assert attrs["fabric.wire.api"] == "openai.chat_completions"
        streamed = index == 1
        states = streamed_states if streamed else {"complete"}
        assert attrs["fabric.wire.response_state"] in states, (index, attrs)
        assert attrs["fabric.wire.store_status"] == "stored"
        assert attrs["fabric.wire.truncated"] is False
        assert attrs["http.response.status_code"] == 200
        assert attrs["gen_ai.operation.name"] == "chat"
        present = EXCHANGE_METADATA & set(attrs)
        assert present == (set() if streamed else EXCHANGE_METADATA), (index, present)
        if not streamed:
            assert HASHED_MODEL.fullmatch(attrs["gen_ai.response.model"]), attrs
        for ref_key, digest_key, role in (
            (
                "fabric.content.request_ref",
                "fabric.wire.request_sha256",
                "model.exchange.request",
            ),
            (
                "fabric.content.result_ref",
                "fabric.wire.response_sha256",
                "model.exchange.response",
            ),
        ):
            assert OBJECT_ID.fullmatch(attrs[ref_key]), (ref_key, attrs[ref_key])
            descriptor = descriptors[attrs[ref_key]]
            assert descriptor["role"] == role
            assert descriptor["operation_id"] == attrs["fabric.wire.exchange_id"]
            assert descriptor["stored_sha256"] == "sha256:" + attrs[digest_key]
            assert descriptor["source_sequence"] == attrs["fabric.source.sequence"]
            # A response the client closed before end-of-stream is stored as
            # exactly the bytes it read, described as ``partial``.
            complete = attrs["fabric.wire.response_state"] == "complete"
            exact = role == "model.exchange.request" or complete
            assert descriptor["representation"] == ("exact" if exact else "partial")
        if streamed:
            response = descriptors[attrs["fabric.content.result_ref"]]
            assert response["media_type"] == "text/event-stream"
    heartbeats = [s for s in spans if s["name"] == "fabric.capture_heartbeat"]
    assert heartbeats, "no heartbeat reached the sink"
    # Decision E1: every heartbeat names its kind; a clean interpreter exit
    # emits a final heartbeat covering the last allocated sequence.
    kinds = {s["attributes"].get("fabric.heartbeat.kind") for s in heartbeats}
    assert kinds <= HEARTBEAT_KINDS, kinds
    finals = {
        s["attributes"]["fabric.heartbeat.last_sequence"]
        for s in heartbeats
        if s["attributes"]["fabric.heartbeat.kind"] == "final"
    }
    assert finals == {2}, f"expected one final heartbeat at sequence 2, got {finals}"
    epoch = exchanges[0]["attributes"]["fabric.source.epoch"]
    assert all(s["attributes"]["fabric.source.epoch"] == epoch for s in heartbeats)
    assert not [s for s in spans if s["name"] == "fabric.capture_loss"], (
        "unexpected capture loss"
    )
    return exchanges


def _assert_complete(report: dict[str, Any], code: int, runs: set[str]) -> None:
    by_run = {run["run_id"]: run for run in report["runs"]}
    assert runs <= set(by_run), (runs, set(by_run))
    for run_id, run in by_run.items():
        assert run["verdict"] == "complete_for_declared_scope", (
            run_id,
            run["gaps"],
            run["checks"],
        )
        assert run["gaps"] == [], (run_id, run["gaps"])
        # Decision E2: completeness is proven by the epoch's final heartbeat
        # (no run markers: the agent never calls fabric.wire.run()).
        windows = run["declared_scope"]["windows"]
        closers = {window.get("closed_by") for window in windows}
        assert closers == {"final_heartbeat"}, (run_id, windows)
        assert set(run["checks"].values()) <= {"passed", "not_applicable"}, run[
            "checks"
        ]
    for run_id in runs:
        assert by_run[run_id]["counts"]["exchanges"] == 3
        # One thread: request N+1 continues response N, tool calls matched.
        assert len(by_run[run_id]["threads"]) == 1, by_run[run_id]["threads"]
    assert code == 0


# --------------------------------------------------------------------------
# Tests (module order matters: they share one Node and one sink)
# --------------------------------------------------------------------------


def _assert_store_holds_content(run: AgentRun, exchanges: list[dict[str, Any]]) -> None:
    """This run's Node-written objects hold the content; headers were never stored."""
    stored = b"".join(
        (run.store / TENANT / "evidence" / s["attributes"][key]).read_bytes()
        for s in exchanges
        for key in ("fabric.content.request_ref", "fabric.content.result_ref")
    )
    for marker in CONTENT_MARKERS:
        assert marker.encode() in stored, f"{marker} was not captured into the store"
    for secret in SECRET_MARKERS:
        assert secret.encode() not in stored, f"{secret} was written to the store"
    descriptors = _store_descriptors(run.store)
    for span in exchanges:
        descriptor = descriptors[span["attributes"]["fabric.content.request_ref"]]
        # Written by the Node's file backend, in the SDK layout and format.
        assert descriptor["encoding"] == "binary"
        assert descriptor["ref"].startswith(
            f"file://{NODE_CONTENT_DIR}/{TENANT}/evidence/"
        )
        assert descriptor["tenant_id"] == TENANT


def test_wire_capture_streams_through_production_node_and_reconstructs(
    stack: Stack,
) -> None:
    # The Node boots through fabric-gate, which validated this config.
    container = stack.compose("ps", "-q", "fabric-node").stdout.strip()
    entrypoint = subprocess.run(
        ["docker", "inspect", "--format", "{{json .Config.Entrypoint}}", container],
        check=True, capture_output=True, text=True, timeout=30,
    ).stdout.strip()  # fmt: skip
    assert entrypoint == '["/fabric-gate"]'

    run = stack.run_agent("wire-e2e-agent")
    spans = _delivered(stack, run)
    exchanges = _assert_capture_spans(spans, run)
    _assert_store_holds_content(run, exchanges)
    _assert_no_leak(stack)

    code, report = stack.reconstruct(run.store)
    _assert_complete(report, code, {exchanges[0]["attributes"]["fabric.run.id"]})


def test_real_openai_sdk_through_production_node_reconstructs(stack: Stack) -> None:
    """The deployment-relevant proof: an unmodified OpenAI SDK (>=3, httpx2)
    application, sync and streamed, captured with zero code and delivered
    through the production Node."""
    run = stack.run_agent("wire-e2e-openai", client="openai")
    spans = _delivered(stack, run)
    exchanges = _assert_capture_spans(
        spans, run, streamed_states=frozenset({"complete", "closed_early"})
    )
    states = [s["attributes"]["fabric.wire.response_state"] for s in exchanges]
    print(f"openai SDK exchange states: {states}")
    _assert_store_holds_content(run, exchanges)
    _assert_no_leak(stack)

    code, report = stack.reconstruct(run.store)
    _assert_complete(report, code, {exchanges[0]["attributes"]["fabric.run.id"]})


def test_queued_spans_survive_sink_outage_and_node_restart(stack: Stack) -> None:
    stack.sink.stop()
    try:
        run = stack.run_agent("wire-e2e-outage")
        # The Node accepted every record (the agent's spool drained) and holds
        # the spans in its persistent queue because the destination is down.
        wait_until(
            lambda: stack.queue_size() >= 1 and not spool_records(run.spool), 60,
            lambda: f"queued={stack.queue_size()} spool={spool_records(run.spool)}",
        )  # fmt: skip
        assert not stack.spans_of(run.service)
        stack.compose("restart", "fabric-node")
        stack.wait_health()
    finally:
        stack.sink.start()
    spans = _delivered(stack, run, timeout_s=180)
    exchanges = _assert_capture_spans(spans, run)
    duplicates = len([s for s in spans if s["name"] == "fabric.model_call"]) - len(
        exchanges
    )
    print(f"durable queue redelivered {duplicates} duplicate exchange span(s)")
    _assert_no_leak(stack)

    # The whole sink file, duplicates included, still reconstructs cleanly.
    code, report = stack.reconstruct(run.store)
    _assert_complete(report, code, {exchanges[0]["attributes"]["fabric.run.id"]})


def test_wrong_ingress_token_is_rejected_and_agent_is_unaffected(stack: Stack) -> None:
    context = ssl.create_default_context(cafile=str(stack.tls / "ca.crt"))
    for port, path, ctype in (
        (stack.ports["otlp_http"], "/v1/traces", "application/json"),
        (stack.ports["otlp_content"], "/v1/logs", "application/x-protobuf"),
    ):
        node = f"127.0.0.1:{port}"
        request = urllib.request.Request(
            f"https://{node}{path}", data=b"{}", method="POST",
            headers={"Content-Type": ctype, "Authorization": f"Bearer {WRONG_TOKEN}"},
        )  # fmt: skip
        with pytest.raises(urllib.error.HTTPError) as rejected:
            urllib.request.urlopen(request, timeout=10, context=context)
        assert rejected.value.code in (401, 403), (path, rejected.value.code)
        # Receiver TLS is enforced: a plaintext request is not served.
        with pytest.raises(
            (urllib.error.HTTPError, urllib.error.URLError, OSError)
        ) as plain:
            urllib.request.urlopen(f"http://{node}{path}", data=b"{}", timeout=10)
        if isinstance(plain.value, urllib.error.HTTPError):
            assert plain.value.code == 400

    started = time.monotonic()
    bad = stack.run_agent("wire-e2e-wrong-token", token=WRONG_TOKEN)
    # The host is unaffected: the exit handler is bounded (047 E9) even
    # though nothing could be delivered.
    assert time.monotonic() - started < 60
    # Capture itself still worked: every record waits on disk for replay.
    headers = [spool_header(path) for path in spool_records(bad.spool)]
    rejected_ids = {
        h["span"]["attributes"]["fabric.wire.exchange_id"]
        for h in headers if h["record_kind"] == "exchange"
    }  # fmt: skip
    assert len(rejected_ids) == 3, [h["record_kind"] for h in headers]
    # J1: undelivered records carry the source only as its pseudonym.
    spooled = b"".join(path.read_bytes() for path in spool_records(bad.spool))
    assert pseudonym("s-", source_of(bad.service), ID_KEY).encode() in spooled
    for label in (bad.service, source_of(bad.service)):
        assert label.encode() not in spooled, f"clear label {label} was spooled"

    # Barrier: a correctly authenticated run sent afterwards arrives, so
    # anything the rejected agent sent would have arrived by now.
    barrier = stack.run_agent("wire-e2e-barrier")
    _delivered(stack, barrier)
    assert stack.spans_of(bad.service) == [], (
        "spans with a wrong token reached the sink"
    )
    sink_text = stack.records.read_text("utf-8")
    assert not [i for i in rejected_ids if i in sink_text]
    stored_ops = {d["operation_id"] for d in _store_descriptors(barrier.store).values()}
    assert not rejected_ids & stored_ops, "content sent with a wrong token was stored"
    _assert_no_leak(stack)

    code, report = stack.reconstruct(barrier.store)
    _assert_complete(report, code, set())
