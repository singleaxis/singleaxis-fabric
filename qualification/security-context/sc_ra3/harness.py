# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Runs SC-RA-3: the agent sessions, the fixture approval service, the Fabric Node with the
customer's mapping profile, the destination, and the reader over what was delivered.

Capture on: one Node (local profile, ``fabricmap`` directly before ``fabricguard``, the
profile in ``approval-service.profile.json`` and the agents' id key) receives the agents'
telemetry and the approval service's spans and delivers both to one loopback sink. Every
session is its own agent process and so its own run (the reader's ``source:`` run of the
process's epoch); the service runs once for all of them, in its own process, with its own
traces, and is never told the agent's trace or run. The reader is the
operator's: ``python -m fabric.reconstruct`` (report and projection) and ``... actions``
(``--json`` and the text view) over the sink.

Capture off: the same sessions again, no Fabric variable, the service sending nothing.
The fixture model answers both runs with the same bytes; in live mode the capture-on run
talks to the real model and the capture-off twin replays what it answered.
"""

# The harness runs its own fixed command lines (the agent, the service, the reader).
# ruff: noqa: S603

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import model as fixture
from ._ar1 import Node, Sink, node_dist

HERE = Path(__file__).resolve().parent
AGENT = HERE / "agent.py"
SERVICE = HERE / "approval_service.py"
PROFILE = HERE / "approval-service.profile.json"
TENANT = "sc-ra3-tenant"
SOURCE = "sc-ra3-agent"
# A fixed, published test key (spec 049 §2.9: at least 16 bytes); it protects nothing. The
# agents and the Node's mapping processor pseudonymise with the same bytes.
ID_KEY = "sc-ra3-test-id-key-not-a-secret"
LIVE_MODEL = "deepseek-ai/DeepSeek-V4.1-Flash-1017"
KEY_ENV = "SC_RA3_MODEL_KEY"
EXIT_BUDGET_S = 15
SYSTEM = (
    "You are a customer-support agent for an online shop. Use the tools to do what the "
    "user asks. Refunds need approval, which issue_refund requests for you; report what "
    "happened in one sentence."
)
ORDERS = {
    "A1001": {"customer": "c-17", "total": 120.0, "status": "delivered, damaged"},
    "B2002": {"customer": "c-23", "total": 35.0, "status": "delivered"},
    "C3003": {"customer": "c-23", "total": 1250.0, "status": "delivered"},
    "D4004": {"customer": "c-31", "total": 60.0, "status": "lost in transit"},
}
CONTENT_ROLES = (
    "model.exchange.request",
    "model.exchange.response",
    "terminal.argv",
    "terminal.stdout",
    "terminal.stderr",
)

Call = tuple[str, str, dict[str, Any]]


@dataclass(frozen=True)
class Session:
    """One agent process. ``script`` is the fixture model's turns; ``record_request``
    False leaves out the agent's one Fabric line (the agent side is missing)."""

    name: str
    task: str
    script: tuple[Sequence[Call] | str, ...]
    record_request: bool = True
    max_turns: int = 6


SESSIONS: tuple[Session, ...] = (
    Session(
        "approved",
        "Order A1001 arrived damaged. Look it up, then refund 40 of it to the customer.",
        (
            (("call_sc3_a1", "lookup_order", {"order_id": "A1001"}),),
            (("call_sc3_a2", "issue_refund", {"amount": 40, "order_id": "A1001"}),),
            "I refunded 40 for order A1001.",
        ),
    ),
    Session(
        "mixed",
        "Refund 35 on order B2002 and 900 on order C3003, both at once.",
        (
            (
                ("call_sc3_b1", "issue_refund", {"amount": 35, "order_id": "B2002"}),
                ("call_sc3_c1", "issue_refund", {"amount": 900, "order_id": "C3003"}),
            ),
            "B2002 was refunded 35; the 900 refund on C3003 was not approved.",
        ),
    ),
    Session(
        "agent-missing",
        "Order D4004 was lost in transit. Refund 60 on it.",
        (
            (("call_sc3_d1", "issue_refund", {"amount": 60, "order_id": "D4004"}),),
            "I refunded 60 for order D4004.",
        ),
        record_request=False,
    ),
)


@dataclass(frozen=True)
class Canaries:
    """Fresh per harness run. The service puts ``email``, ``note`` and ``org`` on its spans
    (the profile maps none of them); ``tag`` is in every clear ticket id."""

    tag: str
    email: str
    note: str
    org: str

    @classmethod
    def fresh(cls) -> Canaries:
        tag = os.urandom(5).hex()
        return cls(
            tag,
            f"scra3.{tag}@example.com",
            f"SCRA3NOTE{tag} customer asked twice",
            f"org-scra3-{tag}",
        )

    def needles(self) -> dict[str, str]:
        return {
            "email": self.email,
            "note": f"SCRA3NOTE{self.tag}",
            "org": self.org,
            "ticket": f"tkt{self.tag}",
        }


@dataclass
class Options:
    out: Path
    mode: str = "fixture"  # "fixture" or "live"
    sessions: Sequence[str] = tuple(s.name for s in SESSIONS)
    node: str | None = None  # an explicit Node dist
    base_url: str = ""
    model_key: str = ""  # live: given to the agent process only, never printed or written
    log: Callable[[str], None] = print


@dataclass
class AgentResult:
    session: Session
    capture: bool
    directory: Path
    returncode: int
    ledger: list[dict[str, Any]]
    outputs: dict[str, Any]
    stderr: str
    exhausted: int


@dataclass
class Run:
    """What one harness run produced, for :mod:`check`."""

    options: Options
    canaries: Canaries
    on: dict[str, AgentResult] = field(default_factory=dict)
    off: dict[str, AgentResult] = field(default_factory=dict)
    service_on: list[dict[str, Any]] = field(default_factory=list)
    service_off: list[dict[str, Any]] = field(default_factory=list)
    sink_rows: list[dict[str, Any]] = field(default_factory=list)
    sink_bytes: bytes = b""
    report: dict[str, Any] = field(default_factory=dict)
    projection: dict[str, Any] = field(default_factory=dict)
    actions: dict[str, Any] = field(default_factory=dict)
    view: str = ""
    reader_logs: str = ""
    node_log: str = ""
    reader_codes: dict[str, int] = field(default_factory=dict)


def rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text("utf-8").splitlines() if line.strip()]


SECRET_MARKS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTH", "COOKIE")


def base_environment(environ: Mapping[str, str]) -> dict[str, str]:
    """The caller's environment without Fabric, OpenTelemetry or harness variables, without
    ``PYTHONPATH`` and without anything named like a credential."""
    return {
        k: v
        for k, v in environ.items()
        if not k.startswith(("FABRIC_", "OTEL_", "SC_RA3_"))
        and k != "PYTHONPATH"
        and not any(mark in k.upper() for mark in SECRET_MARKS)
    }


def autoload_path() -> str:
    return subprocess.run(
        [sys.executable, "-m", "fabric.wire", "--print-autoload-path"],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout.strip()


def write_policy(path: Path) -> Path:
    """A local-profile deployment-policy/v1 retaining the roles the reader reads."""
    path.write_text(
        json.dumps(
            {
                "schema_version": "fabric.deployment-policy/v1",
                "policy_id": "sc-ra3-local",
                "policy_version": 1,
                "tenant_id": TENANT,
                "workload_id": "sc-ra3-agent",
                "privacy": dict.fromkeys(CONTENT_ROLES, "retain_original"),
                "storage": {"backend": "local", "region": "local", "key_id": "sc-ra3-local"},
                "retention": {"days": 1},
                "required_integrations": [],
                "deployment": {
                    "profile": "local",
                    "image_digest": "local",
                    "tls_required": False,
                    "encrypted_store_required": False,
                },
            },
            indent=2,
        )
    )
    return path


def live_endpoints(base_url: str) -> str:
    scheme, _, rest = base_url.partition("://")
    hostport, _, path = rest.partition("/")
    host, _, port = hostport.partition(":")
    row: dict[str, Any] = {
        "endpoint_id": "sc-ra3-live",
        "dialect": "openai",
        "hosts": [host],
        "path_prefix": "/" + path.rstrip("/"),
        "schemes": [scheme],
        "provider_name": "openai",
    }
    if port:
        row["ports"] = [int(port)]
    return json.dumps([row])


def node_config(node: Node, id_key_file: Path) -> None:
    """The AR-1 local-profile Node with the customer's mapping profile directly before
    fabricguard on the traces pipeline (spec 057 §4.5; fabric-gate checks the order)."""
    config = json.loads(node.config_path.read_text())
    config["processors"]["fabricmap"] = {
        "profile_file": str(PROFILE),
        "id_key_file": str(id_key_file),
    }
    config["service"]["pipelines"]["traces"]["processors"] = [
        "memory_limiter",
        "fabricmap",
        "fabricguard",
    ]
    node.config_path.write_text(json.dumps(config, indent=2))


class Harness:
    def __init__(self, options: Options) -> None:
        self.o = options
        self.canaries = Canaries.fresh()
        options.out.mkdir(parents=True, exist_ok=True)
        self.autoload = autoload_path()
        self.policy = write_policy(options.out / "policy.json")
        self.store = options.out / "store"
        self.workspace = options.out / "workspace"

    def sessions(self) -> list[Session]:
        return [s for s in SESSIONS if s.name in self.o.sessions]

    # -- the whole run ----------------------------------------------------------------

    def run(self) -> Run:
        dist = node_dist(self.o.node)
        if dist is None:
            raise RuntimeError(
                "no built Fabric Node: run `make -C components/otel-collector-fabric build` "
                "(needs Go and the OCB builder) or set FABRIC_NODE_DIST to a dist/ holding "
                "fabric-gate and otelcol-fabric"
            )
        result = Run(self.o, self.canaries)
        key_file = self.o.out / "node" / "id-key"
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_bytes(ID_KEY.encode())
        key_file.chmod(0o400)
        sink = Sink(self.o.out / "sink").start()
        node = Node(dist, self.o.out / "node", sink.url)
        node_config(node, key_file)
        node.start()
        try:
            with self.service("on", node.otlp_http) as ledger:
                for session in self.sessions():
                    self.o.log(f"capture on: {session.name}")
                    result.on[session.name] = self.agent(
                        session, capture=True, otlp=node.otlp_http, approvals=ledger
                    )
            result.service_on = rows(self.o.out / "service-on.jsonl")
            self.settle(sink, result.service_on)
        finally:
            node.stop()
            sink.close()
            result.node_log = node.log_path.read_text("utf-8", errors="replace")
        result.sink_rows = rows(sink.records)
        result.sink_bytes = sink.raw.read_bytes() if sink.raw.exists() else b""
        self.read(result)
        with self.service("off", "") as ledger:
            for session in self.sessions():
                self.o.log(f"capture off: {session.name}")
                replay = None
                if self.o.mode == "live":
                    replay = [
                        e["response"]
                        for e in result.on[session.name].ledger
                        if e["type"] == "model"
                    ]
                result.off[session.name] = self.agent(
                    session, capture=False, otlp="", approvals=ledger, replay=replay
                )
        result.service_off = rows(self.o.out / "service-off.jsonl")
        return result

    def settle(
        self, sink: Sink, decisions: Sequence[Mapping[str, Any]], timeout_s: float = 30.0
    ) -> None:
        """Wait until the sink holds a mapped record for every decision the service emitted
        and nothing new has arrived for a second (the Node delivers asynchronously)."""
        deadline = time.monotonic() + timeout_s
        last, quiet_since, mapped = -1, time.monotonic(), 0
        while time.monotonic() < deadline:
            found = rows(sink.records)
            mapped = sum(
                1
                for r in found
                if r.get("attributes", {}).get("fabric.capture.point") == "otlp.mapping_profile@1"
            )
            if len(found) != last:
                last, quiet_since = len(found), time.monotonic()
            elif mapped >= len(decisions) and time.monotonic() - quiet_since > 1.0:
                return
            time.sleep(0.2)
        self.o.log(
            f"the sink holds {mapped} mapped records for {len(decisions)} service decisions "
            f"after {timeout_s:g} s; reading what arrived (check the Node's log, "
            f"{self.o.out / 'node'}, for refused or dropped spans)"
        )

    # -- the approval service -----------------------------------------------------------

    class _Service:
        def __init__(self, harness: Harness, tag: str, otlp: str) -> None:
            self.h, self.tag, self.otlp = harness, tag, otlp
            self.process: subprocess.Popen[bytes] | None = None
            self.url = ""

        def __enter__(self) -> str:
            out = self.h.o.out
            port_file = out / f"service-{self.tag}.port"
            port_file.unlink(missing_ok=True)
            ledger = out / f"service-{self.tag}.jsonl"
            ledger.unlink(missing_ok=True)
            c = self.h.canaries
            log = (out / f"service-{self.tag}.log").open("wb")
            self.process = subprocess.Popen(
                [
                    sys.executable,
                    "-X",
                    "faulthandler",  # SIGABRT on a start timeout dumps where it waits
                    str(SERVICE),
                    "--port-file",
                    str(port_file),
                    "--ledger",
                    str(ledger),
                    "--otlp",
                    self.otlp,
                    "--email",
                    c.email,
                    "--note",
                    c.note,
                    "--org",
                    c.org,
                ],
                env=base_environment(os.environ),
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            deadline = time.monotonic() + 30
            while not port_file.exists() or not port_file.read_text().strip():
                code = self.process.poll()
                if code is not None or time.monotonic() > deadline:
                    if code is None:
                        self.process.send_signal(signal.SIGABRT)
                        try:
                            self.process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            self.process.kill()
                            self.process.wait(timeout=10)
                    log.flush()
                    why = f"exited with {code}" if code is not None else "wrote no port in 30 s"
                    tail = Path(log.name).read_text(errors="replace")[-4000:].strip()
                    raise RuntimeError(
                        f"the approval service did not start ({why}); its log, {log.name}, "
                        f"ends with:\n{tail or '(empty)'}\nCheck that the OpenTelemetry SDK and "
                        "OTLP/HTTP exporter are installed (the sdk/python dev group)."
                    )
                time.sleep(0.05)
            self.url = f"http://127.0.0.1:{port_file.read_text().strip()}"
            return self.url

        def __exit__(self, *exc: object) -> None:
            if self.process is not None and self.process.poll() is None:
                self.process.send_signal(signal.SIGTERM)
                try:
                    self.process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=30)

    def service(self, tag: str, otlp: str) -> Harness._Service:
        return Harness._Service(self, tag, otlp)

    # -- one agent process --------------------------------------------------------------

    def agent(
        self,
        session: Session,
        *,
        capture: bool,
        otlp: str,
        approvals: str,
        replay: Sequence[str] | None = None,
    ) -> AgentResult:
        tag = "on" if capture else "off"
        directory = self.o.out / tag / session.name
        directory.mkdir(parents=True, exist_ok=True)
        for name in ("ledger.jsonl", "outputs.json"):
            (directory / name).unlink(missing_ok=True)
        workspace = directory / "workspace"
        (workspace / "orders").mkdir(parents=True, exist_ok=True)
        for order_id, order in ORDERS.items():
            (workspace / "orders" / f"{order_id}.json").write_text(json.dumps(order) + "\n")
        (workspace / "refunds.log").unlink(missing_ok=True)
        live = self.o.mode == "live" and replay is None
        model = (
            None
            if live
            else fixture.FixtureModel(
                replay if replay is not None else fixture.scripted(session.script)
            ).start()
        )
        base_url = self.o.base_url if live else model.base_url  # type: ignore[union-attr]
        plan = {
            "model": LIVE_MODEL if live else fixture.MODEL,
            "api_key_env": KEY_ENV if live else None,
            "base_url": base_url,
            "system": SYSTEM,
            "task": session.task,
            "max_turns": session.max_turns,
            "approvals_url": approvals,
            "record_request": session.record_request,
            "ticket_prefix": f"tkt{self.canaries.tag}-{tag}-{session.name}",
            "ledger": str(directory / "ledger.jsonl"),
            "outputs": str(directory / "outputs.json"),
        }
        plan_path = directory / "plan.json"
        plan_path.write_text(json.dumps(plan, indent=1))
        env = base_environment(os.environ)
        env["PYTHONUNBUFFERED"] = "1"
        if live and self.o.model_key:
            env[KEY_ENV] = self.o.model_key
        if capture:
            env.update(
                {
                    "PYTHONPATH": self.autoload,
                    "FABRIC_WIRE_AUTOLOAD": "1",
                    "FABRIC_TENANT_ID": TENANT,
                    "FABRIC_SOURCE_ID": SOURCE,
                    "FABRIC_WIRE_STORE": f"file://{self.store}",
                    "FABRIC_WIRE_ENDPOINTS": live_endpoints(base_url)
                    if live
                    else model.endpoints_json(),  # type: ignore[union-attr]
                    "FABRIC_WIRE_ID_KEY": ID_KEY,
                    "FABRIC_CAPTURE_POLICY": str(self.policy),
                    "FABRIC_WIRE_EXEC": "1",
                    "FABRIC_CLOCK_UNCERTAINTY_MS": "1",
                    "FABRIC_HOST_LABEL": "sc-ra3-host",
                    "FABRIC_WIRE_SHUTDOWN_TIMEOUT_S": str(EXIT_BUDGET_S),
                    "OTEL_EXPORTER_OTLP_ENDPOINT": otlp,
                    "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
                }
            )
        try:
            done = subprocess.run(
                [sys.executable, str(AGENT), str(plan_path)],
                env=env,
                cwd=workspace,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
        finally:
            if model is not None:
                model.close()
        (directory / "agent.stdout").write_text(done.stdout)
        (directory / "agent.stderr").write_text(done.stderr)
        outputs = directory / "outputs.json"
        return AgentResult(
            session,
            capture,
            directory,
            done.returncode,
            rows(directory / "ledger.jsonl"),
            json.loads(outputs.read_text()) if outputs.exists() else {},
            done.stderr,
            model.exhausted if model is not None else 0,
        )

    # -- the reader -----------------------------------------------------------------------

    def read(self, result: Run) -> None:
        out = self.o.out / "reader"
        out.mkdir(parents=True, exist_ok=True)
        records = str(self.o.out / "sink" / "records.jsonl")
        # lookup_order runs in the agent's own code (no subprocess): said so, it is not a
        # call 056 should look for an effect of (spec 056 §4.2).
        common = [
            "--store-root",
            str(self.store),
            "--tenant",
            TENANT,
            "--in-process-tool",
            "lookup_order",
        ]
        env = {**base_environment(os.environ), "FABRIC_WIRE_ID_KEY": ID_KEY}
        logs = []
        report = out / "report.json"
        projection = out / "projection.json"
        steps = {
            "report": [
                sys.executable,
                "-m",
                "fabric.reconstruct",
                "--spans",
                records,
                *common,
                "--out",
                str(report),
                "--projection",
                str(projection),
            ],
            "actions_json": [
                sys.executable,
                "-m",
                "fabric.reconstruct",
                "actions",
                records,
                *common,
                "--json",
            ],
            "actions_view": [
                sys.executable,
                "-m",
                "fabric.reconstruct",
                "actions",
                records,
                *common,
            ],
        }
        outputs: dict[str, str] = {}
        for name, command in steps.items():
            done = subprocess.run(
                command, env=env, capture_output=True, text=True, timeout=300, check=False
            )
            result.reader_codes[name] = done.returncode
            outputs[name] = done.stdout
            logs.append(done.stderr)
            (out / f"{name}.stdout").write_text(done.stdout)
            (out / f"{name}.stderr").write_text(done.stderr)
        result.reader_logs = "\n".join(logs)
        result.report = json.loads(report.read_text()) if report.exists() else {}
        result.projection = json.loads(projection.read_text()) if projection.exists() else {}
        try:
            result.actions = json.loads(outputs["actions_json"])
        except ValueError:
            result.actions = {}
        result.view = outputs["actions_view"]
        (out / "actions.txt").write_text(result.view)
