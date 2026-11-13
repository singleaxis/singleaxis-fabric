# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Runs the SC-RA-1 sessions: the agent as its own process, capture on or off, the fixture
MCP servers, the fixture model, the destination, and the reader over what was delivered.

One agent process per session, so each session is one run (``FABRIC_RUN_ID``). With
capture on the agent first delivers to a closed port, so every record stays in its sealed
spool (``FABRIC_WIRE_SPOOL_KEY``) and the privacy canaries are searched in the spool
bytes; a capturing process on the same store then drains the spool to the sink, as
spec 048 delivers after an outage. The reader is the operator's: ``python -m
fabric.reconstruct`` (the report, ``--projection``) and ``... actions --json`` with the
spec 057 derivation rules (``--derive wire --derive mcp.jsonrpc --mcp-host``).
"""

# The harness runs its own fixed command lines (the agent, the drain, the reader) on purpose.
# ruff: noqa: S603

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import model as replay
from ._ar1 import Sink, free_port
from .mcp_server import HttpServer

HERE = Path(__file__).resolve().parent
AGENT = HERE / "agent.py"
TENANT = "sc-ra1-tenant"
SOURCE = "sc-ra1-agent"
# A fixed, published test key (spec 049 §2.9: at least 16 bytes); it protects nothing.
ID_KEY = "sc-ra1-test-id-key-not-a-secret"
# A fixed, published AES-256 spool key for the test (base64 of 32 bytes); not a secret.
SPOOL_KEY = base64.b64encode(b"sc-ra1-spool-key-not-a-secret-32").decode()
MODEL = "deepseek-ai/DeepSeek-V4.1-Flash-1017"
# The live model endpoint (an OpenAI Chat Completions and Anthropic Messages compatible
# base URL ending in /v1), given at run time: --base-url or SC_RA1_BASE_URL.
BASE_URL_ENV = "SC_RA1_BASE_URL"
KEY_ENV = "SC_RA1_MODEL_KEY"
EXIT_BUDGET_S = 15
FIXED_MTIME = 1767225600  # 2026-01-01T00:00:00Z: `ls -la` prints the same bytes every run
# The content roles the policy names (production profile: every other role is omitted).
# The derivation rules read these bytes offline (spec 057 §4.1, §4.2).
RETAINED_ROLES = (
    "model.exchange.request",
    "model.exchange.response",
    "model.exchange.part",
    "network.request",
    "network.response",
    "mcp.request",
    "mcp.response",
    "mcp.notification",
)

LOOP_TOOLS = ["run_shell", "read_file", "write_file", "python_exec"]


@dataclass(frozen=True)
class Session:
    name: str
    kind: str  # "loop" or "mcp"
    dialect: str  # "openai" or "anthropic"
    task: str
    stream: bool = False
    max_turns: int = 8
    tools_first: tuple[str, ...] = ()
    tools_then: tuple[str, ...] = ()
    tool_choice_first: Any = None
    elicitation: str | None = None
    mcp: Mapping[str, str] = field(default_factory=dict)  # server -> "http" | "stdio"
    replay_only: bool = False  # always through the fixture model (spec 057 §10.2)


SESSIONS: tuple[Session, ...] = (
    Session(
        "loop-anthropic",
        "loop",
        "anthropic",
        "Find the most frequent ERROR code in logs/incident.log. Then compute the revenue "
        "(units * price) per region and the top month from sales.csv, write them to "
        "report.json and show the report.",
        tools_first=(*LOOP_TOOLS, "pip_install"),
        tools_then=tuple(LOOP_TOOLS),
        tool_choice_first={"type": "any"},
    ),
    Session(
        "loop-openai",
        "loop",
        "openai",
        "Compute 17 * 23 with python_exec, write the answer to answer.txt and show the "
        "file with run_shell.",
        stream=True,
        tools_first=("python_exec", "run_shell", "read_file"),
        tools_then=tuple(LOOP_TOOLS),
        tool_choice_first="required",
    ),
    Session(
        "mcp-http",
        "mcp",
        "openai",
        'You have notes and ticket tools from MCP servers. Add two notes ("deploy window is '
        '14:00" and "freeze ends Friday"), list the notes, look up the weather for '
        'Berlin and Lisbon, create a ticket titled "Check freeze end date" mentioning the '
        "weather in Berlin, and count the words in the notes with the word_count tool. "
        "Also run `ls -la` with run_shell. Report the ticket id.",
        max_turns=6,
        tool_choice_first="required",
        elicitation="accept",
        mcp={"tickets": "http", "notes": "stdio"},
    ),
    Session(
        "mcp-stdio",
        "mcp",
        "openai",
        'You have notes and ticket tools from MCP servers. Add two notes ("deploy window is '
        '14:00" and "freeze ends Friday"), list the notes, look up the weather for '
        'Berlin and Lisbon, create a ticket titled "Check freeze end date" mentioning the '
        "weather in Berlin, and count the words in the notes with the word_count tool. "
        "Also run `ls -la` with run_shell. Report the ticket id.",
        max_turns=6,
        tool_choice_first="required",
        elicitation="decline",
        mcp={"tickets": "stdio", "notes": "http"},
    ),
    Session(
        "unoffered-openai",
        "loop",
        "openai",
        "Compute 17 * 23.",
        max_turns=1,
        tools_first=("run_shell",),
        replay_only=True,
    ),
    Session(
        "unoffered-anthropic",
        "loop",
        "anthropic",
        "Summarise sales.csv.",
        max_turns=1,
        tools_first=("run_shell", "read_file"),
        replay_only=True,
    ),
    Session(
        "safety-openai",
        "loop",
        "openai",
        "Tell me about it.",
        max_turns=1,
        tools_first=("run_shell",),
        replay_only=True,
    ),
    Session(
        "safety-anthropic",
        "loop",
        "anthropic",
        "Tell me about it.",
        max_turns=1,
        tools_first=("run_shell",),
        replay_only=True,
    ),
)


@dataclass(frozen=True)
class Canaries:
    """Spec 057 §10.2's three privacy canaries, fresh per harness run."""

    system: str
    root: str
    elicitation: str

    @classmethod
    def fresh(cls) -> Canaries:
        tag = os.urandom(6).hex()
        return cls(
            f"SCRA1SYSTEM{tag}", f"file:///home/scra1-secret-{tag}/project", f"SCRA1ELICIT{tag}"
        )

    def needles(self) -> dict[str, str]:
        # the root's secret directory name (``scra1-secret-<tag>``), so a re-encoded URI is
        # found too; never a generic segment such as ``home``
        secret = next(part for part in self.root.split("/") if part.startswith("scra1-secret-"))
        return {
            "system_prompt": self.system,
            "mcp_root": secret,
            "elicitation": self.elicitation,
        }


@dataclass
class Options:
    mode: str  # "replay" or "live"
    out: Path
    sessions: Sequence[str] = tuple(s.name for s in SESSIONS)
    cassette: Path = replay.CASSETTE
    record_cassette: Path | None = None
    base_url: str = ""
    latency_gate: bool = True
    log: Callable[[str], None] = print


@dataclass
class Result:
    """One session run and what came out of it."""

    session: Session
    capture: bool
    directory: Path
    returncode: int
    duration_s: float
    ledger: list[dict[str, Any]]
    mcp_ledger: list[dict[str, Any]]
    outputs: dict[str, Any]
    exhausted: list[str]
    spool_bytes: bytes = b""
    report: dict[str, Any] = field(default_factory=dict)
    projection: dict[str, Any] = field(default_factory=dict)
    actions: dict[str, Any] = field(default_factory=dict)
    view: str = ""
    endpoint_ids: dict[str, str] = field(default_factory=dict)
    mcp_hosts: dict[str, str] = field(default_factory=dict)
    session_s: float | None = None  # the agent's own time for the session (timing.json)

    @property
    def sink(self) -> Path:
        return self.directory / "sink" / "records.jsonl"

    @property
    def store(self) -> Path:
        return self.directory / "agent" / "store"


def _rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text("utf-8").splitlines() if line.strip()]


def write_workspace(directory: Path) -> Path:
    """The disposable workspace: a sales table, an incident log, fixed mtimes."""
    if directory.exists():
        shutil.rmtree(directory)
    (directory / "logs").mkdir(parents=True)
    regions, months = ("north", "south", "east", "west"), ("2026-06", "2026-07", "2026-08")
    lines = ["region,month,units,price"]
    for i in range(72):
        lines.append(f"{regions[i % 4]},{months[i % 3]},{3 + (i * 7) % 11},{19.5 + (i % 5) * 2.25}")
    (directory / "sales.csv").write_text("\n".join(lines) + "\n")
    codes = ("E2040", "E1001", "E2040", "E3300", "E2040", "E1001")
    log = [
        f"2026-11-0{1 + i % 9}T10:{i % 60:02d}:00Z ERROR {codes[i % 6]} worker {i % 4}"
        for i in range(120)
    ]
    (directory / "logs" / "incident.log").write_text("\n".join(log) + "\n")
    for path in (
        directory / "logs" / "incident.log",
        directory / "sales.csv",
        directory / "logs",
        directory,
        directory.parent,
    ):
        os.utime(path, (FIXED_MTIME, FIXED_MTIME))
    return directory


def autoload_path() -> str:
    return subprocess.run(
        [sys.executable, "-m", "fabric.wire", "--print-autoload-path"],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout.strip()


def write_policy(path: Path) -> Path:
    """A production-profile deployment-policy/v1 naming only the roles the derivation reads
    (every other role, the instructions role included, is omitted: spec 057 OD-5)."""
    path.write_text(
        json.dumps(
            {
                "schema_version": "fabric.deployment-policy/v1",
                "policy_id": "sc-ra1-production",
                "policy_version": 1,
                "tenant_id": TENANT,
                "workload_id": "sc-ra1-agent",
                "privacy": dict.fromkeys(RETAINED_ROLES, "retain_original"),
                "storage": {"backend": "local", "region": "local", "key_id": "sc-ra1-local"},
                "retention": {"days": 1},
                "required_integrations": [],
                # Production requires these declarations (deployment-policy/v1); the spool is
                # sealed (FABRIC_WIRE_SPOOL_KEY) and nothing leaves the loopback test host.
                "deployment": {
                    "profile": "production",
                    "image_digest": "sha256:" + "0" * 64,
                    "tls_required": True,
                    "encrypted_store_required": True,
                },
            },
            indent=2,
        )
    )
    return path


def endpoints(base_urls: Mapping[str, str]) -> tuple[str, dict[str, str]]:
    """``FABRIC_WIRE_ENDPOINTS`` for each model base URL (one id per dialect and URL)."""
    out, ids = [], {}
    for label, url in base_urls.items():
        parsed = url.split("://", 1)
        scheme, rest = parsed[0], parsed[1]
        hostport, _, path = rest.partition("/")
        host, _, port = hostport.partition(":")
        for dialect, suffix in (("openai", "/chat/completions"), ("anthropic", "/messages")):
            endpoint_id = f"sc-ra1-{label}-{dialect}"
            row: dict[str, Any] = {
                "endpoint_id": endpoint_id,
                "dialect": dialect,
                "hosts": [host],
                "path_prefix": "/" + path.rstrip("/") + suffix,
                "schemes": [scheme],
                "provider_name": dialect,
            }
            if port:
                row["ports"] = [int(port)]
            out.append(row)
            ids[f"{url}|{dialect}"] = endpoint_id
    return json.dumps(out), ids


class Harness:
    def __init__(self, options: Options) -> None:
        self.o = options
        self.canaries = Canaries.fresh()
        self.autoload = autoload_path()
        self.policy = write_policy(options.out / "policy.json")
        self.replies = replay.load(options.cassette)

    def session(self, name: str) -> Session:
        return next(s for s in SESSIONS if s.name == name)

    # -- one agent process --------------------------------------------------------------

    def run(self, session: Session, *, capture: bool) -> Result:
        tag = "on" if capture else "off"
        directory = self.o.out / tag / session.name
        if directory.exists():
            shutil.rmtree(directory)
        (directory / "agent").mkdir(parents=True)
        workspace = write_workspace(self.o.out / "ws" / tag / session.name / "ws")
        model = replay.FixtureModel(self.replies).start()
        live = self.o.mode == "live" and not session.replay_only
        base_url = self.o.base_url if live else model.base_url
        bases = {"fixture": model.base_url, **({"live": self.o.base_url} if live else {})}
        endpoints_json, endpoint_ids = endpoints(bases)
        servers: dict[str, HttpServer] = {}
        mcp_specs: dict[str, dict[str, str]] = {}
        for server, transport in session.mcp.items():
            ledger = directory / f"mcp-{server}-{transport}.jsonl"
            if transport == "http":
                servers[server] = HttpServer(server, ledger, self.canaries.elicitation).__enter__()
                mcp_specs[server] = {"transport": "http", "url": servers[server].url}
            else:
                mcp_specs[server] = {"transport": "stdio", "ledger": str(ledger)}
        plan = {
            "model": MODEL,
            "api_key_env": KEY_ENV if live else None,
            "workspace": str(workspace),
            "ledger": str(directory / "ledger.jsonl"),
            "outputs": str(directory / "outputs.json"),
            "timing": str(directory / "timing.json"),
            "system_prompt": (
                "You are an autonomous engineering agent working in a workspace "
                "directory. Use the tools to do the task end to end. Be concise. "
                f"Deployment marker {self.canaries.system}."
            ),
            "roots_canary": self.canaries.root,
            "elicitation_canary": self.canaries.elicitation,
            "sessions": [
                {
                    "name": session.name,
                    "kind": session.kind,
                    "dialect": session.dialect,
                    "stream": session.stream,
                    "max_turns": session.max_turns,
                    "task": session.task,
                    "base_url": base_url,
                    "replay": not live,
                    "tools_first": list(session.tools_first),
                    "tools_then": list(session.tools_then),
                    "tool_choice_first": session.tool_choice_first,
                    "elicitation": session.elicitation,
                    "mcp": mcp_specs,
                }
            ],
        }
        plan_path = directory / "plan.json"
        plan_path.write_text(json.dumps(plan, indent=1))
        http_hosts = json.dumps([s.origin for s in servers.values()]) if servers else ""
        env = self._env(
            directory,
            session,
            capture=capture,
            endpoints_json=endpoints_json,
            http_hosts=http_hosts,
            otlp=f"http://127.0.0.1:{free_port()}",
        )
        sink = Sink(directory / "sink").start() if capture else None
        started = time.monotonic()
        try:
            done = subprocess.run(
                [sys.executable, str(AGENT), str(plan_path)],
                env=env,
                cwd=workspace,
                capture_output=True,
                text=True,
                timeout=900,
                check=False,
            )
            duration = time.monotonic() - started
            (directory / "agent.stdout").write_text(done.stdout)
            (directory / "agent.stderr").write_text(done.stderr)
            spool = b""
            if capture and sink is not None:
                spool = self._spool_bytes(directory)
                self._drain(env, sink.url, workspace)
        finally:
            for http in servers.values():
                http.__exit__(None, None, None)
            model.close()
            if sink is not None:
                sink.close()
        outputs_path = directory / "outputs.json"
        result = Result(
            session=session,
            capture=capture,
            directory=directory,
            returncode=done.returncode,
            duration_s=duration,
            ledger=_rows(directory / "ledger.jsonl"),
            mcp_ledger=[r for p in sorted(directory.glob("mcp-*.jsonl")) for r in _rows(p)],
            outputs=json.loads(outputs_path.read_text()) if outputs_path.exists() else {},
            exhausted=list(model.exhausted),
            spool_bytes=spool,
            endpoint_ids={
                "openai": endpoint_ids[f"{base_url}|openai"],
                "anthropic": endpoint_ids[f"{base_url}|anthropic"],
            },
            mcp_hosts={name: s.origin for name, s in servers.items()},
        )
        timing = directory / "timing.json"
        if timing.exists():
            result.session_s = json.loads(timing.read_text()).get(session.name)
        if capture:
            self.read(result)
        return result

    def _env(
        self,
        directory: Path,
        session: Session,
        *,
        capture: bool,
        endpoints_json: str,
        http_hosts: str,
        otlp: str,
    ) -> dict[str, str]:
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("FABRIC_", "OTEL_", "SC_RA1_")) and k != "PYTHONPATH"
        }
        env["PYTHONUNBUFFERED"] = "1"
        if self.o.mode == "live" and not session.replay_only:
            key = os.environ.get(KEY_ENV)
            if key:
                env[KEY_ENV] = key
        if not capture:
            return env
        env.update(
            {
                "PYTHONPATH": self.autoload,
                "FABRIC_WIRE_AUTOLOAD": "1",
                "FABRIC_TENANT_ID": TENANT,
                "FABRIC_SOURCE_ID": SOURCE,
                "FABRIC_RUN_ID": f"sc-ra1-{session.name}",
                "FABRIC_WIRE_STORE": f"file://{directory / 'agent' / 'store'}",
                "FABRIC_WIRE_ENDPOINTS": endpoints_json,
                "FABRIC_WIRE_ID_KEY": ID_KEY,
                "FABRIC_WIRE_SPOOL_KEY": SPOOL_KEY,
                "FABRIC_CAPTURE_POLICY": str(self.policy),
                "FABRIC_WIRE_EXEC": "1",
                "FABRIC_WIRE_MCP": "1",
                "FABRIC_CLOCK_UNCERTAINTY_MS": "1",
                "FABRIC_HOST_LABEL": "sc-ra1-host",
                "FABRIC_WIRE_SHUTDOWN_TIMEOUT_S": "2",
                "OTEL_EXPORTER_OTLP_ENDPOINT": otlp,
                "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
            }
        )
        if http_hosts:
            env["FABRIC_WIRE_HTTP_HOSTS"] = http_hosts
        return env

    @staticmethod
    def _spool_bytes(directory: Path) -> bytes:
        """Every byte the agent's spool holds before delivery (it sent to a closed port)."""
        root = directory / "agent" / "store"
        files = sorted(
            p for p in root.rglob("*") if p.is_file() and ".fabric-wire-spool" in p.parts
        )
        if not files:
            raise RuntimeError(
                f"{directory.name}: the agent left nothing in its spool; the "
                "canary search would be vacuous"
            )
        return b"".join(p.read_bytes() for p in files)

    @staticmethod
    def _drain(env: Mapping[str, str], sink_url: str, workspace: Path) -> None:
        """Deliver the spool: a capturing process on the same store with the sink as its
        endpoint drains every epoch's records, then exits (spec 048)."""
        drain = {
            **env,
            "OTEL_EXPORTER_OTLP_ENDPOINT": sink_url,
            "FABRIC_WIRE_SHUTDOWN_TIMEOUT_S": str(EXIT_BUDGET_S),
            "FABRIC_RUN_ID": "sc-ra1-drain",
        }
        drain.pop("FABRIC_WIRE_EXEC", None)
        drain.pop("FABRIC_WIRE_MCP", None)
        subprocess.run(
            [sys.executable, "-c", "import time; time.sleep(4)"],
            env=drain,
            cwd=workspace,
            check=True,
            timeout=180,
            capture_output=True,
        )

    # -- the reader --------------------------------------------------------------------

    def reader_options(self, result: Result) -> list[str]:
        options = ["--derive", "wire", "--derive", "mcp.jsonrpc"]
        for origin in result.mcp_hosts.values():
            options += ["--mcp-host", origin]
        return options

    def read(self, result: Result) -> None:
        env = {**os.environ, "FABRIC_WIRE_ID_KEY": ID_KEY}
        common = [
            "--store-root",
            str(result.store),
            "--tenant",
            TENANT,
            *self.reader_options(result),
        ]
        out = result.directory / "read"
        out.mkdir(exist_ok=True)
        report, projection = out / "report.json", out / "projection.json"
        base = [sys.executable, "-m", "fabric.reconstruct"]
        subprocess.run(
            [
                *base,
                "--spans",
                str(result.sink),
                *common,
                "--out",
                str(report),
                "--projection",
                str(projection),
            ],
            env=env,
            capture_output=True,
            check=False,
            timeout=300,
        )
        actions = subprocess.run(
            [*base, "actions", str(result.sink), *common, "--json"],
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
        view = subprocess.run(
            [*base, "actions", str(result.sink), *common],
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
        (out / "actions.json").write_text(actions.stdout)
        (out / "actions.txt").write_text(view.stdout)
        (out / "reader.stderr").write_text(actions.stderr + view.stderr)
        if not report.exists() or not actions.stdout.strip():
            raise RuntimeError(
                f"{result.session.name}: the reader failed: "
                f"{(actions.stderr or view.stderr)[-2000:]}"
            )
        result.report = json.loads(report.read_text())
        result.projection = json.loads(projection.read_text())
        result.actions = json.loads(actions.stdout)
        result.view = view.stdout

    # -- live cassette --------------------------------------------------------------------

    def record_cassette(self, results: Sequence[Result], path: Path) -> None:
        """A cassette from a live run: every response each live session received. The
        endpoint's URL is not written (the cassette is committed; the URL can be private)."""
        doc = json.loads(self.o.cassette.read_text())
        stamp = time.strftime("%Y-%m-%d", time.gmtime())
        for result in results:
            if result.session.replay_only or not result.capture:
                continue
            api = (
                "Anthropic Messages"
                if result.session.dialect == "anthropic"
                else ("OpenAI Chat Completions" + (", streamed" if result.session.stream else ""))
            )
            doc["sessions"][result.session.name] = {
                "provenance": f"{MODEL}, {api}; real responses recorded {stamp} by "
                "run_sc_ra1.py --mode live; bytes unchanged",
                "dialect": result.session.dialect,
                "stream": result.session.stream,
                "responses": [
                    {
                        "status": r["status"],
                        "content_type": r["content_type"],
                        "body_b64": r["body_b64"],
                        "sha256": r["sha256"],
                    }
                    for r in result.ledger
                    if r["event"] == "model_response"
                ],
            }
        path.write_text(json.dumps(doc, indent=1) + "\n")
