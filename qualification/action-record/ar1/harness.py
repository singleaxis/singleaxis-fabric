# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""AR-1 (spec 056 §6.2): every variant end to end, then the privacy canaries.

Per agent run: the fixture host and model, the sink and a local-profile Node (built
``dist/``), the agent with wire capture and the ``exec.subprocess`` hook (zero code),
the host chain (live: the sensor; hermetic: ``replay.py`` posted through the Node), and
then ``python -m fabric.reconstruct actions --json`` and the report CLI over the Node's
export, with ``--host-records`` for the host chain. Assertions are ``expect.py``'s.

Variants: ``base`` (the §6.2 run), ``a`` (the base export without host records),
``b`` (one effect record dropped from the agent's spool before delivery), ``c`` (the
hook off), ``d`` (``terminal.stdout``/``stderr`` as ``metadata_only``) and ``e`` (the
agent with capture off: same outputs and exit codes as ``base``, plus the spec 053 §4.4
latency gate of the subprocess hook).
"""

# The harness runs its own fixed command lines (the verifier, the drain, the gate) on purpose.
# ruff: noqa: S603

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fabric.content_store import LocalFilesystemContentStore
from fabric.wire import _spool

from . import expect, replay, scenario
from .expect import Checks, HostTruth
from .fixture_host import FixtureHost
from .fixture_model import FixtureModel, Script
from .node import REPO, Node, free_port, node_dist
from .scenario import ID_KEY, TENANT, AgentConfig, AgentRun, Canaries
from .sensor import AuditdSensor, EbpfSensor, SensorUnavailableError
from .sink import Sink

VARIANTS = ("base", "a", "b", "c", "d", "e")
SDK = REPO / "sdk" / "python"
DEFAULT_EMITTER = REPO / "components" / "host-emitter" / "fabric-host-emitter"
LATENCY_GATE = (
    "tests/test_hooks_exec_passivity.py",
    "-k",
    "within_budget or timed_calls or gate_fails",
)


@dataclass
class Options:
    mode: str  # "hermetic" or "live"
    out: Path
    variants: Sequence[str] = VARIANTS
    node: str = "auto"  # "auto", "required" or "off"
    node_dist: str | None = None
    sensor: str = "auto"  # live: "auto" (eBPF, else auditd), "ebpf" or "auditd"
    emitter: Path = DEFAULT_EMITTER
    latency_gate: bool = True
    log: Callable[[str], None] = print


@dataclass
class Run:
    """One agent run and what came out of it."""

    name: str
    directory: Path
    agent: AgentRun
    rows: list[dict[str, Any]]
    records: Path
    run_id: str | None
    steps: dict[str, str]
    host_file: Path | None = None
    truth: HostTruth | None = None
    model_host: str = "127.0.0.1"
    spool_scanned: list[Path] = field(default_factory=list)
    agent_pid: int | None = None  # as the agent reports it (the epoch registration's pid)

    @property
    def store(self) -> Path:
        return self.agent.config.store


def _rows(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text("utf-8").splitlines() if line.strip()]


def _agent_epochs(rows: Sequence[Mapping[str, Any]]) -> set[tuple[str, int]]:
    return {
        (r["attributes"]["fabric.source_id"], int(r["attributes"]["fabric.source.epoch"]))
        for r in rows
        if r.get("name") == "fabric.model_call"
    }


def _delivered(rows: Sequence[Mapping[str, Any]]) -> bool:
    finals = {
        (r["attributes"].get("fabric.source_id"), r["attributes"].get("fabric.source.epoch"))
        for r in rows
        if r.get("name") == "fabric.capture_heartbeat"
        and r["attributes"].get("fabric.heartbeat.kind") == "final"
    }
    epochs = _agent_epochs(rows)
    return bool(epochs) and all(e in finals for e in epochs)


def _wait(condition: Callable[[], bool], timeout_s: float, what: str) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.25)
    raise TimeoutError(f"timed out waiting for {what}")


def _settled(sink: Sink) -> Callable[[], bool]:
    """True once the sink's row count held still for a second."""
    seen = [-1]

    def check() -> bool:
        count = len(sink.rows())
        if count == seen[0]:
            return True
        seen[0] = count
        time.sleep(1.0)
        return False

    return check


def _sha_tool() -> str:
    return "sha256sum" if shutil.which("sha256sum") else "shasum -a 256"


def _bwrap_works() -> bool:
    if shutil.which("bwrap") is None:
        return False
    probe = subprocess.run(
        ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "true"],  # noqa: S607
        capture_output=True,
        timeout=30,
        check=False,
    )
    return probe.returncode == 0


class Harness:
    def __init__(self, options: Options) -> None:
        self.o = options
        self.canaries = Canaries.fresh()
        self.sandbox = "bwrap" if options.mode == "live" and _bwrap_works() else "python"
        self.dist = None if options.node == "off" else node_dist(options.node_dist)
        if self.dist is None and options.node == "required":
            raise SystemExit(
                "--node required: no built Node dist (make -C "
                "components/otel-collector-fabric build, or FABRIC_NODE_DIST)"
            )
        self.sensor_kind: str | None = None
        self.checks: list[Checks] = []
        self.runs: dict[str, Run] = {}

    # -- one agent run ------------------------------------------------------------------

    def agent_run(  # noqa: PLR0912, PLR0915 - one branch per variant knob
        self,
        name: str,
        *,
        exec_hook: bool = True,
        metadata_only: bool = False,
        capture: bool = True,
        deliver_later: bool = False,
        before_delivery: Callable[[Run], None] | None = None,
        sensor_on: bool = True,
    ) -> Run:
        directory = self.o.out / name
        directory.mkdir(parents=True, exist_ok=True)
        data = scenario.write_data(self.o.out / "data")  # one path: (e) compares outputs
        policy = scenario.write_policy(
            directory / "policy.json", metadata_only_output=metadata_only
        )
        host = FixtureHost(self.canaries.bearer_token).start()
        model = FixtureModel(Script(str(data), host.url, _sha_tool())).start()
        sink = Sink(directory / "sink").start()
        live = self.o.mode == "live" and sensor_on and capture
        sensor: Any = None
        node: Node | None = None
        try:
            if live:
                sensor = self._sensor(directory)
            if self.dist is not None:
                node = Node(
                    self.dist, directory, sink.url, audit=isinstance(sensor, AuditdSensor)
                ).start()
            if isinstance(sensor, EbpfSensor) and node is not None:
                sensor.node_grpc = node.otlp_grpc
            if sensor is not None:
                sensor.start()
            endpoint = node.otlp_http if node is not None else sink.url
            config = AgentConfig(
                workdir=directory / "agent",
                model_base_url=model.base_url,
                model_endpoints=model.endpoints_json(),
                fixture_host=host.host,
                fixture_port=host.port,
                otlp_endpoint=f"http://127.0.0.1:{free_port()}" if deliver_later else endpoint,
                canaries=self.canaries,
                sandbox=self.sandbox,
                run_id=f"ar1-{name}",
                capture=capture,
                exec_hook=exec_hook,
                policy=policy,
            )
            config.workdir.mkdir(parents=True, exist_ok=True)
            if isinstance(sensor, AuditdSensor):  # the scope user runs the agent
                self.o.out.chmod(0o755)
                for path in (directory, config.workdir):
                    path.chmod(0o777)  # it writes its store and spool here
            started = time.monotonic()
            environ = scenario.agent_env(config)
            wrapper = sensor.wrapper(environ) if sensor is not None else None
            process = scenario.start_agent(config, wrapper=wrapper, env=environ)
            if sensor is not None:
                sensor.admit(process)
            elif process.stdin is not None:
                process.stdin.close()
            agent = scenario.finish_agent(config, process, started)
            if sensor is not None:
                sensor.after_run()
            run = Run(name, directory, agent, [], sink.records, None, {}, model_host=model.host)
            if not capture:
                return run
            if deliver_later:
                if before_delivery is not None:
                    before_delivery(run)
                self._drain(config, endpoint)
            _wait(lambda: _delivered(sink.rows()), 60, f"{name}: the agent's records at the sink")
            time.sleep(1.0)
            rows = sink.rows()
            store = LocalFilesystemContentStore(root=str(config.store), tenant_id=TENANT)
            effects = replay.exec_effects(rows, store)
            run.steps = self._steps(effects)
            epochs = sorted(_agent_epochs(rows))
            run.run_id = f"source:{epochs[0][0]}:{epochs[0][1]}" if len(epochs) == 1 else None
            agent_pids = {e.parent_pid for e in effects}
            reported = agent.summary.get("pid")
            run.agent_pid = reported if isinstance(reported, int) else None
            if run.agent_pid is None and len(agent_pids) == 1:
                run.agent_pid = agent_pids.pop()
            if self.o.mode == "hermetic" and (effects or run.agent_pid is not None):
                # Also without effects (the hook off): the agent's own events still reach
                # the sensor, and H4 must link them by the declared agent pid.
                run.truth, run.host_file = self._replay(
                    directory, sink, node, rows, effects, host, model, run.agent_pid
                )
            elif live:
                time.sleep(3.0)  # the sensor's last batch
                _wait(_settled(sink), 30, f"{name}: the host records")
                run.host_file = sink.records
                run.truth = HostTruth(run.agent_pid)
            run.rows = sink.rows()
            (directory / "fixture-visits.json").write_text(
                json.dumps(
                    [
                        {"kind": v.kind, "time_ns": v.time_ns, "authorized": v.authorized}
                        for v in host.visits
                    ]
                )
            )
            (directory / "model-requests.json").write_text(
                json.dumps([{"fed": s.fed, "status": s.status} for s in model.seen])
            )
            return run
        finally:
            if sensor is not None:
                sensor.stop()
            if node is not None:
                node.stop()
            sink.close()
            model.close()
            host.close()

    def _sensor(self, directory: Path) -> Any:
        kinds = {"auto": ("ebpf", "auditd"), "ebpf": ("ebpf",), "auditd": ("auditd",)}
        failures: list[str] = []
        for kind in kinds[self.o.sensor]:
            if self.sensor_kind not in (None, kind):
                continue
            try:
                if self.dist is None:
                    raise SensorUnavailableError(
                        "the sensor reports to the Node, which is not built"
                    )
                sensor: Any = (
                    EbpfSensor(self.o.emitter, directory, node_grpc="")
                    if kind == "ebpf"
                    else AuditdSensor(directory, self.dist / "otelcol-fabric").prepare()
                )
                if isinstance(sensor, EbpfSensor) and not sensor.loadable():
                    raise SensorUnavailableError("the eBPF programs do not load on this kernel")
                self.sensor_kind = kind
                return sensor
            except SensorUnavailableError as exc:
                failures.append(f"{kind}: {exc}")
        raise SystemExit("no live host sensor: " + "; ".join(failures))

    def _drain(self, config: AgentConfig, endpoint: str) -> None:
        """Deliver what the agent left in its spool: a capturing process on the same store
        with the real endpoint drains every epoch's records, then exits."""
        env = scenario.agent_env(
            AgentConfig(**{**config.__dict__, "otlp_endpoint": endpoint, "exec_hook": False})
        )
        subprocess.run(
            [sys.executable, "-c", "import time; time.sleep(4)"],
            env=env,
            cwd=config.workdir,
            check=True,
            timeout=120,
            capture_output=True,
        )

    @staticmethod
    def _steps(effects: Sequence[replay.Effect]) -> dict[str, str]:
        template = json.loads(replay.TEMPLATE.read_text())
        steps: dict[str, str] = {}
        for effect in effects:
            tree = next((t for t in template["effects"] if t["match"] in effect.command), None)
            steps[effect.attempt_uid] = str(tree["step"]) if tree else "unknown"
        return steps

    def _replay(
        self,
        directory: Path,
        sink: Sink,
        node: Node | None,
        rows: list[dict[str, Any]],
        effects: Sequence[replay.Effect],
        host: FixtureHost,
        model: FixtureModel,
        agent_pid: int | None,
    ) -> tuple[HostTruth, Path]:
        visits: dict[str, list[int]] = {}
        for visit in host.visits:
            visits.setdefault(
                "fixture_http" if visit.kind == "http" else "fixture_ping", []
            ).append(visit.time_ns)
        bound = replay.bind(
            effects,
            replay.exchange_starts(rows),
            peers={"model": (model.host, model.port), "fixture_host": (host.host, host.port)},
            visits=visits,
            agent_ppid=os.getpid(),
            agent_pid=agent_pid,
        )
        replayed = directory / "host-replay.otlp.json"
        replayed.write_text(json.dumps(bound.export, indent=1))
        truth = HostTruth(
            agent_pid=agent_pid,
            anchors=bound.anchors,
            lineage=bound.lineage,
            model_connects=bound.agent_events.get("model", ()),
            uncalled_connects=bound.agent_events.get("fixture_host", ()),
            exact=True,
        )
        if node is None:
            return truth, replayed
        before = sum(1 for r in sink.rows() if r.get("kind") == "log")
        request = urllib.request.Request(  # noqa: S310 - the harness's own loopback Node
            f"{node.otlp_http}/v1/logs",
            data=replayed.read_bytes(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            response.read()
        want = before + bound.count()
        _wait(
            lambda: sum(1 for r in sink.rows() if r.get("kind") == "log") >= want,
            30,
            "the replayed host records at the sink",
        )
        return truth, sink.records

    # -- the verifier -------------------------------------------------------------------

    def reconstruct(
        self, run: Run, *, host: bool = True, tag: str = ""
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, int]]:
        env = {**os.environ, "FABRIC_WIRE_ID_KEY": ID_KEY}
        common = [str(run.records), "--store-root", str(run.store), "--tenant", TENANT]
        if run.run_id is not None:
            common += ["--run", run.run_id]
        hosted = []
        if host and run.host_file is not None:
            hosted = [
                "--host-records",
                str(run.host_file),
                "--host-label",
                scenario.HOST_LABEL,
                "--endpoint-peer",
                f"ar1-model={run.model_host}",
                # The sensor runs from before the agent starts until after it exits (the
                # replay covers the whole run by construction): declared, since local
                # records carry no positions that could prove it.
                "--host-coverage-declared",
            ]
            if run.agent_pid is not None:
                hosted += ["--agent-pid", str(run.agent_pid)]
            # The agent's own telemetry goes to the Node (or the sink) on loopback: Fabric's
            # delivery, not an action of the agent. Same address as the model here.
            hosted += ["--known-peer", "127.0.0.1"]
        out = run.directory / f"actions{tag}.json"
        report, projection = (
            run.directory / f"report{tag}.json",
            run.directory / f"projection{tag}.json",
        )
        view = subprocess.run(
            [sys.executable, "-m", "fabric.reconstruct", "actions", *common, "--json", *hosted],
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        out.write_text(view.stdout)
        (run.directory / f"actions{tag}.stderr").write_text(view.stderr)
        text = subprocess.run(
            [sys.executable, "-m", "fabric.reconstruct", "actions", *common, *hosted],
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        (run.directory / f"actions{tag}.txt").write_text(text.stdout)
        spans = common[:]
        spans[0:1] = ["--spans", str(run.records)]
        full = subprocess.run(
            [
                sys.executable,
                "-m",
                "fabric.reconstruct",
                *spans,
                *hosted,
                "--out",
                str(report),
                "--projection",
                str(projection),
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        codes = {
            "actions": view.returncode,
            "actions_text": text.returncode,
            "report": full.returncode,
        }
        document = json.loads(view.stdout) if view.stdout.strip() else {"runs": []}
        written = json.loads(report.read_text()) if report.exists() else {"runs": []}
        return document, written, codes

    # -- the variants -------------------------------------------------------------------

    def run(self) -> dict[str, Any]:
        self.o.out.mkdir(parents=True, exist_ok=True)
        wanted = set(self.o.variants)
        if wanted & {"a", "d", "e"}:
            wanted.add("base")
        order = [v for v in VARIANTS if v in wanted]
        for variant in order:
            self.o.log(f"AR-1 {self.o.mode}: variant {variant}")
            getattr(self, f"variant_{variant}")()
        self.canaries_check()
        result = {
            "schema": "fabric.ar1-result/v0",
            "mode": self.o.mode,
            "node": str(self.dist) if self.dist else None,
            "sensor": self.sensor_kind if self.o.mode == "live" else "replay",
            "sandbox": self.sandbox,
            "passed": all(c.passed for c in self.checks),
            "variants": {
                c.variant: {"passed": c.passed, "checks": [vars(i) for i in c.items]}
                for c in self.checks
            },
        }
        (self.o.out / "ar1-result.json").write_text(json.dumps(result, indent=2))
        return result

    def _new(self, variant: str) -> Checks:
        checks = Checks(variant)
        self.checks.append(checks)
        return checks

    def _common(
        self, checks: Checks, run: Run
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
        checks.equal("agent exit code", run.agent.returncode, 0)
        checks.check("agent answered", run.agent.summary.get("answer"), run.agent.stderr[-800:])
        checks.check("one agent run in the export", run.run_id is not None, run.run_id)
        checks.check("no unknown effect", "unknown" not in run.steps.values(), run.steps)
        document, report, codes = self.reconstruct(run)
        checks.check(
            "actions view printed one run",
            len(document.get("runs", ())) == 1,
            (run.directory / "actions.stderr").read_text()[-800:],
        )
        checks.check("report has one run", len(report.get("runs", ())) == 1, codes)
        if len(document.get("runs", ())) != 1 or len(report.get("runs", ())) != 1:
            return None
        view, entry = expect.only_view(document), expect.only_run(report)
        checks.equal("report chains = view chains", entry.get("chains"), view["chains"])
        partial = any(c["verdict"] == "partial" for c in view["chains"].values())
        checks.equal("exit codes", codes, dict.fromkeys(codes, 1 if partial else 0))
        return view, entry

    def variant_base(self) -> None:
        checks = self._new("base")
        run = self.runs["base"] = self.agent_run("base")
        got = self._common(checks, run)
        if got is None:
            return
        view, entry = got
        expect.chains(
            checks,
            view,
            {
                "decisions": {"verdict": "complete"},
                "actions": {"verdict": "complete"},
                "effects": {"verdict": "partial", "reasons": ["unattributed_effect"]},
                "corroboration": {"verdict": "partial", "reasons": ["unexplained_host_event"]},
            },
        )
        expect.model_calls(checks, view)
        expect.attribution(checks, view, run.steps, metadata_only=False)
        if run.truth is not None:
            expect.corroboration(checks, view, run.steps, run.truth)
        checks.check("the report lists sensor events", entry.get("sensor_events"), entry.keys())
        visits = json.loads((run.directory / "fixture-visits.json").read_text())
        checks.equal(
            "fixture host: curl (authorized) and the ping",
            [(v["kind"], v["authorized"]) for v in visits],
            [("http", True), ("ping", False)],
        )
        self._projection(checks, run)

    def _projection(self, checks: Checks, run: Run) -> None:
        projection = json.loads((run.directory / "projection.json").read_text())
        steps = {s["attempt_id"]: s for s in projection.get("steps", ()) if "attempt_id" in s}
        for uid, step in run.steps.items():
            if step in expect.UNLINKED_STEPS:
                continue
            kinds = [
                (link["type"], link.get("method")) for link in steps.get(uid, {}).get("links", ())
            ]
            checks.equal(
                f"projection step {step}: links",
                kinds,
                [
                    (
                        "caused_by",
                        "output_match"
                        if step != "2" or kinds[:1] == [("caused_by", "output_match")]
                        else "sequence_bracket",
                    ),
                    ("corroborated_by", "process_anchor"),
                ],
            )

    def variant_a(self) -> None:
        checks = self._new("a")
        base = self.runs["base"]
        document, _report, _ = self.reconstruct(base, host=False, tag="-a")
        base_view = json.loads((base.directory / "actions.json").read_text())
        if not (document.get("runs") and base_view.get("runs")):
            checks.check("a: one run", False, document)
            return
        view, before = expect.only_view(document), expect.only_view(base_view)
        checks.equal(
            "corroboration not observed",
            view["chains"]["corroboration"],
            {"verdict": "not_observed", "reasons": ["not_configured"]},
        )
        for name in ("decisions", "actions", "effects"):
            checks.equal(f"{name} unchanged", view["chains"][name], before["chains"][name])
        checks.equal(
            "caused_by unchanged",
            expect.targets_by_step(view, base.steps),
            expect.targets_by_step(before, base.steps),
        )
        checks.equal("no host rows", expect.host_rows(view), {})

    def variant_b(self) -> None:
        checks = self._new("b")
        dropped: list[str] = []

        def drop(run: Run) -> None:
            run.spool_scanned.append(run.agent.config.spool)
            self.canaries_scan_spool(checks, run.agent.config.spool)
            dropped.extend(self._drop_effect_record(run))

        run = self.runs["b"] = self.agent_run("b", deliver_later=True, before_delivery=drop)
        checks.equal("one effect record dropped", len(dropped), 1)
        checks.equal("agent exit code", run.agent.returncode, 0)
        document, _report, _codes = self.reconstruct(run)
        if not document.get("runs"):
            checks.check("b: one run", False, document)
            return
        view = expect.only_view(document)
        # Every chain, not only effects: the dropped record held a position of the shared
        # allocator on the epoch the exchanges use, and nothing proves it was not an
        # exchange, so decisions is partial(sequence_gap) too (fixture
        # ar1-negative-b-effect-dropped). Actions and corroboration are as in base.
        expect.chains(
            checks,
            view,
            {
                "decisions": {"verdict": "partial", "reasons": ["sequence_gap"]},
                "actions": {"verdict": "complete"},
                "effects": {
                    "verdict": "partial",
                    "reasons": ["sequence_gap", "unattributed_effect"],
                },
                "corroboration": {"verdict": "partial", "reasons": ["unexplained_host_event"]},
            },
        )

    def _drop_effect_record(self, run: Run) -> list[str]:
        """Rewrite the spool without step 1's ``completed`` exec record (its batch file is
        re-framed with a valid digest, so only that one record is missing)."""
        store = LocalFilesystemContentStore(root=str(run.store), tenant_id=TENANT)
        directory = next(run.agent.config.spool.iterdir())
        step1: str | None = None
        files = sorted(p for p in directory.iterdir() if p.name.endswith(".rec"))
        entries = [(p, _spool.unframe_all(p.read_bytes())) for p in files]
        for _, records in entries:
            for doc, _ in records:
                attrs = doc.get("span", {}).get("attributes", {})
                if attrs.get("fabric.step.lifecycle_state") != "running":
                    continue
                for object_id in attrs.get("fabric.content.object_ids", ()):
                    uri = store.evidence_ref_for(object_id)
                    if store.read_descriptor(uri).get("role") == "terminal.argv" and (
                        " && " in json.loads(store.read(uri)).get("command", {}).get("v", "")
                    ):
                        step1 = attrs["fabric.attempt.uid"]
        for path, records in entries:
            kept = [
                (d, b)
                for d, b in records
                if not (
                    d.get("span", {}).get("attributes", {}).get("fabric.attempt.uid") == step1
                    and d["span"]["attributes"].get("fabric.step.lifecycle_state") == "completed"
                )
            ]
            if len(kept) == len(records):
                continue
            if not kept:
                path.unlink()
            else:
                frames = [_spool.frame(d, [bytes(b)] if len(b) else []) for d, b in kept]
                data = (
                    b"".join(_spool.batch_frame(frames))
                    if len(frames) > 1 or path.read_bytes().startswith(_spool.BATCH_MAGIC)
                    else b"".join(frames[0])
                )
                path.write_bytes(data)
            return [str(step1)]
        return []

    def variant_c(self) -> None:
        checks = self._new("c")
        run = self.runs["c"] = self.agent_run("c", exec_hook=False)
        checks.equal("agent exit code", run.agent.returncode, 0)
        checks.equal("no exec records", run.steps, {})
        checks.check(
            "manifest: exec.subprocess disabled(hook_disabled)",
            "disabled:hook_disabled" in expect.manifest_reason(run.rows, "exec.subprocess"),
            expect.manifest_reason(run.rows, "exec.subprocess"),
        )
        document, _report, _ = self.reconstruct(run)
        if not document.get("runs"):
            checks.check("c: one run", False, document)
            return
        view = expect.only_view(document)
        checks.equal(
            "effects not_observed(channel_disabled)",
            view["chains"]["effects"],
            {"verdict": "not_observed", "reasons": ["channel_disabled"]},
        )
        checks.equal(
            "every tool call effect_not_observed(channel_disabled)",
            [(c["call"], c["reason"]) for c in view["tool_calls_without_effect"]],
            [(f"T{n}", "channel_disabled") for n in range(1, 6)],
        )
        for name in ("decisions", "actions"):
            checks.equal(f"{name} complete", view["chains"][name], {"verdict": "complete"})
        # The host chain runs without effects too: the agent's own events are linked by
        # H4 through the declared agent pid, and step 6 is still unexplained. Live, the
        # children the hook no longer records are unexplained as well.
        checks.equal(
            "corroboration partial(unexplained_host_event)",
            view["chains"]["corroboration"],
            {"verdict": "partial", "reasons": ["unexplained_host_event"]},
        )
        to_run = sorted(
            e
            for e, h in expect.host_rows(view).items()
            if any(p["namespace"] == "run" for p in h.get("part_of", ()))
        )
        unexplained = view["unexplained_host_events"]
        if run.truth is not None and run.truth.exact:
            checks.equal(
                "H4 without effects: the agent's connections are part_of the run",
                to_run,
                sorted([*run.truth.model_connects, *run.truth.uncalled_connects]),
            )
            checks.equal(
                "step 6: the only unexplained host event",
                unexplained,
                {
                    "count": len(run.truth.uncalled_connects),
                    "event_ids": sorted(run.truth.uncalled_connects),
                },
            )
        else:
            checks.check("H4 without effects: agent events part_of the run", to_run, view)

    def variant_d(self) -> None:
        checks = self._new("d")
        run = self.runs["d"] = self.agent_run("d", metadata_only=True)
        got = self._common(checks, run)
        if got is None:
            return
        view, _ = got
        expect.chains(
            checks,
            view,
            {
                "decisions": {"verdict": "complete"},
                "actions": {"verdict": "complete"},
                "effects": {
                    "verdict": "partial",
                    "reasons": ["unattributed_effect", "ambiguous_attribution"],
                },
            },
        )
        expect.attribution(checks, view, run.steps, metadata_only=True)
        base = self.runs["base"]
        base_view = expect.only_view(json.loads((base.directory / "actions.json").read_text()))
        mine = expect.targets_by_step(view, run.steps)
        theirs = expect.targets_by_step(base_view, base.steps)
        for step in ("1", "2", "4"):
            mine_step = next((t for s, t in mine.items() if s == step), None)
            checks.equal(f"step {step}: same target as base", mine_step, theirs.get(step))

    def variant_e(self) -> None:
        checks = self._new("e")
        base = self.runs["base"]
        off = self.runs["e"] = self.agent_run("e", capture=False, sensor_on=False)
        checks.equal("exit codes off/on", (off.agent.returncode, base.agent.returncode), (0, 0))
        keys = ("answer", "tools", "background", "ping", "sandbox")

        def outputs(summary: Mapping[str, Any]) -> dict[str, Any]:
            return {
                k: sorted(v, key=lambda t: t["call"]) if k == "tools" else v
                for k, v in summary.items()
                if k in keys
            }

        checks.equal(
            "agent outputs identical off/on",
            outputs(off.agent.summary),
            outputs(base.agent.summary),
        )
        (self.o.out / "e" / "durations.json").write_text(
            json.dumps(
                {"capture_off_s": off.agent.duration_s, "capture_on_s": base.agent.duration_s}
            )
        )
        if self.o.latency_gate:
            gate = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    "-p",
                    "no:cacheprovider",
                    "--no-cov",
                    *LATENCY_GATE,
                ],
                cwd=SDK,
                capture_output=True,
                text=True,
                timeout=1200,
                check=False,
            )
            (self.o.out / "e" / "latency-gate.txt").write_text(gate.stdout + gate.stderr)
            checks.check(
                "053 §4.4 latency gate (test_hooks_exec_passivity)",
                gate.returncode == 0,
                gate.stdout[-1500:],
            )

    # -- privacy canaries ---------------------------------------------------------------

    def canaries_scan_spool(self, checks: Checks, spool: Path) -> None:
        files = [p for p in spool.rglob("*") if p.is_file()]
        checks.check(
            "spool holds records before delivery",
            any(p.name.endswith(".rec") for p in files),
            [p.name for p in files],
        )
        leaks = [
            p.name for p in files for c in self.canaries.values() if c.encode() in p.read_bytes()
        ]
        checks.equal("canaries: not in the spool", leaks, [])

    def canaries_check(self) -> None:
        """§6.2: neither canary appears in clear in any spool file, Node export or report;
        every file the harness wrote is searched, the content store included."""
        checks = self._new("canaries")
        files = [
            p for p in self.o.out.rglob("*") if p.is_file() and p.name not in ("agent.stdout",)
        ]
        leaks = sorted(
            {
                str(p.relative_to(self.o.out))
                for p in files
                for c in self.canaries.values()
                if c.encode() in p.read_bytes()
            }
        )
        checks.equal("canaries: in no file (spools, Node exports, reports, store)", leaks, [])
        exported = [p for p in files if p.name in ("records.jsonl", "raw.bin")]
        checks.check("Node exports were searched", exported, files[:5])
        visits = [json.loads(p.read_text()) for p in self.o.out.glob("*/fixture-visits.json")]
        checks.check(
            "the bearer token reached the fixture host",
            any(v["kind"] == "http" and v["authorized"] for vs in visits for v in vs),
            visits,
        )
