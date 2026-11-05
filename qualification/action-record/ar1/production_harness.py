# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""AR-1 production (spec 056 §6.2 "AR-1 production"): every variant against a
production-profile Node, then the privacy canaries.

``replay`` (hermetic, macOS and Linux): the native Node with the static ingress groups of
:mod:`ar1.production`, the agent in node mode with the ``exec.subprocess`` and
``remote.sandbox`` hooks, the fixture ``docker`` for step 8 and the fixture E2B service
for step 9, then ``hostrecords-replay`` staging the host side through the host-records
library and posting it to the ``ebpf`` group, and a quiet node to the ``quiet`` group.
``live`` (Linux, :mod:`ar1.live`): the Compose production Node, the eBPF emitter in
production mode, the agent in a container, a real ``docker run`` and bwrap.

The verifier reads only the sink's export (host and agent records together):
``--trusted-source --profile production``, the Node's content store and key, the id key,
``--host-label``, ``--host-source host.ebpf=<s- id>`` for each sensor, ``--sandbox-peer
ADDRESS:PORT`` and no ``--host-coverage-declared``.

Variants: ``base``; ``a`` host source removed; ``b`` one effect record dropped from the
agent's (encrypted) spool; ``c`` the exec hook off; ``d`` the subprocess output
``metadata_only``; ``e`` capture off, then on; ``f`` the remote sandbox hook off with its
provider declared; ``g`` step 8 without ``-d``; ``h`` swapped credentials, both ways.
"""

# The harness runs its own fixed command lines (the verifier, the replay, the drain).
# ruff: noqa: S603

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fabric.content_store import LocalFilesystemContentStore

from . import expect, production, replay, scenario
from .expect import Checks, ProductionTruth
from .fixture_host import FixtureHost
from .fixture_model import REMOTE_COMMAND, REMOTE_OUTPUT, FixtureModel, Script
from .harness import (
    LATENCY_GATE,
    SDK,
    Options,
    _agent_epochs,
    _bwrap_works,
    _delivered,
    _rows,
    _sha_tool,
    _wait,
)
from .node import REPO, free_port, node_dist
from .sink import Sink

sys.path.insert(0, str(REPO / "qualification" / "remote-sandbox"))
from fixture_e2b import FixtureE2B
from fixture_e2b import Script as RemoteScript

PRODUCTION_VARIANTS = ("base", "a", "b", "c", "d", "e", "f", "g", "h")


@dataclass
class ProdRun:
    """One production agent run and what came out of it."""

    name: str
    directory: Path
    agent: scenario.AgentRun
    rows: list[dict[str, Any]]
    records: Path
    content_root: Path
    run_id: str | None = None
    steps: dict[str, str] = field(default_factory=dict)
    truth: ProductionTruth | None = None
    model_host: str = "127.0.0.1"
    sandbox_peer: str = ""
    fixture_port: int = 0  # the uncalled fixture host (step 6)
    agent_pid: int | None = None
    container_id: str = ""
    replay_codes: dict[str, int] = field(default_factory=dict)
    e2b_ledger: list[dict[str, Any]] = field(default_factory=list)
    spool: Path | None = None


def _provider_host() -> str:
    """An address of its own for the fixture E2B service (spec 056 §6.2): 127.0.0.2 where
    the loopback network answers it (Linux), else 127.0.0.1 (macOS has only that on lo0;
    the sandbox peer then names the port as well)."""
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.2", 0))
        except OSError:
            return "127.0.0.1"
    return "127.0.0.2"


def _container_id() -> str:
    return os.urandom(32).hex()


class ProductionHarness:
    def __init__(self, options: Options) -> None:
        self.o = options
        self.canaries = scenario.Canaries.fresh()
        self.e2b_key = "e2b_ar1" + os.urandom(16).hex()
        self.remote_secret = "AR1REMOTESECRET" + os.urandom(12).hex()
        self.dist = node_dist(options.node_dist)
        if self.dist is None and not self.live:  # live runs the Compose Node image
            raise SystemExit(
                "AR-1 production replay needs a built Node dist (make -C "
                "components/otel-collector-fabric build, or FABRIC_NODE_DIST)"
            )
        self.sandbox = "bwrap" if _bwrap_works() else "python"
        self.provider_host = _provider_host()
        self.material = production.Material.create(options.out / "secrets", self.cert_hosts)
        self.sources = {
            "agent": production.agent_source_id(),
            "ebpf": production.host_source_id(production.EBPF_SOURCE_LABEL),
            "quiet": production.host_source_id(production.QUIET_SOURCE_LABEL),
        }
        self.replay_bin = None if self.live else replay.build_replay(options.out / "bin", REPO)
        self.docker = production.FixtureDocker(options.out)
        self.checks: list[Checks] = []
        self.runs: dict[str, ProdRun] = {}
        self.container_ids: list[str] = []
        self.peer_addresses: set[str] = set()

    # -- one agent run ------------------------------------------------------------------

    def agent_run(  # noqa: PLR0915 - one branch per variant knob
        self,
        name: str,
        *,
        exec_hook: bool = True,
        metadata_only: bool = False,
        capture: bool = True,
        detach: bool = True,
        remote_sandbox: bool = True,
        before_delivery: Callable[[ProdRun], None] | None = None,
        host_to: str = "ebpf",  # the group the host replay posts to (h: "agent")
        agent_to: str = "agent",  # the group the agent sends to (h: "ebpf")
    ) -> ProdRun:
        directory = self.o.out / name
        directory.mkdir(parents=True, exist_ok=True)
        data = scenario.write_data(self.o.out / "data")
        policy = production.write_production_policy(
            directory / "policy.json", metadata_only_output=metadata_only
        )
        host = FixtureHost(self.canaries.bearer_token).start()
        model = FixtureModel(Script(str(data), host.url, _sha_tool(), production=True)).start()
        e2b = FixtureE2B(api_key=self.e2b_key, host=self.provider_host,
                         env_canary=self.remote_secret).start()  # fmt: skip
        e2b.script(REMOTE_COMMAND, RemoteScript(stdout=REMOTE_OUTPUT))
        sink = self._sink(directory).start()
        node = self._node(directory, sink)
        sensor: Any = None
        container = _container_id()
        self.container_ids.append(container)
        sandbox_peer = (
            f"{self.provider_host}:{e2b.port}"
            if ":" not in self.provider_host
            else f"[{self.provider_host}]:{e2b.port}"
        )
        self.peer_addresses |= {model.host, host.host, self.provider_host}
        try:
            node.start()
            sensor = self._sensor(directory, node, host_to)
            delivery = production.Delivery(
                otlp_endpoint=node.url(agent_to),
                content_endpoint=node.url("content", path="/v1/logs"),
                token=self.material.token(agent_to),
                ca=self.material.ca,
            )
            later = before_delivery is not None
            config = scenario.AgentConfig(
                workdir=directory / "agent",
                model_base_url=model.base_url,
                model_endpoints=model.endpoints_json(),
                fixture_host=host.host,
                fixture_port=host.port,
                otlp_endpoint=delivery.otlp_endpoint,
                canaries=self.canaries,
                sandbox=self.sandbox,
                run_id=f"ar1-production-{name}",
                capture=capture,
                exec_hook=exec_hook,
                policy=policy,
            )
            config.workdir.mkdir(parents=True, exist_ok=True)
            held = production.Delivery(
                otlp_endpoint=f"https://127.0.0.1:{free_port()}",
                content_endpoint=f"https://127.0.0.1:{free_port()}/v1/logs",
                token=delivery.token,
                ca=delivery.ca,
            )
            env = production.production_env(
                config,
                delivery=held if later else delivery,
                material=self.material,
                e2b_env=e2b.env(),
                remote_secret=self.remote_secret,
                remote_sandbox=remote_sandbox,
                sandbox_host=sandbox_peer,
                detach=detach,
                extra=self._extra_env(container),
                shutdown_s=3 if agent_to != "agent" or later else None,
            )
            agent = self._launch(config, env)
            run = ProdRun(
                name, directory, agent, [], sink.records, node.content_root,
                model_host=model.host, sandbox_peer=sandbox_peer, container_id=container,
                spool=config.workdir / "spool", fixture_port=host.port,
            )  # fmt: skip
            run.e2b_ledger = e2b.ledger_json()
            (directory / "e2b-ledger.json").write_text(json.dumps(run.e2b_ledger, indent=1))
            if not capture:
                return run
            if later and before_delivery is not None:
                before_delivery(run)
                self._drain(env, delivery)
            if agent_to == "agent":
                _wait(lambda: _delivered(sink.rows()), 90, f"{name}: the agent's records")
            else:
                time.sleep(3.0)
            time.sleep(1.0)
            rows = sink.rows()
            if hasattr(node, "content_readable"):
                node.content_readable()
            store = self._store(run)
            effects = self._effects(rows, store)
            remote = replay.remote_effects(rows)
            epochs = sorted(_agent_epochs(rows))
            run.run_id = f"source:{epochs[0][0]}:{epochs[0][1]}" if len(epochs) == 1 else None
            reported = agent.summary.get("pid")
            run.agent_pid = reported if isinstance(reported, int) else None
            visits: dict[str, list[int]] = {}
            for visit in host.visits:
                kind = "fixture_http" if visit.kind == "http" else "fixture_ping"
                visits.setdefault(kind, []).append(visit.time_ns)
            bound = replay.bind_production(
                effects,
                remote,
                replay.exchange_starts(rows),
                peers={
                    "model": (model.host, model.port),
                    "fixture_host": (host.host, host.port),
                    "sandbox": (self.provider_host, e2b.port),
                },
                visits=visits,
                agent_ppid=os.getpid(),
                agent_pid=run.agent_pid,
                container_id=container,
                quiet_container_id=_container_id(),
            )
            run.steps = dict(bound.steps)
            for effect in effects:
                run.steps.setdefault(effect.attempt_uid, "unknown")
            if sensor is None:
                run.truth = self._replay(run, node, sink, bound, host_to=host_to, linked=detach)
            else:
                run.truth = self._sensed(run, sensor, sink, linked=detach)
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
            node.stop()
            sink.close()
            e2b.close()
            model.close()
            host.close()

    # -- what the live harness replaces ---------------------------------------------------

    live = False
    host_groups: tuple[str, ...] = ("ebpf", "quiet")  # the sensors the verifier declares
    cert_hosts: tuple[str, ...] = ()  # extra names on the Node's (and sink's) certificate

    def _sink(self, directory: Path) -> Sink:
        return Sink(
            directory / "sink",
            tls=(self.material.server_cert, self.material.server_key),
            token=self.material.token("sink"),
        )

    def _node(self, directory: Path, sink: Sink) -> Any:
        if self.dist is None:
            raise RuntimeError("no Node dist")
        return production.GroupNode(self.dist, directory, self.material, sink.url, self.sources)

    def _sensor(self, directory: Path, node: Any, host_to: str) -> Any:
        """Replay: no sensor runs during the agent run (the host side is replayed after)."""
        del directory, node, host_to
        return None

    def _extra_env(self, container: str) -> dict[str, str]:
        return self.docker.env(os.environ, container)

    def _launch(self, config: scenario.AgentConfig, env: Mapping[str, str]) -> scenario.AgentRun:
        started = time.monotonic()
        process = scenario.start_agent(config, env=env)
        if process.stdin is not None:
            process.stdin.close()
        return scenario.finish_agent(config, process, started)

    def _sensed(self, run: ProdRun, sensor: Any, sink: Sink, *, linked: bool) -> ProductionTruth:
        raise NotImplementedError  # live only

    def _store(self, run: ProdRun) -> LocalFilesystemContentStore:
        return LocalFilesystemContentStore(
            root=str(run.content_root),
            tenant_id=scenario.TENANT,
            envelope_key=self.material.content_key.read_bytes(),
        )

    @staticmethod
    def _effects(rows: list[dict[str, Any]], store: Any) -> list[replay.Effect]:
        """The exec effects, re-read until every command line is in the Node's store (the
        content path may land a moment after the spans)."""
        effects: list[replay.Effect] = []
        for _ in range(40):
            effects = replay.exec_effects(rows, store)
            if all(e.command for e in effects):
                return effects
            time.sleep(0.25)
        return effects

    def _drain(self, env: Mapping[str, str], delivery: production.Delivery) -> None:
        """Deliver what the agent left in its spool: a capturing process with the real
        endpoints drains it, then exits."""
        drain = dict(env)
        drain.pop("FABRIC_WIRE_EXEC", None)
        drain["OTEL_EXPORTER_OTLP_ENDPOINT"] = delivery.otlp_endpoint
        drain["FABRIC_WIRE_CONTENT_ENDPOINT"] = delivery.content_endpoint
        drain["FABRIC_WIRE_SHUTDOWN_TIMEOUT_S"] = str(scenario.EXIT_BUDGET_S)
        subprocess.run(
            [sys.executable, "-c", "import time; time.sleep(6)"],
            env=drain,
            check=True,
            timeout=120,
            capture_output=True,
        )

    def _replay(
        self,
        run: ProdRun,
        node: production.GroupNode,
        sink: Sink,
        bound: replay.ProductionBound,
        *,
        host_to: str,
        linked: bool,
    ) -> ProductionTruth:
        """Stage and post both host sources; map the library's event ids back."""
        inputs = run.directory / "replay-input"  # the kernel's view: clear ids, by design
        inputs.mkdir(exist_ok=True)
        orders: dict[str, list[int]] = {}
        for group, events, label, host_label in (
            ("ebpf", bound.events, production.EBPF_SOURCE_LABEL, scenario.HOST_LABEL),
            ("quiet", bound.quiet, production.QUIET_SOURCE_LABEL, production.QUIET_HOST_LABEL),
        ):
            orders[group] = replay.write_events(inputs / f"{group}.jsonl", events)
            config = replay.write_keyless_config(
                inputs / f"{group}.config.json",
                tenant=scenario.TENANT,
                source_label=label,
                host_label=host_label,
                version=production.SENSOR_VERSION,
            )
            target = host_to if group == "ebpf" else "quiet"
            if self.replay_bin is None:
                raise RuntimeError("hostrecords-replay is not built")
            done = replay.run_replay(
                self.replay_bin,
                config=config,
                id_key_file=self.material.id_key,
                state_key_file=self.material.state_keys[group],
                state_dir=run.directory / "sensor-state" / group,
                events=inputs / f"{group}.jsonl",
                endpoint=node.url(target, path="/v1/traces"),
                token_file=self.material.tokens[target],
                ca_file=self.material.ca,
            )
            run.replay_codes[group] = done.returncode
            (run.directory / f"replay-{group}.txt").write_text(done.stdout + done.stderr)
        want = {
            self.sources["ebpf"]: len(bound.events) if host_to == "ebpf" else 0,
            self.sources["quiet"]: len(bound.quiet),
        }

        def arrived() -> bool:
            rows = sink.rows()
            return all(
                sum(
                    1
                    for r in rows
                    if r.get("kind") == "span"
                    and r["attributes"].get("fabric.source_id") == source
                    and "fabric.sensor.event_class" in r["attributes"]
                )
                >= count
                for source, count in want.items()
            )

        _wait(arrived, 60, f"{run.name}: the replayed host records at the sink")
        time.sleep(1.5)  # the heartbeats and final markers after the records
        rows = sink.rows()
        ids = replay.map_event_ids(rows, self.sources["ebpf"], orders["ebpf"])
        quiet = replay.map_event_ids(rows, self.sources["quiet"], orders["quiet"])

        def named(indexes: Sequence[int]) -> list[str]:
            return [ids[i] for i in indexes if i in ids]

        sandbox = {uid: named(v) for uid, v in bound.sandbox.items()}
        return ProductionTruth(
            agent_pid=run.agent_pid,
            anchors={uid: ids[i] for uid, i in bound.anchors.items() if i in ids},
            lineage={uid: named(v) for uid, v in bound.lineage.items()},
            sandbox=sandbox,
            model_connects=named(bound.agent_events.get("model", ())),
            uncalled_connects=named(bound.agent_events.get("fixture_host", ())),
            sandbox_connects=named(bound.agent_events.get("sandbox", ())),
            quiet_events=list(quiet.values()),
            unlinked_sandbox=[] if linked else [e for v in sandbox.values() for e in v],
            exact=True,
            certain=bound.recorded,
        )

    # -- the verifier -------------------------------------------------------------------

    def reconstruct(
        self, run: ProdRun, *, host: bool = True, tag: str = "", records: Path | None = None
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, int]]:
        env = {**os.environ, "FABRIC_WIRE_ID_KEY": scenario.ID_KEY}
        spans = records or run.records
        common = [
            "--store-root", str(run.content_root), "--tenant", scenario.TENANT,
            "--content-key-file", str(self.material.content_key),
            "--trusted-source", "--profile", "production", "--wait-for-objects", "10",
        ]  # fmt: skip
        if run.run_id is not None:
            common += ["--run", run.run_id]
        hosted: list[str] = []
        if host:
            # No --host-label: production records name their host (the CLI takes the label
            # only with --host-records, for local records).
            hosted = [
                "--endpoint-peer", f"ar1-model={run.model_host}",
                "--sandbox-peer", run.sandbox_peer,
                *(f"--host-source=host.ebpf={self.sources[g]}" for g in self.host_groups),
            ]  # fmt: skip
            if run.agent_pid is not None:
                hosted += ["--agent-pid", str(run.agent_pid)]
            if self.live:  # the agent's own delivery to the Node (loopback, as the model)
                hosted += ["--known-peer", "127.0.0.1"]
        out = run.directory / f"actions{tag}.json"
        report = run.directory / f"report{tag}.json"
        projection = run.directory / f"projection{tag}.json"
        command = [sys.executable, "-m", "fabric.reconstruct"]
        view = subprocess.run(
            [*command, "actions", str(spans), *common, "--json", *hosted],
            env=env, capture_output=True, text=True, timeout=300, check=False,
        )  # fmt: skip
        out.write_text(view.stdout)
        (run.directory / f"actions{tag}.stderr").write_text(view.stderr)
        text = subprocess.run(
            [*command, "actions", str(spans), *common, *hosted],
            env=env, capture_output=True, text=True, timeout=300, check=False,
        )  # fmt: skip
        (run.directory / f"actions{tag}.txt").write_text(text.stdout)
        full = subprocess.run(
            [*command, "--spans", str(spans), *common, *hosted, "--out", str(report),
             "--projection", str(projection)],
            env=env, capture_output=True, text=True, timeout=300, check=False,
        )  # fmt: skip
        (run.directory / f"report{tag}.stderr").write_text(full.stderr)
        codes = {"actions": view.returncode, "actions_text": text.returncode,
                 "report": full.returncode}  # fmt: skip
        document = json.loads(view.stdout) if view.stdout.strip() else {"runs": []}
        written = json.loads(report.read_text()) if report.exists() else {"runs": []}
        return document, written, codes

    # -- the variants -------------------------------------------------------------------

    def run(self) -> dict[str, Any]:
        self.o.out.mkdir(parents=True, exist_ok=True)
        wanted = set(self.o.variants)
        if wanted & {"a", "d", "e"}:
            wanted.add("base")
        for variant in [v for v in PRODUCTION_VARIANTS if v in wanted]:
            self.o.log(f"AR-1 production {self.o.mode}: variant {variant}")
            getattr(self, f"variant_{variant}")()
        self.canaries_check()
        result = {
            "schema": "fabric.ar1-result/v0",
            "profile": "production",
            "mode": self.o.mode,
            "node": str(self.dist) if self.dist else "compose",
            "sensor": "replay",
            "sandbox": self.sandbox,
            "provider_host": self.provider_host,
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
        self, checks: Checks, run: ProdRun
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
        checks.equal("agent exit code", run.agent.returncode, 0)
        checks.check("agent answered", run.agent.summary.get("answer"), run.agent.stderr[-800:])
        checks.check("one agent run in the export", run.run_id is not None, run.run_id)
        checks.check("no unknown effect", "unknown" not in run.steps.values(), run.steps)
        if not self.live:
            checks.equal("host replay acknowledged (ebpf, quiet)", run.replay_codes,
                         {"ebpf": 0, "quiet": 0})  # fmt: skip
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

    def _quiet_out_of_sources(self, checks: Checks, entry: Mapping[str, Any]) -> None:
        sources = json.dumps(entry.get("sources", []))
        checks.check(
            "host sources never in sources[] (the quiet node included)",
            self.sources["quiet"] not in sources and self.sources["ebpf"] not in sources,
            sources[:400],
        )

    def _ledger(self, checks: Checks, run: ProdRun) -> None:
        checks.check(
            "E2B canaries reached the provider (api key, envs value)",
            any(e.get("canaries", {}).get("api_key") for e in run.e2b_ledger)
            and any(e.get("canaries", {}).get("env_value") for e in run.e2b_ledger),
            run.e2b_ledger,
        )

    def variant_base(self) -> None:
        checks = self._new("base")
        run = self.runs["base"] = self.agent_run("base")
        got = self._common(checks, run)
        if got is None or run.truth is None:
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
        expect.model_calls(checks, view, production=True)
        expect.attribution(checks, view, run.steps, metadata_only=False, production=True)
        expect.production_corroboration(checks, view, run.steps, run.truth, entry=entry)
        self._quiet_out_of_sources(checks, entry)
        self._ledger(checks, run)
        checks.equal(
            "step 8's effect reported its container (created_id)",
            sum(1 for r in run.rows if "fabric.sandbox.created_id" in r.get("attributes", {})),
            1,
        )
        visits = json.loads((run.directory / "fixture-visits.json").read_text())
        checks.equal(
            "fixture host: curl (authorized) and the ping",
            [(v["kind"], v["authorized"]) for v in visits],
            [("http", True), ("ping", False)],
        )

    def variant_a(self) -> None:
        """Host source removed: the export without any host source's spans, nothing
        declared: ``corroboration`` not_observed, the other chains unchanged."""
        checks = self._new("a")
        base = self.runs["base"]
        hosts = {self.sources["ebpf"], self.sources["quiet"]}
        stripped = base.directory / "records-without-host.jsonl"
        stripped.write_text(
            "".join(
                json.dumps(r, sort_keys=True) + "\n"
                for r in _rows(base.records)
                if r.get("attributes", {}).get("fabric.source_id") not in hosts
            )
        )
        document, _report, _ = self.reconstruct(base, host=False, tag="-a", records=stripped)
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

        def drop(run: ProdRun) -> None:
            if run.spool is not None:
                self.canaries_scan_spool(checks, run.spool)
                dropped.extend(self._drop_effect_record(run.spool))

        run = self.runs["b"] = self.agent_run("b", before_delivery=drop)
        checks.equal("one effect record dropped", len(dropped), 1)
        checks.equal("agent exit code", run.agent.returncode, 0)
        document, _report, _codes = self.reconstruct(run)
        if not document.get("runs"):
            checks.check("b: one run", False, document)
            return
        view = expect.only_view(document)
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

    def _drop_effect_record(self, spool: Path) -> list[str]:
        """Rewrite the encrypted spool without step 1's ``completed`` exec record: open each
        record file's envelope with the spool key, drop that one record, re-frame the rest
        and seal it again under the same name (so only that record is missing)."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415
        from fabric.wire import _spool  # noqa: PLC0415
        from fabric.wire._keys import envelope_key_id  # noqa: PLC0415

        key = self.material.spool_key.read_bytes()
        cipher, kid = AESGCM(key), envelope_key_id(key)
        directory = next(
            (d for d in (spool, *spool.iterdir()) if d.is_dir() and any(d.glob("*.rec"))), spool
        )
        files = sorted(p for p in directory.iterdir() if p.name.endswith(".rec"))
        entries = [
            (p, _spool.unframe_all(_spool.unseal(p.read_bytes(), p.name, cipher, kid)))
            for p in files
        ]
        step1: str | None = None
        for _, records in entries:
            for doc, blob in records:
                attrs = doc.get("span", {}).get("attributes", {})
                if attrs.get("fabric.step.lifecycle_state") == "running" and b" && " in bytes(blob):
                    step1 = str(attrs.get("fabric.attempt.uid"))
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
                plain = b"".join(_spool.batch_frame(frames) if len(frames) > 1 else frames[0])
                nonce = os.urandom(12)
                aad = _spool.ENVELOPE_MAGIC + kid.encode("ascii") + path.name.encode("ascii")
                path.write_bytes(
                    _spool.ENVELOPE_MAGIC + kid.encode("ascii") + nonce
                    + cipher.encrypt(nonce, plain, aad)
                )  # fmt: skip
            return [str(step1)]
        return []

    def variant_c(self) -> None:
        """The exec hook off, remote sandbox on: every local tool call (T1 to T6)
        ``effect_not_observed(channel_disabled)``; T7's remote effect still attributed, so
        ``effects`` is partial(channel_disabled), not not_observed: one effect channel
        stays enabled (§4.5)."""
        checks = self._new("c")
        run = self.runs["c"] = self.agent_run("c", exec_hook=False)
        checks.equal("agent exit code", run.agent.returncode, 0)
        checks.equal("only the remote effect recorded", sorted(run.steps.values()), ["9"])
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
            "effects partial(channel_disabled)",
            view["chains"]["effects"],
            {"verdict": "partial", "reasons": ["channel_disabled"]},
        )
        checks.equal(
            "every local tool call effect_not_observed(channel_disabled)",
            [(c["call"], c["reason"]) for c in view["tool_calls_without_effect"]],
            [(f"T{n}", "channel_disabled") for n in range(1, 7)],
        )
        for name in ("decisions", "actions"):
            checks.equal(f"{name} complete", view["chains"][name], {"verdict": "complete"})
        checks.equal(
            "corroboration partial(unexplained_host_event)",
            view["chains"]["corroboration"],
            {"verdict": "partial", "reasons": ["unexplained_host_event"]},
        )

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
        expect.attribution(checks, view, run.steps, metadata_only=True, production=True)

    def variant_e(self) -> None:
        checks = self._new("e")
        base = self.runs["base"]
        off = self.runs["e"] = self.agent_run("e", capture=False)
        checks.equal("exit codes off/on", (off.agent.returncode, base.agent.returncode), (0, 0))

        def outputs(summary: Mapping[str, Any]) -> dict[str, Any]:
            # Step 8 prints a new container id on every run: its exit code is compared,
            # not its output digest.
            tools = sorted(summary.get("tools", ()), key=lambda t: t["call"])
            return {
                "answer": summary.get("answer"),
                "tools": [
                    {**t, "stdout_sha256": None} if t["tool"] == "run_container" else t
                    for t in tools
                ],
                **{k: summary.get(k) for k in ("background", "ping", "sandbox")},
            }

        checks.equal(
            "agent outputs identical off/on",
            outputs(off.agent.summary),
            outputs(base.agent.summary),
        )
        if self.o.latency_gate:
            gate = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--no-cov",
                 *LATENCY_GATE],
                cwd=SDK, capture_output=True, text=True, timeout=1200, check=False,
            )  # fmt: skip
            (self.o.out / "e" / "latency-gate.txt").write_text(gate.stdout + gate.stderr)
            checks.check("053 §4.4 latency gate (test_hooks_exec_passivity)",
                         gate.returncode == 0, gate.stdout[-1500:])  # fmt: skip

    def variant_f(self) -> None:
        """The remote sandbox hook off, its provider declared."""
        checks = self._new("f")
        run = self.runs["f"] = self.agent_run("f", remote_sandbox=False)
        got = self._common(checks, run)
        if got is None or run.truth is None:
            return
        view, _ = got
        checks.check(
            "manifest: remote.sandbox disabled(remote_sandbox)",
            "disabled:remote_sandbox" in expect.manifest_reason(run.rows, "remote.sandbox"),
            expect.manifest_reason(run.rows, "remote.sandbox"),
        )
        expect.chains(
            checks,
            view,
            {
                "decisions": {"verdict": "complete"},
                "actions": {"verdict": "complete"},
                "effects": {
                    "verdict": "partial",
                    "reasons": ["unattributed_effect", "remote_sandbox"],
                },
                "corroboration": {"verdict": "partial", "reasons": ["unexplained_host_event"]},
            },
        )
        expect.attribution(checks, view, run.steps, metadata_only=False, production=True,
                           without_effect=[("T7", "channel_disabled")])  # fmt: skip
        expect.production_corroboration(checks, view, run.steps, run.truth, remote_calls=True)

    def variant_g(self) -> None:
        """Step 8 without ``-d``: no H5 link; its container events unlinked."""
        checks = self._new("g")
        run = self.runs["g"] = self.agent_run("g", detach=False)
        got = self._common(checks, run)
        if got is None or run.truth is None:
            return
        view, _ = got
        checks.equal(
            "no created_id reported",
            sum(1 for r in run.rows if "fabric.sandbox.created_id" in r.get("attributes", {})),
            0,
        )
        checks.equal(
            "corroboration unchanged",
            view["chains"]["corroboration"],
            {"verdict": "partial", "reasons": ["unexplained_host_event"]},
        )
        expect.production_corroboration(checks, view, run.steps, run.truth, sandbox_linked=False)

    def variant_h(self) -> None:
        """Swapped credentials: the host side to the agent group with its token, then the
        agent to the host group with that group's token."""
        checks = self._new("h")
        host_side = self.runs["h-host"] = self.agent_run("h-host", host_to="agent")
        hosts = {self.sources["ebpf"]}
        host_rows = [
            r for r in host_side.rows if r.get("attributes", {}).get("fabric.source_id") in hosts
        ]
        if not self.live:  # live: the emitter retries and spools; the sink is the evidence
            refused = host_side.replay_codes.get("ebpf") != 0
            checks.check("host to the agent group: the replay was refused", refused,
                         host_side.replay_codes)  # fmt: skip
        checks.equal("host to the agent group: no host record at the sink", len(host_rows), 0)
        document, _report, _ = self.reconstruct(host_side)
        if document.get("runs"):
            # §6.2 names source_gap; the verifier also reports anchor_missing: no record of
            # the declared source names the agent's host, so the effects there have no
            # anchor (README, "Where this departs from §6.2").
            checks.equal(
                "declared source without records: corroboration partial(source_gap)",
                expect.only_view(document)["chains"]["corroboration"],
                {"verdict": "partial", "reasons": ["source_gap", "anchor_missing"]},
            )
        else:
            checks.check("h: one run", False, document)
        agent_side = self.runs["h-agent"] = self.agent_run("h-agent", agent_to="ebpf")
        agent_rows = [
            r
            for r in agent_side.rows
            if r.get("attributes", {}).get("fabric.source_id") == self.sources["agent"]
        ]
        checks.equal("agent to the host group: no agent record at the sink", len(agent_rows), 0)
        checks.equal("agent to the host group: the agent still exits 0",
                     agent_side.agent.returncode, 0)  # fmt: skip

    # -- privacy canaries ---------------------------------------------------------------

    def canaries_scan_spool(self, checks: Checks, spool: Path) -> None:
        files = [p for p in spool.rglob("*") if p.is_file()]
        checks.check(
            "spool holds records before delivery",
            any(p.name.endswith(".rec") for p in files),
            [p.name for p in files],
        )
        leaks = [p.name for p in files for c in self._secrets() if c.encode() in p.read_bytes()]
        checks.equal("canaries: not in the spool", leaks, [])

    def _secrets(self) -> tuple[str, ...]:
        return (*self.canaries.values(), self.e2b_key, self.remote_secret)

    def canaries_check(self) -> None:
        """§6.2 and its M2 additions: the step 1 secret, the step 2 bearer token, the E2B
        API key and step 9's ``envs`` value appear in no file at all; the clear container
        ids appear in no file but the replay input (the kernel's view the replay stands in
        for; the agent's content is sealed at rest, so no Fabric file holds it in clear);
        the clear peer addresses appear in no sensor state, host span or report."""
        checks = self._new("canaries")
        files = [p for p in self.o.out.rglob("*") if p.is_file() and p.name != "agent.stdout"]
        content = {p: p.read_bytes() for p in files}
        leaks = sorted(
            {str(p.relative_to(self.o.out)) for p, b in content.items()
             for c in self._secrets() if c.encode() in b}
        )  # fmt: skip
        checks.equal("secrets in no file (spools, Node exports, store, reports)", leaks, [])
        ids = sorted(
            {str(p.relative_to(self.o.out)) for p, b in content.items()
             if "replay-input" not in p.parts for c in self.container_ids if c.encode() in b}
        )  # fmt: skip
        checks.equal("clear container ids only in the replay input", ids, [])
        sensor = [p for p in files if "sensor-state" in p.parts]
        checks.check("sensor state was searched", sensor, files[:5])
        host_sources = {self.sources["ebpf"], self.sources["quiet"]}
        host_spans = [
            json.dumps(r)
            for run in self.runs.values()
            for r in run.rows
            if r.get("attributes", {}).get("fabric.source_id") in host_sources
        ]
        reports = [p for p in files if p.name.startswith(("report", "projection", "actions"))]
        peers = sorted(
            {f"{p.relative_to(self.o.out)}:{a}" for p in [*sensor, *reports]
             for a in self.peer_addresses if a.encode() in content[p]}
            | {f"host span:{a}" for s in host_spans for a in self.peer_addresses if a in s}
        )  # fmt: skip
        checks.equal("clear peer addresses in no sensor state, host span or report", peers, [])
        exported = [p for p in files if p.name in ("records.jsonl", "raw.bin")]
        checks.check("Node exports were searched", exported, files[:5])
        visits = [json.loads(p.read_text()) for p in self.o.out.glob("*/fixture-visits.json")]
        checks.check(
            "the bearer token reached the fixture host",
            any(v["kind"] == "http" and v["authorized"] for vs in visits for v in vs),
            visits,
        )


def tools_present() -> list[str]:
    """What the replay needs on this host that may be missing (Go builds the replay)."""
    return [] if shutil.which("go") else ["go"]
