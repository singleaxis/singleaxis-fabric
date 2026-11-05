# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""AR-1 production, live (spec 056 §6.2 "AR-1 production"): Linux only, with Docker on
the ``systemd`` cgroup driver (cgroup v2), passwordless ``sudo`` and the eBPF emitter
built for this kernel (``go generate ./... && go build`` in ``components/host-emitter``).

Per variant:

- **slices** (once): ``fabric-agents.slice`` and ``fabric-sandboxes.slice`` as runtime
  units under ``/run/systemd/system``, started; both directories must appear under
  ``/sys/fs/cgroup/fabric.slice``. The harness fails, never skips, when ``docker info``
  reports another cgroup driver. ``kernel.apparmor_restrict_unprivileged_userns`` is set
  to 0 for the run when it is 1 (bwrap needs user namespaces) and restored after.
- **Node**: ``deploy/compose`` with ``docker-compose.yml``,
  ``docker-compose.production.yml``, ``docker-compose.host-ingress.yml`` and
  ``docker-compose.host-ingress-content.yml`` unchanged, plus one harness overlay: two
  more ``--config`` files (the agent group's ``fabriccontent`` exporter on the file
  backend, sealed with the content key, in place of S3; the test CA as the export trust
  root), the content directory and ``host.docker.internal`` for the sink. The agent
  group (telemetry and content) and the ``ebpf`` group each have their own token
  (root:65532, 0440) and TLS listeners on loopback; delivery is verified HTTPS to the
  authenticated test sink.
- **emitter**: ``EMIT_PRODUCTION=true`` with ``EMIT_AGENT_CGROUP_ROOTS`` the agents' slice
  and ``EMIT_SANDBOX_CGROUP_ROOTS`` the sandboxes' slice, its source id from
  ``print-source-id``, sending to the ``ebpf`` group (variant h: the agent group, with its
  token).
- **agent**: a container (``--cgroup-parent fabric-agents.slice``, its own pid namespace,
  host network, the harness's uid with the Docker socket's group, seccomp and AppArmor
  unconfined for bwrap's user namespace) from an image the harness builds once (python,
  bubblewrap, curl, the static docker CLI, the SDK with the E2B extra), in node mode as
  in the replay. Step 8 is a real ``docker run -d --cgroup-parent
  fabric-sandboxes.slice`` of a pinned image; step 9 calls the fixture E2B service on
  127.0.0.2, an address of its own; step 4 must be bwrap.

The content overlay's S3 backend is replaced by the file backend (the job runs no S3);
the rest of the content path (listener, token, binding, sealed queue) is WP4-09's.
"""

# The harness runs fixed, harness-owned command lines (docker, sudo, systemctl).
# ruff: noqa: S603, S607

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import production, scenario
from .expect import Checks, ProductionTruth
from .harness import DEFAULT_EMITTER, Options, _settled, _wait
from .node import REPO, free_port
from .production_harness import ProdRun, ProductionHarness
from .sink import Sink

COMPOSE = REPO / "deploy" / "compose"
CGROUP = Path("/sys/fs/cgroup")
SLICES = ("fabric-agents.slice", "fabric-sandboxes.slice")
AGENT_ROOT = CGROUP / "fabric.slice" / "fabric-agents.slice"
SANDBOX_ROOT = CGROUP / "fabric.slice" / "fabric-sandboxes.slice"
USERNS_SYSCTL = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
AGENT_IMAGE = "fabric-ar1-agent:production"
# Step 8's pinned image (spec 056 §6.2): busybox 1.37.0, by its index digest.
SANDBOX_IMAGE = (
    "busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
NODE_GID = 65532  # the distroless Node image's nonroot group
# The agent image: pinned python base, bubblewrap and curl, the static docker CLI (step 8
# talks to the runner's daemon through the mounted socket) and this checkout's SDK.
DOCKER_CLI = (
    "docker:27.5.1-cli@sha256:851f91d241214e7c6db86513b270d58776379aacc5eb9c4a87e5b47115e3065c"
)
PYTHON_BASE = "python:3.12-slim-bookworm@sha256:" + (
    "e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337"
)
AGENT_DOCKERFILE = f"""\
FROM {DOCKER_CLI} AS cli
FROM {PYTHON_BASE}
COPY --from=cli /usr/local/bin/docker /usr/local/bin/docker
RUN apt-get update \\
 && apt-get install -y --no-install-recommends bubblewrap curl \\
 && rm -rf /var/lib/apt/lists/*
COPY sdk /src/sdk
RUN pip install --no-cache-dir "/src/sdk[otlp,hooks-sandbox-e2b]" "openai>=3.26.1" \\
    opentelemetry-exporter-otlp-proto-grpc
"""


def _sudo(*argv: str, check: bool = True, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["sudo", "-n", *argv], check=check, capture_output=True, text=True,
                          timeout=timeout)  # fmt: skip


def _run(*argv: str, check: bool = True, timeout: float = 900, **kw: Any
         ) -> subprocess.CompletedProcess[str]:  # fmt: skip
    return subprocess.run(list(argv), check=check, capture_output=True, text=True,
                          timeout=timeout, **kw)  # fmt: skip


class LiveError(SystemExit):
    """A live precondition failed: the job fails (never skips)."""


def preflight(emitter: Path) -> None:
    """§6.2: Linux, cgroup v2, Docker on the systemd driver, sudo, the emitter built."""
    if sys.platform != "linux" or not (CGROUP / "cgroup.controllers").exists():
        raise LiveError("AR-1 production live needs Linux with cgroup v2")
    driver = _run("docker", "info", "--format", "{{.CgroupDriver}}").stdout.strip()
    if driver != "systemd":
        raise LiveError(
            f"AR-1 production live needs Docker's systemd cgroup driver, not {driver!r}"
        )
    if _sudo("true", check=False).returncode != 0:
        raise LiveError("AR-1 production live needs passwordless sudo")
    if not emitter.is_file():
        raise LiveError(f"the eBPF emitter is not built: {emitter}")


def install_slices() -> None:
    for name in SLICES:
        _sudo("sh", "-c", f"printf '[Slice]\\n' > /run/systemd/system/{name}")
    _sudo("systemctl", "daemon-reload")
    for name in SLICES:
        _sudo("systemctl", "start", name)
    for path in (AGENT_ROOT, SANDBOX_ROOT):
        if not path.is_dir():
            raise LiveError(f"the slice did not appear: {path}")


@contextlib.contextmanager
def userns_allowed() -> Any:
    """bwrap needs unprivileged user namespaces: relax the AppArmor restriction for the
    run when the runner sets it, and restore it."""
    before = USERNS_SYSCTL.read_text().strip() if USERNS_SYSCTL.exists() else None
    if before == "1":
        _sudo("sysctl", "-w", "kernel.apparmor_restrict_unprivileged_userns=0")
    try:
        yield
    finally:
        if before == "1":
            _sudo("sysctl", "-w", "kernel.apparmor_restrict_unprivileged_userns=1", check=False)


def build_agent_image(directory: Path) -> None:
    """The agent image: python, bubblewrap, curl and this checkout's SDK (with E2B)."""
    context = directory / "agent-image"
    shutil.rmtree(context, ignore_errors=True)
    shutil.copytree(
        REPO / "sdk" / "python",
        context / "sdk",
        ignore=shutil.ignore_patterns(".venv", "__pycache__", ".pytest_cache", ".mypy_cache",
                                      ".ruff_cache", "htmlcov", "dist", "build"),
    )  # fmt: skip
    (context / "Dockerfile").write_text(AGENT_DOCKERFILE)
    _run("docker", "build", "-q", "-t", AGENT_IMAGE, str(context), timeout=1800)


class ComposeNode:
    """The production-profile Node from the Compose overlays (see the module docstring)."""

    def __init__(self, directory: Path, material: production.Material, sink_port: int,
                 sources: Mapping[str, str]) -> None:  # fmt: skip
        self.directory = directory
        self.project = f"ar1-{os.getpid()}-{directory.name}"
        self.ports = {
            k: free_port() for k in ("grpc", "http", "content", "ebpf", "health", "metrics")
        }
        secrets = directory / "node-secrets"
        tls = secrets / "tls"
        _sudo("install", "-d", "-m", "0755", str(secrets), str(tls))
        for name, source in (("agent.token", material.tokens["agent"]),
                             ("ebpf.token", material.tokens["ebpf"]),
                             ("content.key", material.content_key)):  # fmt: skip
            _sudo("install", "-o", "root", "-g", str(NODE_GID), "-m", "0440", str(source),
                  str(secrets / name))  # fmt: skip
        for name, source, mode in (("server.crt", material.server_cert, "0444"),
                                   ("server.key", material.server_key, "0440"),
                                   ("ca.crt", material.ca, "0444")):  # fmt: skip
            _sudo("install", "-o", "root", "-g", str(NODE_GID), "-m", mode, str(source),
                  str(tls / name))  # fmt: skip
        trust = directory / "ar1-export-ca.yaml"
        trust.write_text(
            "exporters:\n  otlp_http/fabric:\n    tls:\n"
            "      ca_file: /run/fabric-node/tls/ca.crt\n"
        )
        content = directory / "ar1-content-file.yaml"
        content.write_text(
            "exporters:\n  fabriccontent/agent:\n    backend: file\n    file:\n"
            "      directory: /var/lib/fabric-node/content\n"
            "      encryption_key_file: /run/secrets/fabric_content_key\n"
        )
        self.content_root = directory / "node-content"
        _sudo("install", "-d", "-m", "0700", "-o", str(NODE_GID), "-g", str(NODE_GID),
              str(self.content_root))  # fmt: skip
        override = directory / "ar1-compose.override.json"
        service: dict[str, Any] = {
            "command": ["--config=/etc/fabric-node/collector-production-groups.yaml",
                        "--config=/etc/fabric-node/collector-production-groups-content.yaml",
                        "--config=/etc/fabric-node/ar1-content-file.yaml",
                        "--config=/etc/fabric-node/ar1-export-ca.yaml"],
            "extra_hosts": ["host.docker.internal:host-gateway"],
            "volumes": [f"{trust}:/etc/fabric-node/ar1-export-ca.yaml:ro",
                        f"{content}:/etc/fabric-node/ar1-content-file.yaml:ro",
                        f"{self.content_root}:/var/lib/fabric-node/content"],
        }  # fmt: skip
        # AR1_NODE_IMAGE: a Node image built from this checkout already (the job builds
        # it once); otherwise Compose builds it, as `make up-prod-groups` does.
        self.prebuilt = os.environ.get("AR1_NODE_IMAGE", "")
        if self.prebuilt:
            service["pull_policy"] = "never"
        override.write_text(json.dumps({"services": {"fabric-node": service}}, indent=2))
        self.env = {
            **os.environ,
            "COMPOSE_PROJECT_NAME": self.project,
            "FABRIC_NODE_IMAGE": self.prebuilt or "fabric/node:ar1-production",
            "FABRIC_EXPORT_ENDPOINT": f"https://host.docker.internal:{sink_port}",
            "FABRIC_EXPORT_AUTH_HEADER": f"Bearer {material.token('sink')}",
            "FABRIC_TENANT_ID": scenario.TENANT,
            "FABRIC_SOURCE_ID": sources["agent"],
            "FABRIC_AGENT_SOURCE_ID": sources["agent"],
            "FABRIC_EBPF_SOURCE_ID": sources["ebpf"],
            "FABRIC_INGRESS_TOKEN_FILE": str(secrets / "agent.token"),
            "FABRIC_EBPF_TOKEN_FILE": str(secrets / "ebpf.token"),
            "FABRIC_INGRESS_TLS_DIR": str(tls),
            "FABRIC_CONTENT_KEY_FILE": str(secrets / "content.key"),
            "FABRIC_CONTENT_S3_BUCKET": "ar1-unused",  # the file backend replaces S3
            "FABRIC_CONTENT_S3_REGION": "local",
            "FABRIC_OTLP_CONTENT_PORT": str(self.ports["content"]),
            "FABRIC_BIND_ADDR": "127.0.0.1",
            "FABRIC_OTLP_GRPC_PORT": str(self.ports["grpc"]),
            "FABRIC_OTLP_HTTP_PORT": str(self.ports["http"]),
            "FABRIC_EBPF_GRPC_PORT": str(self.ports["ebpf"]),
            "FABRIC_HEALTH_PORT": str(self.ports["health"]),
            "FABRIC_METRICS_PORT": str(self.ports["metrics"]),
        }
        overlays = ("docker-compose.yml", "docker-compose.production.yml",
                    "docker-compose.host-ingress.yml", "docker-compose.host-ingress-content.yml",
                    str(override))  # fmt: skip
        self.files = [arg for name in overlays for arg in ("-f", name)]

    def compose(self, *args: str, check: bool = True, timeout: float = 1800
                ) -> subprocess.CompletedProcess[str]:  # fmt: skip
        return _run("docker", "compose", *self.files, *args, cwd=COMPOSE, env=self.env,
                    check=check, timeout=timeout)  # fmt: skip

    def url(self, group: str, *, path: str = "") -> str:
        if group == "agent":
            return f"https://127.0.0.1:{self.ports['http']}{path}"
        if group == "content":
            return f"https://127.0.0.1:{self.ports['content']}{path}"
        if group == "ebpf":  # gRPC only: the agent then exports with OTLP/gRPC (variant h)
            return f"https://127.0.0.1:{self.ports['ebpf']}"
        raise ValueError(f"no listener for group {group!r} live")

    def grpc(self, group: str) -> str:
        return f"127.0.0.1:{self.ports['grpc' if group == 'agent' else 'ebpf']}"

    def start(self) -> ComposeNode:
        build = [] if self.prebuilt else ["--build"]
        done = self.compose("up", "-d", *build, "--wait", check=False)
        if done.returncode != 0:
            self.save_logs()
            raise RuntimeError(f"compose up failed: {done.stderr[-1500:]}")
        return self

    def content_readable(self) -> None:
        """The Node (uid 65532) writes the sealed content store; let the harness read it."""
        _sudo("chmod", "-R", "a+rX", str(self.content_root), check=False)

    def save_logs(self) -> None:
        logs = self.compose("logs", "--no-color", "fabric-node", check=False, timeout=120)
        (self.directory / "node.log").write_text(logs.stdout + logs.stderr)

    def stop(self) -> None:
        self.save_logs()
        self.compose("down", "-v", "--timeout", "30", check=False, timeout=300)
        _sudo("chown", "-R", f"{os.getuid()}:{os.getgid()}", str(self.content_root), check=False)


class Emitter:
    """The eBPF emitter in production mode, as root, for one variant."""

    def __init__(self, binary: Path, directory: Path, material: production.Material,
                 endpoint: str, token: Path) -> None:  # fmt: skip
        self.binary, self.directory = binary, directory
        self.state = directory / "sensor-state" / "ebpf"
        self.keys = directory / "sensor-keys"
        self.log = directory / "emitter.log"
        _sudo("install", "-d", "-m", "0700", "-o", "root", str(self.state), str(self.keys))
        keys = (("id.key", material.id_key), ("state.key", material.state_keys["ebpf"]),
                ("token", token), ("ca.crt", material.ca))  # fmt: skip
        for name, source in keys:
            _sudo("install", "-o", "root", "-m", "0400", str(source), str(self.keys / name))
        self.env = [
            "EMIT_PRODUCTION=true",
            f"EMIT_TENANT_ID={scenario.TENANT}",
            f"EMIT_SOURCE_LABEL={production.EBPF_SOURCE_LABEL}",
            f"EMIT_HOST_LABEL={scenario.HOST_LABEL}",
            f"EMIT_ID_KEY_FILE={self.keys / 'id.key'}",
            f"EMIT_STATE_KEY_FILE={self.keys / 'state.key'}",
            f"EMIT_STATE_DIR={self.state}",
            f"EMIT_AGENT_CGROUP_ROOTS={AGENT_ROOT}",
            f"EMIT_SANDBOX_CGROUP_ROOTS={SANDBOX_ROOT}",
            f"EMIT_ENDPOINT={endpoint}",
            f"EMIT_BEARER_TOKEN_FILE={self.keys / 'token'}",
            f"EMIT_TLS_CA_FILE={self.keys / 'ca.crt'}",
            "EMIT_EXEC=true",
            "EMIT_CONNECT=true",
            "EMIT_FILE_ACCESS=false",
            "EMIT_DEDUPE_WINDOW=0",
            "EMIT_HEARTBEAT_INTERVAL=1s",
        ]
        self.process: subprocess.Popen[bytes] | None = None

    def source_id(self) -> str:
        return _sudo("env", *self.env, str(self.binary), "print-source-id").stdout.strip()

    def start(self, timeout_s: float = 60) -> Emitter:
        log = self.log.open("ab")
        self.process = subprocess.Popen(["sudo", "-n", "env", *self.env, str(self.binary)],
                                        stdout=log, stderr=subprocess.STDOUT)  # fmt: skip
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"the emitter exited: {self.log.read_text()[-1500:]}")
            if b"bpf loaded" in self.log.read_bytes():
                return self
            time.sleep(0.2)
        raise RuntimeError("the emitter did not load its programs; see emitter.log")

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.process.wait(timeout=60)
        self.process = None
        _sudo("chown", "-R", f"{os.getuid()}:{os.getgid()}", str(self.directory), check=False)


class LiveProductionHarness(ProductionHarness):
    live = True
    host_groups = ("ebpf",)  # one sensor live; the quiet node is the replay's
    cert_hosts = ("host.docker.internal",)  # the sink, as the Node's container reaches it
    node: ComposeNode

    def __init__(self, options: Options) -> None:
        emitter = options.emitter if options.emitter != DEFAULT_EMITTER else DEFAULT_EMITTER
        preflight(emitter)
        super().__init__(options)
        self.emitter = emitter
        self.sandbox = "bwrap"  # refused otherwise: the run records the branch and checks it
        install_slices()
        build_agent_image(options.out)
        _run("docker", "pull", "-q", SANDBOX_IMAGE, timeout=600)
        probe = Emitter(emitter, options.out / "probe", self.material, "127.0.0.1:9",
                        self.material.tokens["ebpf"])  # fmt: skip
        printed = probe.source_id()
        probe.stop()  # never started: hands its root-owned key directory back
        if printed != self.sources["ebpf"]:
            raise LiveError("print-source-id disagrees with the label pseudonym of the source")
        self._userns = userns_allowed()
        self._userns.__enter__()

    def run(self) -> dict[str, Any]:
        try:
            result = super().run()
        finally:
            self._userns.__exit__(None, None, None)
        result["sensor"] = "ebpf"
        (self.o.out / "ar1-result.json").write_text(json.dumps(result, indent=2))
        return result

    # -- the steps the replay harness leaves open ----------------------------------------

    def _sink(self, directory: Path) -> Sink:
        return Sink(directory / "sink", tls=(self.material.server_cert, self.material.server_key),
                    token=self.material.token("sink"), host="0.0.0.0")  # noqa: S104 - the Node's container reaches it  # fmt: skip

    def _node(self, directory: Path, sink: Sink) -> Any:
        self.node = ComposeNode(directory, self.material, sink.port, self.sources)
        return self.node

    def _sensor(self, directory: Path, node: Any, host_to: str) -> Any:
        return Emitter(self.emitter, directory, self.material, node.grpc(host_to),
                       self.material.tokens[host_to]).start()  # fmt: skip

    def _extra_env(self, container: str) -> dict[str, str]:
        del container
        return {"AR1_CONTAINER_IMAGE": SANDBOX_IMAGE, "AR1_SANDBOX": "bwrap"}

    def _launch(self, config: scenario.AgentConfig, env: Mapping[str, str]) -> scenario.AgentRun:
        """The agent in its container: its own pid namespace, the agents' slice."""
        name = f"ar1-agent-{os.getpid()}-{config.workdir.parent.name}"
        # The image's own site-packages hold the SDK: the host's PYTHONPATH is not passed.
        prefixes = ("FABRIC_", "OTEL_", "AR1_", "E2B_")
        passed = {k: v for k, v in env.items() if k.startswith(prefixes)}
        if passed.get("OTEL_EXPORTER_OTLP_ENDPOINT") == self.node.url("ebpf"):
            passed["OTEL_EXPORTER_OTLP_PROTOCOL"] = "grpc"  # the host group listens on gRPC
        autoload = _run("docker", "run", "--rm", AGENT_IMAGE, "python", "-m", "fabric.wire",
                        "--print-autoload-path").stdout.strip()  # fmt: skip
        if "FABRIC_WIRE_AUTOLOAD" in passed:
            passed["PYTHONPATH"] = autoload
        ar1 = Path(__file__).resolve().parent
        mounts = {str(ar1): "ro", str(self.o.out / "data"): "ro",
                  str(self.material.directory): "ro", str(config.workdir): "rw"}  # fmt: skip
        if config.policy is not None:
            mounts[str(config.policy)] = "ro"
        socket_gid = os.stat("/var/run/docker.sock").st_gid
        argv = ["docker", "run", "--rm", "-i", "--name", name,
                "--cgroup-parent", SLICES[0], "--network", "host",
                # Not root: bwrap then makes its own user namespace (as root without
                # CAP_SYS_ADMIN it cannot unshare anything).
                "--user", f"{os.getuid()}:{os.getgid()}", "--group-add", str(socket_gid),
                "-e", "HOME=/tmp",
                "--security-opt", "seccomp=unconfined", "--security-opt", "apparmor=unconfined",
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
                "-w", str(config.workdir)]  # fmt: skip
        for path, mode in mounts.items():
            argv += ["-v", f"{path}:{path}:{mode}"]
        for key, value in passed.items():
            argv += ["-e", f"{key}={value}"]
        argv += [AGENT_IMAGE, "python", str(ar1 / "agent.py")]
        started = time.monotonic()
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)  # fmt: skip
        if process.stdin is not None:
            process.stdin.close()
        run = scenario.finish_agent(config, process, started, timeout_s=300)
        _sudo("chown", "-R", f"{os.getuid()}:{os.getgid()}", str(config.workdir), check=False)
        return run

    def _sensed(self, run: ProdRun, sensor: Any, sink: Sink, *, linked: bool) -> ProductionTruth:
        """Stop the emitter after its last batch; live truth is judged by shape."""
        time.sleep(3.0)  # heartbeats past the run's end (EMIT_HEARTBEAT_INTERVAL=1s)
        sensor.stop()
        _wait(_settled(sink), 60, f"{run.name}: the host records")
        del linked
        # The report lists no pid namespace or peer: shape checks read them from the
        # host spans the sink holds, by event id.
        attributes = {
            str(r["attributes"]["fabric.event_id"]): r["attributes"]
            for r in sink.rows()
            if r.get("kind") == "span"
            and "fabric.sensor.event_class" in r.get("attributes", {})
            and "fabric.event_id" in r["attributes"]
        }
        return ProductionTruth(
            agent_pid=run.agent_pid,
            exact=False,
            certain=True,
            host_attributes=attributes,
            uncalled_port=run.fixture_port,
        )

    # -- live-only checks ---------------------------------------------------------------

    def variant_base(self) -> None:
        super().variant_base()
        run, checks = self.runs["base"], self.checks[-1]
        self._sandbox_branch(checks, run)

    def _sandbox_branch(self, checks: Checks, run: ProdRun) -> None:
        summary = run.agent.summary
        checks.equal("step 4 ran in bwrap (no python -I fallback)", summary.get("sandbox"), "bwrap")
        t4 = [t for t in summary.get("tools", ()) if t.get("tool") == "run_python"]
        checks.equal("step 4's bwrap exited 0", [t.get("exit_code") for t in t4], [0])
