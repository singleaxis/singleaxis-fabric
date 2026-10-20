# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The production Fabric Node for the chaos harness: the shipped Compose overlays
(``docker-compose.yml`` + ``.production.yml`` + ``.content.yml``, optionally
``.s3-eval.yml``), their documented TLS edits, a bound source, a sealed content queue and
store, an HTTPS fsync sink as the customer destination. Built from the e2e helpers in
``scripts/tests/_wire_capture_common.py`` (no pytest), plus fault controls:

- container lifecycle: ``stop``/``start``/``kill``/``restart``/``pause``/``unpause``;
- network: ``netem(...)`` and ``iptables(...)`` from a sidecar sharing the Node's network
  namespace (``nicolaka/netshoot``, pinned by digest);
- disk: optional size-limited tmpfs for the content queue and the content store;
- observation: Prometheus metrics, ``docker stats`` memory, sealed store snapshots,
  ``fabric.reconstruct`` on trusted readback.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / "scripts" / "tests"))

import _wire_capture_common  # noqa: E402
from _wire_capture_common import (  # noqa: E402
    COMPOSE_DIR,
    Sink,
    capture_protection,
    content_config_with_tls,
    free_port,
    production_config_with_tls,
    pseudonym,
    wait_until,
    write_tls,
)

# The e2e sink handshakes TLS on its accept thread; one stalled handshake under netem
# wedges it. Use the chaos wrapper (same handler, deferred handshake, timeouts).
_wire_capture_common.SINK = HERE / "sink.py"

CHAOS_NETWORK = os.environ.get("CHAOS_NETWORK", "fabric-chaos-net")
NODE_IMAGE = os.environ.get("CHAOS_NODE_IMAGE", "fabric/node:chaos")
# nicolaka/netshoot (tc, iptables) pinned by digest for repeatable network faults.
NETSHOOT = os.environ.get(
    "CHAOS_NETSHOOT_IMAGE",
    "nicolaka/netshoot:v0.13@sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b",
)
NODE_CONTENT_DIR = "/var/lib/fabric-node/content"
NODE_MAGIC = b"FABRIC-NODE-CONTENT-1\n"
MIB = 1024 * 1024


class Node:
    """One production Node project; every secret and label is per instance."""

    def __init__(
        self, root: Path, *, mark: str, backend: str = "file",
        queue_tmpfs_mib: int | None = None, store_tmpfs_mib: int | None = None,
        content_max_body: int | None = None, tenant: str = "chaos-tenant",
    ) -> None:  # fmt: skip
        self.root, self.mark, self.backend, self.tenant = root, mark, backend, tenant
        root.mkdir(parents=True, exist_ok=True)
        self.project = f"fabric-chaos-{uuid.uuid4().hex[:10]}"
        (root / "project.txt").write_text(self.project)
        self.tls = root / "tls"
        names = ("otlp_http", "otlp_grpc", "otlp_content", "health", "metrics", "store")
        self.ports = {name: free_port() for name in names}
        self.ingress_token = f"{mark}_ingress_token_0123456789abcdef"
        self.egress_auth = f"Bearer {mark}_egress_token"
        self.id_key = f"{mark}_idkey_0123456789"
        self.source = f"{mark}-src"
        self.content_key = os.urandom(32)
        self.spool_key = os.urandom(32)
        secrets = root / "secrets"
        secrets.mkdir(exist_ok=True)
        self.token_file = secrets / "ingress.token"
        self.token_file.write_text(self.ingress_token, "utf-8")
        self.token_file.chmod(0o640)
        self.key_file = secrets / "content.key"
        self.key_file.write_bytes(base64.b64encode(self.content_key) + b"\n")
        self.key_file.chmod(0o640)
        write_tls(self.tls)
        self.sink = Sink(root / "sink", self.tls, self.egress_auth, id_key=self.id_key)
        self.config = root / "collector-production.yaml"
        production_config_with_tls(self.config)
        self.content_config = root / "collector-content.yaml"
        content_config_with_tls(self.content_config)
        if content_max_body is not None:
            text = self.content_config.read_text("utf-8")
            text = text.replace("\n  fabriccontent:\n",
                                f"\n  fabriccontent:\n    max_body_bytes: {content_max_body}\n")
            self.content_config.write_text(text, "utf-8")
        self.s3_secrets = {
            "root": ("fabric-chaos-root", f"{mark}_rootpw"),
            "node": ("fabric-node-writer", f"{mark}_nodesecret"),
            "reader": ("fabric-reader", f"{mark}_readersecret"),
        }
        override = [
            "services:", "  fabric-node:", "    pull_policy: never",
            f'    user: "65532:{os.getgid()}"', "    volumes:",
            f"      - {self.config}:/etc/fabric-node/collector-production.yaml:ro",
            f"      - {self.content_config}:/etc/fabric-node/collector-content.yaml:ro",
        ]  # fmt: skip
        if backend == "s3":
            s3prod = COMPOSE_DIR / "collector-config" / "collector-content-s3-production.yaml"
            override += [f"      - {s3prod}:/etc/fabric-node/collector-content-s3-production.yaml:ro"]
        override += ["    extra_hosts:", '      - "host.docker.internal:host-gateway"']
        if backend == "s3":
            override += [
                "    command:",
                "      - --config=/etc/fabric-node/collector-production.yaml",
                "      - --config=/etc/fabric-node/collector-content.yaml",
                "      - --config=/etc/fabric-node/collector-content-s3.yaml",
                "      - --config=/etc/fabric-node/collector-content-s3-production.yaml",
            ]
        tmpfs = []
        if queue_tmpfs_mib:
            tmpfs.append(f"      - /var/lib/fabric-node/content-queue:size={queue_tmpfs_mib}m,"
                         f"uid=65532,gid={os.getgid()},mode=0700")
        if store_tmpfs_mib:
            tmpfs.append(f"      - {NODE_CONTENT_DIR}:size={store_tmpfs_mib}m,"
                         f"uid=65532,gid={os.getgid()},mode=0700")
        if tmpfs:
            override += ["    tmpfs:", "      - /tmp", *tmpfs]
        # One shared, pre-created bridge for every chaos stack (Docker address pools may be
        # exhausted by other projects). Service DNS names collide on a shared network, so
        # chaos stacks run one at a time.
        override += ["networks:", "  fabric-node:", f"    name: {CHAOS_NETWORK}",
                     "    external: true"]  # fmt: skip
        self.override = root / "compose.override.yml"
        self.override.write_text("\n".join(override) + "\n", "utf-8")
        if tmpfs:  # a tmpfs replaces the named volume at that target: drop the volume mount
            self._strip_volume_targets(queue_tmpfs_mib, store_tmpfs_mib)
        (root / "empty.env").write_text("", "utf-8")
        self.env = {
            **{k: v for k, v in os.environ.items() if not k.startswith(("FABRIC_", "AWS_"))},
            "FABRIC_NODE_IMAGE": NODE_IMAGE, "FABRIC_BIND_ADDR": "127.0.0.1",
            "FABRIC_OTLP_HTTP_PORT": str(self.ports["otlp_http"]),
            "FABRIC_OTLP_GRPC_PORT": str(self.ports["otlp_grpc"]),
            "FABRIC_OTLP_CONTENT_PORT": str(self.ports["otlp_content"]),
            "FABRIC_HEALTH_PORT": str(self.ports["health"]),
            "FABRIC_METRICS_PORT": str(self.ports["metrics"]),
            "FABRIC_INGRESS_TOKEN_FILE": str(self.token_file),
            "FABRIC_INGRESS_TLS_DIR": str(self.tls),
            "FABRIC_EXPORT_ENDPOINT": self.sink.endpoint,
            "FABRIC_EXPORT_AUTH_HEADER": self.egress_auth,
            "FABRIC_TENANT_ID": tenant,
            "FABRIC_SOURCE_ID": pseudonym("s-", self.source, self.id_key),
            "FABRIC_CONTENT_KEY_FILE": str(self.key_file),
            "FABRIC_S3_EVAL_PORT": str(self.ports["store"]),
            "FABRIC_S3_EVAL_BUCKET": "fabric-content",
            "FABRIC_S3_EVAL_ROOT_ACCESS_KEY": self.s3_secrets["root"][0],
            "FABRIC_S3_EVAL_ROOT_SECRET_KEY": self.s3_secrets["root"][1],
            "FABRIC_S3_EVAL_NODE_ACCESS_KEY": self.s3_secrets["node"][0],
            "FABRIC_S3_EVAL_NODE_SECRET_KEY": self.s3_secrets["node"][1],
            "FABRIC_S3_EVAL_READER_ACCESS_KEY": self.s3_secrets["reader"][0],
            "FABRIC_S3_EVAL_READER_SECRET_KEY": self.s3_secrets["reader"][1],
            "FABRIC_S3_EVAL_SSE_KEK": uuid.uuid4().hex + uuid.uuid4().hex,
        }  # fmt: skip
        self.sealed: dict[Path, Path] = {}
        self.reports: list[str] = []

    def _strip_volume_targets(self, queue: int | None, store: int | None) -> None:
        """Compose merges the content overlay's named-volume mounts; a tmpfs on the same
        target conflicts, so a small extra overlay remaps those volumes to unused paths."""
        lines = ["services:", "  fabric-node:", "    volumes: !override",
                 f"      - {self.config}:/etc/fabric-node/collector-production.yaml:ro",
                 f"      - {self.content_config}:/etc/fabric-node/collector-content.yaml:ro",
                 "      - fabric-queue:/var/lib/fabric-node/queue",
                 "      - ${FABRIC_INGRESS_TLS_DIR:-./tls}:/run/fabric-node/tls:ro"]  # fmt: skip
        if not queue:
            lines.append("      - fabric-content-queue:/var/lib/fabric-node/content-queue")
        if not store:
            lines.append(f"      - fabric-content:{NODE_CONTENT_DIR}")
        self.tmpfs_override = self.root / "compose.tmpfs.yml"
        self.tmpfs_override.write_text("\n".join(lines) + "\n", "utf-8")

    # -- compose ----------------------------------------------------------------

    def files(self) -> list[str]:
        names = ["docker-compose.yml", "docker-compose.production.yml",
                 "docker-compose.content.yml"]  # fmt: skip
        if self.backend == "s3":
            names.append("docker-compose.s3-eval.yml")
        out = [arg for name in names for arg in ("-f", str(COMPOSE_DIR / name))]
        out += ["-f", str(self.override)]
        if getattr(self, "tmpfs_override", None):
            out += ["-f", str(self.tmpfs_override)]
        return out

    def compose(self, *args: str, check: bool = True,
                timeout: float = 900) -> subprocess.CompletedProcess[str]:  # fmt: skip
        command = ["docker", "compose", "-p", self.project, "--project-directory",
                   str(COMPOSE_DIR), "--env-file", str(self.root / "empty.env"),
                   *self.files(), *args]  # fmt: skip
        return subprocess.run(command, cwd=COMPOSE_DIR, env=self.env, check=check,
                              capture_output=True, text=True, timeout=timeout)  # fmt: skip

    def up(self) -> None:
        if self.docker("network", "inspect", CHAOS_NETWORK, check=False).returncode != 0:
            self.docker("network", "create", "--driver", "bridge", CHAOS_NETWORK)
        self.sink.start()
        up = self.compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "180",
                          check=False)  # fmt: skip
        if up.returncode != 0:
            raise RuntimeError(f"compose up failed:\n{up.stdout}\n{up.stderr}\n"
                               f"{self.logs()[-4000:]}")  # fmt: skip
        self.wait_health()

    def down(self) -> None:
        self.compose("down", "-v", "--remove-orphans", check=False)
        self.sink.stop()

    def container(self, service: str = "fabric-node") -> str:
        return self.compose("ps", "-a", "-q", service).stdout.strip()

    def docker(self, *args: str, check: bool = True,
               timeout: float = 300) -> subprocess.CompletedProcess[str]:  # fmt: skip
        return subprocess.run(["docker", *args], check=check, capture_output=True,
                              text=True, timeout=timeout)  # fmt: skip

    def logs(self, service: str = "fabric-node") -> str:
        result = self.compose("logs", "--no-color", service, check=False)
        return result.stdout + result.stderr

    def healthy(self) -> bool:
        try:
            url = f"http://127.0.0.1:{self.ports['health']}/"
            with urllib.request.urlopen(url, timeout=2) as response:
                return bool(response.status == 200)
        except (OSError, ValueError):
            return False

    def wait_health(self, timeout_s: float = 120.0) -> None:
        wait_until(self.healthy, timeout_s,
                   lambda: f"Node never became healthy:\n{self.logs()[-4000:]}")  # fmt: skip

    # -- faults -------------------------------------------------------------------

    def kill(self, service: str = "fabric-node") -> None:
        self.docker("kill", "-s", "KILL", self.container(service))

    def stop(self, service: str = "fabric-node") -> None:
        self.docker("stop", "-t", "60", self.container(service))

    def start(self, service: str = "fabric-node") -> None:
        self.docker("start", self.container(service))
        if service == "fabric-node":
            self.wait_health()

    def restart(self, service: str = "fabric-node") -> None:
        self.docker("restart", "-t", "60", self.container(service))
        if service == "fabric-node":
            self.wait_health()

    def pause(self, service: str = "fabric-node") -> None:
        self.docker("pause", self.container(service))

    def unpause(self, service: str = "fabric-node") -> None:
        self.docker("unpause", self.container(service))

    def netshoot(self, script: str, service: str = "fabric-node",
                 check: bool = True) -> subprocess.CompletedProcess[str]:  # fmt: skip
        """Run ``script`` (sh) in the network namespace of ``service``."""
        return self.docker("run", "--rm", "--net", f"container:{self.container(service)}",
                           "--cap-add", "NET_ADMIN", NETSHOOT, "sh", "-ec", script,
                           check=check)  # fmt: skip

    def resize_tmpfs(self, target: str, mib: int, service: str = "fabric-node") -> str:
        """Grow a size-limited tmpfs in place (``mount -o remount``) from a privileged
        sidecar in the container's mount namespace: clears a disk-full fault without a
        restart, so nothing already written there is lost."""
        pid = self.docker("inspect", "-f", "{{.State.Pid}}", self.container(service)).stdout.strip()
        # The Node image is distroless (no mount/df), so the sidecar's Python enters the
        # mount namespace with setns(2) and calls mount(2)/statvfs(3) itself.
        script = (
            "import ctypes,os,sys;libc=ctypes.CDLL(None,use_errno=True);"
            f"fd=os.open('/proc/{pid}/ns/mnt',os.O_RDONLY);"
            "assert libc.setns(fd,0)==0,os.strerror(ctypes.get_errno());"
            f"t=b'{target}';"
            f"r=libc.mount(b'tmpfs',t,b'tmpfs',32,b'size={mib}m');"  # MS_REMOUNT
            "e=ctypes.get_errno();st=os.statvfs(t);"
            "print('remount',r,os.strerror(e) if r else 'ok','size_mib',st.f_blocks*st.f_frsize>>20,"
            "'free_mib',st.f_bavail*st.f_frsize>>20)"
        )  # fmt: skip
        out = self.docker("run", "--rm", "--privileged", "--pid", "host", NETSHOOT,
                          "python3", "-c", script, check=False)  # fmt: skip
        return (out.stdout + out.stderr).strip()

    def netem(self, spec: str | None, service: str = "fabric-node") -> None:
        """``tc qdisc`` netem on the service's eth0 (``None`` clears it)."""
        if spec is None:
            self.netshoot("tc qdisc del dev eth0 root 2>/dev/null || true", service)
        else:
            self.netshoot(f"tc qdisc replace dev eth0 root netem {spec}", service)

    def iptables(self, rules: list[str], service: str = "fabric-node") -> None:
        self.netshoot("; ".join(f"iptables {r}" for r in rules), service)

    # -- observation ----------------------------------------------------------------

    def metrics(self) -> str:
        url = f"http://127.0.0.1:{self.ports['metrics']}/metrics"
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                return response.read().decode()
        except OSError:
            return ""

    def metric(self, name: str, **labels: str) -> float:
        total = 0.0
        for line in self.metrics().splitlines():
            if not line.startswith(name + "{") and not line.startswith(name + " "):
                continue
            if all(f'{k}="{v}"' in line for k, v in labels.items()):
                total += float(line.rsplit(" ", 1)[1])
        return total

    def queue_sizes(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for line in self.metrics().splitlines():
            if line.startswith("otelcol_exporter_queue_size{"):
                found = re.search(r'exporter="([^"]+)"', line)
                if found:
                    out[found.group(1)] = float(line.rsplit(" ", 1)[1])
        return out

    def mem_mib(self) -> float:
        out = self.docker("stats", "--no-stream", "--format", "{{.MemUsage}}",
                          self.container(), check=False).stdout.strip()  # fmt: skip
        value = out.split("/")[0].strip()
        found = re.match(r"([0-9.]+)\s*([KMG]i?B)", value)
        if not found:
            return -1.0
        scale = {"KiB": 1 / 1024, "MiB": 1, "GiB": 1024, "KB": 1 / 1024, "MB": 1, "GB": 1024}
        return float(found.group(1)) * scale.get(found.group(2), 1)

    def cgroup_mem(self, service: str = "fabric-node") -> dict[str, int]:
        """The container cgroup's ``memory.stat`` anon/file split (``docker stats`` counts
        active page cache too, so growth there is not necessarily a heap leak)."""
        pid = self.docker("inspect", "-f", "{{.State.Pid}}", self.container(service),
                          check=False).stdout.strip()  # fmt: skip
        out = self.docker("run", "--rm", "--privileged", "--pid", "host", NETSHOOT, "sh", "-c",
                          f"cat /proc/{pid}/root/sys/fs/cgroup/memory.stat", check=False).stdout
        keys = ("anon", "file", "active_file", "inactive_file", "shmem")
        return {k: int(v) for k, v in (ln.split() for ln in out.splitlines() if ln.strip())
                if k in keys}  # fmt: skip

    def volume_bytes(self, path: str) -> int:
        """Apparent size of everything below ``path`` in the Node container (a probe that
        shares the container's volumes)."""
        out = self.docker("run", "--rm", "--volumes-from", self.container(), "--network",
                          "none", "alpine:latest", "sh", "-c",
                          f"du -sb {path} 2>/dev/null | cut -f1 || echo 0",
                          check=False).stdout.strip()  # fmt: skip
        try:
            return int(out.split()[0])
        except (ValueError, IndexError):
            return -1

    def grep_volumes(self, needles: list[str]) -> dict[str, list[str]]:
        """Files below the Node's queue, content queue and content directories holding
        any needle in clear (read-only probe)."""
        found: dict[str, list[str]] = {}
        for needle in needles:
            probe = self.docker("run", "--rm", "--volumes-from", self.container(),
                                "--network", "none", "alpine:latest", "grep", "-rlF", needle,
                                "/var/lib/fabric-node", check=False)  # fmt: skip
            hits = [h for h in probe.stdout.split() if h]
            if hits:
                found[needle] = hits
        return found

    def content_snapshot(self) -> Path:
        """A host copy of the content volume (file backend), with every Node envelope
        opened into a plain tree. The returned path is the plain tree; ``self.sealed[path]``
        is the sealed copy the ``fabric.reconstruct`` reader reads (it opens the envelopes
        itself with ``--content-key-file``). Also asserts each stored file IS sealed at
        rest (never plaintext)."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415

        sealed = self.root / f"sealed-{uuid.uuid4().hex[:8]}"
        self.compose("cp", f"fabric-node:{NODE_CONTENT_DIR}", str(sealed))
        plain = self.root / f"content-{uuid.uuid4().hex[:8]}"
        cipher = AESGCM(self.content_key)
        for path in sealed.rglob("*"):
            rel = path.relative_to(sealed).as_posix()
            target = plain / rel
            if path.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if path.name.startswith(".fabric-root-barrier"):
                continue
            data = path.read_bytes()
            if not data.startswith(NODE_MAGIC):
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)  # not sealed: a finding the caller can scan for
                continue
            aad = json.dumps(["fabric.node-content-envelope/v1", rel],
                             separators=(",", ":")).encode()  # fmt: skip
            body = cipher.decrypt(data[len(NODE_MAGIC):len(NODE_MAGIC) + 12],
                                  data[len(NODE_MAGIC) + 12:], aad)  # fmt: skip
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        self.sealed[plain] = sealed
        return plain

    def store_object_count(self) -> int:
        snap = self.content_snapshot()
        count = sum(1 for p in (snap / self.tenant / "evidence").glob("*") if p.is_file())
        shutil.rmtree(snap, ignore_errors=True)
        return count

    def reconstruct(self, store: Path | None = None, runs: list[str] | None = None,
                    extra: list[str] | None = None) -> tuple[int, dict[str, Any], str]:  # fmt: skip
        """``fabric.reconstruct`` on trusted readback (sink + sealed store)."""
        out = self.root / f"report-{uuid.uuid4().hex[:8]}.json"
        args = [sys.executable, "-m", "fabric.reconstruct", "--spans", str(self.sink.records),
                "--tenant", self.tenant, "--trusted-source", "--profile", "production",
                "--out", str(out)]  # fmt: skip
        env = {**{k: v for k, v in os.environ.items() if not k.startswith(("FABRIC_", "AWS_"))},
               "FABRIC_WIRE_ID_KEY": self.id_key}  # fmt: skip
        if self.backend == "s3":
            args += ["--store-uri", "s3://fabric-content/fabric/content/", "--s3-endpoint-url",
                     f"http://127.0.0.1:{self.ports['store']}", "--s3-region", "us-east-1",
                     "--s3-path-style"]  # fmt: skip
            key, secret = self.s3_secrets["reader"]
            env |= {"AWS_ACCESS_KEY_ID": key, "AWS_SECRET_ACCESS_KEY": secret,
                    "AWS_EC2_METADATA_DISABLED": "true", "AWS_CONFIG_FILE": os.devnull,
                    "AWS_SHARED_CREDENTIALS_FILE": os.devnull}  # fmt: skip
        else:
            store = store or self.content_snapshot()
            # The reader opens the Node envelopes itself: give it the sealed copy.
            sealed = self.sealed.get(store, store)
            args += ["--store-root", str(sealed), "--content-key-file", str(self.key_file)]
        for run in runs or ():
            args += ["--run", run]
        args += extra or []
        # Peak RSS of the reader is recorded too: on large, loss-heavy runs it can reach
        # gigabytes (the OS then SIGKILLs it, exit -9).
        args = ["/usr/bin/time", "-l", *args] if sys.platform == "darwin" else args
        result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=3600,
                                check=False)  # fmt: skip
        peak = re.search(r"(\d+)\s+maximum resident set size", result.stderr)
        self.reconstruct_peak_rss = int(peak.group(1)) if peak else None
        text = out.read_text("utf-8") if out.exists() else "{}"
        self.reports.append(text + result.stdout + result.stderr)
        return result.returncode, json.loads(text), result.stderr

    # -- agents -----------------------------------------------------------------------

    def agent_env(self, spool: Path, *, autoload: str, hooks: str | None = None,
                  mode: str = "retain_original", extra: dict[str, str] | None = None,
                  service: str = "chaos-agent") -> dict[str, str]:  # fmt: skip
        base = {k: v for k, v in os.environ.items()
                if not k.startswith(("FABRIC_", "OTEL_", "AWS_")) and k != "PYTHONPATH"}  # fmt: skip
        path = hooks or autoload  # the hooks directory replaces (and does) the autoload
        env = {
            **base, "PYTHONPATH": path, "FABRIC_WIRE_AUTOLOAD": "1",
            "FABRIC_TENANT_ID": self.tenant,
            "FABRIC_WIRE_CONTENT_ENDPOINT":
                f"https://127.0.0.1:{self.ports['otlp_content']}/v1/logs",
            "FABRIC_WIRE_SPOOL_DIR": str(spool), "FABRIC_WIRE_ID_KEY": self.id_key,
            "FABRIC_SOURCE_ID": self.source, "OTEL_SERVICE_NAME": service,
            "OTEL_EXPORTER_OTLP_ENDPOINT": f"https://127.0.0.1:{self.ports['otlp_http']}",
            "OTEL_EXPORTER_OTLP_HEADERS": "Authorization=Bearer%20" + self.ingress_token,
            "OTEL_EXPORTER_OTLP_CERTIFICATE": str(self.tls / "ca.crt"),
        }  # fmt: skip
        env |= capture_protection(self.root, self.tenant, self.spool_key, mode)
        env |= extra or {}
        return env


def autoload_dir() -> str:
    return subprocess.run([sys.executable, "-m", "fabric.wire", "--print-autoload-path"],
                          check=True, capture_output=True, text=True).stdout.strip()  # fmt: skip


def wait_for(condition: Any, timeout_s: float, step: float = 0.5) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(step)
    return bool(condition())
