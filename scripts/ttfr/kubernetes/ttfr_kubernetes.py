#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Time to first record on Kubernetes (spec 058 §3.1, §3.3 ``ttfr-kubernetes``, G4):
the Get started page for Kubernetes, executed as written against a kind cluster, timed,
and held to its 600 s budget.

Before the clock (cluster creation is excluded, §3.1; image builds are the build under
test, not the user's): a kind cluster whose node mounts ``<work>/project/
destination-export`` (where the test destination writes its span files); the Node, CLI,
host sensor and agent images built from this change and loaded into it; the customer's
destination, content store (behind a private CA), model and agent Deployment
(``fixtures.py``); the customer's ``destination.yaml`` in the project directory and the
workstation's AWS configuration for its store; and a fresh virtualenv on this machine.
Then the clock runs the page's marked blocks for path ``kubernetes`` verbatim
(``scripts/docs_as_tests/run.py``): the install, ``fabric up --kubernetes`` with the
``production-host-sensor`` preset, the namespace label and the pod annotation, and
``fabric verify --kubernetes``, which must exit 0 with ``corroboration: complete``.

The build under test reaches the page's commands the way a release does: ``pip``
resolves ``singleaxis-fabric`` from ``--wheel-dir`` through a loopback index
(``../local_index.py``; every other project from PyPI), and ``FABRIC_CHART`` points the
CLI at a copy of this tree's chart whose image values name the images loaded into the
cluster (a release's chart names its own digests). With ``--published`` neither is set.

    python3 scripts/ttfr/kubernetes/ttfr_kubernetes.py --node-image fabric-otelcol:e2e \\
        --cli-image fabric-cli:e2e --sensor-image fabric-host-emitter:e2e \\
        --agent-image fabric-agent:e2e --wheel-dir sdk/python/dist --out ttfr.json

Needs docker, kind, kubectl, helm and Python 3.11+ with PyYAML and ``cryptography``.
``--keep-cluster`` leaves the cluster (and ``<work>/kubeconfig``) for the E2 acceptance
script that runs after it (``charts/fabric/tests/kind/e2e-kubernetes.sh``).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
TTFR = HERE.parent
ROOT = TTFR.parents[1]
sys.path.insert(0, str(TTFR))

from ttfr import load_report, summarize, wait_file  # noqa: E402

sys.path.insert(0, str(HERE))
from fixtures import S3_HOST_PORT, S3_NODE_PORT  # noqa: E402

PAGE = ROOT / "docs" / "get-started" / "kubernetes.md"
RUNNER = ROOT / "scripts" / "docs_as_tests" / "run.py"
CHART = ROOT / "charts" / "fabric"
PIN = ROOT / "scripts" / "qualification" / "pin_kind_node_image.sh"
PATH_NAME = "kubernetes"
BUDGET_S = 600.0  # G4
PREFIX = "f058-ttfr-k8s"
#: A node image whose CNI (kindnet with network policies, kind v0.24 and later) enforces
#: NetworkPolicy, so the chart's default-deny policy is really in force (the audit's
#: emitter workaround is a regression test only where it is enforced). Pinned by digest.
KIND_NODE_IMAGE = "kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f"
RELEASE_NS = "fabric-system"
AGENT_NS = "agents"
EXPORT_IN_NODE = "/var/fabric-export"


class TtfrError(RuntimeError):
    """A prerequisite could not be set up (the clock never started)."""


def _sh(argv: Sequence[str], *, env: Mapping[str, str] | None = None, check: bool = True,
        timeout: float = 900, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:  # fmt: skip
    done = subprocess.run(  # noqa: S603 - the harness's own fixed tools
        list(argv), capture_output=True, text=True, check=False, timeout=timeout,
        env=None if env is None else dict(env), cwd=cwd,
    )  # fmt: skip
    if check and done.returncode != 0:
        raise TtfrError(f"{' '.join(argv[:5])}: {done.stderr.strip()[-1200:]}")
    return done


def canonical(image: str) -> str:
    """``docker.io/library/NAME:TAG`` for a short local name, as containerd lists it."""
    name, _, tag = image.rpartition(":")
    if "/" not in name:
        name = f"docker.io/library/{name}"
    elif "." not in name.split("/")[0] and ":" not in name.split("/")[0]:
        name = f"docker.io/{name}"
    return f"{name}:{tag}"


def create_cluster(name: str, work: Path, kubeconfig: Path, node_image: str) -> None:
    """The kind cluster, with the destination's export directory mounted from this
    machine so ``fabric verify --spans`` reads what the destination wrote."""
    export = work / "project" / "destination-export"
    export.mkdir(parents=True, exist_ok=True)
    export.chmod(
        0o777
    )  # the test destination runs as root in the node; the reader is us
    config = work / "kind.yaml"
    config.write_text(json.dumps({
        "kind": "Cluster", "apiVersion": "kind.x-k8s.io/v1alpha4",
        "nodes": [{"role": "control-plane",
                   "extraMounts": [{"hostPath": str(export), "containerPath": EXPORT_IN_NODE}],
                   # The customer's content store, reached from this workstation.
                   "extraPortMappings": [{"containerPort": S3_NODE_PORT,
                                          "hostPort": S3_HOST_PORT,
                                          "listenAddress": "127.0.0.1"}]}],
    }) + "\n", "utf-8")  # fmt: skip
    _sh(["kind", "create", "cluster", "--name", name, "--image", node_image, "--config",
         str(config), "--kubeconfig", str(kubeconfig), "--wait", "180s"], timeout=600)  # fmt: skip


def load_images(cluster: str, images: Sequence[str]) -> None:
    for image in images:
        _sh(["kind", "load", "docker-image", image, "--name", cluster], timeout=600)


def chart_under_test(work: Path, options: argparse.Namespace, node_digest: str) -> Path:
    """A copy of this tree's chart whose image values name the images loaded into the
    cluster, by digest for the Node (the production preset refuses a tag), never pulled."""
    import yaml  # noqa: PLC0415 - the CLI's own dependency, installed for the harness

    chart = work / "chart"
    if chart.exists():
        shutil.rmtree(chart)
    shutil.copytree(CHART, chart, ignore=shutil.ignore_patterns("tests"))
    values_path = chart / "values.yaml"
    values = yaml.safe_load(values_path.read_text("utf-8"))

    def split(image: str) -> tuple[str, str]:
        name, _, tag = canonical(image).rpartition(":")
        return name, tag

    node_repo, _ = split(options.node_image)
    cli_repo, cli_tag = split(options.cli_image)
    sensor_repo, sensor_tag = split(options.sensor_image)
    values["cliImage"].update(
        repository=cli_repo, tag=cli_tag, digest="", pullPolicy="Never"
    )
    values["hostSensor"]["image"].update(
        repository=sensor_repo, tag=sensor_tag, digest="", pullPolicy="Never"
    )
    collector = values.setdefault("otel-collector", {}) or {}
    collector["image"] = {"repository": node_repo, "tag": "", "digest": node_digest,
                          "pullPolicy": "Never"}  # fmt: skip
    values["otel-collector"] = collector
    values_path.write_text(yaml.safe_dump(values, sort_keys=False), "utf-8")
    return chart


def fresh_venv(work: Path, python: str) -> Path:
    venv = work / "venv"
    _sh([python, "-m", "venv", str(venv)])
    return venv


@contextlib.contextmanager
def local_index(work: Path, wheel_dir: Path) -> Iterator[str]:
    process = subprocess.Popen(  # noqa: S603 - this harness's own index
        [sys.executable, "-I", str(TTFR / "local_index.py"), "--wheel-dir", str(wheel_dir),
         "--ready-file", str(work / "index.json")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )  # fmt: skip
    try:
        yield f"http://127.0.0.1:{wait_file(work / 'index.json')['port']}/simple/"
    finally:
        process.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=10)


def diagnostics(env: Mapping[str, str], out: Path) -> None:
    """What the cluster looked like when the page failed (kept as an artifact)."""
    lines = []
    for argv in (
        ["kubectl", "get", "pods,jobs", "-A", "-o", "wide"],
        ["kubectl", "get", "events", "-A", "--sort-by=.lastTimestamp"],
        ["kubectl", "-n", RELEASE_NS, "logs", "-l", "app.kubernetes.io/name=otel-collector",
         "--tail=80"],
        ["kubectl", "-n", RELEASE_NS, "logs", "-l", "app.kubernetes.io/name=fabric-host-emitter",
         "--tail=80"],
        ["kubectl", "-n", RELEASE_NS, "logs", "-l", "app.kubernetes.io/name=fabric-injector",
         "--tail=40"],
        ["kubectl", "-n", AGENT_NS, "logs", "deployment/support-agent", "--tail=40"],
    ):  # fmt: skip
        done = _sh(argv, env=env, check=False, timeout=60)
        lines.append(f"$ {' '.join(argv)}\n{done.stdout}{done.stderr}")
    out.write_text("\n".join(lines), "utf-8")


def run(options: argparse.Namespace, work: Path) -> dict[str, Any]:
    cluster = options.cluster or f"{PREFIX}-{uuid.uuid4().hex[:6]}"
    kubeconfig = work / "kubeconfig"
    project = work / "project"
    env = {
        "PATH": os.environ.get("PATH", os.defpath), "HOME": str(work / "home"),
        "KUBECONFIG": str(kubeconfig), "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        **{k: v for k, v in os.environ.items() if k.startswith(("DOCKER_", "XDG_RUNTIME"))},
    }  # fmt: skip
    (work / "home").mkdir(parents=True, exist_ok=True)
    created = False
    try:
        if options.create_cluster:
            create_cluster(cluster, work, kubeconfig, options.kind_node_image)
            created = True
        elif not kubeconfig.is_file():
            _sh(["kind", "get", "kubeconfig", "--name", cluster], check=True)
            kubeconfig.write_text(
                _sh(["kind", "get", "kubeconfig", "--name", cluster]).stdout, "utf-8"
            )
        images = [
            options.node_image,
            options.cli_image,
            options.sensor_image,
            options.agent_image,
        ]
        load_images(cluster, images)
        node_digest = _sh(
            ["bash", str(PIN), cluster, canonical(options.node_image)]
        ).stdout.strip()
        _sh([sys.executable, str(HERE / "fixtures.py"), "up", "--out", str(project), "--image",
             options.agent_image, "--agent-image", options.agent_image, "--release-namespace",
             RELEASE_NS, "--agent-namespace", AGENT_NS, "--export-path", EXPORT_IN_NODE],
            env=env, timeout=600)  # fmt: skip
        # The workstation's AWS configuration for its own content store (read-only keys,
        # the store's CA and address): the customer has it before Fabric, like
        # destination.yaml. The reader in `fabric verify` uses it.
        fixture = json.loads((project / "fixture.json").read_text("utf-8"))
        env.update(fixture["aws_environment"])
        venv = fresh_venv(work, options.python)
        env["PATH"] = f"{venv}/bin:{env['PATH']}"
        env["VIRTUAL_ENV"] = str(venv)
        source = "pypi and the published chart"
        index: contextlib.AbstractContextManager[str | None] = contextlib.nullcontext(
            None
        )
        if not options.published:
            env["FABRIC_CHART"] = str(chart_under_test(work, options, node_digest))
            index = local_index(work, Path(options.wheel_dir).resolve())
            source = (
                "local wheel and chart (the build under test), dependencies from PyPI"
            )
        with index as url:
            if url:
                env["PIP_INDEX_URL"] = url
            report_file = work / "steps.json"
            started = time.monotonic()
            done = _sh([sys.executable, "-I", str(RUNNER), str(PAGE), "--path", PATH_NAME,
                        "--workdir", str(project), "--json", str(report_file)],
                       env=env, check=False, timeout=1800)  # fmt: skip
            report = load_report(report_file, done)
            if not report.get("ok"):
                diagnostics(env, work / "diagnostics.txt")
            elapsed = time.monotonic() - started
        result = summarize(report, budget=options.budget, path=PATH_NAME, agent="httpx",
                           mode="kind", package_source=source, evicted=[])  # fmt: skip
        result["wall_clock_s"] = round(elapsed, 3)
        result["cluster"] = cluster
        result["customer_inputs"] = [
            "destination.yaml (the destination and content store the customer runs)",
            "the workstation's AWS configuration for that store (read-only keys, its CA)",
        ]
        return result
    finally:
        if created and not options.keep_cluster:
            _sh(
                ["kind", "delete", "cluster", "--name", cluster],
                check=False,
                timeout=300,
            )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--cluster", help="kind cluster name (default: a new f058-ttfr-k8s-*)"
    )
    parser.add_argument("--create-cluster", action=argparse.BooleanOptionalAction, default=True,
                        help="create the kind cluster (default); --no-create-cluster uses "
                        "--cluster as it is, with the export mount of an earlier run")  # fmt: skip
    parser.add_argument("--keep-cluster", action="store_true")
    parser.add_argument("--kind-node-image", default=KIND_NODE_IMAGE,
                        help="the kind node image (default: pinned; its CNI enforces NetworkPolicy)")  # fmt: skip
    for name in ("node", "cli", "sensor", "agent"):
        parser.add_argument(f"--{name}-image", required=True)
    parser.add_argument("--wheel-dir", default=str(ROOT / "sdk" / "python" / "dist"))
    parser.add_argument("--published", action="store_true",
                        help="install the published wheel and chart (release candidates)")  # fmt: skip
    parser.add_argument(
        "--python", default=sys.executable, help="the workstation's Python"
    )
    parser.add_argument("--budget", type=float, default=BUDGET_S)
    parser.add_argument(
        "--work", type=Path, help="work directory (default: a new temp dir)"
    )
    parser.add_argument("--out", type=Path, default=Path("ttfr.json"))
    options = parser.parse_args(argv)
    work = (options.work or Path(tempfile.mkdtemp(prefix=f"{PREFIX}-"))).resolve()
    work.mkdir(parents=True, exist_ok=True)
    try:
        result = run(options, work)
    except TtfrError as exc:
        print(
            f"ttfr-kubernetes: setup failed before the clock started: {exc}",
            file=sys.stderr,
        )
        return 2
    options.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for step in result["steps"]:
        print(f"step {step['step']} {'ok' if step['ok'] else 'FAILED'} "
              f"{step['seconds']:7.1f} s  {' && '.join(step['commands'])}")  # fmt: skip
    print(f"TTFR {result['ttfr_s']:.1f} s (budget {result['budget_s']:g} s), "
          f"{result['install_commands']} install + {result['commands']} commands, "
          f"{result['flags']} flags, {result['page_lines']} page lines: "
          + ("PASS" if result["ok"] else "FAIL " + "; ".join(result["failures"])))  # fmt: skip
    if not result["ok"]:
        with contextlib.suppress(OSError, ValueError, KeyError):
            for step in json.loads((work / "steps.json").read_text("utf-8"))["steps"]:
                if not step["ok"]:
                    print(step["output_tail"], file=sys.stderr)
        with contextlib.suppress(OSError):
            print(
                (work / "diagnostics.txt").read_text("utf-8")[-6000:], file=sys.stderr
            )
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
