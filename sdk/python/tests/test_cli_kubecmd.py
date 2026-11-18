# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric plan``, ``up``, ``down``, ``verify`` and ``doctor`` with ``--kubernetes``
(spec 058 §5.2, §5.4, §5.6, §5.7, §10.5, §10.6; WP8-15), against a fake cluster.

The fake answers what ``kubectl`` would and records every call, so the tests also hold
the boundary: the read commands run only reads (I5), ``up`` and ``down`` touch only the
Fabric release and the Secrets labelled as Fabric's, and nothing prints a secret value
(I7). The real cluster runs are ``charts/fabric/tests/kind/e2e-kubernetes.sh`` and
``scripts/ttfr/kubernetes/ttfr_kubernetes.py``."""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import subprocess
import sys
import time
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import pytest

from fabric import cli
from fabric._version import __version__
from fabric.cli import _kubecmd, _kubectl, _kubeview
from fabric.cli._kubectl import Forbidden
from fabric.cli._report import CliError, Finding
from fabric.content_store.s3 import S3ContentStore

NS = "fabric-system"
AGENTS = "agents"
OLD = "2026-11-01T00:00:00Z"
NEW = "2026-11-17T00:00:00Z"


def _install(**changes: Any) -> dict[str, Any]:
    info: dict[str, Any] = {
        "schema": "fabric.install-info/v1", "version": __version__, "release": "fabric",
        "namespace": NS, "preset": "production-host-sensor", "production": True,
        "tenantId": "acme", "caSecret": "fabric-ca",
        "node": {"service": "fabric-otel-collector", "healthPort": 13133},
        "secrets": ["fabric-ca", "fabric-node-receiver-tls"],
        "agentNamespaces": [{"name": AGENTS, "secret": "fabric-agent",
                             "nodeSecret": "fabric-ingress-agents",
                             "ports": {"grpc": 4337, "http": 4338}}],
        "injector": {"enabled": True, "deployment": "fabric-fabric-injector",
                     "webhook": "fabric-injector-fabric-system-fabric", "capturePolicy": True},
        "hostSensor": {"enabled": True, "idKeySecret": "fabric-id-key",
                       "nodes": [{"name": "kind-control-plane", "port": 4417,
                                  "secret": "fabric-host-kind-control-plane"}]},
    }  # fmt: skip
    info.update(changes)
    return info


def _pod(name: str, namespace: str = AGENTS, *, annotations: Mapping[str, str] | None = None,
         ready: bool = True, created: str = NEW, node: str = "kind-control-plane",
         labels: Mapping[str, str] | None = None, **spec: Any) -> dict[str, Any]:  # fmt: skip
    return {
        "metadata": {"name": name, "namespace": namespace, "creationTimestamp": created,
                     "annotations": dict(annotations or {}), "labels": dict(labels or {})},
        "spec": {"nodeName": node, "containers": [{"name": "agent", "env": []}], **spec},
        "status": {"phase": "Running" if ready else "Pending",
                   "conditions": [{"type": "Ready", "status": "True" if ready else "False"}]},
    }  # fmt: skip


HEALTH_OK = (
    "2026/11/17 10:00:00 fabric-host-emitter: health partial_quarantined_batches=0 "
    "pod_roots=1 pod_selector_matched=1 pod_cgroups_found=1 pods_selected=1 pods_scoped=1 "
    "pods_unscoped=0 pods_unscoped_cgroup_not_found=0 pods_unscoped_unsupported_runtime=0 "
    "pods_unscoped_node_not_supported=0 pods_unscoped_pod_limit=0 pods_runtime_unknown=0\n"
)


@dataclass
class FakeCluster:
    """What ``kubectl`` answers for one cluster; every call is recorded as (verb, args)."""

    install: dict[str, Any] | None = field(default_factory=_install)
    objects: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    lists: dict[tuple[str, str], list[dict[str, Any]]] = field(default_factory=dict)
    secrets: dict[tuple[str, str], dict[str, bytes]] = field(default_factory=dict)
    logs_by_pod: dict[str, str] = field(default_factory=dict)
    forbidden: set[str] = field(default_factory=set)
    calls: list[tuple[str, tuple[Any, ...]]] = field(default_factory=list)
    forwards: list[tuple[str, str, int]] = field(default_factory=list)
    kubectl: str = "/usr/bin/kubectl"

    def version(self) -> dict[str, Any]:
        self.calls.append(("version", ()))
        return {"serverVersion": {"gitVersion": "v1.30.0"}}

    def items(self, kind: str, namespace: str | None = None, selector: str | None = None,
              *, all_namespaces: bool = False) -> list[dict[str, Any]]:  # fmt: skip
        self.calls.append(("items", (kind, namespace, selector)))
        if kind in self.forbidden:
            raise Forbidden(f"{kind} is forbidden")
        if kind == "configmap":
            if self.install is None:
                return []
            return [{"data": {"info.json": json.dumps(self.install)}}]
        found = self.lists.get((kind, namespace or ""), [])
        if selector:
            terms = dict(term.split("=", 1) for term in selector.split(","))
            found = [o for o in found if _kubeview.selects({"matchLabels": terms},
                                                           _kubeview._labels(o))]  # fmt: skip
        return found

    def find(self, kind: str, name: str, namespace: str | None = None) -> dict[str, Any] | None:
        self.calls.append(("find", (kind, name, namespace)))
        if kind in self.forbidden:
            raise Forbidden(f"{kind} is forbidden")
        return self.objects.get((kind, name, namespace or ""))

    def raw(self, path: str) -> Any:
        self.calls.append(("raw", (path,)))
        raise _kubeview.NotFound(path)

    def secret_keys(self, namespace: str, name: str) -> list[str] | None:
        self.calls.append(("secret_keys", (namespace, name)))
        found = self.secrets.get((namespace, name))
        return None if found is None else sorted(found)

    def secret_value(self, namespace: str, name: str, key: str) -> bytes | None:
        self.calls.append(("secret_value", (namespace, name, key)))
        return (self.secrets.get((namespace, name)) or {}).get(key)

    def logs(self, namespace: str, pod: str, container: str | None = None, tail: int = 400,
             *, previous: bool = False) -> str:  # fmt: skip
        self.calls.append(("logs", (namespace, pod, previous)))
        return "" if previous else self.logs_by_pod.get(pod, "")

    @contextlib.contextmanager
    def port_forward(self, namespace: str, target: str, remote_port: int,
                     timeout: float = 15.0) -> Iterator[int]:  # fmt: skip
        self.forwards.append((namespace, target, remote_port))
        yield 40000 + len(self.forwards)


def _c(fake: FakeCluster) -> _kubectl.Cluster:
    """The fake, typed as the client it stands in for."""
    return cast(_kubectl.Cluster, fake)


def _healthy() -> FakeCluster:
    """A production-host-sensor release that works: every Secret, a ready Node, an
    injector with its caBundle, a labelled agent namespace, an injected agent pod and a
    sensor that scopes it."""
    cluster = FakeCluster()
    for name, keys in (
        ("fabric-ca", ["ca.crt", "tls.crt", "tls.key"]),
        ("fabric-node-receiver-tls", ["ca.crt", "tls.crt", "tls.key"]),
        ("fabric-ingress-agents", ["source-id", "token"]),
        ("fabric-host-kind-control-plane", ["source-id", "state-key", "token"]),
        ("fabric-id-key", ["id_key"]),
    ):
        cluster.secrets[(NS, name)] = dict.fromkeys(keys, b"x")
    cluster.secrets[(NS, "fabric-id-key")] = {"id_key": b"k" * 64 + b"\n"}
    cluster.secrets[(AGENTS, "fabric-agent")] = dict.fromkeys(("ca.crt", "id.key", "headers"), b"x")
    node_labels = {
        "app.kubernetes.io/name": "otel-collector",
        "app.kubernetes.io/instance": "fabric",
    }
    sensor_labels = {"app.kubernetes.io/name": "fabric-host-emitter",
                     "app.kubernetes.io/instance": "fabric"}  # fmt: skip
    cluster.lists[("pods", NS)] = [
        _pod("fabric-otel-collector-0", NS, labels=node_labels),
        _pod("fabric-host-emitter-abc", NS, labels=sensor_labels),
    ]
    cluster.logs_by_pod["fabric-host-emitter-abc"] = HEALTH_OK
    cluster.objects[("deployment", "fabric-fabric-injector", NS)] = {
        "metadata": {"creationTimestamp": OLD}, "spec": {"replicas": 2},
        "status": {"readyReplicas": 2},
    }  # fmt: skip
    cluster.objects[
        ("mutatingwebhookconfiguration", "fabric-injector-fabric-system-fabric", "")
    ] = {"webhooks": [{"clientConfig": {"caBundle": "LS0t"}}]}
    cluster.objects[("namespace", AGENTS, "")] = {
        "metadata": {"labels": {"fabric.singleaxis.ai/injection": "enabled"}}
    }
    cluster.lists[("pods", AGENTS)] = [
        _pod(
            "agent-1",
            annotations={
                "fabric.singleaxis.ai/inject": "python",
                "fabric.singleaxis.ai/injected": __version__,
            },
        )
    ]
    cluster.lists[("nodes", "")] = [
        {"metadata": {"name": "kind-control-plane", "labels": {"kubernetes.io/os": "linux"}},
         "status": {"nodeInfo": {"kernelVersion": "6.12.76-linuxkit"}}}
    ]  # fmt: skip
    return cluster


def _options(command: str, *argv: str) -> argparse.Namespace:
    parser = cli.build_parser()
    return parser.commands[command].parse_args(list(argv))


def _ids(findings: Sequence[Any]) -> list[str]:
    return [f.id for f in findings]


def _never_probe(port: int) -> bool:
    return True


def _no_canary(*args: Any) -> dict[str, Any]:
    raise AssertionError("a production Node gets no canary")


# ---------------------------------------------------------------- the read-only client


def test_kubectl_client_runs_only_reads_and_never_reads_a_secret_value_by_get() -> None:
    assert frozenset({"get", "version", "logs", "port-forward"}) == _kubectl.READ_VERBS
    seen: list[list[str]] = []

    def runner(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, "ca.crt\nid.key\n", "")

    cluster = _kubectl.Cluster(kubectl="/bin/kubectl", runner=runner)
    assert cluster.secret_keys(AGENTS, "fabric-agent") == ["ca.crt", "id.key"]
    # The template prints key names only: the values never reach this process.
    template = seen[-1][-1]
    assert (
        template.startswith("go-template=")
        and ".data" in template
        and "$v" not in template[template.index("}}") :]
    )
    for kind in ("secret", "secrets", "Secret.v1"):
        with pytest.raises(AssertionError):
            cluster.items(kind, AGENTS)
        with pytest.raises(AssertionError):
            cluster.get(kind, "x", AGENTS)
    with pytest.raises(AssertionError):
        cluster._run(["delete", "pod", "x"])
    for verb in ("exec", "apply", "scale", "rollout", "cp", "patch"):
        with pytest.raises(AssertionError):
            cluster._run([verb])


@pytest.mark.parametrize(
    ("stderr", "kind"),
    [
        ('Error from server (NotFound): configmaps "x" not found', _kubectl.NotFound),
        ("Error from server (Forbidden): pods is forbidden: User cannot list", Forbidden),
        ("The connection to the server localhost:8080 was refused", CliError),
    ],
)
def test_kubectl_errors_are_told_apart(stderr: str, kind: type[Exception]) -> None:
    assert isinstance(_kubectl.Cluster._problem(stderr), kind)


def test_port_forward_yields_the_local_port_and_stops_kubectl() -> None:
    class Process:
        def __init__(self) -> None:
            self.stdout = iter(["Forwarding from 127.0.0.1:45123 -> 4318\n"])
            self.stderr = None
            self.terminated = False

        def poll(self) -> int | None:
            return None

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: float) -> int:
            return 0

    process = Process()
    started: list[list[str]] = []

    def popen(argv: list[str], **kwargs: Any) -> Process:
        started.append(argv)
        return process

    cluster = _kubectl.Cluster(kubectl="/bin/kubectl", popen=popen)
    with cluster.port_forward(NS, "svc/node", 4318, timeout=2) as port:
        assert port == 45123
    assert started[0][1] == "port-forward" and "127.0.0.1" in started[0]
    assert process.terminated


def test_port_forward_keeps_reading_kubectls_output(tmp_path: Path) -> None:
    """kubectl prints a line per forwarded connection: the forward keeps emptying the
    pipe, or a long verify would stop kubectl once the pipe is full."""
    marker = tmp_path / "drained"
    kubectl = tmp_path / "kubectl"
    kubectl.write_text(
        f"#!{sys.executable}\n"
        "import sys, time\n"
        "print('Forwarding from 127.0.0.1:45124 -> 4318', flush=True)\n"
        "for _ in range(20000):\n"
        "    print('Handling connection for 45124', flush=True)\n"
        f"open({str(marker)!r}, 'w').close()\n"
        "time.sleep(30)\n",
        "utf-8",
    )
    kubectl.chmod(0o700)
    cluster = _kubectl.Cluster(kubectl=str(kubectl))
    with cluster.port_forward(NS, "svc/node", 4318, timeout=10) as port:
        assert port == 45124
        deadline = time.monotonic() + 10
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert marker.exists(), "kubectl blocked on a full stdout pipe"


# ---------------------------------------------------------------- the sensor's log


def test_sensor_log_gives_the_last_counts_and_a_current_export_failure() -> None:
    log = (
        HEALTH_OK.replace("pods_scoped=1", "pods_scoped=0")
        .replace("pods_unscoped=0", "pods_unscoped=1")
        .replace("pods_unscoped_unsupported_runtime=0", "pods_unscoped_unsupported_runtime=1")
        + "2026/11/17 10:00:20 fabric-host-emitter: export retry pending grpc_code=Unavailable "
        'grpc_message="connection refused" hint="a NetworkPolicy may block the sensor"\n'
    )
    seen = _kubeview.read_sensor_log(log)
    assert seen.scope is not None and seen.scope["pods_selected"] == 1
    assert seen.unscoped == {"unsupported_runtime": 1}
    assert seen.export_code == "Unavailable"
    assert seen.node_supported
    # A failure from before two later health lines is history, not the state now.
    assert _kubeview.read_sensor_log(log + HEALTH_OK + HEALTH_OK).export_code is None
    stopped = _kubeview.read_sensor_log(
        "fabric-host-emitter: health node_supported=false pods_unscoped_reason=node_not_supported\n"
    )
    assert not stopped.node_supported


def test_node_sensor_reasons() -> None:
    def node(labels: dict[str, str], kernel: str = "6.8.0") -> dict[str, Any]:
        return {"metadata": {"name": "n", "labels": labels},
                "status": {"nodeInfo": {"kernelVersion": kernel}}}  # fmt: skip

    assert _kubeview.node_sensor_reason(node({"kubernetes.io/os": "linux"})) is None
    assert "fargate" in str(
        _kubeview.node_sensor_reason(node({"eks.amazonaws.com/compute-type": "fargate"}))
    )
    assert "windows" in str(_kubeview.node_sensor_reason(node({"kubernetes.io/os": "windows"})))
    assert "5.8" in str(_kubeview.node_sensor_reason(node({}, kernel="5.4.0-1")))


# ---------------------------------------------------------------- verify / doctor


def test_verify_on_a_working_production_release_passes_without_a_canary() -> None:
    cluster = _healthy()
    report, lines = _kubecmd.run_verify(
        _options("verify", "--kubernetes"), {}, cluster=_c(cluster),
        probe=_never_probe, canary=_no_canary,
    )  # fmt: skip
    ids = _ids(report.findings)
    assert report.exit_code == 0, [f.line() for f in report.findings]
    for wanted in ("FC-127", "FC-131", "FC-136", "FC-142", "FC-074"):
        assert wanted in ids
    assert report.data["kubernetes"]["sensor"]["nodes"]["kind-control-plane"]["pods_scoped"] == 1
    assert "agent_pods" not in report.data["kubernetes"]
    assert any("host sensor on kind-control-plane: pods_selected=1 pods_scoped=1" in line
               for line in lines)  # fmt: skip
    # I5: reads only; no exec into a pod; the health port is forwarded and closed.
    assert {verb for verb, _ in cluster.calls} <= {
        "version",
        "items",
        "find",
        "raw",
        "secret_keys",
        "secret_value",
        "logs",
    }
    assert cluster.forwards == [(NS, "pod/fabric-otel-collector-0", 13133)]


def test_webhook_outage_is_reported_with_its_cause() -> None:
    """E2 acceptance: with the injector scaled to zero an annotated pod is admitted
    uncaptured; ``doctor`` says why (the webhook's 2 s timeout, failurePolicy Ignore)."""
    cluster = _healthy()
    cluster.objects[("deployment", "fabric-fabric-injector", NS)]["status"] = {}
    cluster.lists[("pods", AGENTS)].append(
        _pod("agent-2", annotations={"fabric.singleaxis.ai/inject": "python"})
    )
    report, _ = _kubecmd.run_doctor(
        _options("doctor", "--kubernetes"),
        {},
        cluster=_c(cluster),
        probe=_never_probe,
    )
    by_id = {f.id: f for f in report.findings}
    assert report.exit_code == 1
    assert "0 of 2 ready" in str(by_id["FC-129"].detail)
    detail = str(by_id["FC-130"].detail)
    assert detail.startswith("agents/agent-2:") and "2 s timeout" in detail
    assert "FC-097" not in by_id


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("unlabelled", "lacks the label fabric.singleaxis.ai/injection=enabled"),
        ("before", "created before the injector was installed"),
        ("skipped", "the injector skipped it: sdk_not_found"),
        ("late", "did not answer within its 2 s timeout"),
    ],
)
def test_each_uninjected_pod_gets_its_own_reason(change: str, reason: str) -> None:
    cluster = _healthy()
    notes = {"fabric.singleaxis.ai/inject": "python"}
    created = NEW
    if change == "unlabelled":
        cluster.objects[("namespace", AGENTS, "")] = {"metadata": {"labels": {}}}
    elif change == "before":
        created = "2026-10-01T00:00:00Z"
    elif change == "skipped":
        notes["fabric.singleaxis.ai/inject-skipped"] = "sdk_not_found"
    cluster.lists[("pods", AGENTS)] = [_pod("agent-x", annotations=notes, created=created)]
    report, _ = _kubecmd.run_doctor(
        _options("doctor", "--kubernetes"),
        {},
        cluster=_c(cluster),
        probe=_never_probe,
    )
    assert reason in str(next(f for f in report.findings if f.id == "FC-130").detail)


def test_a_gvisor_runtime_class_pod_is_reported_unsupported_runtime() -> None:
    """E2 acceptance: never silently unscoped."""
    cluster = _healthy()
    cluster.lists[("runtimeclasses", "")] = [
        {"metadata": {"name": "gvisor"}, "handler": "runsc"},
        {"metadata": {"name": "default-runc"}, "handler": "runc"},
    ]
    cluster.logs_by_pod["fabric-host-emitter-abc"] = (
        HEALTH_OK.replace("pods_selected=1", "pods_selected=2")
        .replace("pods_unscoped=0", "pods_unscoped=1")
        .replace("pods_unscoped_unsupported_runtime=0", "pods_unscoped_unsupported_runtime=1")
    )
    report, _ = _kubecmd.run_doctor(
        _options("doctor", "--kubernetes"),
        {},
        cluster=_c(cluster),
        probe=_never_probe,
    )
    by_id = {f.id: str(f.detail) for f in report.findings}
    assert by_id["FC-134"] == "node kind-control-plane: 1 pod(s), unsupported_runtime"
    assert by_id["FC-138"] == "gvisor (handler runsc)"
    assert "FC-136" not in by_id


def test_a_default_deny_policy_and_a_failing_export_are_named() -> None:
    """The audit's workaround F5 as a regression: a policy that blocks the sensor's
    egress is named, and the export's gRPC code is shown."""
    cluster = _healthy()
    cluster.lists[("networkpolicies", NS)] = [
        {"metadata": {"name": "deny-all"},
         "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}},
    ]  # fmt: skip
    cluster.logs_by_pod["fabric-host-emitter-abc"] = (
        HEALTH_OK + "fabric-host-emitter: export retry pending grpc_code=Unavailable\n"
    )
    report, _ = _kubecmd.run_doctor(
        _options("doctor", "--kubernetes"),
        {},
        cluster=_c(cluster),
        probe=_never_probe,
    )
    details = {(f.id, str(f.detail)) for f in report.findings}
    assert ("FC-137", "host sensor egress to the Node on TCP 4417") in details
    assert ("FC-137", "Node ingress on TCP 4417 (host sensor of kind-control-plane)") in details
    assert ("FC-135", "node kind-control-plane: grpc_code=Unavailable") in details
    # The chart's own rule for the sensor port lets it through.
    cluster.lists[("networkpolicies", NS)].append(
        {"metadata": {"name": "fabric-host-sensor-egress"},
         "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "fabric-host-emitter"}},
                  "policyTypes": ["Egress"], "egress": [{"ports": [{"port": 4417}]}]}}
    )  # fmt: skip
    report, _ = _kubecmd.run_doctor(
        _options("doctor", "--kubernetes"),
        {},
        cluster=_c(cluster),
        probe=_never_probe,
    )
    assert ("FC-137", "host sensor egress to the Node on TCP 4417") not in {
        (f.id, str(f.detail)) for f in report.findings
    }


def test_missing_secrets_a_down_node_and_a_missing_sensor_pod_are_errors() -> None:
    cluster = _healthy()
    del cluster.secrets[(AGENTS, "fabric-agent")]
    cluster.secrets[(NS, "fabric-ingress-agents")] = {"token": b"x"}
    cluster.lists[("pods", NS)] = [
        _pod("fabric-otel-collector-0", NS, ready=False,
             labels={"app.kubernetes.io/name": "otel-collector",
                     "app.kubernetes.io/instance": "fabric"})
    ]  # fmt: skip
    cluster.logs_by_pod["fabric-otel-collector-0"] = "Error: invalid configuration: exporter\n"
    report, _ = _kubecmd.run_doctor(
        _options("doctor", "--kubernetes"),
        {},
        cluster=_c(cluster),
        probe=_never_probe,
    )
    details = [(f.id, str(f.detail)) for f in report.findings]
    assert ("FC-125", "agents/fabric-agent does not exist") in details
    assert ("FC-125", "fabric-system/fabric-ingress-agents lacks source-id") in details
    assert any(i == "FC-126" and "invalid configuration" in d for i, d in details)
    assert ("FC-133", "node kind-control-plane: no sensor pod is scheduled") in details
    assert report.exit_code == 1


def test_a_read_the_identity_may_not_make_is_skipped_and_named() -> None:
    cluster = _healthy()
    cluster.forbidden = {"nodes", "runtimeclasses"}
    report, _ = _kubecmd.run_doctor(
        _options("doctor", "--kubernetes"),
        {},
        cluster=_c(cluster),
        probe=_never_probe,
    )
    skipped = [str(f.detail) for f in report.findings if f.id == "FC-147"]
    assert any(d.startswith("nodes:") for d in skipped)
    assert any(d.startswith("runtimeclasses:") for d in skipped)


def test_no_release_or_several_releases_name_the_way_out() -> None:
    cluster = FakeCluster(install=None)
    with pytest.raises(CliError) as caught:
        _kubeview.find_install(_c(cluster), None)
    assert [(f.id, f.detail) for f in caught.value.findings] == [
        ("FC-122", "none in any namespace")
    ]

    class Two(FakeCluster):
        def items(self, kind: str, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            other = _install(namespace="fabric-b")
            return [{"data": {"info.json": json.dumps(i)}} for i in (_install(), other)]

    with pytest.raises(CliError) as caught:
        _kubeview.find_install(_c(Two()), None)
    assert "choose one with --namespace" in str(caught.value.findings[0].detail)


def test_one_shot_pods_with_an_emptydir_spool_are_warned_in_doctor() -> None:
    cluster = _healthy()
    notes = {"fabric.singleaxis.ai/inject": "python", "fabric.singleaxis.ai/injected": __version__}
    spool = [{"name": "fabric-spool", "emptyDir": {}}]
    pod = _pod("job-1", annotations=notes, restartPolicy="Never", volumes=spool)
    cluster.lists[("pods", AGENTS)] = [pod]
    report, _ = _kubecmd.run_doctor(
        _options("doctor", "--kubernetes"),
        {},
        cluster=_c(cluster),
        probe=_never_probe,
    )
    assert ("FC-140", "agents/job-1") in [(f.id, f.detail) for f in report.findings]


def test_local_release_sends_the_canary_through_a_port_forward() -> None:
    cluster = _healthy()
    cluster.install = _install(production=False, preset="local",
                               hostSensor={"enabled": False})  # fmt: skip
    sent: list[str] = []

    def canary(_cluster: Any, install: Any, environ: Any, label: str) -> dict[str, Any]:
        sent.append(label)
        return {"installed": True, "delivered": True}

    report, lines = _kubecmd.run_verify(
        _options("verify", "--kubernetes", "--canary-only"), {}, cluster=_c(cluster),
        probe=_never_probe, canary=canary,
    )  # fmt: skip
    assert report.data["canary"]["delivered"] and sent[0].startswith("canary-")
    assert "canary: recorded and accepted by the Node" in lines
    assert report.exit_code == 0


def test_verify_without_spans_says_where_the_run_is_read_from() -> None:
    report, _ = _kubecmd.run_verify(
        _options("verify", "--kubernetes"), {}, cluster=_c(_healthy()),
        probe=_never_probe, canary=_no_canary,
    )  # fmt: skip
    assert "--spans PATH" in str(next(f for f in report.findings if f.id == "FC-074").detail)


def test_verify_with_unreadable_spans_names_the_accepted_inputs(tmp_path: Path) -> None:
    (tmp_path / "x.txt").write_text("not otlp")
    report, _ = _kubecmd.run_verify(
        _options("verify", "--kubernetes", "--spans", str(tmp_path / "x.txt")), {},
        cluster=_c(_healthy()), probe=_never_probe, canary=_no_canary,
    )  # fmt: skip
    assert report.exit_code == 1
    assert any(f.id in ("FC-073", "FC-067") for f in report.findings)


def _run_doc(run_id: str, started: str, state: str | None) -> dict[str, Any]:
    return {"run_id": run_id, "run_state": state, "exchanges": [{"started_at": started}]}


def test_without_run_the_newest_ended_run_is_judged_never_one_still_running() -> None:
    document = {"runs": [
        _run_doc("r-old", "2026-11-17T00:00:01Z", None),
        _run_doc("r-ended", "2026-11-17T00:00:05Z", "terminated"),
        _run_doc("r-running", "2026-11-17T00:00:09Z", "in_progress"),
    ]}  # fmt: skip
    assert _kubecmd.ended_run_id(document) == "r-ended"
    # None has ended yet: the newest run, so the report still names one.
    running = {"runs": [_run_doc("r-a", "2026-11-17T00:00:01Z", "in_progress"),
                        _run_doc("r-b", "2026-11-17T00:00:02Z", "in_progress")]}  # fmt: skip
    assert _kubecmd.ended_run_id(running) == "r-b"
    assert _kubecmd.ended_run_id({"runs": []}) is None


def _judged(run_id: str, started: str, corroboration: str) -> dict[str, Any]:
    return {**_run_doc(run_id, started, "terminated"), "verdict": "complete_for_declared_scope",
            "chains": {"decisions": {"verdict": "complete"},
                       "corroboration": {"verdict": corroboration}}}  # fmt: skip


def test_a_run_judged_on_an_earlier_look_is_reported_once_its_evidence_arrives() -> None:
    """A looping agent ends a run every few seconds, each younger than the host sensor's
    last delivered heartbeat (``source_gap`` until the next one): the newest run alone
    would never be seen corroborated, so a run an earlier look judged stays a candidate.
    The newest run wins whenever it is complete; nothing older is reported otherwise."""
    document = {"runs": [
        _judged("r-1", "2026-11-17T00:00:01Z", "complete"),
        _judged("r-2", "2026-11-17T00:00:07Z", "complete"),
        _judged("r-3", "2026-11-17T00:00:13Z", "partial"),
    ]}  # fmt: skip
    judged = _kubecmd.judged_run_id
    assert judged(document, sensor=True) == "r-3"  # no earlier look: the newest
    assert judged(document, ["r-2", "r-1"], sensor=True) == "r-2"
    assert judged(document, ["r-gone"], sensor=True) == "r-3"
    assert judged(document, ["r-2"], sensor=False) == "r-3"  # complete without a sensor
    document["runs"][2]["chains"]["corroboration"]["verdict"] = "complete"
    assert judged(document, ["r-2"], sensor=True) == "r-3"
    # An earlier run that is not complete either is never preferred to the newest.
    document["runs"][1]["chains"]["decisions"]["verdict"] = "partial"
    document["runs"][2]["chains"]["corroboration"]["verdict"] = "partial"
    assert judged(document, ["r-2"], sensor=True) == "r-3"


def test_verify_offers_the_runs_it_judged_before_to_the_next_look(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:  # fmt: skip
    offered: list[list[str]] = []
    ids = iter(["r-1", "r-2", "r-1"])

    def read(cluster: Any, install: Any, view: Any, *args: Any) -> dict[str, Any]:
        offered.append(list(args[-1]))
        run_id = next(ids)
        view.findings.append(Finding("FC-069" if len(offered) == 3 else "FC-068", run_id))
        return {"run_id": run_id, "chains": {"corroboration": "complete"}}

    monkeypatch.setattr(_kubecmd, "_read_run", read)
    clock = _Clock()
    report, _ = _kubecmd.run_verify(
        _options("verify", "--kubernetes", "--spans", str(tmp_path)), {},
        cluster=_c(_healthy()), probe=_never_probe, canary=_no_canary,
        sleep=clock.sleep, clock=clock,
    )  # fmt: skip
    assert offered == [[], ["r-1"], ["r-2", "r-1"]] and report.exit_code == 0


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def _reads(monkeypatch: pytest.MonkeyPatch,
           answers: Sequence[tuple[str, str | None]]) -> list[int]:  # fmt: skip
    """``_read_run`` answering (finding id, corroboration) in turn, the last one forever."""
    calls: list[int] = []

    def read(cluster: Any, install: Any, view: Any, *args: Any) -> dict[str, Any] | None:
        finding, corroboration = answers[min(len(calls), len(answers) - 1)]
        calls.append(1)
        view.findings.append(Finding(finding, f"read {len(calls)}"))
        view.lines.append(f"read {len(calls)}")
        if finding == "FC-073":
            return None
        return {"run_id": "r", "chains": {"corroboration": corroboration}}

    monkeypatch.setattr(_kubecmd, "_read_run", read)
    return calls


def test_verify_waits_for_a_complete_corroborated_run_and_reports_the_last_read_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:  # fmt: skip
    calls = _reads(monkeypatch, [("FC-068", None), ("FC-069", "partial"),
                                 ("FC-069", "complete")])  # fmt: skip
    clock = _Clock()
    report, lines = _kubecmd.run_verify(
        _options("verify", "--kubernetes", "--spans", str(tmp_path)), {},
        cluster=_c(_healthy()), probe=_never_probe, canary=_no_canary,
        sleep=clock.sleep, clock=clock,
    )  # fmt: skip
    assert len(calls) == 3 and clock.slept == [_kubecmd._POLL_S] * 2
    reads = [f.detail for f in report.findings if f.id in ("FC-068", "FC-069")]
    assert reads == ["read 3"] and "read 3" in lines and "read 1" not in lines
    assert report.exit_code == 0


def test_verify_stops_waiting_at_its_bound_and_reports_what_it_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:  # fmt: skip
    calls = _reads(monkeypatch, [("FC-068", None)])
    clock = _Clock()
    report, _ = _kubecmd.run_verify(
        _options("verify", "--kubernetes", "--spans", str(tmp_path)), {},
        cluster=_c(_healthy()), probe=_never_probe, canary=_no_canary,
        sleep=clock.sleep, clock=clock,
    )  # fmt: skip
    # No --wait: the cluster default, for the operator's own rollout and a run.
    assert clock.now == pytest.approx(_kubecmd.KUBERNETES_WAIT_S)
    assert len(calls) == int(_kubecmd.KUBERNETES_WAIT_S / _kubecmd._POLL_S) + 1
    assert _ids(report.findings).count("FC-068") == 1 and report.exit_code == 1
    # --wait SECONDS is the operator's bound; an unreadable export is not waited for.
    clock = _Clock()
    _kubecmd.run_verify(
        _options("verify", "--kubernetes", "--spans", str(tmp_path), "--wait", "12"), {},
        cluster=_c(_healthy()), probe=_never_probe, canary=_no_canary,
        sleep=clock.sleep, clock=clock,
    )  # fmt: skip
    assert clock.now == pytest.approx(12.0)
    # --wait 30 (the local default) is kept as given too.
    clock = _Clock()
    _kubecmd.run_verify(
        _options("verify", "--kubernetes", "--spans", str(tmp_path), "--wait", "30"), {},
        cluster=_c(_healthy()), probe=_never_probe, canary=_no_canary,
        sleep=clock.sleep, clock=clock,
    )  # fmt: skip
    assert clock.now == pytest.approx(30.0)
    calls = _reads(monkeypatch, [("FC-073", None)])
    clock = _Clock()
    _kubecmd.run_verify(
        _options("verify", "--kubernetes", "--spans", str(tmp_path)), {},
        cluster=_c(_healthy()), probe=_never_probe, canary=_no_canary,
        sleep=clock.sleep, clock=clock,
    )  # fmt: skip
    assert len(calls) == 1 and clock.slept == []


def test_a_startup_export_failure_is_waited_out_not_reported(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:  # fmt: skip
    """A sensor that exported once before the Node listened (FC-135 on the first look)
    is checked again with the run: the report holds the last look only."""
    _reads(monkeypatch, [("FC-069", "complete")])
    gather = _kubeview.gather
    looks: list[int] = []

    def flaky(*args: Any, **kwargs: Any) -> Any:
        view = gather(*args, **kwargs)
        looks.append(1)
        if len(looks) == 1:
            view.findings.append(Finding("FC-135", "node n: grpc_code=Unavailable"))
        return view

    monkeypatch.setattr(_kubeview, "gather", flaky)
    clock = _Clock()
    report, _ = _kubecmd.run_verify(
        _options("verify", "--kubernetes", "--spans", str(tmp_path)), {},
        cluster=_c(_healthy()), probe=_never_probe, canary=_no_canary,
        sleep=clock.sleep, clock=clock,
    )  # fmt: skip
    assert len(looks) == 2 and "FC-135" not in _ids(report.findings)
    assert report.exit_code == 0


def test_the_content_port_is_checked_only_with_content_delivery_on() -> None:
    cluster = _healthy()
    cluster.lists[("networkpolicies", NS)] = [
        {"metadata": {"name": "deny-all"},
         "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}},
        {"metadata": {"name": "fabric-node-ingress"},
         "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "otel-collector"}},
                  "policyTypes": ["Ingress"],
                  "ingress": [{"ports": [{"port": 4337}, {"port": 4338}, {"port": 4417}]}]}},
    ]  # fmt: skip
    agents = [{"name": AGENTS, "secret": "fabric-agent", "nodeSecret": "fabric-ingress-agents",
               "ports": {"grpc": 4337, "http": 4338, "content": 4339}}]  # fmt: skip
    for content, blocked in ((False, False), (True, True)):
        cluster.install = _install(
            agentNamespaces=agents,
            node={"service": "fabric-otel-collector", "healthPort": 13133, "content": content},
        )
        report, _ = _kubecmd.run_doctor(_options("doctor", "--kubernetes"), {},
                                        cluster=_c(cluster), probe=_never_probe)  # fmt: skip
        found = ("FC-137", f"Node ingress on TCP 4339 (agents of {AGENTS})") in {
            (f.id, str(f.detail)) for f in report.findings
        }
        assert found is blocked, (content, report.findings)


def _store_install(**store: Any) -> _kubeview.Install:
    node = {"service": "fabric-otel-collector", "healthPort": 13133, "content": bool(store),
            "contentStore": store or {"backend": ""}}  # fmt: skip
    injector = {"enabled": True, "deployment": "fabric-fabric-injector", "capturePolicy": True}
    return _kubeview.Install(_install(node=node, injector=injector))


def test_verify_reads_the_release_content_store_with_the_workstations_aws_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    """Decisions are verified against the model bodies: the S3 store the Node writes,
    opened with the operator's AWS configuration. An endpoint that configuration names
    wins over the Node's (which may be an address only the cluster reaches)."""
    monkeypatch.setattr(S3ContentStore, "ensure_client", lambda self: None)
    install = _store_install(backend="s3", bucket="acme-content", prefix="fabric/content/",
                             region="us-east-1", endpoint="https://s3.store.svc:8333",
                             pathStyle=True)  # fmt: skip
    view = _kubeview.View()
    store, tenant = _kubecmd.content_store(install, view, {})
    assert isinstance(store, S3ContentStore) and tenant == "acme"
    assert store.bucket == "acme-content" and store.prefix == "fabric/content/"
    assert store.endpoint_url == "https://s3.store.svc:8333" and store.region_name == "us-east-1"
    assert not view.findings
    store, _ = _kubecmd.content_store(
        install, _kubeview.View(), {"AWS_ENDPOINT_URL_S3": "https://127.0.0.1:30833"}
    )
    assert store is not None and store.endpoint_url is None  # botocore reads the variable


def test_doctor_and_verify_name_a_production_injector_without_a_capture_policy() -> None:
    """A production SDK keeps model bodies out without a capture policy (FW-008), so the
    decisions cannot be verified whatever the content store: ``doctor`` and ``verify``
    say why, with or without ``--spans`` and an S3 store."""
    for policy, expected in ((False, True), (True, False)):
        cluster = _healthy()
        cast(dict[str, Any], cluster.install)["injector"]["capturePolicy"] = policy
        doctor, _ = _kubecmd.run_doctor(
            _options("doctor", "--kubernetes"), {}, cluster=_c(cluster), probe=_never_probe
        )
        verify, _ = _kubecmd.run_verify(
            _options("verify", "--kubernetes"), {}, cluster=_c(cluster),
            probe=_never_probe, canary=_no_canary,
        )  # fmt: skip
        for report in (doctor, verify):
            found = [f for f in report.findings if f.id == "FC-155"]
            assert bool(found) is expected, report.command
            if expected:
                assert "injector.capturePolicy" in str(found[0].detail)
                assert "FC-097" not in _ids(report.findings)


def test_the_sensor_reports_pods_whose_runtime_class_it_cannot_read() -> None:
    """The emitter's ``pods_runtime_unknown`` (RBAC without get on runtimeclasses): a
    gVisor pod could pass for scoped, so doctor names it with the fix, never silence."""
    cluster = _healthy()
    cluster.logs_by_pod["fabric-host-emitter-abc"] = HEALTH_OK.replace(
        "pods_runtime_unknown=0", "pods_runtime_unknown=2"
    )
    report, _ = _kubecmd.run_doctor(
        _options("doctor", "--kubernetes"), {}, cluster=_c(cluster), probe=_never_probe
    )
    by_id = {f.id: str(f.detail) for f in report.findings}
    assert by_id["FC-156"] == "node kind-control-plane: 2 pod(s)"
    assert "FC-136" not in by_id and "FC-097" not in by_id
    nodes = report.data["kubernetes"]["sensor"]["nodes"]
    assert nodes["kind-control-plane"]["pods_runtime_unknown"] == 2


def test_verify_says_why_decisions_cannot_be_verified_without_a_readable_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    for install, detail in (
        (_store_install(), "content delivery is off"),
        (_store_install(backend="file"), "content backend file"),
    ):
        view = _kubeview.View()
        assert _kubecmd.content_store(install, view, {}) == (None, None)
        assert _ids(view.findings) == ["FC-154"] and detail in str(view.findings[0].detail)

    def no_boto3(self: Any) -> None:
        raise ImportError("boto3")

    monkeypatch.setattr(S3ContentStore, "ensure_client", no_boto3)
    view = _kubeview.View()
    install = _store_install(backend="s3", bucket="acme-content", region="us-east-1")
    assert _kubecmd.content_store(install, view, {}) == (None, None)
    assert _ids(view.findings) == ["FC-153"]


def test_reader_peers_come_from_the_cluster_never_from_dns() -> None:
    cluster = _healthy()
    cluster.lists[("services", NS)] = [
        {"metadata": {"labels": {"app.kubernetes.io/name": "otel-collector",
                                 "app.kubernetes.io/instance": "fabric"}},
         "spec": {"clusterIP": "10.96.0.50"}}
    ]  # fmt: skip
    cluster.lists[("services", "kube-system")] = [
        {"metadata": {"labels": {"k8s-app": "kube-dns"}}, "spec": {"clusterIP": "10.96.0.10"}}
    ]
    cluster.objects[("service", "model", "fabric-model")] = {"spec": {"clusterIP": "10.96.0.80"}}
    matchers = [{"endpoint_id": "lbl-model", "hosts": ["model.fabric-model.svc", "192.0.2.7"]}]
    pod = _pod("agent-1")
    pod["spec"]["containers"][0]["env"] = [
        {"name": "FABRIC_WIRE_ENDPOINTS", "value": json.dumps(matchers)}
    ]
    install = _kubeview.Install(_install())
    endpoints, known = _kubecmd.reader_peers(
        _c(cluster),
        install,
        [pod],
        [{"status": {"podIP": "10.244.0.9"}}],
    )
    assert endpoints == {"lbl-model": ["10.96.0.80", "192.0.2.7"]}
    assert known == ["10.96.0.50", "10.96.0.10", "10.244.0.9"]


# ---------------------------------------------------------------- plan --kubernetes


def test_plan_reads_the_cluster_and_predicts_without_changing_anything() -> None:
    cluster = FakeCluster(install=None)
    cluster.lists[("nodes", "")] = [
        {"metadata": {"name": "worker-a", "creationTimestamp": OLD,
                      "labels": {"kubernetes.io/os": "linux"}},
         "status": {"nodeInfo": {"kernelVersion": "6.8.0", "containerRuntimeVersion": "containerd://1.7"}}},
        {"metadata": {"name": "fargate-x", "labels": {"eks.amazonaws.com/compute-type": "fargate"}},
         "status": {"nodeInfo": {"kernelVersion": "5.10.0"}}},
    ]  # fmt: skip
    cluster.lists[("runtimeclasses", "")] = [{"metadata": {"name": "gvisor"}, "handler": "runsc"}]
    report, lines = _kubecmd.run_plan(
        _options("plan", "--kubernetes"),
        {},
        cluster=_c(cluster),
    )
    assert report.exit_code == 0
    assert lines[0] == "shape: kubernetes   server: v1.30.0"
    assert any("fargate-x" in line and "cannot run" in line for line in lines)
    rows = {row["row"]: row for row in report.data["coverage"]}
    assert rows["host evidence (kernel sensor)"]["state"] == "fix"
    assert "1 of 2 node(s)" in rows["host evidence (kernel sensor)"]["note"]
    assert rows["pods under RuntimeClass gvisor"]["state"] == "invisible"
    assert "unsupported_runtime" in rows["pods under RuntimeClass gvisor"]["note"]
    assert any(line.startswith("next: fabric up --kubernetes") for line in lines)
    assert {"FC-138", "FC-148"} <= set(_ids(report.findings))
    assert {verb for verb, _ in cluster.calls} <= {"version", "items", "find", "raw"}


def test_plan_without_kubernetes_is_still_not_built(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["plan", "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["findings"][0]["id"] == "FC-010"


# ---------------------------------------------------------------- up / down --kubernetes


@dataclass
class FakeHelm:
    code: int = 0
    stderr: str = ""
    calls: list[list[str]] = field(default_factory=list)

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, self.code, "", self.stderr)


def _which(name: str, path: str | None = None) -> str:
    return f"/usr/bin/{name}"


def _no_tool(name: str, path: str | None = None) -> None:
    return None


def test_up_runs_one_helm_upgrade_install_of_this_release(tmp_path: Path) -> None:
    helm = FakeHelm()
    options = _options("up", "--kubernetes", "--preset", "production-host-sensor",
                       "--agent-namespace", AGENTS, "--injector", "--tenant", "acme")  # fmt: skip
    report, lines = _kubecmd.run_up(options, {}, tmp_path, runner=helm, which=_which)
    [argv] = helm.calls
    assert argv[:5] == ["/usr/bin/helm", "upgrade", "--install", "fabric", _kubecmd.CHART]
    assert argv[5:7] == ["--version", __version__]
    joined = " ".join(argv)
    for part in ("--set preset=production-host-sensor", "--set-string tenant.id=acme",
                 "--set agentNamespaces={agents}", "--set injector.enabled=true",
                 "--namespace fabric-system --create-namespace", "--wait"):  # fmt: skip
        assert part in joined
    assert _ids(report.findings) == ["FC-124"]
    assert any("kubectl label namespace agents fabric.singleaxis.ai/injection=enabled" in line
               for line in lines)  # fmt: skip


def test_up_wait_is_helms_timeout_and_an_explicit_value_is_kept(tmp_path: Path) -> None:
    """Without ``--wait`` Helm waits 300 s; any value given is used as given (``--wait
    60``, the local default, was once replaced by 300)."""
    for argv, timeout in (((), "300s"), (("--wait", "60"), "60s"), (("--wait", "45"), "45s")):
        helm = FakeHelm()
        _kubecmd.run_up(_options("up", "--kubernetes", *argv), {}, tmp_path,
                        runner=helm, which=_which)  # fmt: skip
        command = helm.calls[0]
        assert command[command.index("--timeout") + 1] == timeout, argv


def test_up_takes_the_operators_values_last_and_never_restarts_a_workload(tmp_path: Path) -> None:
    helm = FakeHelm()
    values = tmp_path / "destination.yaml"
    values.write_text("{}\n")
    options = _options("up", "--kubernetes", "--values", str(values), "--set", "a.b=c")
    _kubecmd.run_up(options, {}, tmp_path, runner=helm, which=_which)
    argv = helm.calls[0]
    assert argv.index("--values") > argv.index("preset=local")
    assert argv[argv.index("--values") + 1] == str(values)
    assert not set(argv) & {"rollout", "restart", "scale", "delete"}


def test_a_chart_override_is_a_warning(tmp_path: Path) -> None:
    helm = FakeHelm()
    report, _ = _kubecmd.run_up(
        _options("up", "--kubernetes"), {"FABRIC_CHART": str(tmp_path)}, tmp_path,
        runner=helm, which=_which,
    )  # fmt: skip
    assert helm.calls[0][4] == str(tmp_path) and "--version" not in helm.calls[0]
    assert ("FC-152", str(tmp_path)) in [(f.id, f.detail) for f in report.findings]


@pytest.mark.parametrize(
    ("argv", "detail"),
    [
        (["--injector"], "--injector needs --agent-namespace"),
        (["--set", "novalue"], "--set takes KEY=VALUE"),
        (["--values", "/no/such/file.yaml"], "no such file"),
    ],
)
def test_up_refuses_unusable_options_before_anything_runs(
    argv: list[str], detail: str, tmp_path: Path
) -> None:
    helm = FakeHelm()
    with pytest.raises(CliError) as caught:
        _kubecmd.run_up(_options("up", "--kubernetes", *argv), {}, tmp_path, runner=helm,
                        which=_which)  # fmt: skip
    assert caught.value.findings[0].id == "FC-151"
    assert detail in str(caught.value.findings[0].detail)
    assert helm.calls == []


def test_up_without_helm_or_with_a_failing_helm_says_why(tmp_path: Path) -> None:
    with pytest.raises(CliError) as caught:
        _kubecmd.run_up(_options("up", "--kubernetes"), {}, tmp_path, runner=FakeHelm(),
                        which=_no_tool)  # fmt: skip
    assert (caught.value.exit_code, caught.value.findings[0].id) == (3, "FC-121")
    helm = FakeHelm(code=1, stderr="Error: INSTALLATION FAILED: hostSensor needs agentNamespaces\n")
    with pytest.raises(CliError) as caught:
        _kubecmd.run_up(_options("up", "--kubernetes"), {}, tmp_path, runner=helm, which=_which)
    assert caught.value.findings[-1].id == "FC-123"
    assert "hostSensor needs agentNamespaces" in str(caught.value.findings[-1].detail)


def test_up_render_writes_values_and_private_secrets_and_installs_nothing(tmp_path: Path) -> None:
    helm = FakeHelm()
    out = tmp_path / "out"
    options = _options("up", "--kubernetes", "--render", str(out), "--preset",
                       "production-host-sensor", "--agent-namespace", AGENTS, "--injector",
                       "--host-node", "worker-a", "--tenant", "acme")  # fmt: skip
    report, lines = _kubecmd.run_up(options, {}, tmp_path, runner=helm, which=_which)
    assert helm.calls == []
    values = json.loads((out / "values.yaml").read_text())
    assert values == {
        "preset": "production-host-sensor", "tenant": {"id": "acme"},
        "agentNamespaces": [AGENTS], "injector": {"enabled": True},
        "hostSensor": {"nodes": ["worker-a"]},
    }  # fmt: skip
    assert (out.stat().st_mode & 0o777) == 0o700
    manifests = sorted((out / "secrets").rglob("*.yaml"))
    # One Secret per sensor node (its name is derived from the node's).
    assert (
        len(
            [p for p in manifests if re.fullmatch(r"secret-fabric-host-[0-9a-f]{12}\.yaml", p.name)]
        )
        == 1
    )
    printed = "\n".join(lines) + json.dumps(report.data)
    for path in manifests:
        for value in json.loads(path.read_text()).get("data", {}).values():
            assert value not in printed
    assert "FC-143" in _ids(report.findings)


def test_up_render_with_the_host_sensor_needs_nodes(tmp_path: Path) -> None:
    cluster = FakeCluster()
    cluster.forbidden = {"nodes"}
    options = _options("up", "--kubernetes", "--render", str(tmp_path / "o"), "--preset",
                       "production-host-sensor", "--agent-namespace", AGENTS)  # fmt: skip
    with pytest.raises(CliError) as caught:
        _kubecmd.run_up(options, {}, tmp_path, runner=FakeHelm(), which=_which,
                        cluster=_c(cluster))  # fmt: skip
    assert caught.value.findings[0].id == "FC-150"


def test_down_uninstalls_and_keeps_secrets_unless_purged() -> None:
    helm = FakeHelm()
    report, _ = _kubecmd.run_down(_options("down", "--kubernetes"), {}, runner=helm,
                                  which=_which)  # fmt: skip
    assert helm.calls == [["/usr/bin/helm", "uninstall", "fabric", "--namespace", NS, "--wait"]]
    assert _ids(report.findings) == ["FC-149"]
    helm = FakeHelm()
    report, _ = _kubecmd.run_down(_options("down", "--kubernetes", "--purge"), {}, runner=helm,
                                  which=_which, cluster=_c(_healthy()))  # fmt: skip
    deletes = [argv for argv in helm.calls if "delete" in argv]
    assert [argv[argv.index("--namespace") + 1] for argv in deletes] == [NS, AGENTS]
    for argv in deletes:
        assert argv[1:3] == ["delete", "secret"]
        selector = argv[argv.index("--selector") + 1]
        assert (
            selector
            == "app.kubernetes.io/managed-by=fabric-cli,fabric.singleaxis.ai/release=fabric"
        )
    assert "FC-144" in _ids(report.findings)


def test_down_of_a_release_that_is_not_there_says_so() -> None:
    helm = FakeHelm(
        code=1, stderr="Error: uninstall: Release not loaded: fabric: release: not found"
    )
    with pytest.raises(CliError) as caught:
        _kubecmd.run_down(_options("down", "--kubernetes"), {}, runner=helm, which=_which)
    assert caught.value.findings[0].id == "FC-122"


def test_kubernetes_commands_never_name_a_workload_verb() -> None:
    """I5: no code path of the Kubernetes commands rolls out, restarts, scales, execs into
    or deletes anything but Fabric's own release and labelled Secrets."""
    source = Path(_kubecmd.__file__).read_text() + Path(_kubeview.__file__).read_text()
    source += Path(_kubectl.__file__).read_text()
    for verb in ("rollout", "scale", "exec", "patch", "apply", "annotate", "cordon", "drain"):
        assert not re.search(rf'"{verb}"', source), verb
    assert source.count('"delete"') == 1  # the labelled Secrets of --purge


def test_cli_dispatches_kubernetes_forms(monkeypatch: pytest.MonkeyPatch,
                                         capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    called: list[str] = []
    for name in ("run_plan", "run_up", "run_down", "run_verify", "run_doctor"):

        def handler(*args: Any, _name: str = name, **kwargs: Any) -> Any:
            called.append(_name)
            from fabric.cli._report import Report  # noqa: PLC0415

            return Report(_name), []

        monkeypatch.setattr(_kubecmd, name, handler)
    for command in ("plan", "up", "down", "verify", "doctor"):
        cli.main([command, "--kubernetes", "--quiet"])
    assert called == ["run_plan", "run_up", "run_down", "run_verify", "run_doctor"]


def test_the_commands_row_names_the_fix_only_where_the_exec_hook_is_off() -> None:
    """With the host sensor the chart turns the exec hook on, so a run without commands is
    ``not observed`` (and why that matters to the sensor's join), not a fix to apply."""
    run: dict[str, Any] = {"chains": {"effects": {"verdict": "not_observed"},
                                      "corroboration": {"verdict": "complete"}}}  # fmt: skip
    chains = {"decisions": "complete"}
    rows = {r.question: r for r in _kubecmd._coverage(_kubeview.Install(_install()), run,
                                                      chains, 2)}  # fmt: skip
    row = rows["commands the agent ran"]
    assert row.state == "not observed" and "FABRIC_WIRE_EXEC" in row.note
    assert rows["host evidence (kernel sensor)"].state == "recorded"
    off = _kubeview.Install(_install(hostSensor={"enabled": False}))
    row = {r.question: r for r in _kubecmd._coverage(off, run, chains, 2)}[
        "commands the agent ran"]  # fmt: skip
    assert row.state == "fix" and "injector.env.FABRIC_WIRE_EXEC=1" in row.note
