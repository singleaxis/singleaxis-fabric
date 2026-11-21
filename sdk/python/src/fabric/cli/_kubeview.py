# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""What a Fabric release looks like in a cluster, as ``fabric verify --kubernetes`` and
``fabric doctor --kubernetes`` judge it (spec 058 §5.7, §10.6).

Everything here reads through :class:`fabric.cli._kubectl.Cluster` (``kubectl get`` and
``kubectl logs`` only): no ``exec`` into a pod, no change to any object. Each check
returns catalogue findings whose detail names the object, never a secret value.

The release describes itself in the ``fabric.install-info/v1`` ConfigMap the chart
renders with a preset (names and ports only): the Node's Service, the Secrets the
secrets Job generates, the agent namespaces, the injector and the host sensor."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ._kubectl import Cluster, Forbidden, NotFound
from ._report import EXIT_FINDINGS, CliError, Finding

INSTALL_SELECTOR = "fabric.singleaxis.ai/install-info=true"
INSTALL_SCHEMA = "fabric.install-info/v1"
DEFAULT_NAMESPACE = "fabric-system"
INJECT = "fabric.singleaxis.ai/inject"
INJECTED = "fabric.singleaxis.ai/injected"
SKIPPED = "fabric.singleaxis.ai/inject-skipped"
INJECTION_LABEL = "fabric.singleaxis.ai/injection"
SENSOR_APP = "fabric-host-emitter"
NODE_APP = "otel-collector"
SPOOL_VOLUME = "fabric-spool"
DRAIN = "FABRIC_WIRE_DRAIN_ON_EXIT_S"
#: RuntimeClass handlers whose pods never reach the node's kernel tracepoints (the
#: emitter's own list, components/host-emitter/podscope.go).
_SANDBOX_HANDLER = re.compile(r"^(runsc(-.*)?|gvisor|kata(-.*)?)$")
#: Node labels of a node no DaemonSet pod can run on (the chart's list).
VIRTUAL_NODE_LABELS = {
    "eks.amazonaws.com/compute-type": "fargate",
    "type": "virtual-kubelet",
    "kubernetes.azure.com/mode": "virtual",
}
_FIELD = re.compile(r"\b([a-z][a-z0-9_]*)=(\"(?:[^\"\\]|\\.)*\"|\S+)")
_MAX_NAMED = 8
#: The oldest kernel whose tracepoint programs the emitter loads (CAP_BPF, BTF).
MIN_KERNEL = (5, 8)


@dataclass
class Install:
    """One Fabric release, from its install-info ConfigMap."""

    info: dict[str, Any]

    @property
    def namespace(self) -> str:
        return str(self.info.get("namespace") or DEFAULT_NAMESPACE)

    @property
    def release(self) -> str:
        return str(self.info.get("release") or "fabric")

    @property
    def production(self) -> bool:
        return bool(self.info.get("production"))

    @property
    def agents(self) -> list[dict[str, Any]]:
        return [a for a in self.info.get("agentNamespaces") or [] if isinstance(a, dict)]

    @property
    def injector(self) -> dict[str, Any]:
        found = self.info.get("injector")
        return found if isinstance(found, dict) else {}

    @property
    def sensor(self) -> dict[str, Any]:
        found = self.info.get("hostSensor")
        return found if isinstance(found, dict) else {}

    @property
    def node(self) -> dict[str, Any]:
        found = self.info.get("node")
        return found if isinstance(found, dict) else {}

    @property
    def sensor_nodes(self) -> list[dict[str, Any]]:
        return [n for n in self.sensor.get("nodes") or [] if isinstance(n, dict)]

    def summary(self) -> str:
        preset = self.info.get("preset") or "none"
        return (
            f"release {self.release} in namespace {self.namespace}: preset {preset}, chart "
            f"{self.info.get('version', '?')}, tenant {self.info.get('tenantId') or '-'}"
        )


@dataclass
class View:
    """What the checks found: findings, the lines printed above them, and ``--json`` data."""

    findings: list[Finding] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def skipped(self, what: str, exc: Forbidden) -> None:
        self.findings.append(Finding("FC-147", f"{what}: {str(exc)[:200]}"))


def find_install(cluster: Cluster, namespace: str | None) -> Install:
    """The release's install-info: in ``namespace``, else the only one in the cluster
    (``fabric-system`` when the identity may not list across namespaces). ``FC-122``
    when there is none, or more than one and no ``--namespace`` chose."""
    try:
        if namespace:
            found = cluster.items("configmap", namespace, INSTALL_SELECTOR)
        else:
            try:
                found = cluster.items("configmap", None, INSTALL_SELECTOR, all_namespaces=True)
            except Forbidden:
                found = cluster.items("configmap", DEFAULT_NAMESPACE, INSTALL_SELECTOR)
    except Forbidden as exc:
        raise CliError(
            [Finding("FC-102", f"configmaps in {namespace or DEFAULT_NAMESPACE}: {exc}"[:300])],
            EXIT_FINDINGS,
        ) from None
    installs = []
    for item in found:
        try:
            info = json.loads((item.get("data") or {}).get("info.json") or "")
        except ValueError:
            continue
        if isinstance(info, dict) and info.get("schema") == INSTALL_SCHEMA:
            installs.append(Install(info))
    if not installs:
        where = f"namespace {namespace}" if namespace else "any namespace"
        raise CliError([Finding("FC-122", f"none in {where}")], EXIT_FINDINGS)
    if len(installs) > 1:
        names = ", ".join(sorted(f"{i.namespace}/{i.release}" for i in installs))
        raise CliError(
            [Finding("FC-122", f"several releases ({names}): choose one with --namespace")],
            EXIT_FINDINGS,
        )
    return installs[0]


# ---------------------------------------------------------------- small readers


def _labels(item: Mapping[str, Any]) -> dict[str, str]:
    found = (item.get("metadata") or {}).get("labels") or {}
    return {str(k): str(v) for k, v in found.items()}


def _annotations(item: Mapping[str, Any]) -> dict[str, str]:
    found = (item.get("metadata") or {}).get("annotations") or {}
    return {str(k): str(v) for k, v in found.items()}


def _name(item: Mapping[str, Any]) -> str:
    return str((item.get("metadata") or {}).get("name") or "")


def _created(item: Mapping[str, Any]) -> str:
    return str((item.get("metadata") or {}).get("creationTimestamp") or "")


def pod_ready(pod: Mapping[str, Any]) -> bool:
    conditions = (pod.get("status") or {}).get("conditions") or []
    return any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions)


def pod_state(pod: Mapping[str, Any]) -> str:
    """A pod's state in a few words: its phase, and the reason a container is waiting or
    was last terminated (``CrashLoopBackOff``, ``ImagePullBackOff``, ``Error``)."""
    status = pod.get("status") or {}
    words = [str(status.get("phase") or "Unknown")]
    for container in status.get("containerStatuses") or []:
        state = container.get("state") or {}
        for kind in ("waiting", "terminated"):
            reason = (state.get(kind) or {}).get("reason")
            if reason:
                words.append(str(reason))
        if container.get("restartCount"):
            words.append(f"{container['restartCount']} restart(s)")
    return ", ".join(dict.fromkeys(words))


def _last_line(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-1][:300] if lines else "no log output"


def _named(names: Sequence[str]) -> str:
    shown = ", ".join(names[:_MAX_NAMED])
    return shown + (f" and {len(names) - _MAX_NAMED} more" if len(names) > _MAX_NAMED else "")


def selects(selector: Mapping[str, Any] | None, labels: Mapping[str, str]) -> bool:
    """Whether a Kubernetes label selector selects ``labels`` (an empty selector selects
    everything)."""
    selector = selector or {}
    for key, value in (selector.get("matchLabels") or {}).items():
        if labels.get(str(key)) != str(value):
            return False
    for expression in selector.get("matchExpressions") or []:
        key, operator = str(expression.get("key")), expression.get("operator")
        values = [str(v) for v in expression.get("values") or []]
        present = key in labels
        ok = {
            "In": present and labels.get(key) in values,
            "NotIn": not present or labels.get(key) not in values,
            "Exists": present,
            "DoesNotExist": not present,
        }.get(str(operator), False)
        if not ok:
            return False
    return True


# ---------------------------------------------------------------- Secrets


def check_secrets(cluster: Cluster, install: Install, view: View) -> None:
    """Every Secret the release mounts exists with the keys it reads (by key name: no
    value is read)."""
    wanted: list[tuple[str, str, tuple[str, ...]]] = [
        (install.namespace, str(name), ()) for name in install.info.get("secrets") or []
    ]
    for agent in install.agents:
        keys = ("ca.crt", "id.key") + (("headers",) if install.production else ())
        wanted.append((str(agent.get("name")), str(agent.get("secret") or "fabric-agent"), keys))
        if install.production and agent.get("nodeSecret"):
            wanted.append((install.namespace, str(agent["nodeSecret"]), ("token", "source-id")))
    for node in install.sensor_nodes:
        wanted.append(
            (install.namespace, str(node.get("secret")), ("token", "state-key", "source-id"))
        )
    missing = 0
    for namespace, name, keys in dict.fromkeys(wanted):
        try:
            found = cluster.secret_keys(namespace, name)
        except Forbidden as exc:
            view.skipped(f"Secret {namespace}/{name}", exc)
            continue
        if found is None:
            missing += 1
            view.findings.append(Finding("FC-125", f"{namespace}/{name} does not exist"))
        elif [key for key in keys if key not in found]:
            missing += 1
            lacking = ", ".join(key for key in keys if key not in found)
            view.findings.append(Finding("FC-125", f"{namespace}/{name} lacks {lacking}"))
    view.data["secrets"] = {"checked": len(dict.fromkeys(wanted)), "missing": missing}
    view.lines.append(
        f"secrets: {len(dict.fromkeys(wanted)) - missing} of {len(dict.fromkeys(wanted))} present"
    )


# ---------------------------------------------------------------- the Node


def node_pods(cluster: Cluster, install: Install) -> list[dict[str, Any]]:
    selector = f"app.kubernetes.io/name={NODE_APP},app.kubernetes.io/instance={install.release}"
    return cluster.items("pods", install.namespace, selector)


def check_node(
    cluster: Cluster, install: Install, view: View, probe: Callable[[int], bool] | None = None
) -> list[dict[str, Any]]:
    """The Node's pods are ready and, through a port-forward that is closed again, its
    health endpoint answers. Returns the Node's pods."""
    try:
        pods = node_pods(cluster, install)
    except Forbidden as exc:
        view.skipped(f"pods in {install.namespace}", exc)
        return []
    ready = [pod for pod in pods if pod_ready(pod)]
    view.data["node"] = {"pods": len(pods), "ready": len(ready)}
    view.lines.append(f"node: {len(ready)} of {len(pods)} pod(s) ready")
    if not ready:
        if not pods:
            view.findings.append(
                Finding("FC-126", f"no Node pod of release {install.release} exists")
            )
        for pod in pods[:2]:
            log = cluster.logs(install.namespace, _name(pod), tail=20) or cluster.logs(
                install.namespace, _name(pod), tail=20, previous=True
            )
            view.findings.append(
                Finding("FC-126", f"{_name(pod)}: {pod_state(pod)}; {_last_line(log)}")
            )
        return pods
    if probe is None:
        return pods
    port = int(install.node.get("healthPort") or 13133)
    try:
        with cluster.port_forward(install.namespace, f"pod/{_name(ready[0])}", port) as local:
            healthy = probe(local)
    except CliError as exc:
        view.findings.extend(exc.findings)
        return pods
    view.data["node"]["healthy"] = healthy
    if healthy:
        view.findings.append(Finding("FC-127", f"{len(ready)} pod(s) ready"))
    else:
        log = cluster.logs(install.namespace, _name(ready[0]), tail=20)
        view.findings.append(
            Finding("FC-126", f"{_name(ready[0])}: health endpoint not ok; {_last_line(log)}")
        )
    return pods


# ---------------------------------------------------------------- the injector and pods


def check_injector(cluster: Cluster, install: Install, view: View) -> bool | None:
    """The injector's Deployment has a ready pod, its webhook carries a caBundle, and
    every agent namespace is labelled. Returns whether the injector is available
    (None: not installed)."""
    if not install.agents:
        view.findings.append(Finding("FC-146", f"release {install.release}"))
    if not install.injector.get("enabled"):
        view.lines.append("injector: not installed (injector.enabled=false)")
        view.data["injector"] = {"enabled": False}
        return None
    name = str(install.injector.get("deployment"))
    available = False
    try:
        deployment = cluster.find("deployment", name, install.namespace)
        ready = int(((deployment or {}).get("status") or {}).get("readyReplicas") or 0)
        available = ready > 0
        if not available:
            wanted = ((deployment or {}).get("spec") or {}).get("replicas")
            view.findings.append(
                Finding(
                    "FC-129",
                    f"deployment {install.namespace}/{name}: "
                    + ("does not exist" if deployment is None else f"0 of {wanted} ready"),
                )
            )
    except Forbidden as exc:
        view.skipped(f"deployment {install.namespace}/{name}", exc)
    webhook_name = str(install.injector.get("webhook"))
    try:
        webhook = cluster.find("mutatingwebhookconfiguration", webhook_name)
        hooks = (webhook or {}).get("webhooks") or []
        if webhook is None:
            view.findings.append(Finding("FC-145", f"{webhook_name} does not exist"))
        elif not hooks or not all((h.get("clientConfig") or {}).get("caBundle") for h in hooks):
            view.findings.append(Finding("FC-145", webhook_name))
    except Forbidden as exc:
        view.skipped(f"mutatingwebhookconfiguration {webhook_name}", exc)
    unlabelled = []
    for agent in install.agents:
        try:
            namespace = cluster.find("namespace", str(agent.get("name")))
        except Forbidden as exc:
            view.skipped(f"namespace {agent.get('name')}", exc)
            continue
        if namespace is None:
            view.findings.append(Finding("FC-101", str(agent.get("name"))))
        elif _labels(namespace).get(INJECTION_LABEL) != "enabled":
            unlabelled.append(str(agent.get("name")))
            view.findings.append(Finding("FC-132", str(agent.get("name"))))
    if install.production and not install.injector.get("capturePolicy"):
        # Without a capture policy a production SDK keeps model bodies out (FW-008), so
        # decisions cannot be verified however content is delivered.
        view.findings.append(Finding("FC-155", "injector.capturePolicy is empty"))
    view.data["injector"] = {"enabled": True, "available": available, "unlabelled": unlabelled}
    view.lines.append("injector: " + ("available" if available else "not available"))
    return available


def agent_pods(cluster: Cluster, install: Install, view: View) -> list[dict[str, Any]]:
    pods: list[dict[str, Any]] = []
    for agent in install.agents:
        try:
            pods.extend(cluster.items("pods", str(agent.get("name"))))
        except Forbidden as exc:
            view.skipped(f"pods in {agent.get('name')}", exc)
    return pods


def _why_not_injected(
    pod: Mapping[str, Any], install: Install, available: bool | None, unlabelled: Iterable[str],
    injector_created: str,
) -> str:  # fmt: skip
    namespace = str((pod.get("metadata") or {}).get("namespace") or "")
    if available is None:
        return "the injector is not installed (injector.enabled=true installs it)"
    if namespace in set(unlabelled):
        return f"namespace {namespace} lacks the label {INJECTION_LABEL}=enabled"
    if injector_created and _created(pod) and _created(pod) < injector_created:
        return "it was created before the injector was installed"
    if not available:
        return (
            "the injector has no ready pod, so the webhook was skipped after its 2 s "
            "timeout (failurePolicy Ignore)"
        )
    return (
        "the webhook did not answer within its 2 s timeout when the pod was created "
        "(failurePolicy Ignore); the injector's log says more"
    )


def check_pods(
    cluster: Cluster, install: Install, view: View, available: bool | None,
    pods: Sequence[Mapping[str, Any]], *, one_shot: bool = False,
) -> None:  # fmt: skip
    """Pods that ask for injection: injected, skipped with the injector's own reason, or
    not injected, with why. ``one_shot``: also the pods whose ``emptyDir`` spool is lost
    when they exit (S7)."""
    unlabelled = (view.data.get("injector") or {}).get("unlabelled") or []
    injector_created = ""
    if install.injector.get("enabled"):
        try:
            deployment = cluster.find(
                "deployment", str(install.injector.get("deployment")), install.namespace
            )
            injector_created = _created(deployment or {})
        except Forbidden:
            injector_created = ""
    asked = [pod for pod in pods if INJECT in _annotations(pod)]
    injected, problems = 0, 0
    lost: list[str] = []
    for pod in asked:
        notes = _annotations(pod)
        where = f"{(pod.get('metadata') or {}).get('namespace')}/{_name(pod)}"
        if INJECTED in notes:
            injected += 1
            if one_shot and _one_shot_emptydir(pod):
                lost.append(where)
            continue
        problems += 1
        if problems > _MAX_NAMED:
            continue
        if SKIPPED in notes:
            why = f"the injector skipped it: {notes[SKIPPED]}"
        else:
            why = _why_not_injected(pod, install, available, unlabelled, injector_created)
        view.findings.append(Finding("FC-130", f"{where}: {why}"))
    if problems > _MAX_NAMED:
        view.findings.append(Finding("FC-130", f"and {problems - _MAX_NAMED} more pod(s)"))
    if injected and not problems:
        view.findings.append(Finding("FC-131", f"{injected} pod(s)"))
    if lost:
        view.findings.append(Finding("FC-140", _named(lost)))
    view.data["pods"] = {"annotated": len(asked), "injected": injected, "not_injected": problems}
    view.lines.append(f"agent pods: {len(asked)} annotated, {injected} injected")


def _one_shot_emptydir(pod: Mapping[str, Any]) -> bool:
    spec = pod.get("spec") or {}
    owners = (pod.get("metadata") or {}).get("ownerReferences") or []
    once = spec.get("restartPolicy") in ("Never", "OnFailure") or any(
        owner.get("kind") == "Job" for owner in owners
    )
    spool = any(
        volume.get("name") == SPOOL_VOLUME and "emptyDir" in volume
        for volume in spec.get("volumes") or []
    )
    drains = any(
        entry.get("name") == DRAIN
        for container in spec.get("containers") or []
        for entry in container.get("env") or []
    )
    return bool(once and spool and not drains)


# ---------------------------------------------------------------- the host sensor


def parse_fields(line: str) -> dict[str, str]:
    """The ``key=value`` fields of an emitter log line (a quoted value keeps its spaces)."""
    out = {}
    for key, value in _FIELD.findall(line):
        out[key] = value[1:-1] if value.startswith('"') else value
    return out


@dataclass
class SensorLog:
    """What one sensor pod's log says about its node."""

    scope: dict[str, int] | None = None  # pods_selected, pods_scoped, pods_unscoped_<reason>
    export_code: str | None = None  # the gRPC code of an export that is failing now
    node_supported: bool = True

    @property
    def unscoped(self) -> dict[str, int]:
        prefix = "pods_unscoped_"
        return {
            key[len(prefix) :]: count
            for key, count in (self.scope or {}).items()
            if key.startswith(prefix) and count > 0
        }


def read_sensor_log(text: str) -> SensorLog:
    """The last pod-scope counters (the health line, or the ``pod scope`` line a change is
    logged with), whether exports fail now (a retry line after the last health line but
    one), and the node-not-supported line the emitter exits with."""
    out = SensorLog()
    health_seen = 0
    for line in reversed(text.splitlines()):
        if "fabric-host-emitter:" not in line:
            continue
        if "node_supported=false" in line:
            out.node_supported = False
        if " health " in line or " pod scope " in line:
            if out.scope is None and "pods_selected=" in line:
                fields = parse_fields(line)
                out.scope = {
                    key: int(value)
                    for key, value in fields.items()
                    if key.startswith("pods_") and value.isdigit()
                }
            if " health " in line:
                health_seen += 1
        elif "export retry pending" in line and health_seen < 2 and out.export_code is None:  # noqa: PLR2004
            out.export_code = parse_fields(line).get("grpc_code") or "unknown"
    return out


def check_sensor(cluster: Cluster, install: Install, view: View) -> None:
    """Per node of the release: the sensor's pod runs, what it scopes and what it cannot
    (``pods_unscoped`` by reason), and whether its exports reach the Node."""
    if not install.sensor.get("enabled"):
        view.lines.append("host sensor: not installed (hostSensor.enabled=false)")
        view.data["sensor"] = {"enabled": False}
        return
    selector = f"app.kubernetes.io/name={SENSOR_APP},app.kubernetes.io/instance={install.release}"
    try:
        pods = cluster.items("pods", install.namespace, selector)
    except Forbidden as exc:
        view.skipped(f"pods in {install.namespace}", exc)
        return
    by_node = {str((pod.get("spec") or {}).get("nodeName")): pod for pod in pods}
    nodes: dict[str, Any] = {}
    for entry in install.sensor_nodes:
        node = str(entry.get("name"))
        pod = by_node.get(node)
        if pod is None:
            nodes[node] = {"running": False}
            view.findings.append(Finding("FC-133", f"node {node}: no sensor pod is scheduled"))
            continue
        log = cluster.logs(install.namespace, _name(pod), tail=400)
        if not pod_ready(pod):
            previous = cluster.logs(install.namespace, _name(pod), tail=50, previous=True)
            unsupported = not read_sensor_log(previous or log).node_supported
            nodes[node] = {"running": False, "node_supported": not unsupported}
            view.findings.append(
                Finding(
                    "FC-133",
                    f"node {node}: {pod_state(pod)}; "
                    + (
                        "node_not_supported: its BPF programs cannot load on this node"
                        if unsupported
                        else _last_line(previous or log)
                    ),
                )
            )
            continue
        seen = read_sensor_log(log)
        scope = seen.scope or {}
        nodes[node] = {
            "running": True,
            "pods_selected": scope.get("pods_selected"),
            "pods_scoped": scope.get("pods_scoped"),
            "pods_unscoped": seen.unscoped,
            "export_error": seen.export_code,
        }
        for reason, count in seen.unscoped.items():
            view.findings.append(Finding("FC-134", f"node {node}: {count} pod(s), {reason}"))
        if scope.get("pods_runtime_unknown"):
            nodes[node]["pods_runtime_unknown"] = scope["pods_runtime_unknown"]
            view.findings.append(
                Finding("FC-156", f"node {node}: {scope['pods_runtime_unknown']} pod(s)")
            )
        if seen.export_code:
            view.findings.append(Finding("FC-135", f"node {node}: grpc_code={seen.export_code}"))
        counts = (
            f"pods_selected={scope.get('pods_selected')} pods_scoped={scope.get('pods_scoped')}"
            if seen.scope is not None
            else "no health line yet (it logs one every 30 s)"
        )
        view.lines.append(f"host sensor on {node}: {counts}")
        if (seen.scope is not None and not seen.unscoped and not seen.export_code
                and not scope.get("pods_runtime_unknown")):  # fmt: skip
            view.findings.append(Finding("FC-136", f"node {node}: {counts}"))
    view.data["sensor"] = {"enabled": True, "nodes": nodes}


# ---------------------------------------------------------------- nodes and runtimes


def kernel_version(text: str) -> tuple[int, int] | None:
    found = re.match(r"(\d+)\.(\d+)", text or "")
    return (int(found[1]), int(found[2])) if found else None


def node_sensor_reason(node: Mapping[str, Any]) -> str | None:
    """Why the host sensor cannot run on ``node``, or None when it can."""
    labels = _labels(node)
    info = (node.get("status") or {}).get("nodeInfo") or {}
    system = str(labels.get("kubernetes.io/os") or info.get("operatingSystem") or "linux")
    if system != "linux":
        return f"its operating system is {system}"
    for key, value in VIRTUAL_NODE_LABELS.items():
        if labels.get(key) == value:
            return f"it is a serverless or virtual node ({key}={value}): no DaemonSet runs there"
    kernel = kernel_version(str(info.get("kernelVersion") or ""))
    if kernel is not None and kernel < MIN_KERNEL:
        return f"its kernel is {info.get('kernelVersion')} (the sensor needs 5.8 or later with BTF)"
    return None


def sandbox_runtime_classes(cluster: Cluster, view: View) -> list[tuple[str, str]]:
    """The RuntimeClasses whose handler is gVisor or Kata: (name, handler)."""
    try:
        classes = cluster.items("runtimeclasses")
    except Forbidden as exc:
        view.skipped("runtimeclasses", exc)
        return []
    return [
        (_name(item), str(item.get("handler")))
        for item in classes
        if _SANDBOX_HANDLER.match(str(item.get("handler") or "").strip().lower())
    ]


def check_runtime_classes(cluster: Cluster, install: Install, view: View) -> None:
    if not install.sensor.get("enabled"):
        return
    found = sandbox_runtime_classes(cluster, view)
    view.data["runtime_classes"] = [name for name, _ in found]
    if found:
        view.findings.append(
            Finding("FC-138", ", ".join(f"{name} (handler {handler})" for name, handler in found))
        )


def check_nodes(cluster: Cluster, install: Install, view: View) -> None:
    """Nodes of the cluster the sensor does not cover: one that cannot run it, or one
    that joined after the install (it gets its Secret at the next ``helm upgrade``)."""
    if not install.sensor.get("enabled"):
        return
    try:
        nodes = cluster.items("nodes")
    except Forbidden as exc:
        view.skipped("nodes", exc)
        return
    listed = {str(entry.get("name")) for entry in install.sensor_nodes}
    for node in nodes:
        if _name(node) in listed:
            continue
        reason = node_sensor_reason(node) or "it is not in the release's node list"
        view.findings.append(Finding("FC-139", f"node {_name(node)}: {reason}"))


# ---------------------------------------------------------------- NetworkPolicies (F5)


def _allows(policies: Sequence[Mapping[str, Any]], labels: Mapping[str, str], direction: str,
            port: int) -> bool | None:  # fmt: skip
    """Whether pods with ``labels`` may send (``Egress``) or receive (``Ingress``) on TCP
    ``port``, by the namespace's NetworkPolicies alone: None when no policy isolates them
    in that direction, True when a selecting policy has a rule for the port or a named port
    (peers are not judged), False when they are isolated and no rule names the port."""
    isolated = False
    for policy in policies:
        spec = policy.get("spec") or {}
        if not selects(spec.get("podSelector"), labels):
            continue
        types = spec.get("policyTypes") or (["Ingress"] + (["Egress"] if "egress" in spec else []))
        if direction not in types:
            continue
        isolated = True
        for rule in spec.get(direction.lower()) or []:
            ports = rule.get("ports") or []
            if not ports:
                return True
            for entry in ports:
                first, last = entry.get("port"), entry.get("endPort")
                if first is None or first == port:
                    return True
                if isinstance(first, str) and not first.isdigit():
                    # A named port resolves against the pods' container ports, which
                    # this check does not read: never call it blocked.
                    return True
                if isinstance(first, str):
                    first = int(first)
                    if first == port:
                        return True
                if isinstance(first, int) and isinstance(last, int) and first <= port <= last:
                    return True
    return False if isolated else None


def check_network_policies(cluster: Cluster, install: Install, view: View) -> None:
    """The NetworkPolicies that select Fabric's pods leave the paths records travel open:
    host sensor to its Node port, the Node's ingress on those ports, and, in an agent
    namespace with an egress default-deny, the agents' Node port."""
    try:
        policies = cluster.items("networkpolicies", install.namespace)
    except Forbidden as exc:
        view.skipped(f"networkpolicies in {install.namespace}", exc)
        return
    node_labels = {
        "app.kubernetes.io/name": NODE_APP,
        "app.kubernetes.io/instance": install.release,
    }
    sensor_labels = {
        "app.kubernetes.io/name": SENSOR_APP,
        "app.kubernetes.io/instance": install.release,
        "app.kubernetes.io/component": "host-sensor",
    }
    blocked: list[str] = []
    if install.sensor.get("enabled"):
        for entry in install.sensor_nodes:
            port = int(entry.get("port") or 0)
            if _allows(policies, sensor_labels, "Egress", port) is False:
                blocked.append(f"host sensor egress to the Node on TCP {port}")
            if _allows(policies, node_labels, "Ingress", port) is False:
                blocked.append(f"Node ingress on TCP {port} (host sensor of {entry.get('name')})")
    content = bool(install.node.get("content"))
    for agent in install.agents:
        # The group's content port is served (and opened by the chart) only with content
        # delivery on: without it nothing listens there and nothing needs to pass.
        ports = [int(p) for name, p in (agent.get("ports") or {}).items()
                 if isinstance(p, int) and (content or name != "content")]  # fmt: skip
        for port in ports or [4318]:
            if _allows(policies, node_labels, "Ingress", port) is False:
                blocked.append(f"Node ingress on TCP {port} (agents of {agent.get('name')})")
        try:
            own = cluster.items("networkpolicies", str(agent.get("name")))
        except Forbidden as exc:
            view.skipped(f"networkpolicies in {agent.get('name')}", exc)
            continue
        default_deny = [
            p for p in own
            if not ((p.get("spec") or {}).get("podSelector") or {})
            and "Egress" in ((p.get("spec") or {}).get("policyTypes") or [])
        ]  # fmt: skip
        for port in ports or [4318]:
            if default_deny and _allows(own, {}, "Egress", port) is False:
                blocked.append(
                    f"egress of namespace {agent.get('name')} to the Node on TCP {port} "
                    f"(policy {_name(default_deny[0])})"
                )
    for what in dict.fromkeys(blocked):
        view.findings.append(Finding("FC-137", what))
    view.data["network_policies"] = {"release_namespace": len(policies), "blocked": blocked}


def gather(
    cluster: Cluster, install: Install, *, probe: Callable[[int], bool] | None = None,
    one_shot: bool = False,
) -> View:  # fmt: skip
    """Every check of §10.6, in its order."""
    view = View()
    view.lines.append(install.summary())
    view.data["release"] = {
        "name": install.release, "namespace": install.namespace,
        "preset": install.info.get("preset"), "version": install.info.get("version"),
        "production": install.production,
    }  # fmt: skip
    check_secrets(cluster, install, view)
    check_node(cluster, install, view, probe)
    available = check_injector(cluster, install, view)
    pods = agent_pods(cluster, install, view)
    check_pods(cluster, install, view, available, pods, one_shot=one_shot)
    check_sensor(cluster, install, view)
    check_runtime_classes(cluster, install, view)
    check_nodes(cluster, install, view)
    check_network_policies(cluster, install, view)
    view.data["agent_pods"] = pods  # for the reader's peers; removed before printing
    return view


__all__ = [
    "Install",
    "NotFound",
    "SensorLog",
    "View",
    "find_install",
    "gather",
    "kernel_version",
    "node_sensor_reason",
    "parse_fields",
    "read_sensor_log",
    "sandbox_runtime_classes",
    "selects",
]
