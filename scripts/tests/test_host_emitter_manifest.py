# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Host sensor deployment examples (spec 053 §6.2.8, §6.2.9; spec 056 §7.3.3 (c), (n)).

* ``deploy/kubernetes/host-emitter-daemonset.yaml`` is the production eBPF
  emitter: the production environment is complete (per-node source and host
  labels from ``spec.nodeName``, the per-node provisioning directory, the pod
  selector), the exact local-mode cgroup is gone, no secret value is in the
  manifest, credentials come from per-node hostPaths and Secret references,
  and its RBAC is only ``get``, ``list``, ``watch`` on ``pods``.
* ``deploy/kubernetes/auditd-sensor-collector.yaml`` is the auditd sensor
  collector: unprivileged, read-only on the audit log, and its configuration
  is the sensor-collector profile.
* ``scripts/qualification/check_host_emitter_manifest.py`` remains the static
  preflight of a spec 031 local-mode DaemonSet; its tests run on an inline
  local-mode manifest.
"""

from __future__ import annotations

import copy
import importlib.util
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from contracts import ingress_groups  # noqa: E402
from scripts.qualification.check_host_emitter_manifest import (  # noqa: E402
    UniqueKeyLoader,
    check_manifest,
)

EMITTER = ROOT / "deploy/kubernetes/host-emitter-daemonset.yaml"
SENSOR = ROOT / "deploy/kubernetes/auditd-sensor-collector.yaml"
IMAGE = "ghcr.io/singleaxis/fabric-host-emitter@sha256:" + "a" * 64
PROVISIONING = "/etc/fabric-host-emitter"
STATE = "/var/lib/fabric-host-emitter"
REVIEWED_CAPABILITIES = {"BPF", "PERFMON", "SYS_RESOURCE", "DAC_READ_SEARCH"}


def _documents(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    # One v1 List document per manifest; its items are the objects.
    (doc,) = list(yaml.load_all(text, Loader=UniqueKeyLoader))  # noqa: S506 - SafeLoader subclass
    assert doc["apiVersion"] == "v1" and doc["kind"] == "List"
    docs = doc["items"]
    assert all(isinstance(d, dict) for d in docs)
    return list(docs)


def _one(docs: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    (doc,) = [d for d in docs if d["kind"] == kind]
    return doc


def _emitter() -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    docs = _documents(EMITTER)
    pod = _one(docs, "DaemonSet")["spec"]["template"]["spec"]
    (container,) = pod["containers"]
    return docs, pod, container


def _env(container: dict[str, Any]) -> dict[str, dict[str, Any]]:
    names = [item["name"] for item in container["env"]]
    assert len(names) == len(set(names)), "duplicate environment keys"
    return {item["name"]: item for item in container["env"]}


# --------------------------------------------------------------------------
# The production eBPF emitter
# --------------------------------------------------------------------------


def test_production_environment_is_complete() -> None:
    _, _, container = _emitter()
    env = _env(container)
    values = {name: item.get("value") for name, item in env.items()}
    assert env["NODE_NAME"]["valueFrom"] == {"fieldRef": {"fieldPath": "spec.nodeName"}}
    # Dependent variables expand only names defined earlier in the list.
    order = [item["name"] for item in container["env"]]
    for name, value in values.items():
        for ref in re.findall(r"\$\((\w+)\)", value or ""):
            assert order.index(ref) < order.index(name), (name, ref)
    assert values["EMIT_PRODUCTION"] == "true"
    assert values["EMIT_SOURCE_LABEL"] == "$(NODE_NAME)/ebpf"
    assert values["EMIT_HOST_LABEL"] == "$(NODE_NAME)"
    assert values["EMIT_NODE_NAME"] == "$(NODE_NAME)"
    assert values["EMIT_AGENT_POD_SELECTOR"] == "fabric.singleaxis.ai/agent=true"
    assert values["EMIT_DEDUPE_WINDOW"] == "0"
    assert values["EMIT_DIGESTS"] in ("omitted", "permitted")
    assert values["EMIT_ALL_HOST"] == "false"
    assert values["EMIT_MAX_EVENTS_PER_SEC"] == "0"
    interval = re.fullmatch(r"(\d+)s", values["EMIT_HEARTBEAT_INTERVAL"] or "")
    assert interval and 1 <= int(interval.group(1)) <= 60
    # Production refuses the exact local-mode cgroup and an insecure
    # transport; the node's group comes from its provisioning directory.
    for refused in ("EMIT_CGROUP_PATH", "EMIT_ENDPOINT", "EMIT_INSECURE"):
        assert refused not in env
    assert values["EMIT_ENDPOINT_FILE"] == f"{PROVISIONING}/endpoint"
    assert values["EMIT_BEARER_TOKEN_FILE"] == f"{PROVISIONING}/token"
    assert values["EMIT_STATE_KEY_FILE"] == f"{PROVISIONING}/state_key"
    assert values["EMIT_ID_KEY_FILE"] == "/var/run/secrets/fabric-id-key/id_key"
    assert (values["EMIT_STATE_DIR"] or "").startswith(f"{STATE}/")
    assert (values["EMIT_SPOOL_DIR"] or "").startswith(f"{STATE}/")
    for name in ("EMIT_TLS_CA_FILE", "EMIT_TLS_CERT_FILE", "EMIT_TLS_KEY_FILE"):
        assert (values[name] or "").startswith("/var/run/secrets/fabric/")
    # Required in production and deliberately left for the operator.
    assert values["EMIT_TENANT_ID"] == ""


def test_every_file_the_environment_names_is_mounted() -> None:
    _, pod, container = _emitter()
    values = {name: item.get("value") or "" for name, item in _env(container).items()}
    mounts = {m["mountPath"]: m for m in container["volumeMounts"]}
    volumes = {v["name"]: v for v in pod["volumes"]}
    for name, value in values.items():
        if name.endswith(("_FILE", "_DIR")):
            assert any(
                value == p or value.startswith(p.rstrip("/") + "/") for p in mounts
            ), name
    provisioning = mounts[PROVISIONING]
    assert provisioning["readOnly"] is True
    assert volumes[provisioning["name"]]["hostPath"] == {
        "path": PROVISIONING,
        "type": "Directory",
    }
    state = mounts[STATE]
    assert not state.get("readOnly")
    assert volumes[state["name"]]["hostPath"] == {"path": STATE, "type": "Directory"}
    id_key = mounts["/var/run/secrets/fabric-id-key/id_key"]
    assert id_key["subPath"] == "id_key" and id_key["readOnly"] is True
    assert volumes[id_key["name"]]["secret"] == {
        "secretName": "fabric-wire-id-key",
        "defaultMode": 0o400,
        "items": [{"key": "id_key", "path": "id_key"}],
    }
    # A node without its directories fails visibly: nothing is created.
    for volume in pod["volumes"]:
        assert volume.get("hostPath", {}).get("type", "Directory") == "Directory"
    writable = [
        m["mountPath"] for m in container["volumeMounts"] if not m.get("readOnly")
    ]
    assert writable == [STATE]


def test_no_secret_is_in_the_manifest() -> None:
    docs, pod, container = _emitter()
    assert {d["kind"] for d in docs} == {
        "ServiceAccount",
        "ClusterRole",
        "ClusterRoleBinding",
        "DaemonSet",
    }
    assert all("data" not in d and "stringData" not in d for d in docs)
    for item in container["env"]:
        value = item.get("value", "")
        assert not re.search(r"[A-Za-z0-9+=_-]{32,}", value), item[
            "name"
        ]  # token-shaped
        if "valueFrom" in item:
            assert set(item["valueFrom"]) == {"fieldRef"}, "a secret value reaches env"
    # Tokens are per node (hostPath); no Secret every emitter pod reads holds one.
    secrets = sorted(v["secret"]["secretName"] for v in pod["volumes"] if "secret" in v)
    assert secrets == ["fabric-host-emitter-tls", "fabric-wire-id-key"]


def test_rbac_is_read_only_on_pods() -> None:
    docs, pod, container = _emitter()
    roles = [d for d in docs if d["kind"] in ("Role", "ClusterRole")]
    assert len(roles) == 1
    assert roles[0]["rules"] == [
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]}
    ]
    (binding,) = [d for d in docs if d["kind"] in ("RoleBinding", "ClusterRoleBinding")]
    assert binding["roleRef"] == {
        "apiGroup": "rbac.authorization.k8s.io",
        "kind": roles[0]["kind"],
        "name": roles[0]["metadata"]["name"],
    }
    account = _one(docs, "ServiceAccount")
    assert binding["subjects"] == [
        {
            "kind": "ServiceAccount",
            "name": account["metadata"]["name"],
            "namespace": account["metadata"]["namespace"],
        }
    ]
    assert pod["serviceAccountName"] == account["metadata"]["name"]
    # The token is projected into the emitter only, short-lived and read-only.
    assert account["automountServiceAccountToken"] is False
    assert pod["automountServiceAccountToken"] is False
    api = {m["name"]: m for m in container["volumeMounts"]}["api-access"]
    assert api == {
        "name": "api-access",
        "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
        "readOnly": True,
    }
    (projected,) = [v["projected"] for v in pod["volumes"] if v["name"] == "api-access"]
    token = projected["sources"][0]["serviceAccountToken"]
    assert token["path"] == "token" and token["expirationSeconds"] <= 3600


def test_emitter_privilege_is_the_reviewed_bounded_set() -> None:
    _, pod, container = _emitter()
    assert pod["hostPID"] is True and pod["hostNetwork"] is False
    assert "hostIPC" not in pod
    security = container["securityContext"]
    assert security.get("privileged", False) is False
    assert security["allowPrivilegeEscalation"] is False
    assert security["readOnlyRootFilesystem"] is True
    assert security["capabilities"]["drop"] == ["ALL"]
    assert set(security["capabilities"]["add"]) == REVIEWED_CAPABILITIES
    assert not any(
        t.get("operator") == "Exists" and not t.get("key")
        for t in pod.get("tolerations", [])
    )
    assert re.fullmatch(
        r"ghcr\.io/singleaxis/fabric-host-emitter@sha256:0{64}", container["image"]
    )


def test_dedicated_node_pool_note_sits_where_the_roots_are_set() -> None:
    text = EMITTER.read_text(encoding="utf-8")
    note = text.index("Dedicated node pool (spec 056")
    assert "EMIT_SANDBOX_CGROUP_ROOTS" in text[note : note + 400]
    assert "every workload on that node" in text[note : note + 600]
    roots = text.index("- name: EMIT_SANDBOX_CGROUP_ROOTS")
    assert "Dedicated node pool only" in text[roots - 300 : roots]


def test_generated_endpoint_names_the_chart_node_service() -> None:
    """The per-node endpoint the generator writes addresses the Service the chart
    renders for the documented install (release ``fabric`` in ``fabric-system``)."""
    if shutil.which("helm") is None:
        pytest.skip("helm not installed")
    spec = importlib.util.spec_from_file_location(
        "host_bindings", ROOT / "deploy/kubernetes/host-bindings.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    name, namespace, svc, *domain = module.DEFAULT_SERVICE.split(".")
    assert (svc, domain) == ("svc", ["cluster", "local"])
    docs, _, _ = _emitter()
    assert namespace == _one(docs, "DaemonSet")["metadata"]["namespace"]
    rendered = subprocess.run(
        ["helm", "template", "fabric", str(ROOT / "charts/fabric"), "-n", namespace],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    services = [d for d in yaml.safe_load_all(rendered) if d and d["kind"] == "Service"]
    assert [s for s in services if s["metadata"]["name"] == name]


# --------------------------------------------------------------------------
# The auditd sensor collector
# --------------------------------------------------------------------------


def test_sensor_collector_is_unprivileged_and_read_only() -> None:
    docs = _documents(SENSOR)
    assert {d["kind"] for d in docs} == {"ConfigMap", "DaemonSet"}
    pod = _one(docs, "DaemonSet")["spec"]["template"]["spec"]
    (container,) = pod["containers"]
    assert pod["automountServiceAccountToken"] is False
    assert pod["hostPID"] is False and pod["hostNetwork"] is False
    security = container["securityContext"]
    assert security["capabilities"] == {"drop": ["ALL"]}
    assert security["allowPrivilegeEscalation"] is False
    assert security["readOnlyRootFilesystem"] is True
    mounts = {m["mountPath"]: m for m in container["volumeMounts"]}
    assert mounts["/var/log/audit"]["readOnly"] is True
    writable = [
        m["mountPath"] for m in container["volumeMounts"] if not m.get("readOnly")
    ]
    assert writable == ["/var/lib/fabric-auditd-sensor"]
    for volume in pod["volumes"]:
        assert volume.get("hostPath", {}).get("type", "Directory") == "Directory"
    env = {item["name"]: item for item in container["env"]}
    assert env["FABRIC_SENSOR_SOURCE_LABEL"]["value"] == "$(NODE_NAME)/auditd"
    assert env["FABRIC_SENSOR_HOST_LABEL"]["value"] == "$(NODE_NAME)"
    assert container["args"] == [
        "--config=/etc/fabric-auditd-sensor-config/sensor-auditd.yaml",
        "--config=/etc/fabric-auditd-sensor/endpoint.yaml",
    ]


def test_sensor_collector_config_is_the_sensor_profile() -> None:
    config = yaml.safe_load(
        _one(_documents(SENSOR), "ConfigMap")["data"]["sensor-auditd.yaml"]
    )
    # The per-node endpoint.yaml, merged as the second --config.
    config["exporters"]["otlp_http/node"]["endpoint"] = (
        "https://node.example.invalid:4428"
    )
    assert ingress_groups.check(config, lambda _: None) is None
    assert config["receivers"]["audit"]["mode"] == "production"
    weakened = copy.deepcopy(config)
    weakened["receivers"]["otlp"] = {
        "protocols": {"grpc": {"endpoint": "127.0.0.1:4317"}}
    }
    assert ingress_groups.check(weakened, lambda _: None) == ingress_groups.ERRORS["s1"]


# --------------------------------------------------------------------------
# The spec 031 local-mode static preflight
# --------------------------------------------------------------------------

LOCAL_MODE = """
kind: DaemonSet
spec:
  template:
    spec:
      hostPID: true
      hostNetwork: false
      automountServiceAccountToken: false
      containers:
        - name: emitter
          image: IMAGE
          env:
            - {name: EMIT_TLS_CA_FILE, value: /var/run/secrets/fabric/ca.crt}
            - {name: EMIT_TLS_CERT_FILE, value: /var/run/secrets/fabric/tls.crt}
            - {name: EMIT_TLS_KEY_FILE, value: /var/run/secrets/fabric/tls.key}
            - {name: EMIT_BEARER_TOKEN_FILE, value: /var/run/secrets/fabric/emitter-token}
            - {name: EMIT_CGROUP_PATH, value: /sys/fs/cgroup/customer-agent}
            - {name: EMIT_ALL_HOST, value: "false"}
            - {name: EMIT_MAX_EVENTS_PER_SEC, value: "0"}
            - {name: EMIT_SPOOL_DIR, value: /var/lib/fabric-host-emitter}
            - {name: EMIT_SPOOL_MAX_BYTES, value: "1073741824"}
          securityContext:
            runAsUser: 0
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: {drop: [ALL], add: [BPF, PERFMON, SYS_RESOURCE, DAC_READ_SEARCH]}
          volumeMounts:
            - {name: btf, mountPath: /sys/kernel/btf, readOnly: true}
            - {name: cgroupfs, mountPath: /sys/fs/cgroup, readOnly: true}
            - {name: tracefs, mountPath: /sys/kernel/tracing, readOnly: true}
            - {name: debugfs, mountPath: /sys/kernel/debug, readOnly: true}
            - {name: emitter-credentials, mountPath: /var/run/secrets/fabric, readOnly: true}
            - {name: emitter-spool, mountPath: /var/lib/fabric-host-emitter}
      volumes:
        - name: emitter-credentials
          secret: {secretName: fabric-host-emitter-credentials, defaultMode: 0400}
        - name: emitter-spool
          hostPath: {path: /var/lib/fabric-host-emitter, type: Directory}
"""


def _local_shape() -> dict[str, Any]:
    loaded = yaml.safe_load(LOCAL_MODE.replace("IMAGE", IMAGE))
    assert isinstance(loaded, dict)
    return loaded


def test_filled_local_manifest_passes_static_preflight_only() -> None:
    assert check_manifest(_local_shape(), IMAGE) == []


def test_the_production_template_is_not_a_qualified_local_manifest() -> None:
    failures = check_manifest(_one(_documents(EMITTER), "DaemonSet"), IMAGE)
    assert any("placeholder" in item for item in failures)
    assert any("EMIT_CGROUP_PATH" in item for item in failures)


def test_mutable_image_and_wrong_approved_digest_fail() -> None:
    manifest = _local_shape()
    emitter = manifest["spec"]["template"]["spec"]["containers"][0]
    emitter["image"] = "ghcr.io/singleaxis/fabric-host-emitter:latest"
    assert any("sha256" in item for item in check_manifest(manifest, IMAGE))
    emitter["image"] = "ghcr.io/singleaxis/fabric-host-emitter@sha256:" + "b" * 64
    assert any("approved artifact" in item for item in check_manifest(manifest, IMAGE))


def test_missing_spool_credentials_and_scope_fail() -> None:
    manifest = copy.deepcopy(_local_shape())
    pod = manifest["spec"]["template"]["spec"]
    emitter = pod["containers"][0]
    emitter["env"] = [
        item
        for item in emitter["env"]
        if item["name"] not in {"EMIT_CGROUP_PATH", "EMIT_TLS_KEY_FILE"}
    ]
    emitter["volumeMounts"] = [
        item for item in emitter["volumeMounts"] if item["name"] != "emitter-spool"
    ]
    pod["volumes"] = [
        item for item in pod["volumes"] if item["name"] != "emitter-credentials"
    ]
    failures = check_manifest(manifest, IMAGE)
    assert any("EMIT_CGROUP_PATH" in item for item in failures)
    assert any("EMIT_TLS_KEY_FILE" in item for item in failures)
    assert any("emitter-spool" in item for item in failures)
    assert any("Secret" in item for item in failures)


def test_sampling_and_insecure_transport_fail() -> None:
    manifest = _local_shape()
    emitter = manifest["spec"]["template"]["spec"]["containers"][0]
    emitter["env"].extend(
        [
            {"name": "EMIT_INSECURE", "value": "true"},
            {"name": "EMIT_MAX_EVENTS_PER_SEC", "value": "20"},
        ]
    )
    failures = check_manifest(manifest, IMAGE)
    assert any("EMIT_INSECURE" in item for item in failures)
    assert any("rate limiting" in item for item in failures)


def test_duplicate_yaml_security_field_is_rejected() -> None:
    with pytest.raises(yaml.constructor.ConstructorError):
        yaml.load("kind: DaemonSet\nkind: Pod\n", Loader=UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass


def test_broad_node_schedule_and_public_credential_mode_fail() -> None:
    manifest = _local_shape()
    pod = manifest["spec"]["template"]["spec"]
    pod["tolerations"] = [{"operator": "Exists"}]
    for volume in pod["volumes"]:
        if volume["name"] == "emitter-credentials":
            volume["secret"]["defaultMode"] = 0o644
    failures = check_manifest(manifest, IMAGE)
    assert any("all-node toleration" in item for item in failures)
    assert any("mode 0400" in item for item in failures)
