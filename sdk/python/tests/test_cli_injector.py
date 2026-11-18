# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 WP8-13: the opt-in pod injector (§10.4) and its autoload shim.

Pinned: the webhook only ever allows; a patch only adds (variables the container does not
set, Fabric's own volumes and mounts, one annotation) and never replaces or removes
anything of the pod; a pod it should not or cannot change gets at most an annotation
saying why; any error is an empty patch. The shim uses the standard library, hands over
to the image's own SDK, chains to the image's own ``sitecustomize`` exactly once, leaves
the program's output and exit code unchanged, and records why when the SDK is absent."""

from __future__ import annotations

import ast
import base64
import copy
import dataclasses
import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from fabric.cli import _injector, _providers, _secrets
from fabric.wire._config import WireConfig

REPO = Path(__file__).resolve().parents[3]
SHIM = REPO / "charts/fabric/files/autoload/sitecustomize.py"
ENV = {
    "FABRIC_OTLP_ENDPOINT": "https://node.fabric-system.svc:4318",
    "FABRIC_WIRE_ID_KEY_FILE": "/var/run/fabric/secrets/id.key",
    "FABRIC_SOURCE_ID": "agents",
}
CONFIG = _injector.Config(version="0.12.1", namespaces={"agents": ENV})


def _pod(annotations: dict[str, str] | None = None, **spec: Any) -> dict[str, Any]:
    containers = spec.pop("containers", [{"name": "agent", "image": "agent:1"}])
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "p",
            "namespace": "agents",
            "annotations": {_injector.INJECT: "python"} if annotations is None else annotations,
        },
        "spec": {"containers": containers, **spec},
    }


def _request(
    pod: dict[str, Any], namespace: str = "agents", operation: str = "CREATE"
) -> dict[str, Any]:
    return {
        "uid": "u-1",
        "kind": {"group": "", "version": "v1", "kind": "Pod"},
        "operation": operation,
        "namespace": namespace,
        "object": pod,
    }


def _apply(document: dict[str, Any], ops: list[dict[str, Any]]) -> dict[str, Any]:
    """RFC 6902 ``add`` (the only operation the injector may use)."""
    out = copy.deepcopy(document)
    for op in ops:
        assert op["op"] == "add", op
        parts = [p.replace("~1", "/").replace("~0", "~") for p in op["path"].split("/")[1:]]
        node: Any = out
        for part in parts[:-1]:
            node = node[int(part)] if isinstance(node, list) else node[part]
        last = parts[-1]
        if isinstance(node, list):
            assert last == "-"
            node.append(op["value"])
        else:
            assert last not in node, f"add would replace {op['path']}"
            node[last] = op["value"]
    return out


def _contains(before: Any, after: Any) -> None:
    """Every value of ``before`` is still in ``after`` unchanged (lists only grow)."""
    if isinstance(before, dict):
        for key, value in before.items():
            assert key in after, key
            _contains(value, after[key])
    elif isinstance(before, list):
        assert len(after) >= len(before)
        for old, new in zip(before, after, strict=False):
            _contains(old, new)
    else:
        assert before == after


def _inject(pod: dict[str, Any], config: _injector.Config = CONFIG) -> tuple[dict[str, Any], str]:
    ops, outcome = _injector.plan_patch(_request(pod), config)
    after = _apply(pod, ops)
    _contains(pod, after)  # nothing of the pod is replaced or removed
    return after, outcome


def _env(container: dict[str, Any]) -> dict[str, str]:
    return {e["name"]: e.get("value") for e in container.get("env", [])}


# ---------------------------------------------------------------- the patch


def test_python_pod_gets_variables_secret_spool_and_shim() -> None:
    after, outcome = _inject(_pod())
    assert outcome == "injected"
    container = after["spec"]["containers"][0]
    assert _env(container) == {
        **ENV,
        "FABRIC_WIRE_AUTOLOAD": "1",
        "PYTHONPATH": "/var/run/fabric/autoload",
    }
    assert {m["mountPath"]: m.get("readOnly", False) for m in container["volumeMounts"]} == {
        "/var/run/fabric/secrets": True,
        "/var/lib/fabric": False,
        "/var/run/fabric/autoload": True,
    }
    volumes = {v["name"]: v for v in after["spec"]["volumes"]}
    assert volumes["fabric-secrets"]["secret"]["secretName"] == "fabric-agent"
    assert volumes["fabric-spool"] == {"name": "fabric-spool", "emptyDir": {"sizeLimit": "1Gi"}}
    assert volumes["fabric-autoload"]["configMap"]["name"] == "fabric-autoload"
    assert after["metadata"]["annotations"][_injector.INJECTED] == "0.12.1"


def test_env_mode_adds_no_autoload() -> None:
    after, _ = _inject(_pod({_injector.INJECT: "env"}))
    container = after["spec"]["containers"][0]
    assert _env(container) == ENV
    assert {v["name"] for v in after["spec"]["volumes"]} == {"fabric-secrets", "fabric-spool"}


def test_nothing_the_pod_sets_is_changed() -> None:
    container = {
        "name": "agent",
        "image": "agent:1",
        "command": ["python", "agent.py"],
        "args": ["-v"],
        "env": [{"name": "FABRIC_SOURCE_ID", "value": "mine"}, {"name": "API_KEY", "value": "k"}],
        "volumeMounts": [{"name": "data", "mountPath": "/data"}],
        "resources": {"limits": {"memory": "1Gi"}},
        "securityContext": {"runAsUser": 1000},
        "readinessProbe": {"exec": {"command": ["true"]}},
    }
    pod = _pod(
        containers=[container, {"name": "sidecar", "image": "s:1"}],
        volumes=[{"name": "data", "emptyDir": {}}],
        serviceAccountName="agent",
        initContainers=[{"name": "init", "image": "i:1"}],
    )
    after, _ = _inject(pod)
    first, second = after["spec"]["containers"]
    assert _env(first)["FABRIC_SOURCE_ID"] == "mine"  # never overridden
    assert [e["name"] for e in first["env"]].count("FABRIC_SOURCE_ID") == 1
    assert _env(second)["FABRIC_SOURCE_ID"] == "agents"
    for key in ("command", "args", "resources", "securityContext", "readinessProbe", "image"):
        assert first[key] == container[key]
    assert after["spec"]["initContainers"] == [{"name": "init", "image": "i:1"}]
    assert after["spec"]["serviceAccountName"] == "agent"
    assert len(after["spec"]["containers"]) == 2  # no container added


def test_a_pythonpath_in_the_pod_spec_is_kept_and_named() -> None:
    pod = _pod(containers=[{"name": "agent", "env": [{"name": "PYTHONPATH", "value": "/app"}]}])
    after, _ = _inject(pod)
    env = _env(after["spec"]["containers"][0])
    assert env["PYTHONPATH"] == "/app" and "FABRIC_WIRE_AUTOLOAD" not in env
    assert after["metadata"]["annotations"][_injector.NOTE] == "agent: pythonpath_in_pod_spec"


def test_pythonpath_annotation_and_env_from_keep_the_image_paths() -> None:
    pod = _pod(
        {_injector.INJECT: "python", _injector.PYTHONPATH_ANNOTATION: "/app:/lib"},
        containers=[{"name": "a", "envFrom": [{"configMapRef": {"name": "c"}}]}],
    )
    after, _ = _inject(pod)
    assert _env(after["spec"]["containers"][0])["PYTHONPATH"] == (
        "/var/run/fabric/autoload:/app:/lib:$(PYTHONPATH)"
    )


def test_a_setting_the_container_gives_by_value_keeps_its_file_twin_away() -> None:
    """The SDK refuses FABRIC_WIRE_ID_KEY together with FABRIC_WIRE_ID_KEY_FILE (FW-018):
    injecting the twin of a variable the container sets would turn its capture off."""
    by_value = [{"name": "FABRIC_WIRE_ID_KEY", "value": "the-container's-own-key"}]
    after, outcome = _inject(_pod(containers=[{"name": "agent", "env": list(by_value)}]))
    env = _env(after["spec"]["containers"][0])
    assert outcome == "injected"
    assert (
        "FABRIC_WIRE_ID_KEY_FILE" not in env and env["FABRIC_WIRE_ID_KEY"] == by_value[0]["value"]
    )
    assert env["FABRIC_OTLP_ENDPOINT"] == ENV["FABRIC_OTLP_ENDPOINT"]  # the rest still arrives
    # The reverse: a file the container names keeps a configured value away.
    config = _injector.Config(version="1", namespaces={"agents": {"FABRIC_OTLP_HEADERS": "a=b"}})
    by_file = [{"name": "FABRIC_OTLP_HEADERS_FILE", "value": "/etc/agent/headers"}]
    after, _ = _inject(_pod(containers=[{"name": "agent", "env": by_file}]), config)
    assert "FABRIC_OTLP_HEADERS" not in _env(after["spec"]["containers"][0])


def test_a_missing_secret_or_shim_never_keeps_the_pod_from_starting() -> None:
    """I3: the kubelet holds a pod in ContainerCreating while a required Secret or
    ConfigMap volume is missing (a namespace added before its Secret exists, a Secret
    deleted to regenerate it). Both injected sources are optional: the pod starts and the
    SDK leaves capture off."""
    after, _ = _inject(_pod())
    volumes = {v["name"]: v for v in after["spec"]["volumes"]}
    assert volumes[_injector.VOLUME_SECRETS]["secret"]["optional"] is True
    assert volumes[_injector.VOLUME_AUTOLOAD]["configMap"]["optional"] is True


def test_pvc_spool_by_annotation() -> None:
    after, _ = _inject(_pod({_injector.INJECT: "env", _injector.SPOOL: "pvc"}))
    volumes = {v["name"]: v for v in after["spec"]["volumes"]}
    assert volumes["fabric-spool"]["persistentVolumeClaim"] == {"claimName": "fabric-spool"}


def test_an_emptydir_spool_bounds_the_sdk_spool_under_the_volume_limit() -> None:
    """The kubelet evicts a pod whose emptyDir passes its sizeLimit. The SDK's default
    spool bound is 1 GiB, the volume's default limit too: without a smaller bound a
    spool that filled during a Node outage would cost the agent its pod."""
    config = dataclasses.replace(CONFIG, spool_max_bytes=268435456)
    after, _ = _inject(_pod(), config)
    assert _env(after["spec"]["containers"][0])["FABRIC_WIRE_SPOOL_MAX_BYTES"] == "268435456"
    # A claim has no limit the kubelet evicts for: the SDK keeps its own default.
    after, _ = _inject(_pod({_injector.INJECT: "env", _injector.SPOOL: "pvc"}), config)
    assert "FABRIC_WIRE_SPOOL_MAX_BYTES" not in _env(after["spec"]["containers"][0])
    # The container's own value is never changed.
    own = {"name": "agent", "env": [{"name": "FABRIC_WIRE_SPOOL_MAX_BYTES", "value": "70000000"}]}
    after, _ = _inject(_pod(containers=[own]), config)
    assert _env(after["spec"]["containers"][0])["FABRIC_WIRE_SPOOL_MAX_BYTES"] == "70000000"
    # A value from the chart's injector.env wins over the computed one.
    served = {"agents": {**ENV, "FABRIC_WIRE_SPOOL_MAX_BYTES": "99000000"}}
    after, _ = _inject(_pod(), dataclasses.replace(config, namespaces=served))
    assert _env(after["spec"]["containers"][0])["FABRIC_WIRE_SPOOL_MAX_BYTES"] == "99000000"


def test_the_spool_bound_is_read_from_the_chart_configuration() -> None:
    config = _injector.Config.from_json({"version": "1", "spoolMaxBytes": 268435456})
    assert config.spool_max_bytes == 268435456
    assert _injector.Config.from_json({"version": "1"}).spool_max_bytes == 0
    # The SDK accepts the bound the chart computes from its smallest allowed limit.
    smallest = (512 * 1024 * 1024) // 4
    WireConfig(spool_dir="/var/lib/fabric/spool", spool_max_bytes=smallest)


@pytest.mark.parametrize(
    ("pod", "namespace", "reason"),
    [
        (_pod({_injector.INJECT: "node"}), "agents", "node_not_available"),
        (_pod({_injector.INJECT: "ruby"}), "agents", "unknown_mode"),
        (_pod(), "other", "namespace_not_served"),
        (_pod(volumes=[{"name": "fabric-spool", "emptyDir": {}}]), "agents", "volume_name_taken"),
        (
            _pod(
                containers=[{"name": "a", "volumeMounts": [{"name": "x", "mountPath": "/var/lib"}]}]
            ),
            "agents",
            "mount_path_taken",
        ),
    ],
)
def test_pods_it_cannot_change_get_only_the_reason(
    pod: dict[str, Any], namespace: str, reason: str
) -> None:
    ops, outcome = _injector.plan_patch(_request(pod, namespace), CONFIG)
    after = _apply(pod, ops)
    assert outcome == f"skipped: {reason}"
    assert after["metadata"]["annotations"][_injector.SKIPPED] == reason
    assert after["spec"] == pod["spec"]


@pytest.mark.parametrize(
    "request_",
    [
        _request(_pod({})),  # labelled namespace, no annotation
        _request(_pod({_injector.INJECT: "python", _injector.INJECTED: "0.12.0"})),
        _request(_pod(), operation="UPDATE"),
        {**_request(_pod()), "kind": {"kind": "Deployment"}},
    ],
)
def test_unmarked_seen_or_non_pod_requests_get_no_patch(request_: dict[str, Any]) -> None:
    assert _injector.plan_patch(request_, CONFIG)[0] == []


def test_review_always_allows_and_an_error_is_an_empty_patch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    review = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": _request(_pod()),
    }
    answer = _injector.review_response(review, CONFIG)
    assert answer["response"]["allowed"] is True and answer["response"]["uid"] == "u-1"
    ops = json.loads(base64.b64decode(answer["response"]["patch"]))
    assert answer["response"]["patchType"] == "JSONPatch" and ops

    def broken(*_: Any) -> Any:
        raise KeyError("boom")

    monkeypatch.setattr(_injector, "plan_patch", broken)
    answer = _injector.review_response(review, CONFIG)
    assert answer["response"] == {"uid": "u-1", "allowed": True}
    assert _injector.review_response({}, CONFIG)["response"]["allowed"] is True


def test_review_log_line_is_one_line_whatever_the_request_names(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The namespace and pod name are request input: a line break in either must not
    start a second log line (a forged entry)."""
    pod = _pod()
    pod["metadata"]["name"] = "agent\n2026-01-01 forged/pod: injected"
    review = {"request": _request(pod, namespace="agents\r\nforged")}
    with caplog.at_level("INFO", logger="fabric.injector"):
        assert _injector.review_response(review, CONFIG)["response"]["allowed"] is True
    (record,) = caplog.records
    message = record.getMessage()
    assert "\n" not in message and "\r" not in message
    assert message.startswith("agents??forged/agent?2026-01-01?forged?pod??injected: ")


def test_a_review_whose_request_is_not_an_object_is_allowed_unchanged() -> None:
    answer = _injector.review_response({"request": ["not", "an", "object"]}, CONFIG)
    assert answer["response"] == {"uid": "", "allowed": True}


@pytest.mark.parametrize(
    "request_",
    [
        {**_request(_pod()), "object": ["not", "a", "pod"]},
        {**_request(_pod()), "object": {"metadata": "x", "spec": 3}},
        {**_request(_pod()), "object": {"metadata": {"annotations": {_injector.INJECT: "python"}},
                                        "spec": {"containers": ["x"]}}},
        {**_request(_pod()), "kind": "Pod"},
        {**_request(_pod()), "namespace": {"a": 1}},
    ],
)  # fmt: skip
def test_a_malformed_request_is_allowed_unchanged_and_never_raises(
    request_: dict[str, Any],
) -> None:
    """A review this code cannot read is answered, not dropped: a raised error would end
    the connection, which the API server waits out as a webhook failure."""
    answer = _injector.review_response({"request": request_}, CONFIG)
    assert answer["response"]["allowed"] is True
    ops = json.loads(base64.b64decode(answer["response"].get("patch") or "W10="))
    assert all(op["path"].startswith("/metadata/annotations") for op in ops), ops


def test_config_from_the_chart_json() -> None:
    config = _injector.Config.from_json(
        {
            "version": "1.2.3",
            "secret": "s",
            "spoolSizeLimit": "2Gi",
            "namespaces": {"a": {"env": {"X": 1}}},
        }
    )
    assert (config.version, config.secret, config.spool_size_limit) == ("1.2.3", "s", "2Gi")
    assert config.namespaces == {"a": {"X": "1"}}


# ---------------------------------------------------------------- the server


@pytest.fixture()
def server(tmp_path: Path) -> Iterator[tuple[int, Path]]:
    api = _secrets._crypto()
    ca_cert, ca_key = _secrets._new_ca(api, "test")
    cert, key = _secrets._new_leaf(api, ca_cert, ca_key, ["localhost"], ["127.0.0.1"])
    tls = tmp_path / "tls"
    tls.mkdir()
    (tls / "tls.crt").write_bytes(cert)
    (tls / "tls.key").write_bytes(key)
    (tmp_path / "ca.crt").write_bytes(ca_cert)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    httpd = _injector.build_server(CONFIG, tls, port, host="127.0.0.1")
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield port, tmp_path / "ca.crt"
    httpd.shutdown()
    httpd.server_close()


def _call(port: int, ca: Path, path: str, body: bytes | None = None) -> tuple[int, bytes]:
    context = ssl.create_default_context(cafile=str(ca))
    request = urllib.request.Request(
        f"https://localhost:{port}{path}", data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=5) as response:  # noqa: S310
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def test_server_answers_reviews_over_tls(server: tuple[int, Path]) -> None:
    port, ca = server
    assert _call(port, ca, "/healthz") == (200, b"ok\n")
    review = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": _request(_pod()),
    }
    status, body = _call(port, ca, "/mutate", json.dumps(review).encode())
    answer = json.loads(body)
    assert status == 200 and answer["response"]["allowed"] is True
    assert answer["response"]["patchType"] == "JSONPatch"
    assert _call(port, ca, "/mutate", b"not json")[0] == 400
    assert _call(port, ca, "/elsewhere", b"{}")[0] == 404


def test_server_allows_a_review_it_fails_on(
    server: tuple[int, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fault injection (I3): whatever fails inside a review, the answer is allowed: true
    with the request's uid, on a connection that stays usable."""

    def broken(*_: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(_injector, "review_response", broken)
    port, ca = server
    review = {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview",
              "request": _request(_pod())}  # fmt: skip
    status, body = _call(port, ca, "/mutate", json.dumps(review).encode())
    assert status == 200
    assert json.loads(body)["response"] == {"uid": "u-1", "allowed": True}
    assert _call(port, ca, "/healthz") == (200, b"ok\n")


def test_server_keeps_the_connection_so_the_answer_is_never_cut_off(
    server: tuple[int, Path],
) -> None:
    """Regression: answering HTTP/1.0 and closing first raced the client's read through a
    proxy (curl saw a TLS EOF, the API server would see a failed call and admit the pod
    uninjected). HTTP/1.1 keeps the connection: two reviews on one connection."""
    port, ca = server
    connection = http.client.HTTPSConnection(
        "localhost", port, context=ssl.create_default_context(cafile=str(ca)), timeout=5
    )
    review = json.dumps(
        {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": _request(_pod()),
        }
    )
    for _ in range(2):
        connection.request(
            "POST", "/mutate", body=review, headers={"Content-Type": "application/json"}
        )
        response = connection.getresponse()
        assert (response.version, response.status) == (11, 200)
        assert json.loads(response.read())["response"]["allowed"] is True
    connection.close()


def test_a_client_that_never_finishes_its_handshake_blocks_no_one(
    server: tuple[int, Path],
) -> None:
    port, ca = server
    with socket.create_connection(("127.0.0.1", port), timeout=5):  # connects, sends nothing
        assert _call(port, ca, "/healthz") == (200, b"ok\n")


def test_main_without_its_certificate_exits_and_says_why(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"version": "x", "namespaces": {}}))
    assert _injector.main(["--config", str(config), "--tls-dir", str(tmp_path / "none")]) == 1
    assert "injector cannot start" in caplog.text


def test_injector_uses_the_standard_library_only() -> None:
    tree = ast.parse((REPO / "sdk/python/src/fabric/cli/_injector.py").read_text("utf-8"))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported |= {
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0
    }
    assert imported <= set(sys.stdlib_module_names) | {"__future__"}, imported


# ---------------------------------------------------------------- the shim


def _shim_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "autoload"
    directory.mkdir()
    (directory / "sitecustomize.py").write_text(SHIM.read_text("utf-8"))
    return directory


def _python(
    code: str, pythonpath: list[Path], tmp_path: Path, **env: str
) -> subprocess.CompletedProcess[str]:
    environ = {
        k: v for k, v in os.environ.items() if not k.startswith(("FABRIC_", "OTEL_", "PYTHON"))
    }
    environ.update(PYTHONPATH=os.pathsep.join(str(p) for p in pythonpath), **env)
    return subprocess.run(  # noqa: S603 - this interpreter, a fixed test program
        [sys.executable, "-c", code],
        env=environ,
        capture_output=True,
        text=True,
        timeout=60,
        cwd=tmp_path,
        check=False,
    )


def test_shim_hands_over_to_the_sdk_and_chains_the_image_sitecustomize_once(tmp_path: Path) -> None:
    shim = _shim_dir(tmp_path)
    image = tmp_path / "image"
    image.mkdir()
    (image / "sitecustomize.py").write_text(
        "import os\nwith open(os.environ['MARK'], 'a') as f:\n    f.write('image\\n')\n"
    )
    mark = tmp_path / "mark"
    code = (
        "import sys; print(getattr(sys, '_fabric_wire_autoload_ran', False), "
        "getattr(sys, '_fabric_autoload_shim_ran', False), "
        f"{str(shim)!r} in sys.path); sys.exit(7)"
    )
    result = _python(code, [shim, image], tmp_path, MARK=str(mark), FABRIC_WIRE_AUTOLOAD="0")
    assert (result.returncode, result.stdout, result.stderr) == (7, "True True False\n", "")
    assert mark.read_text() == "image\n"


def test_shim_with_capture_on_keeps_output_and_exit_code(tmp_path: Path) -> None:
    shim = _shim_dir(tmp_path)
    code = "import sys; print('hello'); sys.stderr.write('err\\n'); sys.exit(3)"
    plain = _python(code, [], tmp_path)
    shimmed = _python(
        code,
        [shim],
        tmp_path,
        FABRIC_WIRE_AUTOLOAD="1",
        FABRIC_WIRE_SPOOL_DIR=str(tmp_path / "spool"),
    )
    assert (shimmed.returncode, shimmed.stdout, shimmed.stderr) == (
        plain.returncode,
        plain.stdout,
        plain.stderr,
    )


def test_shim_without_the_sdk_records_why_and_still_runs_the_image_sitecustomize(
    tmp_path: Path,
) -> None:
    shim = _shim_dir(tmp_path)
    other = tmp_path / "other"  # another library named "fabric" (no Fabric SDK)
    (other / "fabric").mkdir(parents=True)
    (other / "fabric" / "__init__.py").write_text("")
    (other / "sitecustomize.py").write_text("print('image sitecustomize')\n")
    spool = tmp_path / "lib" / "spool"
    spool.parent.mkdir()
    result = _python(
        "import sys; print(getattr(sys, '_fabric_wire_autoload_ran', False))",
        [shim, other],
        tmp_path,
        FABRIC_WIRE_AUTOLOAD="1",
        FABRIC_WIRE_SPOOL_DIR=str(spool),
    )
    assert (result.returncode, result.stdout, result.stderr) == (
        0,
        "image sitecustomize\nFalse\n",
        "",
    )
    status = json.loads((spool.parent / "autoload-status.json").read_text())
    assert status["state"] == "sdk_not_found"


def test_shim_drops_a_pythonpath_reference_kubernetes_left_unexpanded(tmp_path: Path) -> None:
    """With envFrom the injector appends $(PYTHONPATH); when no source sets one,
    Kubernetes leaves that text in place. It must not stay a module search directory,
    for this program or for one it starts."""
    shim = _shim_dir(tmp_path)
    image = tmp_path / "image"
    image.mkdir()
    code = (
        "import os, sys; print([e for e in sys.path if 'PYTHONPATH' in e], "
        "os.environ['PYTHONPATH'].split(os.pathsep)[1:])"
    )
    result = _python(code, [shim, image, Path("$(PYTHONPATH)")], tmp_path, FABRIC_WIRE_AUTOLOAD="0")
    assert (result.returncode, result.stdout, result.stderr) == (0, f"[] [{str(image)!r}]\n", "")


def test_shim_is_standard_library_python_without_newer_syntax() -> None:
    tree = ast.parse(SHIM.read_text("utf-8"), feature_version=(3, 6))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert imported <= set(sys.stdlib_module_names), imported
    assert not any(isinstance(node, ast.ImportFrom) for node in ast.walk(tree))


# ---------------------------------------------------------------- spec 058 §10.5 and §8.3

MODEL_URL = "http://model.fabric-model.svc:8080/v1"
SENSOR = dataclasses.replace(
    CONFIG, pod_labels={"fabric.singleaxis.ai/agent": "true"}, host_label_from_node=True
)


def test_with_the_host_sensor_an_injected_pod_gets_its_label_and_its_node_name() -> None:
    after, outcome = _inject(_pod(), SENSOR)
    assert outcome == "injected"
    assert after["metadata"]["labels"] == {"fabric.singleaxis.ai/agent": "true"}
    env = {e["name"]: e for e in after["spec"]["containers"][0]["env"]}
    assert env["FABRIC_HOST_LABEL"] == {
        "name": "FABRIC_HOST_LABEL",
        "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}},
    }


def test_the_sensor_label_and_host_label_never_replace_the_pods_own() -> None:
    pod = _pod(containers=[{"name": "agent", "image": "a:1",
                            "env": [{"name": "FABRIC_HOST_LABEL", "value": "mine"}]}])  # fmt: skip
    pod["metadata"]["labels"] = {"fabric.singleaxis.ai/agent": "false", "app": "x"}
    after, _ = _inject(pod, SENSOR)
    assert after["metadata"]["labels"] == {"fabric.singleaxis.ai/agent": "false", "app": "x"}
    hosts = [e for e in after["spec"]["containers"][0]["env"] if e["name"] == "FABRIC_HOST_LABEL"]
    assert hosts == [{"name": "FABRIC_HOST_LABEL", "value": "mine"}]


def test_without_the_host_sensor_no_label_and_no_host_label_are_added() -> None:
    after, _ = _inject(_pod())
    assert "labels" not in after["metadata"]
    assert "FABRIC_HOST_LABEL" not in {e["name"] for e in after["spec"]["containers"][0]["env"]}


def test_config_reads_the_host_sensor_section() -> None:
    config = _injector.Config.from_json(
        {"hostSensor": {"podLabels": {"a/b": "c"}, "hostLabelFromNode": True}}
    )
    assert dict(config.pod_labels) == {"a/b": "c"} and config.host_label_from_node is True
    assert _injector.Config.from_json({"hostSensor": "junk"}).host_label_from_node is False


def _endpoints(after: dict[str, Any]) -> list[dict[str, Any]] | None:
    for entry in after["spec"]["containers"][0]["env"]:
        if entry["name"] == "FABRIC_WIRE_ENDPOINTS":
            parsed: list[dict[str, Any]] = json.loads(entry["value"])
            return parsed
    return None


def test_a_base_url_in_the_pod_spec_becomes_an_endpoint_as_fabric_run_makes_it() -> None:
    """§8.3 for a pod: a model host named by a standard base-URL variable of the
    container's own env, in no built-in row, is matched without a hand-written matcher."""
    pod = _pod(containers=[{"name": "agent", "image": "a:1", "env": [
        {"name": "OPENAI_BASE_URL", "value": MODEL_URL}]}])  # fmt: skip
    after, _ = _inject(pod)
    found = _endpoints(after)
    assert found is not None and len(found) == 1
    assert found[0]["hosts"] == ["model.fabric-model.svc"] and found[0]["ports"] == [8080]
    assert found[0]["dialect"] == "openai" and found[0]["path_prefix"] == "/v1"


def test_a_derived_endpoint_is_added_to_the_charts_own_never_in_its_place() -> None:
    own = json.dumps([{"endpoint_id": "mine", "dialect": "openai", "hosts": ["llm.internal"],
                       "ports": [443], "schemes": ["https"]}])  # fmt: skip
    config = dataclasses.replace(
        CONFIG, namespaces={"agents": {**ENV, "FABRIC_WIRE_ENDPOINTS": own}}
    )
    pod = _pod(containers=[{"name": "agent", "image": "a:1", "env": [
        {"name": "ANTHROPIC_BASE_URL", "value": "https://claude.example.net"}]}])  # fmt: skip
    found = _endpoints(_inject(pod, config)[0])
    assert found is not None and found[0]["endpoint_id"] == "mine"
    assert found[1]["hosts"] == ["claude.example.net"] and found[1]["dialect"] == "anthropic"
    # A host the chart's value already covers adds nothing.
    same = _pod(containers=[{"name": "agent", "image": "a:1", "env": [
        {"name": "OPENAI_BASE_URL", "value": "https://llm.internal/v1"}]}])  # fmt: skip
    assert _endpoints(_inject(same, config)[0]) == json.loads(own)


@pytest.mark.parametrize(
    "env",
    [
        [{"name": "OPENAI_BASE_URL", "value": "https://api.openai.com/v1"}],  # a built-in row
        [{"name": "OPENAI_BASE_URL", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}],
        [{"name": "OPENAI_BASE_URL", "value": "not a url"}],
        [{"name": "OPENAI_API_KEY", "value": "sk-not-read"}],
    ],
)
def test_nothing_is_derived_from_a_covered_unreadable_or_absent_base_url(
    env: list[dict[str, Any]],
) -> None:
    after, outcome = _inject(_pod(containers=[{"name": "agent", "image": "a:1", "env": env}]))
    assert outcome == "injected" and _endpoints(after) is None


def test_the_pods_own_endpoints_are_never_replaced_by_a_derived_one() -> None:
    pod = _pod(containers=[{"name": "agent", "image": "a:1", "env": [
        {"name": "FABRIC_WIRE_ENDPOINTS", "value": "[]"},
        {"name": "OPENAI_BASE_URL", "value": MODEL_URL}]}])  # fmt: skip
    assert _endpoints(_inject(pod)[0]) == []


def test_a_failing_derivation_never_fails_the_admission(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_: Any, **__: Any) -> Any:
        raise RuntimeError("derivation failed")

    monkeypatch.setattr(_providers, "from_environment", boom)
    pod = _pod(containers=[{"name": "agent", "image": "a:1", "env": [
        {"name": "OPENAI_BASE_URL", "value": MODEL_URL}]}])  # fmt: skip
    after, outcome = _inject(pod)
    assert outcome == "injected" and _endpoints(after) is None


def test_the_operators_capture_policy_is_mounted_read_only_when_the_chart_has_one() -> None:
    """``injector.capturePolicy``: the operator's own policy (a production SDK keeps model
    bodies only under one), an optional ConfigMap volume like the shim's; nothing is added
    without it."""
    after, outcome = _inject(_pod())
    assert outcome == "injected"
    assert _injector.VOLUME_POLICY not in {v["name"] for v in after["spec"]["volumes"]}
    config = _injector.Config.from_json({
        "version": "1", "capturePolicyConfigMap": "fabric-capture-policy",
        "namespaces": {"agents": {"env": {**ENV, "FABRIC_CAPTURE_POLICY":
                                          "/var/run/fabric/policy/capture-policy.json"}}},
    })  # fmt: skip
    after, outcome = _inject(_pod(), config)
    assert outcome == "injected"
    volume = next(v for v in after["spec"]["volumes"] if v["name"] == _injector.VOLUME_POLICY)
    assert volume["configMap"] == {"name": "fabric-capture-policy", "defaultMode": 0o444,
                                   "optional": True}  # fmt: skip
    container = after["spec"]["containers"][0]
    assert {"name": _injector.VOLUME_POLICY, "mountPath": "/var/run/fabric/policy",
            "readOnly": True} in container["volumeMounts"]  # fmt: skip
    env = {e["name"]: e.get("value") for e in container["env"]}
    assert env["FABRIC_CAPTURE_POLICY"] == "/var/run/fabric/policy/capture-policy.json"
    # A pod with its own policy keeps it (never overridden), and a mount there is a skip.
    mine = [{"name": "FABRIC_CAPTURE_POLICY", "value": "/own.json"}]
    own = _pod(containers=[{"name": "agent", "image": "a:1", "env": mine}])
    after, _ = _inject(own, config)
    kept = [
        e for e in after["spec"]["containers"][0]["env"] if e["name"] == "FABRIC_CAPTURE_POLICY"
    ]
    assert kept == [{"name": "FABRIC_CAPTURE_POLICY", "value": "/own.json"}]
    taken = _pod(containers=[{"name": "agent", "image": "a:1", "volumeMounts": [
        {"name": "mine", "mountPath": "/var/run/fabric/policy"}]}])  # fmt: skip
    _, outcome = _inject(taken, config)
    assert outcome == "skipped: mount_path_taken"
