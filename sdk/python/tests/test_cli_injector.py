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

from fabric.cli import _injector, _secrets

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


def test_pvc_spool_by_annotation() -> None:
    after, _ = _inject(_pod({_injector.INJECT: "env", _injector.SPOOL: "pvc"}))
    volumes = {v["name"]: v for v in after["spec"]["volumes"]}
    assert volumes["fabric-spool"]["persistentVolumeClaim"] == {"claimName": "fabric-spool"}


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
