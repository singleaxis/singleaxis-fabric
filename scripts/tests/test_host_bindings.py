# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``deploy/kubernetes/host-bindings.py``: one host.ebpf ingress group per node
(spec 056 §7.3.3 (n); spec 053 §6.1, §6.2.2).

* Source ids are ``s-`` label pseudonyms of ``<node>/ebpf`` under the id key, as
  ``run-id-pseudonym-v1.json`` defines them and the emitter's
  ``print-source-id`` prints them; the id key file is read exactly as
  ``id-key-file-v1.json`` says.
* One group per node on ``base + index``; distinct fresh tokens, each in its
  node's provisioning directory and the Node-side token Secret files only;
  files 0400 in 0700 directories; nothing secret on standard output.
* The values fragment renders with the host-ingress profile, and for the three
  fixture nodes it is the ``valid/agent-ebpf-three-nodes.yaml`` golden.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy/kubernetes/host-bindings.py"
CAPTURE = ROOT / "contracts/capture/v1/fixtures"
CHART = ROOT / "charts/fabric"
FIXTURES = CHART / "charts/otel-collector/tests/fixtures/source-bindings"
sys.path.insert(0, str(ROOT / "scripts"))
from contracts import ingress_groups  # noqa: E402


def _module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("host_bindings", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HB = _module()


def _key(
    tmp_path: Path, data: bytes = ingress_groups.KEY.encode(), mode: int = 0o400
) -> Path:
    path = tmp_path / "id_key"
    path.write_bytes(data)
    path.chmod(mode)
    return path


def _nodes(tmp_path: Path, *names: str) -> Path:
    path = tmp_path / "nodes.txt"
    path.write_text("".join(f"{n}\n" for n in names), encoding="utf-8")
    return path


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - the repository's own script
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def _generate(tmp_path: Path, *nodes: str, base: int = 4417) -> tuple[Path, str]:
    tmp_path.mkdir(exist_ok=True)
    out = tmp_path / "out"
    run = _run(
        "--nodes", str(_nodes(tmp_path, *nodes)), "--tenant", "tenant-a",
        "--id-key-file", str(_key(tmp_path)), "--base-port", str(base), "--out", str(out),
    )  # fmt: skip
    assert run.returncode == 0, run.stderr
    return out, run.stdout + run.stderr


def _bindings(out: Path) -> list[dict[str, Any]]:
    doc = yaml.safe_load((out / "source-bindings.yaml").read_text(encoding="utf-8"))
    groups = doc["otel-collector"]["receiver"]["sourceBindings"]
    assert isinstance(groups, list)
    return groups


# --------------------------------------------------------------------------
# Source ids and the id key
# --------------------------------------------------------------------------


def test_label_pseudonym_is_the_run_id_vector() -> None:
    vectors = json.loads((CAPTURE / "run-ids/run-id-pseudonym-v1.json").read_text())
    keyed = [c for c in vectors["cases"] if c["key"]]
    assert keyed
    for case in keyed:
        got = HB.label_pseudonym("s-", case["run_id"], case["key"].encode("utf-8"))
        assert got == "s-" + case["pseudonym"][2:], case["name"]


@pytest.mark.parametrize(
    "case",
    json.loads((CAPTURE / "host/id-key-file-v1.json").read_text())["cases"],
    ids=lambda c: c["name"],
)
def test_id_key_file_is_read_as_the_vector_says(
    tmp_path: Path, case: dict[str, Any]
) -> None:
    path = _key(tmp_path, base64.b64decode(case["file_base64"]), int(case["mode"], 8))
    if "refused" in case:
        with pytest.raises(HB.Refused) as refused:
            HB.read_id_key_file(path)
        assert f"({case['refused']})" in str(refused.value)
        assert base64.b64decode(case["file_base64"]).decode(
            "utf-8", "replace"
        ) not in str(refused.value)
        return
    key = HB.read_id_key_file(path)
    assert key == base64.b64decode(case["key_base64"])
    assert HB.label_pseudonym("s-", "node-a/ebpf", key) == case["source_id"]


def test_source_ids_match_the_emitters_print_source_id(tmp_path: Path) -> None:
    """``fabric-host-emitter print-source-id`` (WP4-07c) prints the id the generator
    wrote for the same label and key."""
    go = shutil.which("go")
    if go is None:
        pytest.skip("go is not installed")
    out, _ = _generate(tmp_path, "node-a")
    binary = tmp_path / "fabric-host-emitter"
    built = subprocess.run(  # noqa: S603
        [go, "build", "-o", str(binary), "."],
        cwd=ROOT / "components/host-emitter",
        capture_output=True,
        text=True,
        check=False,
    )
    if built.returncode != 0:
        pytest.skip("the host emitter does not build on this platform")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "EMIT_PRODUCTION": "true",
        "EMIT_SOURCE_LABEL": "node-a/ebpf",
        "EMIT_ID_KEY_FILE": str(tmp_path / "id_key"),
    }
    run = subprocess.run(  # noqa: S603
        [str(binary), "print-source-id"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if run.returncode != 0 and "print-source-id" not in run.stdout + run.stderr:
        pytest.skip("this host emitter has no print-source-id subcommand yet (WP4-07c)")
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == _bindings(out)[1]["sourceId"]


# --------------------------------------------------------------------------
# Groups, tokens and provisioning directories
# --------------------------------------------------------------------------


def test_one_group_per_node_with_distinct_tokens(tmp_path: Path) -> None:
    nodes = ("node-a", "node-b", "node-c")
    out, output = _generate(tmp_path, *nodes)
    groups = _bindings(out)
    assert [g["name"] for g in groups] == ["agent", "ebpf-0", "ebpf-1", "ebpf-2"]
    hosts = groups[1:]
    assert [g["kind"] for g in hosts] == ["host.ebpf"] * 3
    assert [g["protocols"] for g in hosts] == [
        {"grpc": 4417},
        {"grpc": 4418},
        {"grpc": 4419},
    ]
    assert [g["sourceId"] for g in hosts] == [
        HB.label_pseudonym("s-", f"{n}/ebpf", ingress_groups.KEY.encode())
        for n in nodes
    ]
    assert [g["tokenSecret"] for g in hosts] == [
        {"name": "fabric-node-host-ingress", "key": f"ebpf-{i}"} for i in range(3)
    ]
    assert groups[0]["sourceId"] == "" and groups[0]["kind"] == "agent"
    tokens = []
    for index, node in enumerate(nodes):
        directory = out / "nodes" / node
        token = (directory / "token").read_bytes()
        assert token == (out / "node-secret" / f"ebpf-{index}").read_bytes()
        assert len(token) == 64 and not token.endswith(b"\n")
        tokens.append(token)
        state_key = base64.b64decode(
            (directory / "state_key").read_bytes(), validate=True
        )
        assert len(state_key) == 32
        endpoint = (directory / "endpoint").read_text(encoding="utf-8")
        assert endpoint == f"{HB.DEFAULT_SERVICE}:{4417 + index}\n"
        # Nothing secret on standard output or error.
        assert token.decode() not in output
        assert (directory / "state_key").read_text() not in output
    assert len(set(tokens)) == 3
    assert ingress_groups.KEY not in output
    for group in hosts:
        assert group["sourceId"] not in output
    for path in out.rglob("*"):
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == (0o700 if path.is_dir() else 0o400), path
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    assert sorted(p.name for p in (out / "node-secret").iterdir()) == [
        "ebpf-0",
        "ebpf-1",
        "ebpf-2",
    ]
    # No directory holds another node's token.
    for node in nodes:
        assert sorted(p.name for p in (out / "nodes" / node).iterdir()) == [
            "endpoint",
            "state_key",
            "token",
        ]


def test_a_second_run_mints_fresh_tokens_and_never_overwrites(tmp_path: Path) -> None:
    first, _ = _generate(tmp_path / "a", "node-a")
    second, _ = _generate(tmp_path / "b", "node-a")
    token = "nodes/node-a/token"
    assert (first / token).read_bytes() != (second / token).read_bytes()
    run = _run(
        "--nodes", str(tmp_path / "a/nodes.txt"), "--tenant", "tenant-a",
        "--id-key-file", str(tmp_path / "a/id_key"), "--base-port", "4417", "--out", str(first),
    )  # fmt: skip
    assert run.returncode == 1 and "must not exist" in run.stderr


@pytest.mark.parametrize(
    ("nodes", "base", "message"),
    [
        (("node-a", "node-a"), 4417, "repeats a node"),
        (("Node_A",), 4417, "not a Kubernetes node name"),
        ((), 4417, "names no node"),
        (("node-a", "node-b"), 4316, "overlaps the agent group"),
        (("node-a",), 13133, "overlaps the agent group"),
        (("node-a", "node-b"), 65535, "outside 1-65535"),
        (tuple(f"node-{i}" for i in range(256)), 20000, "more than the ceiling of 256"),
    ],
)
def test_refusals(
    tmp_path: Path, nodes: tuple[str, ...], base: int, message: str
) -> None:
    run = _run(
        "--nodes", str(_nodes(tmp_path, *nodes)), "--tenant", "tenant-a",
        "--id-key-file", str(_key(tmp_path)), "--base-port", str(base),
        "--out", str(tmp_path / "out"),
    )  # fmt: skip
    assert run.returncode == 1
    assert message in run.stderr
    assert not (tmp_path / "out").exists()


def test_an_unsafe_id_key_file_is_refused_without_its_contents(tmp_path: Path) -> None:
    run = _run(
        "--nodes", str(_nodes(tmp_path, "node-a")), "--tenant", "tenant-a",
        "--id-key-file", str(_key(tmp_path, ingress_groups.KEY.encode() + b"\n")),
        "--base-port", "4417", "--out", str(tmp_path / "out"),
    )  # fmt: skip
    assert run.returncode == 1 and "(trailing_newline)" in run.stderr
    assert ingress_groups.KEY not in run.stderr + run.stdout


def test_kubectl_node_names_and_comments_are_read(tmp_path: Path) -> None:
    nodes = tmp_path / "nodes.txt"
    nodes.write_text("# pool a\nnode/node-a\n\nnode-b  # second\n", encoding="utf-8")
    assert HB.read_nodes(nodes) == ["node-a", "node-b"]


def test_more_than_63_nodes_raise_the_group_limit(tmp_path: Path) -> None:
    out, _ = _generate(tmp_path, *(f"node-{i}" for i in range(64)), base=20000)
    doc = yaml.safe_load((out / "source-bindings.yaml").read_text(encoding="utf-8"))
    assert doc["otel-collector"]["receiver"]["maxSourceBindings"] == 65
    assert len(doc["otel-collector"]["receiver"]["sourceBindings"]) == 65
    small, _ = _generate(tmp_path / "small", "node-a")
    assert "maxSourceBindings" not in (small / "source-bindings.yaml").read_text()


# --------------------------------------------------------------------------
# The chart renders the generated values
# --------------------------------------------------------------------------


def _render(out: Path, tmp_path: Path, agent: dict[str, Any]) -> dict[str, Any]:
    if shutil.which("helm") is None:
        pytest.skip("helm not installed")
    doc = yaml.safe_load((out / "source-bindings.yaml").read_text(encoding="utf-8"))
    doc["otel-collector"]["receiver"]["sourceBindings"][0].update(agent)
    filled = tmp_path / "filled.yaml"
    filled.write_text(yaml.safe_dump(doc), encoding="utf-8")
    rendered = subprocess.run(  # noqa: S603
        [
            "helm", "template", "fabric", str(CHART), "-n", "fabric-system",
            "--values", str(CHART / "profiles/shadow-production.yaml"),
            "--values", str(CHART / "profiles/shadow-production-host-ingress.yaml"),
            "--values", str(FIXTURES / "common.yaml"),
            "--values", str(filled),
        ],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert rendered.returncode == 0, rendered.stderr
    docs = [d for d in yaml.safe_load_all(rendered.stdout) if d]
    (cm,) = [
        d
        for d in docs
        if d["kind"] == "ConfigMap" and d["metadata"]["name"].endswith("-config")
    ]
    config = yaml.safe_load(cm["data"]["config.yaml"])
    assert isinstance(config, dict)
    return config


def test_three_nodes_render_the_three_node_golden(tmp_path: Path) -> None:
    out, _ = _generate(tmp_path, *ingress_groups.NODES)
    config = _render(
        out,
        tmp_path,
        {"sourceId": ingress_groups.AGENT_SOURCE, "content": {"port": 4319}},
    )
    golden = (CAPTURE / "ingress-groups/valid/agent-ebpf-three-nodes.yaml").read_text()
    assert ingress_groups.yaml_text(config) == golden


def test_without_the_agent_source_the_render_fails(tmp_path: Path) -> None:
    if shutil.which("helm") is None:
        pytest.skip("helm not installed")
    out, _ = _generate(tmp_path, "node-a")
    run = subprocess.run(  # noqa: S603
        [
            "helm", "template", "fabric", str(CHART), "-n", "fabric-system",
            "--values", str(CHART / "profiles/shadow-production.yaml"),
            "--values", str(CHART / "profiles/shadow-production-host-ingress.yaml"),
            "--values", str(FIXTURES / "common.yaml"),
            "--values", str(out / "source-bindings.yaml"),
            "--set", "otel-collector.content.enabled=false",
        ],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert run.returncode != 0
    assert (
        "receiver.sourceBindings[0].sourceId must be s-<32 lowercase hex>" in run.stderr
    )
