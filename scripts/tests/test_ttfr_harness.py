# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 §3.3: the TTFR harness and its fixtures.

The fixture agents are plain programs that know nothing of Fabric; the fixture model asks
for one tool call and answers; the local index serves the build under test and sends
everything else to PyPI; ``ttfr.json`` fails a run over its budget or with a failed step.
The timed run itself is the ``ttfr-laptop-python`` CI job."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
TTFR = ROOT / "scripts" / "ttfr"
sys.path.insert(0, str(TTFR))

import ttfr  # noqa: E402

AGENTS = sorted((TTFR / "agents").glob("*.py"))


def test_there_are_two_fixture_agents() -> None:
    assert [a.name for a in AGENTS] == ["httpx_tool_loop.py", "openai_tool_loop.py"]
    assert set(ttfr.AGENTS.values()) == {a.name for a in AGENTS}


@pytest.mark.parametrize("agent", AGENTS, ids=lambda p: p.name)
def test_fixture_agents_import_nothing_of_fabric_or_this_repository(
    agent: Path,
) -> None:
    imported: set[str] = set()
    for node in ast.walk(ast.parse(agent.read_text("utf-8"))):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"json", "os", "sys", "openai", "httpx"}, imported
    assert "FABRIC" not in agent.read_text("utf-8")


@pytest.mark.parametrize("name", ["openai", "httpx"])
def test_agent_requirements_are_hashed_and_pinned(name: str) -> None:
    text = (TTFR / "agents" / f"requirements-{name}.txt").read_text("utf-8")
    pins = [
        line
        for line in text.splitlines()
        if line and not line[0].isspace() and "==" in line
    ]
    assert pins and all("--hash=sha256:" in text for _ in pins)
    assert any(line.startswith(f"{name}==") for line in pins)


def test_images_are_pinned_by_digest() -> None:
    for image in (ttfr.PYTHON_IMAGE, ttfr.DOCKER_CLI_IMAGE):
        assert "@sha256:" in image and len(image.split("@sha256:")[1]) == 64


def test_pinned_fabric_images_are_the_clis_own() -> None:
    images = ttfr.pinned_fabric_images()
    assert len(images) == 3 and all("@sha256:" in i for i in images)


@pytest.fixture
def model(tmp_path: Path) -> Iterator[str]:
    ready = tmp_path / "model.json"
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, "-I", str(TTFR / "model_server.py"), "--api-key", ttfr.API_KEY,
         "--ready-file", str(ready)],
    )  # fmt: skip
    try:
        port = ttfr.wait_file(ready, timeout=20)["port"]
        yield f"http://127.0.0.1:{port}/v1"
    finally:
        process.terminate()
        process.wait(timeout=10)


@pytest.mark.parametrize("agent", AGENTS, ids=lambda p: p.name)
@pytest.mark.parametrize("path", ttfr.PATHS)
def test_each_agent_completes_its_tool_loop(model: str, agent: Path, path: str) -> None:
    pytest.importorskip("openai" if "openai" in agent.name else "httpx")
    env = {**os.environ, **ttfr.agent_environment(path, model, None)}
    for name in ("OPENAI_BASE_URL", "AGENT_MODEL_URL"):
        if name not in ttfr.agent_environment(path, model, None):
            env.pop(name, None)
    done = subprocess.run(  # noqa: S603
        [sys.executable, str(agent)], env=env, capture_output=True, text=True, timeout=60,
        check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == {"answer": "It is 18.5 C in Lisbon."}


def test_the_provider_path_hides_the_base_url_from_fabric() -> None:
    base = ttfr.agent_environment("laptop-python", "https://m/v1", None)
    provider = ttfr.agent_environment("laptop-python-provider", "https://m/v1", None)
    assert base["OPENAI_BASE_URL"] == "https://m/v1" and "AGENT_MODEL_URL" not in base
    assert (
        provider["AGENT_MODEL_URL"] == "https://m/v1"
        and "OPENAI_BASE_URL" not in provider
    )


def test_the_local_index_serves_the_build_and_redirects_the_rest(
    tmp_path: Path,
) -> None:
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    (wheels / "singleaxis_fabric-0.12.1-py3-none-any.whl").write_bytes(b"wheel bytes")
    ready = tmp_path / "index.json"
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, "-I", str(TTFR / "local_index.py"), "--wheel-dir", str(wheels),
         "--ready-file", str(ready)],
    )  # fmt: skip
    try:
        base = f"http://127.0.0.1:{ttfr.wait_file(ready, timeout=20)['port']}"
        page = (
            urllib.request.urlopen(f"{base}/simple/singleaxis-fabric/").read().decode()
        )  # noqa: S310
        assert "singleaxis_fabric-0.12.1-py3-none-any.whl" in page
        wheel = urllib.request.urlopen(  # noqa: S310
            f"{base}/files/singleaxis_fabric-0.12.1-py3-none-any.whl"
        ).read()
        assert wheel == b"wheel bytes"

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args: object, **kwargs: object) -> None:
                return None

        opener = urllib.request.build_opener(NoRedirect)
        with pytest.raises(urllib.error.HTTPError) as redirect:
            opener.open(f"{base}/simple/PyYAML/")
        assert redirect.value.code == 302
        assert redirect.value.headers["Location"] == "https://pypi.org/simple/pyyaml/"
    finally:
        process.terminate()
        process.wait(timeout=10)


def _report(*seconds: float, ok: bool = True) -> dict[str, object]:
    steps = [{"step": i + 1, "kind": "install" if i == 0 else "command", "commands": ["x"],
              "seconds": s, "exit_code": 0, "ok": True} for i, s in enumerate(seconds)]  # fmt: skip
    if not ok:
        steps[-1].update(ok=False, exit_code=1)
    counts = {"install": 1, "commands": 3, "flags": 0, "lines": 70}
    return {"steps": steps, "counts": counts, "ok": ok}


def test_ttfr_json_passes_within_the_budget() -> None:
    result = ttfr.summarize(_report(30, 60, 5, 20), budget=300, path="laptop-python",
                            agent="openai", mode="container", package_source="x", evicted=[])  # fmt: skip
    assert result["ok"] and result["ttfr_s"] == 115 and result["hand_made_items"] == 0
    assert result["commands"] == 3 and result["install_commands"] == 1


def test_ttfr_json_fails_over_the_budget_or_on_a_failed_step() -> None:
    over = ttfr.summarize(_report(100, 150, 5, 60), budget=300, path="laptop-python",
                          agent="openai", mode="container", package_source="x", evicted=[])  # fmt: skip
    assert not over["ok"] and "over the 300 s budget" in over["failures"][0]
    failed = ttfr.summarize(_report(10, 10, 10, 10, ok=False), budget=300,
                            path="laptop-python", agent="openai", mode="container",
                            package_source="x", evicted=[])  # fmt: skip
    assert not failed["ok"] and "step 4 failed" in failed["failures"][0]


def test_ci_runs_every_path_and_agent_and_keeps_ttfr_json() -> None:
    ci = yaml.safe_load((ROOT / ".github/workflows/recorder-ci.yml").read_text())
    job = ci["jobs"]["ttfr-laptop-python"]
    assert job["runs-on"] == "ubuntu-latest"
    assert job["strategy"]["matrix"] == {
        "path": list(ttfr.PATHS),
        "agent": ["openai", "httpx"],
    }
    steps = json.dumps(job["steps"])
    assert "scripts/ttfr/ttfr.py" in steps and "ttfr.json" in steps
    assert "upload-artifact" in steps

