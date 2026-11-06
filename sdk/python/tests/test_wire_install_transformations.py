# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The documented masking recipe (docs/production-setup.md, docs/privacy-and-security.md):
``fabric.wire.install_from_env(transformations=...)`` names a customer transformation for
the masking roles with no private import, and installs the hooks the environment asks for,
so a subprocess's argv is stored masked instead of withheld."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from ._wire_live import FakeModel, OtlpSink, capture_env, run_agent, wait_for
from .redaction_server import RedactionServer

CANARY = b"sk-live-CANARY-argv-4c1e9a7b"
AGENT = textwrap.dedent(
    """
    import os, subprocess, sys
    from fabric import wire
    from fabric.wire import Transformation
    mask = Transformation("live-mask", "1")
    handle = wire.install_from_env(transformations={
        "terminal.argv": mask, "terminal.stdout": mask, "model.exchange.request": mask,
    })
    assert handle is not None and handle.capturing
    out = subprocess.run(["echo", sys.argv[1]], capture_output=True, check=True).stdout
    print("RESULT", out.decode().strip() == sys.argv[1])
    handle.close()
    """
)


def _policy(path: Path) -> Path:
    path.write_text(json.dumps({
        "schema_version": "fabric.deployment-policy/v1", "policy_id": "live-argv",
        "policy_version": 1, "tenant_id": "live-tenant", "workload_id": "live-agent",
        "privacy": {"terminal.argv": "redact", "terminal.stdout": "redact",
                    "terminal.context": "metadata_only"},
        "storage": {"backend": "local", "region": "local", "key_id": "live-key"},
        "retention": {"days": 1}, "required_integrations": [],
        "deployment": {"profile": "local", "image_digest": "sha256:" + "0" * 64,
                       "tls_required": False, "encrypted_store_required": False},
    }))  # fmt: skip
    return path


def _holding(store: Path, needle: bytes) -> bool:
    return any(p.is_file() and needle in p.read_bytes() for p in store.rglob("*"))


def test_install_from_env_names_a_transformation_for_masked_argv(tmp_path: Path) -> None:
    model, sink = FakeModel(), OtlpSink(tmp_path / "otlp")
    (store := tmp_path / "store").mkdir()
    (script := tmp_path / "agent.py").write_text(AGENT, encoding="utf-8")
    with RedactionServer() as service:
        service.behaviours |= {"live-mask": lambda d: d.replace(CANARY, b"[masked:key]")}
        try:
            env = capture_env(model, sink, store, FABRIC_WIRE_EXEC="1",
                              FABRIC_CAPTURE_POLICY=str(_policy(tmp_path / "policy.json")),
                              FABRIC_REDACTION_ENDPOINT=service.endpoint)  # fmt: skip
            env.pop("FABRIC_WIRE_AUTOLOAD")
            env.pop("PYTHONPATH")
            done = run_agent(script, env, CANARY.decode())
            assert done["returncode"] == 0, done["stderr"][-2000:]
            assert "RESULT True" in done["stdout"]  # the subprocess is unaffected
            assert wait_for(lambda: _holding(store, b"[masked:key]"))
            assert not _holding(store, CANARY)
            roles = {h.get("X-Fabric-Role") for h, _ in service.requests}
            assert "terminal.argv" in roles
        finally:
            model.close()
            sink.close()
