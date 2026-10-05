# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Build helper must honor Go's module cache independently of GOPATH."""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_patched_build_discovers_custom_module_cache(tmp_path: Path) -> None:
    root = tmp_path / "collector"
    upstream = root / "upstream"
    upstream.mkdir(parents=True)
    script = upstream / "build-patched-bearertokenauth.sh"
    script.write_bytes(
        (ROOT / "components/otel-collector-fabric/upstream" / script.name).read_bytes()
    )
    dist = root / "dist"
    dist.mkdir()
    (dist / "go.mod").write_text("module fixture\n")
    # The existing unmarked directory is a deliberate safe stop AFTER discovery.
    (dist / "bearertokenauth-patched").mkdir()
    cache = tmp_path / "custom module cache"
    module = (
        cache
        / "github.com/open-telemetry/opentelemetry-collector-contrib/extension/bearertokenauthextension@v0.150.0"
    )
    module.mkdir(parents=True)
    (module / "bearertokenauth.go").write_text("package fixture\n")
    commands = tmp_path / "bin"
    commands.mkdir()
    go = commands / "go"
    go.write_text(
        "#!/bin/sh\n"
        'if [ "$*" = "env GOMODCACHE" ]; then\n'
        f"  printf '%s\\n' {shlex.quote(str(cache))}\n"
        "else\n  echo 'unexpected go command' >&2; exit 99\nfi\n"
    )
    go.chmod(0o755)
    result = subprocess.run(
        ["sh", str(script)],
        env={**os.environ, "PATH": f"{commands}{os.pathsep}{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1
    assert "refusing to replace unmarked bearer source" in result.stderr
    assert "unexpected go command" not in result.stderr
    assert (module / "bearertokenauth.go").read_text() == "package fixture\n"
