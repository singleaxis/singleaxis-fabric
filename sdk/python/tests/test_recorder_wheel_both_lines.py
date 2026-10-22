# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Artifact content: the built wheel ships BOTH capture lines.

The explicit evidence line (specs 035-046) and the zero-code wire line
(specs 047-049) coexist; neither may be dropped from the release artifact,
and the shared explicit-wins flag (``fabric/_capture_scope.py``) ships too.
The wheel is built from this source tree and qualified as released.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

SDK = Path(__file__).resolve().parents[1]

EVIDENCE_LINE = (
    "fabric/byte_evidence.py",
    "fabric/source_spool.py",
    "fabric/synthetic_otlp.py",
    "fabric/synthetic_reconcile.py",
    "fabric/adapters/synthetic_evidence.py",
    "fabric/adapters/byte_boundary.py",
    "fabric/call_recorder.py",
    "fabric/byte_spool.py",
    "fabric/metadata_delivery.py",
    "fabric/qualified_run.py",
    "fabric/receipt_sets.py",
)
WIRE_LINE = (
    "fabric/wire/__init__.py",
    "fabric/wire/_transport.py",
    "fabric/wire/_spool.py",
    "fabric/wire/_sender.py",
    "fabric/wire/_content.py",
    "fabric/reconstruct/__init__.py",
    "fabric/_autoload/sitecustomize.py",
    "fabric/_sequence.py",
    "fabric/_loss.py",
    "fabric/_model_names.py",
)
SHARED = ("fabric/_capture_scope.py",)


def _qualifier() -> ModuleType:
    path = SDK / "scripts" / "qualify_recorder_wheel.py"
    spec = importlib.util.spec_from_file_location("qualify_recorder_wheel_both", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("wheel")
    command: list[str] | None = None
    if (uv := shutil.which("uv")) is not None:
        command = [uv, "build", "--wheel", "--out-dir", str(out), str(SDK)]
    elif importlib.util.find_spec("build") is not None:
        command = [sys.executable, "-m", "build", "--wheel", "--outdir", str(out), str(SDK)]
    if command is None:
        pytest.skip("neither uv nor the build package is available to build the wheel")
    subprocess.run(command, check=True, capture_output=True, timeout=300)  # noqa: S603
    (built,) = out.glob("*.whl")
    return built


def test_wheel_contains_both_capture_lines_and_the_shared_flag(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    missing = [m for m in (*EVIDENCE_LINE, *WIRE_LINE, *SHARED) if m not in names]
    assert missing == []


def test_built_wheel_qualifies(wheel: Path) -> None:
    result = _qualifier().qualify(wheel)
    assert result["qualified"] is True
