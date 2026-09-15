"""Tests for exact recorder wheel qualification."""

from __future__ import annotations

import importlib.util
import io
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType

import pytest


def _qualifier() -> ModuleType:
    path = Path(__file__).parents[1] / "scripts" / "qualify_recorder_wheel.py"
    spec = importlib.util.spec_from_file_location("qualify_recorder_wheel", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _wheel(
    path: Path,
    *,
    extra: str | None = None,
    member: str | None = None,
    decision: str = "",
) -> Path:
    metadata = ["Name: singleaxis-fabric", "Version: 1.0.0"]
    if extra:
        metadata.append(f"Provides-Extra: {extra}")
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("fabric/__init__.py", '__all__ = ["Fabric"]\n')
        archive.writestr("fabric/client.py", "")
        archive.writestr("fabric/decision.py", decision)
        archive.writestr("singleaxis_fabric-1.0.0.dist-info/METADATA", "\n".join(metadata))
        if member:
            archive.writestr(member, "")
    return path


def _sdist(path: Path, *, member: str | None = None, decision: str = "") -> Path:
    prefix = "singleaxis_fabric-1.0.0"
    payloads = {
        f"{prefix}/src/fabric/__init__.py": b'__all__ = ["Fabric"]\n',
        f"{prefix}/src/fabric/client.py": b"",
        f"{prefix}/src/fabric/decision.py": decision.encode(),
        f"{prefix}/PKG-INFO": b"Name: singleaxis-fabric\nVersion: 1.0.0\n",
    }
    if member:
        payloads[f"{prefix}/src/{member}"] = b""
    with tarfile.open(path, "w:gz") as archive:
        for name, data in payloads.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def test_qualifies_minimal_recorder_wheel(tmp_path: Path) -> None:
    result = _qualifier().qualify(_wheel(tmp_path / "recorder.whl"))
    assert result["qualified"] is True
    assert len(result["sha256"]) == 64


def test_qualifies_minimal_recorder_sdist(tmp_path: Path) -> None:
    result = _qualifier().qualify(_sdist(tmp_path / "recorder.tar.gz"))
    assert result["qualified"] is True
    assert result["artifact_kind"] == "sdist"


@pytest.mark.parametrize(
    "member",
    ["fabric/judge_runner.py", "fabric/policy_adapters/opa.py", "entry/../escape"],
)
def test_rejects_legacy_or_unsafe_members(tmp_path: Path, member: str) -> None:
    with pytest.raises(ValueError):
        _qualifier().qualify(_wheel(tmp_path / "bad.whl", member=member))


def test_rejects_legacy_extra(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="legacy capability extras"):
        _qualifier().qualify(_wheel(tmp_path / "bad-extra.whl", extra="deepeval"))


@pytest.mark.parametrize("method", ["guard_input", "record_eval", "authorize_tool_call"])
def test_rejects_legacy_decision_method_in_built_code(tmp_path: Path, method: str) -> None:
    decision = f"class Decision:\n    def {method}(self):\n        pass\n"
    with pytest.raises(ValueError, match="legacy methods"):
        _qualifier().qualify(_wheel(tmp_path / "bad-method.whl", decision=decision))


def test_rejects_legacy_module_in_sdist(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="excluded legacy modules"):
        _qualifier().qualify(_sdist(tmp_path / "bad.tar.gz", member="fabric/judge.py"))
