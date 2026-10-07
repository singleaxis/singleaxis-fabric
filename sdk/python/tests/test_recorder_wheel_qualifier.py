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


# Governed-content modules the qualifier requires in every artifact —
# keep this list aligned with `qualify_recorder_wheel.py`'s required set.
_GOVERNED_MEMBERS = (
    "fabric/_content.py",
    "fabric/_content_sink.py",
    "fabric/_content_writer.py",
    "fabric/content_store/__init__.py",
    "fabric/content_store/base.py",
    "fabric/content_store/local.py",
    "fabric/content_store/s3.py",
    "fabric/resolver.py",
    # Spec 042 wire capture and its env-gated autoload.
    "fabric/_autoload/__init__.py",
    "fabric/_autoload/sitecustomize.py",
)
_WIRE_INIT = "def current_handle():\n    return None\n"


def _wheel(
    path: Path,
    *,
    extra: str | None = None,
    member: str | None = None,
    decision: str = "",
    root_init: str = '__all__ = ["Fabric"]\n',
    omit: str | None = None,
) -> Path:
    metadata = ["Name: singleaxis-fabric", "Version: 1.0.0"]
    if extra:
        metadata.append(f"Provides-Extra: {extra}")
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("fabric/__init__.py", root_init)
        archive.writestr("fabric/client.py", "")
        archive.writestr("fabric/decision.py", decision)
        archive.writestr("fabric/wire/__init__.py", _WIRE_INIT)
        for governed in _GOVERNED_MEMBERS:
            if governed != omit:
                archive.writestr(governed, "")
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
        f"{prefix}/src/fabric/wire/__init__.py": _WIRE_INIT.encode(),
        f"{prefix}/PKG-INFO": b"Name: singleaxis-fabric\nVersion: 1.0.0\n",
    }
    for governed in _GOVERNED_MEMBERS:
        payloads[f"{prefix}/src/{governed}"] = b""
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


# ------------------------------------------------------- spec 042 wire capture


def test_rejects_artifact_without_autoload(tmp_path: Path) -> None:
    wheel = _wheel(tmp_path / "no-autoload.whl", omit="fabric/_autoload/sitecustomize.py")
    with pytest.raises(ValueError, match="missing recorder modules"):
        _qualifier().qualify(wheel, import_probe=False)


@pytest.mark.parametrize(
    "member",
    [
        "singleaxis_fabric.pth",
        "fabric/_autoload/fabric.pth",
        "sitecustomize.py",
        "usercustomize.py",
        "fabric/sitecustomize.py",
    ],
)
def test_rejects_interpreter_startup_hooks(tmp_path: Path, member: str) -> None:
    with pytest.raises(ValueError, match="interpreter startup hooks"):
        _qualifier().qualify(_wheel(tmp_path / "hook.whl", member=member), import_probe=False)


def test_rejects_startup_hook_in_sdist(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="interpreter startup hooks"):
        _qualifier().qualify(
            _sdist(tmp_path / "hook.tar.gz", member="fabric/x.pth"), import_probe=False
        )


def test_import_probe_passes_inert_artifacts(tmp_path: Path) -> None:
    qualifier = _qualifier()
    assert qualifier.qualify(_wheel(tmp_path / "ok.whl"))["qualified"] is True
    assert qualifier.qualify(_sdist(tmp_path / "ok.tar.gz"))["qualified"] is True


@pytest.mark.parametrize(
    ("root_init", "problem"),
    [
        (
            "import threading, time\n"
            "threading.Thread(target=time.sleep, args=(5,), daemon=True).start()\n",
            "started a thread",
        ),
        ("from . import _autoload\n", "fabric._autoload"),
    ],
)
def test_import_probe_rejects_import_side_effects(
    tmp_path: Path, root_init: str, problem: str
) -> None:
    wheel = _wheel(tmp_path / "noisy.whl", root_init=root_init)
    with pytest.raises(ValueError, match=problem):
        _qualifier().qualify(wheel)
