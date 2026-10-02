# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Current release modules and complete local license inventories are required."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from release import qualify_release as qualify  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
CURRENT_MODULES = (
    "client.py",
    "decision.py",
    "adapters/byte_boundary.py",
    "byte_evidence.py",
    "byte_resolver.py",
    "byte_spool.py",
    "call_recorder.py",
    "call_otlp.py",
    "source_spool.py",
    "metadata_delivery.py",
    "content_join.py",
    "deployment_policy.py",
    "governed_store.py",
    "governed_reconstruction.py",
)
POLICY = json.loads((ROOT / "scripts/release/release-policy.json").read_text())
METADATA = (
    b"Metadata-Version: 2.4\nName: singleaxis-fabric\n"
    b"Version: 1.2.3\nRequires-Python: >=3.11\n\n"
)


def _archive(tmp_path: Path, kind: str, missing: str | None) -> Path:
    """Minimal structural fixture; empty modules do not demonstrate runtime behavior."""
    required = POLICY["python_distribution"][f"required_{kind}_paths"]
    paths = {path: b"" for path in required}
    if missing is not None:
        paths.pop(("src/" if kind == "sdist" else "") + "fabric/" + missing, None)
    if kind == "wheel":
        path = tmp_path / "singleaxis_fabric-1.2.3-py3-none-any.whl"
        paths["singleaxis_fabric-1.2.3.dist-info/METADATA"] = METADATA
        with zipfile.ZipFile(path, "w") as archive:
            for name, body in paths.items():
                archive.writestr(name, body)
    else:
        path = tmp_path / "singleaxis_fabric-1.2.3.tar.gz"
        paths["PKG-INFO"] = METADATA
        with tarfile.open(path, "w:gz") as archive:
            for name, body in paths.items():
                info = tarfile.TarInfo("singleaxis_fabric-1.2.3/" + name)
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
    return path


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_current_release_policy_structural_fixture(tmp_path: Path, kind: str) -> None:
    path = _archive(tmp_path, kind, None)
    result = getattr(qualify, f"inspect_{kind}")(path, POLICY, "1.2.3")
    assert result["version"] == "1.2.3"


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
@pytest.mark.parametrize("missing", CURRENT_MODULES)
def test_release_policy_rejects_missing_current_module(
    tmp_path: Path, kind: str, missing: str
) -> None:
    path = _archive(tmp_path, kind, missing)
    with pytest.raises(qualify.QualificationError, match="missing required"):
        getattr(qualify, f"inspect_{kind}")(path, POLICY, "1.2.3")


def _script_root(tmp_path: Path) -> Path:
    root = tmp_path / "fixture"
    for relative in (
        "scripts/license_scan.sh",
        "scripts/license_check.py",
        ".github/license-allowlist.txt",
    ):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    return root


def _utilities(bin_dir: Path) -> None:
    bin_dir.mkdir()
    for name in ("dirname", "mktemp", "rm", "mkdir"):
        target = shutil.which(name)
        assert target is not None
        (bin_dir / name).symlink_to(target)


@pytest.mark.parametrize("missing", ["go", "npm"])
def test_local_license_scan_requires_complete_toolchain_before_scanning(
    tmp_path: Path, missing: str
) -> None:
    root = _script_root(tmp_path)
    bin_dir = tmp_path / "bin"
    _utilities(bin_dir)
    available = "npm" if missing == "go" else "go"
    # Presence is sufficient for preflight; no fake inventory may be executed.
    (bin_dir / available).symlink_to("/bin/false")
    result = subprocess.run(
        ["/bin/bash", str(root / "scripts/license_scan.sh")],
        env={**os.environ, "PATH": str(bin_dir)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert f"{missing} is required" in result.stderr
    assert "inventory would be incomplete" in result.stderr
    assert not (root / "build/recorder-license-report").exists()


@pytest.mark.parametrize("gate_license,exit_code", [("MIT", 0), ("GPL-3.0", 1)])
def test_local_license_scan_includes_entrypoint_gate_in_real_policy_check(
    tmp_path: Path, gate_license: str, exit_code: int
) -> None:
    root = _script_root(tmp_path)
    bin_dir = tmp_path / "bin"
    _utilities(bin_dir)
    go_bin = tmp_path / "gopath/bin"
    go_bin.mkdir(parents=True)
    for module in (
        "components/otel-collector-fabric/dist",
        "components/otel-collector-fabric/gate",
        "components/host-emitter",
        "tools/fabricctl",
    ):
        (root / module).mkdir(parents=True)
    # Only external inventory/build commands are fixtures. The shell script and
    # final license_check.py policy evaluation run unchanged in a disposable tree.
    driver = tmp_path / "inventory-driver"
    driver.write_text(
        f"#!{sys.executable}\n"
        "import json, os, pathlib, sys\n"
        "name=pathlib.Path(sys.argv[0]).name; args=sys.argv[1:]\n"
        "if name == 'python':\n"
        " if args[:2] == ['-m','venv']:\n"
        "  target=pathlib.Path(args[2])/'bin'; target.mkdir(parents=True)\n"
        "  for tool in ('python','pip','pip-licenses'):\n"
        "   (target/tool).symlink_to(os.environ['FIXTURE_DRIVER'])\n"
        " elif args[:2] != ['-m','pip']:\n"
        f"  os.execv({sys.executable!r}, [{sys.executable!r}, *args])\n"
        "elif name == 'pip-licenses':\n"
        " print(json.dumps([{'Name':'fixture-python','Version':'1','License':'MIT'}]))\n"
        "elif name == 'go' and args == ['env','GOPATH']:\n"
        " print(os.environ['FIXTURE_GOPATH'])\n"
        "elif name == 'go-licenses':\n"
        " module=pathlib.Path.cwd().name\n"
        " license=os.environ['FIXTURE_GATE_LICENSE'] if module=='gate' else 'MIT'\n"
        " print(f'example.invalid/{module},https://example.invalid/license,{license}')\n"
        "elif name == 'npx':\n"
        " print(json.dumps({'fixture-npm@1':{'licenses':'MIT'}}))\n"
    )
    driver.chmod(0o700)
    for name in ("python", "go", "npm", "npx"):
        (bin_dir / name).symlink_to(driver)
    for name in ("go-licenses", "builder"):
        (go_bin / name).symlink_to(driver)
    result = subprocess.run(
        ["/bin/bash", str(root / "scripts/license_scan.sh")],
        env={
            **os.environ,
            "PATH": str(bin_dir),
            "FABRIC_PYTHON_BIN": str(bin_dir / "python"),
            "FIXTURE_DRIVER": str(driver),
            "FIXTURE_GOPATH": str(go_bin.parent),
            "FIXTURE_GATE_LICENSE": gate_license,
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == exit_code, result.stdout + result.stderr
    report = json.loads(
        (root / "build/recorder-license-report/third-party-licenses.json").read_text()
    )
    assert {row["surface"] for row in report["dependencies"]} == {
        "sdk/python",
        "sdk/typescript",
        "fabric-node",
        "fabricctl",
        "fabric-gate",
        "host-emitter",
    }
    gate = next(
        row for row in report["dependencies"] if row["surface"] == "fabric-gate"
    )
    assert gate["disposition"] == ("ALLOW" if gate_license == "MIT" else "DENY")
