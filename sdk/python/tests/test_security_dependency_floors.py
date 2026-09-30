# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Security floors must survive package metadata, not just CI resolution."""

from __future__ import annotations

import importlib.metadata
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.version import Version

_ROOT = Path(__file__).resolve().parents[1]


def test_declared_optional_security_floors() -> None:
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text())
    extras = project["project"]["optional-dependencies"]
    assert "PyJWT>=2.15.0" in extras["mcp"]
    assert "cryptography>=49" in extras["signing"]
    assert "cryptography>=49" in project["dependency-groups"]["dev"]
    assert "urllib3>=2.8.0" in extras["otlp"]
    assert "urllib3>=2.8.0" in project["dependency-groups"]["dev"]


def test_locked_mcp_authentication_is_patched() -> None:
    lock = tomllib.loads((_ROOT / "uv.lock").read_text())
    versions = [Version(item["version"]) for item in lock["package"] if item["name"] == "pyjwt"]
    assert versions and all(value >= Version("2.15.0") for value in versions)


def test_locked_http_transport_is_patched() -> None:
    lock = tomllib.loads((_ROOT / "uv.lock").read_text())
    versions = [Version(item["version"]) for item in lock["package"] if item["name"] == "urllib3"]
    assert versions and all(value >= Version("2.8.0") for value in versions)


def test_installed_requirements_reject_old_crypto_and_jwt() -> None:
    requirements = [
        Requirement(value) for value in importlib.metadata.requires("singleaxis-fabric") or []
    ]
    for package, extra, old, floor in (
        ("pyjwt", "mcp", "2.13.0", "2.15.0"),
        ("cryptography", "signing", "48.0.0", "49.0.0"),
        ("urllib3", "otlp", "2.7.0", "2.8.0"),
    ):
        matches = [
            item
            for item in requirements
            if item.name.lower() == package
            and item.marker is not None
            and item.marker.evaluate({"extra": extra})
        ]
        assert len(matches) == 1
        assert Version(old) not in matches[0].specifier
        assert Version(floor) in matches[0].specifier
