# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Fabric client construction and env parsing."""

from __future__ import annotations

import pytest

from fabric import DEFAULT_PROFILE, Fabric, FabricConfig


def test_from_env_with_all_fields() -> None:
    client = Fabric.from_env(
        env={
            "FABRIC_TENANT_ID": "acme",
            "FABRIC_AGENT_ID": "support-bot",
            "FABRIC_PROFILE": "eu-ai-act-high-risk",
        }
    )
    assert client.tenant_id == "acme"
    assert client.agent_id == "support-bot"
    assert client.profile == "eu-ai-act-high-risk"


def test_from_env_defaults_profile() -> None:
    client = Fabric.from_env(env={"FABRIC_TENANT_ID": "acme", "FABRIC_AGENT_ID": "support-bot"})
    assert client.profile == DEFAULT_PROFILE


@pytest.mark.parametrize(
    ("env", "missing"),
    [
        ({"FABRIC_AGENT_ID": "a"}, "FABRIC_TENANT_ID"),
        ({"FABRIC_TENANT_ID": "t"}, "FABRIC_AGENT_ID"),
    ],
)
def test_from_env_missing_required_var_raises(env: dict[str, str], missing: str) -> None:
    with pytest.raises(ValueError, match=missing):
        Fabric.from_env(env=env)


def test_config_validates_fields() -> None:
    with pytest.raises(ValueError, match="tenant_id"):
        FabricConfig(tenant_id="", agent_id="a")
    with pytest.raises(ValueError, match="agent_id"):
        FabricConfig(tenant_id="t", agent_id="")
    with pytest.raises(ValueError, match="profile"):
        FabricConfig(tenant_id="t", agent_id="a", profile="")


def test_tracer_property_is_reused() -> None:
    client = Fabric(FabricConfig(tenant_id="t", agent_id="a"))
    assert client.tracer is client.tracer
