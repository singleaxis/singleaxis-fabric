# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Configuration.

Two inputs matter:

* **Trust bundle** — a list of Ed25519 public keys the verifier will
  accept signatures from. In production the SingleAxis release key
  plus any tenant-mirror keys the operator trusts.
* **Installed Fabric version** — the semver string the cluster
  currently runs. Manifests that require a higher version are
  rejected pre-apply.

Both are loaded from YAML files mounted into the webhook pod (the
Helm chart renders them into a ConfigMap)."""

from __future__ import annotations

import base64
import binascii
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

_ED25519_PUBKEY_LEN = 32


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class TrustedKey(_Base):
    """One allowed signer. ``id`` is an arbitrary operator label,
    ``public_key`` is the Ed25519 pubkey in raw base64 (32 bytes —
    not DER SPKI)."""

    id: str
    public_key: str

    @field_validator("public_key")
    @classmethod
    def _valid_ed25519_pubkey(cls, v: str) -> str:
        if not v:
            raise ValueError("public_key must not be empty")
        try:
            raw = base64.b64decode(v, validate=True)
        except (ValueError, binascii.Error) as e:
            raise ValueError(f"public_key is not valid base64: {e}") from e
        if len(raw) != _ED25519_PUBKEY_LEN:
            raise ValueError(
                f"public_key decodes to {len(raw)} bytes, expected {_ED25519_PUBKEY_LEN} "
                "(raw Ed25519 pubkey, not DER SPKI)"
            )
        return v


class VerifierConfig(_Base):
    """Runtime configuration for the verifier.

    ``fabric_version`` is the cluster-installed umbrella chart
    version; the verifier rejects manifests whose
    ``fabric.singleaxis.dev/version-constraint`` annotation excludes
    this version (PEP 440 / ``packaging.specifiers`` grammar —
    e.g. ``>=0.1,<0.2``).

    ``fail_closed`` decides what happens when a manifest is missing
    the signature or version annotation entirely. Production should
    leave it ``True``; leaving it ``False`` means unannotated
    resources are admitted (useful when rolling out to a cluster
    that has pre-existing resources)."""

    fabric_version: str
    trusted_keys: list[TrustedKey] = Field(default_factory=list)
    fail_closed: bool = True


def load_config(path: Path) -> VerifierConfig:
    """Load a verifier config from YAML."""

    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: top-level YAML must be a mapping")
    return VerifierConfig.model_validate(raw)
