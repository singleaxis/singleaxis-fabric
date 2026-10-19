# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Capture policy and the production profile gate (spec 049 §2.7, §7.3, §7.8).

The capture policy maps each content role to a privacy mode (deployment-policy/v1). The
gate decides, once per install, whether wire content may be captured at all:

- ``production`` (node mode, or ``deployment.profile: production`` in the policy) needs a
  capture policy, ``FABRIC_WIRE_ID_KEY`` and, when a spool is used, the spool envelope
  key; a missing one disables content (metadata continues) with that reason;
- ``local`` needs nothing: without a policy the implicit ``fabric.local-default`` applies;
- no content destination at all is metadata-only (``no_store``).

Missing protection is never a configuration error; a malformed policy file is (it raises
at :func:`fabric.wire.install`). Nothing here logs a value, path or key.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from .._roles import ROLE_TABLE_VERSION, ROLES
from ..deployment_policy import DeploymentPolicy

POLICY_ENV = "FABRIC_CAPTURE_POLICY"  # path to a deployment-policy/v1 JSON document
LOCAL_DEFAULT_ID = "fabric.local-default"
MAX_POLICY_BYTES = 1 << 20
# store_reason when production lacks the spool envelope key (§7.8; coordinator decision,
# added to the store_reason and content_capture_reason vocabularies by the contract owner).
MISSING_SPOOL_KEY = "missing_spool_key"
Profile = Literal["local", "production"]
ContentCapture = Literal["enabled", "disabled", "metadata_only"]
BYTE_MODES = frozenset(
    {"retain_original", "redact", "tokenize", "masked_only", "original_plus_masked"}
)


@dataclass(frozen=True, slots=True)
class CapturePolicy:
    """The policy in force: an explicit deployment policy or ``fabric.local-default``."""

    policy_id: str
    policy_version: int
    policy_digest: str
    modes: Mapping[str, str]
    implicit: bool = False
    profile: Profile | None = None  # the policy's declared deployment.profile
    encrypted_store_required: bool = False
    workload_id: str | None = None
    tenant_id: str | None = None

    def mode(self, role: str) -> str:
        """The role's privacy mode by the §2.7 precedence (rules 2-5): named → that mode;
        implicit local default → ``retain_original`` for ``content`` roles, ``omit`` for
        ``off`` roles; a configured policy that does not name the role → ``omit``."""
        if (named := self.modes.get(role)) is not None:
            return named
        row = ROLES.get(role)
        if self.implicit and row is not None and row.default_policy == "content":
            return "retain_original"
        return "omit"

    def block(self) -> dict[str, Any]:
        """The descriptor's policy fields (content-v2: all or none)."""
        return {
            "policy_id": self.policy_id, "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
        }  # fmt: skip

    @classmethod
    def from_deployment(cls, policy: DeploymentPolicy) -> CapturePolicy:
        deployment = policy.deployment
        return cls(
            policy.policy_id, policy.policy_version, policy.digest, dict(policy.privacy),
            profile=deployment["profile"],
            encrypted_store_required=bool(deployment["encrypted_store_required"]),
            workload_id=policy.workload_id, tenant_id=policy.tenant_id,
        )  # fmt: skip


def _local_default() -> CapturePolicy:
    """``fabric.local-default`` (version 1): its digest binds the role → mode table it
    implies and the role table version, so a role-table change is a new digest."""
    modes = {
        role: "retain_original" if row.default_policy == "content" else "omit"
        for role, row in sorted(ROLES.items())
    }
    doc = {"policy_id": LOCAL_DEFAULT_ID, "policy_version": 1, "privacy": modes,
           "role_table_version": ROLE_TABLE_VERSION}  # fmt: skip
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    return CapturePolicy(LOCAL_DEFAULT_ID, 1, digest, {}, implicit=True, profile="local")


LOCAL_DEFAULT = _local_default()


def load_policy(path: str) -> DeploymentPolicy:
    """Read and validate a deployment-policy/v1 file; ``ValueError`` (fixed text, never the
    path or a value) when it is unreadable, oversized, not JSON or schema-invalid."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_POLICY_BYTES + 1)
    except OSError:
        raise ValueError(f"{POLICY_ENV} is not readable") from None
    if len(raw) > MAX_POLICY_BYTES:
        raise ValueError(f"{POLICY_ENV} is too large")
    try:
        return DeploymentPolicy(json.loads(raw))
    except ValueError:
        raise ValueError(f"{POLICY_ENV} is not a valid deployment-policy/v1 document") from None


def policy_from_env(environ: Mapping[str, str]) -> DeploymentPolicy | None:
    path = (environ.get(POLICY_ENV) or "").strip()
    return load_policy(path) if path else None


@dataclass(frozen=True, slots=True)
class ContentGate:
    """The install-time content decision; ``reason`` is the ``fabric.wire.store_reason``
    every exchange span carries while content is not ``enabled``."""

    profile: Profile
    content_capture: ContentCapture
    reason: str | None
    policy: CapturePolicy | None
    spool_encrypted: bool = False
    keyed: bool = False
    key_id: str | None = field(default=None)

    @property
    def enabled(self) -> bool:
        return self.content_capture == "enabled"

    def status(self) -> dict[str, Any]:
        """The manifest's P0-A properties (spec 049 §2.8, §4.2), values only: no keys."""
        policy = self.policy
        return {
            "profile": self.profile, "content_capture": self.content_capture,
            "content_capture_reason": _CAPTURE_REASON.get(self.reason or ""),
            "store_reason": self.reason,
            "capture_policy": None if policy is None else {
                **policy.block(), "encrypted_store_required": policy.encrypted_store_required},
            "pseudonym_mode": "keyed" if self.keyed else "unkeyed", "key_id": self.key_id,
            "spool_encrypted": self.spool_encrypted, "role_table_version": ROLE_TABLE_VERSION,
        }  # fmt: skip


# store_reason -> manifest content_capture_reason
_CAPTURE_REASON = {
    "no_store": "not_configured", "missing_capture_policy": "missing_capture_policy",
    "missing_id_key": "missing_id_key", MISSING_SPOOL_KEY: MISSING_SPOOL_KEY,
}  # fmt: skip


def decide(
    *, node: bool, store: bool, policy: DeploymentPolicy | None, id_key: bytes | None,
    spool: bool, spool_key: bool, key_id: str | None = None,
) -> ContentGate:  # fmt: skip
    """The §7.3 gate. ``store``: a direct (``file://``) store; ``spool``: a spool is used."""
    capture = CapturePolicy.from_deployment(policy) if policy is not None else None
    production = node or (capture is not None and capture.profile == "production")
    profile: Profile = "production" if production else "local"
    keyed, encrypted = id_key is not None, spool and spool_key

    def gate(state: ContentCapture, why: str | None, policy: CapturePolicy | None) -> ContentGate:
        return ContentGate(profile, state, why, policy, encrypted, keyed, key_id)

    if not node and not store:
        return gate("metadata_only", "no_store", capture)
    reason = None
    if production and capture is None:
        reason = "missing_capture_policy"
    elif production and id_key is None:
        reason = "missing_id_key"
    elif production and spool and not spool_key:
        reason = MISSING_SPOOL_KEY
    if reason is not None:
        return gate("disabled", reason, capture)
    return gate("enabled", None, capture or LOCAL_DEFAULT)
