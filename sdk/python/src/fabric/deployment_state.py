# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Local authenticated capture configuration lifecycle for portal adapters.

No HTTP server, remote rollout, SSO, action authorization, or fleet management is
installed. File-backed optimistic revisions and explicit observations give a
future caller a machine-readable interface without treating intent as execution.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import re
import stat
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from .capture_readback import CaptureReadback, assess_readback
from .deployment_policy import DeploymentPolicy

_MAX_STATE_BYTES = 4 * 1024 * 1024
_MAX_HISTORY = 1000
_MAX_CAPABILITIES = 256
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_STATE_FIELDS = frozenset(
    {
        "schema_version",
        "revision",
        "tenant_id",
        "workload_id",
        "desired_policy",
        "desired_digest",
        "approved_digest",
        "applied",
        "history",
    }
)
_EVENT_FIELDS = frozenset(
    {
        "action",
        "revision",
        "policy_digest",
        "actor",
        "observed_at",
        "previous_digest",
        "event_digest",
    }
)


def _event_digest(event: Mapping[str, Any]) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )


def _validate_history(state: Mapping[str, Any]) -> None:  # noqa: PLR0912, PLR0915
    """Check local corruption/invariants, not authenticity against a host administrator."""
    history = state["history"]
    if not isinstance(history, list) or not 1 <= len(history) <= _MAX_HISTORY:
        raise ValueError("registry history integrity mismatch")
    if type(state["revision"]) is not int or state["revision"] != len(history) - 1:
        raise ValueError("registry revision integrity mismatch")
    previous = None
    desired = None
    approved = None
    applied = None
    for revision, event in enumerate(history):
        if not isinstance(event, dict) or event.keys() != _EVENT_FIELDS:
            raise ValueError("registry history integrity mismatch")
        unsigned = {key: value for key, value in event.items() if key != "event_digest"}
        if (
            type(event["revision"]) is not int
            or event["revision"] != revision
            or event["previous_digest"] != previous
            or event["event_digest"] != _event_digest(unsigned)
            or not isinstance(event["actor"], str)
            or not _ID.fullmatch(event["actor"])
            or not isinstance(event["policy_digest"], str)
            or not _DIGEST.fullmatch(event["policy_digest"])
            or not isinstance(event["observed_at"], str)
            or not isinstance(event["action"], str)
        ):
            raise ValueError("registry history integrity mismatch")
        try:
            observed_at = datetime.fromisoformat(event["observed_at"])
            if observed_at.utcoffset() is None:
                raise ValueError
        except ValueError:
            raise ValueError("registry history timestamp integrity mismatch") from None
        action = event["action"]
        digest = event["policy_digest"]
        if revision == 0:
            if action != "initialized":
                raise ValueError("registry history initialization integrity mismatch")
            desired = digest
        elif action == "proposed":
            if digest == desired:
                raise ValueError("registry proposal integrity mismatch")
            desired, approved = digest, None
        elif action in {"approved", "applied_observed"} and digest == desired:
            if action == "approved":
                approved = desired
            elif approved == desired:
                applied = desired
            else:
                raise ValueError("registry applied observation lacks approval")
        else:
            raise ValueError("registry history transition integrity mismatch")
        previous = event["event_digest"]
    if state["desired_digest"] != desired or state["approved_digest"] != approved:
        raise ValueError("registry desired or approval integrity mismatch")
    observation = state["applied"]
    if observation is None:
        if applied is not None:
            raise ValueError("registry applied observation integrity mismatch")
        return
    if (
        not isinstance(observation, dict)
        or observation.keys() != {"policy_digest", "capabilities", "evidence"}
        or applied is None
        or observation["policy_digest"] != applied
        or observation["evidence"] != "authorized_caller_report"
    ):
        raise ValueError("registry applied observation integrity mismatch")
    capabilities = observation["capabilities"]
    if (
        not isinstance(capabilities, list)
        or len(capabilities) > _MAX_CAPABILITIES
        or any(not isinstance(value, str) or not _ID.fullmatch(value) for value in capabilities)
        or capabilities != sorted(set(capabilities))
    ):
        raise ValueError("registry applied capabilities integrity mismatch")


class PolicyAuthority(Protocol):
    def authorize(
        self, capability: Any, *, policy: DeploymentPolicy, permission: str
    ) -> Mapping[str, Any]: ...


class RevisionConflictError(ValueError):
    """The client must read current state before retrying its intended change."""


def validate_policy(value: Mapping[str, Any]) -> dict[str, Any]:
    """Pure dry-run: no storage, credentials, transforms, network, or rollout."""
    policy = DeploymentPolicy.from_dict(value)
    return {
        "valid": True,
        "policy_digest": policy.digest,
        "policy_scope": "capture_configuration",
        "configuration_only": True,
        "production_qualified": False,
    }


class CapturePolicyRegistry:
    """Single-host, bounded policy state; authority and tokens are never persisted.

    Existing records are authorized against their current desired policy. An
    administrator needs a newly bound capability after proposing a new version.
    Applied status is an authorized caller observation, not runtime attestation.
    Local host/file administrators remain outside this isolation threat model.
    History hashes detect corruption; they are unkeyed and not an authenticated
    or independently witnessed audit trail.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        authority: PolicyAuthority,
        initial_policy: DeploymentPolicy,
        capability: Any,
    ) -> None:
        self.authority = authority
        self._initial = initial_policy
        claims = authority.authorize(capability, policy=initial_policy, permission="policy_admin")
        values = initial_policy.to_dict()
        base = Path(root).absolute()
        if any(path.is_symlink() for path in (base, *base.parents)):
            raise ValueError("registry path must not traverse symlinks")
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root = base / values["tenant_id"] / values["workload_id"]
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if any(path.is_symlink() for path in (self.root, self.root.parent)):
            raise ValueError("registry path must not traverse symlinks")
        self.path = self.root / "capture-policy.json"
        with self._lock():
            if not self.path.exists():
                state = {
                    "schema_version": "fabric.capture-deployment-state/v1",
                    "revision": 0,
                    "tenant_id": values["tenant_id"],
                    "workload_id": values["workload_id"],
                    "desired_policy": values,
                    "desired_digest": initial_policy.digest,
                    "approved_digest": None,
                    "applied": None,
                    "history": [],
                }
                self._event(state, "initialized", claims)
                self._write(state)
            else:
                self._authorized(capability, "policy_admin")

    @contextmanager
    def _lock(self) -> Iterator[None]:
        descriptor = os.open(self.root / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("registry lock must be regular")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    def _read(self) -> dict[str, Any]:
        descriptor = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("registry state must be a single regular file")
            data = handle.read(_MAX_STATE_BYTES + 1)
        if len(data) > _MAX_STATE_BYTES:
            raise ValueError("registry state capacity exceeded")
        state: dict[str, Any] = json.loads(data)
        if (
            not isinstance(state, dict)
            or state.keys() != _STATE_FIELDS
            or state["schema_version"] != "fabric.capture-deployment-state/v1"
        ):
            raise ValueError("registry state integrity mismatch")
        policy = DeploymentPolicy.from_dict(state["desired_policy"])
        initial = self._initial.to_dict()
        values = policy.to_dict()
        if (
            any(
                values[key] != initial[key] or state[key] != values[key]
                for key in ("tenant_id", "workload_id")
            )
            or values["policy_id"] != initial["policy_id"]
        ):
            raise ValueError("registry identity mismatch")
        if state["desired_digest"] != policy.digest:
            raise ValueError("registry policy integrity mismatch")
        _validate_history(state)
        return state

    def _write(self, state: dict[str, Any]) -> None:
        _validate_history(state)
        data = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        if len(data) > _MAX_STATE_BYTES:
            raise ValueError("registry state capacity exceeded")
        temporary = self.root / (".state-" + uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _authorized(
        self, capability: Any, permission: str
    ) -> tuple[dict[str, Any], Mapping[str, Any]]:
        state = self._read()
        policy = DeploymentPolicy.from_dict(state["desired_policy"])
        claims = self.authority.authorize(capability, policy=policy, permission=permission)
        return state, claims

    @staticmethod
    def _revision(state: dict[str, Any], expected_revision: int) -> None:
        if type(expected_revision) is not int or state["revision"] != expected_revision:
            raise RevisionConflictError("capture policy revision conflict")

    @staticmethod
    def _event(state: dict[str, Any], action: str, claims: Mapping[str, Any]) -> None:
        if len(state["history"]) >= _MAX_HISTORY:
            raise ValueError("registry audit capacity reached; archival required")
        previous = state["history"][-1]["event_digest"] if state["history"] else None
        event = {
            "action": action,
            "revision": state["revision"],
            "policy_digest": state["desired_digest"],
            "actor": claims.get("subject_id", "unknown"),
            "observed_at": datetime.now(UTC).isoformat(),
            "previous_digest": previous,
        }
        event["event_digest"] = _event_digest(event)
        state["history"].append(event)

    def read(self, capability: Any) -> dict[str, Any]:
        with self._lock():
            state, _ = self._authorized(capability, "policy_read")
        observed = state["applied"]
        lifecycle = "desired"
        if state["approved_digest"] == state["desired_digest"]:
            lifecycle = "approved"
            if observed is not None and observed["policy_digest"] == state["desired_digest"]:
                lifecycle = "applied_observed"
        return {
            **copy.deepcopy(state),
            "policy_scope": "capture_configuration",
            "configuration_lifecycle": lifecycle,
            "drift": observed is None or observed["policy_digest"] != state["desired_digest"],
            "runtime_attestation": "unverified",
            "production_qualified": False,
        }

    def readback(
        self,
        capability: Any,
        *,
        observation: CaptureReadback,
        observer_capability: Any,
        max_age_seconds: int = 300,
    ) -> dict[str, Any]:
        """Compare authenticated workload readback without changing local lifecycle.

        ``policy_read`` sees the assessment; the separate ``policy_observe``
        grant reports runtime configuration without obtaining policy_admin.
        Use IdentityBoundAuthority to bind those grants to explicit workload
        and operator identities. A verified reporter is not runtime attestation.
        """
        if not isinstance(observation, CaptureReadback):
            raise ValueError("capture readback must be validated")
        with self._lock():
            state, _ = self._authorized(capability, "policy_read")
            policy = DeploymentPolicy.from_dict(state["desired_policy"])
            claims = self.authority.authorize(
                observer_capability, policy=policy, permission="policy_observe"
            )
            result = assess_readback(
                state, observation, now=int(time.time()), max_age_seconds=max_age_seconds
            )
        result["reporter"] = {
            "subject_id": claims.get("subject_id", "unknown"),
            "subject_kind": claims.get("subject_kind", "unbound"),
            "authentication": "authorized_caller_report",
        }
        return result

    def propose(self, value: Mapping[str, Any], *, expected_revision: int, capability: Any) -> int:
        candidate = DeploymentPolicy.from_dict(value)
        with self._lock():
            state, claims = self._authorized(capability, "policy_admin")
            self._revision(state, expected_revision)
            old, new = state["desired_policy"], candidate.to_dict()
            if any(old[key] != new[key] for key in ("tenant_id", "workload_id", "policy_id")):
                raise ValueError("policy identity cannot change within a registry")
            if new["policy_version"] <= old["policy_version"]:
                raise ValueError("policy version must increase")
            state.update(desired_policy=new, desired_digest=candidate.digest, approved_digest=None)
            state["revision"] += 1
            self._event(state, "proposed", claims)
            self._write(state)
            return int(state["revision"])

    def approve(self, *, expected_revision: int, capability: Any) -> int:
        with self._lock():
            state, claims = self._authorized(capability, "policy_admin")
            self._revision(state, expected_revision)
            state["approved_digest"] = state["desired_digest"]
            state["revision"] += 1
            self._event(state, "approved", claims)
            self._write(state)
            return int(state["revision"])

    def observe_applied(
        self,
        *,
        policy_digest: str,
        capabilities: list[str],
        expected_revision: int,
        capability: Any,
    ) -> int:
        if len(capabilities) > _MAX_CAPABILITIES or any(
            not isinstance(value, str) or not _ID.fullmatch(value) for value in capabilities
        ):
            raise ValueError("invalid deployment capability identifiers")
        with self._lock():
            state, claims = self._authorized(capability, "policy_admin")
            self._revision(state, expected_revision)
            if (
                policy_digest != state["desired_digest"]
                or state["approved_digest"] != policy_digest
            ):
                raise ValueError("applied observation requires the exact approved desired policy")
            state["applied"] = {
                "policy_digest": policy_digest,
                "capabilities": sorted(set(capabilities)),
                "evidence": "authorized_caller_report",
            }
            state["revision"] += 1
            self._event(state, "applied_observed", claims)
            self._write(state)
            return int(state["revision"])
