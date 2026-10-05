# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Local, versioned capture privacy configuration and pre-persistence protection.

This is not policy authoring, regulatory certification, secret detection, or an
execution gate. Explicitly supplied transforms are customer code. Whole-object
HMAC tokens are irreversible scoped pseudonyms, not encrypted originals or a vault.
Keep credentials out of this public configuration and metadata.
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal

POLICY_SCHEMA_VERSION = "fabric.deployment-policy/v1"
PRIVACY_MODES = frozenset({"metadata_only", "omit", "redact", "tokenize", "retain_original"})
PrivacyMode = Literal["metadata_only", "omit", "redact", "tokenize", "retain_original"]
ProtectionStatus = Literal["withheld", "redacted", "tokenized", "retained", "unsupported", "lost"]
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_VERSION = 2147483647
_MAX_DAYS = 36500
_MAX_PAYLOAD = 64 * 1024 * 1024
_MIN_KEY_BYTES = 32
_MAX_ITEMS = 256
_MAX_ROOT = 4096


def _object(value: object, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not required <= value.keys():
        raise ValueError("invalid deployment policy object or missing fields")
    if value.keys() - required - (optional or set()):
        raise ValueError("unknown deployment policy fields")
    return dict(value)


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("deployment policy requires opaque ASCII identifiers")
    return value


def _positive(value: object, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError("deployment policy integer is outside its bounds")
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


class DeploymentPolicy:
    """Validated immutable snapshot; digest binds every configured field.

    Parse before installing capture. Invalid configuration raises a fixed error
    without echoing values. A valid policy is only configuration, never proof that
    TLS, encryption, retention, redaction quality or region controls exist.
    """

    __slots__ = ("_canonical", "_digest")

    def __init__(self, value: Mapping[str, Any]) -> None:  # noqa: PLR0912
        data = _object(
            value,
            {
                "schema_version",
                "policy_id",
                "policy_version",
                "tenant_id",
                "workload_id",
                "privacy",
                "storage",
                "retention",
                "required_integrations",
                "deployment",
            },
        )
        if data["schema_version"] != POLICY_SCHEMA_VERSION:
            raise ValueError("unsupported deployment policy schema version")
        for key in ("policy_id", "tenant_id", "workload_id"):
            data[key] = _identifier(data[key])
        data["policy_version"] = _positive(data["policy_version"], _MAX_VERSION)
        privacy = data["privacy"]
        if not isinstance(privacy, Mapping) or not 1 <= len(privacy) <= _MAX_ITEMS:
            raise ValueError("deployment privacy requires a bounded role map")
        for role, mode in privacy.items():
            _identifier(role)
            if not isinstance(mode, str) or mode not in PRIVACY_MODES:
                raise ValueError("unsupported deployment privacy mode")
        data["privacy"] = dict(privacy)
        storage = _object(data["storage"], {"backend", "region", "key_id"}, {"root"})
        if storage["backend"] != "local":
            raise ValueError("unsupported deployment storage backend")
        for key in ("region", "key_id"):
            storage[key] = _identifier(storage[key])
        if "root" in storage:
            root = storage["root"]
            if (
                not isinstance(root, str)
                or not 1 <= len(root) <= _MAX_ROOT
                or not re.fullmatch(r"[ -~]+", root)
            ):
                raise ValueError("storage root must be a bounded printable ASCII path")
        data["storage"] = storage
        retention = _object(data["retention"], {"days"})
        retention["days"] = _positive(retention["days"], _MAX_DAYS)
        data["retention"] = retention
        integrations = data["required_integrations"]
        if not isinstance(integrations, list) or len(integrations) > _MAX_ITEMS:
            raise ValueError("required integrations must be a bounded list")
        integrations = [_identifier(item) for item in integrations]
        if len(set(integrations)) != len(integrations):
            raise ValueError("required integrations must be unique")
        data["required_integrations"] = sorted(integrations)
        deployment = _object(
            data["deployment"],
            {
                "profile",
                "image_digest",
                "tls_required",
                "encrypted_store_required",
            },
        )
        if deployment["profile"] not in ("local", "production"):
            raise ValueError("unsupported deployment profile")
        image = deployment["image_digest"]
        if not isinstance(image, str) or (image != "local" and not _DIGEST.fullmatch(image)):
            raise ValueError("image digest must be local or a pinned SHA-256 digest")
        if any(
            type(deployment[key]) is not bool
            for key in ("tls_required", "encrypted_store_required")
        ):
            raise ValueError("deployment security flags must be booleans")
        if deployment["profile"] == "production" and (
            image == "local"
            or not deployment["tls_required"]
            or not deployment["encrypted_store_required"]
        ):
            raise ValueError("production requires pinned image, TLS and encrypted storage")
        data["deployment"] = deployment
        self._canonical = _canonical(data)
        self._digest = "sha256:" + hashlib.sha256(self._canonical).hexdigest()

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> DeploymentPolicy:
        return cls(value)

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = json.loads(self._canonical)
        return value

    @property
    def digest(self) -> str:
        return self._digest

    @property
    def schema_version(self) -> str:
        return POLICY_SCHEMA_VERSION

    @property
    def policy_id(self) -> str:
        return str(self.to_dict()["policy_id"])

    @property
    def policy_version(self) -> int:
        return int(self.to_dict()["policy_version"])

    @property
    def tenant_id(self) -> str:
        return str(self.to_dict()["tenant_id"])

    @property
    def workload_id(self) -> str:
        return str(self.to_dict()["workload_id"])

    @property
    def privacy(self) -> Mapping[str, str]:
        return MappingProxyType(self.to_dict()["privacy"])

    @property
    def storage(self) -> Mapping[str, Any]:
        return MappingProxyType(self.to_dict()["storage"])

    @property
    def retention(self) -> Mapping[str, int]:
        return MappingProxyType(self.to_dict()["retention"])

    @property
    def deployment(self) -> Mapping[str, Any]:
        return MappingProxyType(self.to_dict()["deployment"])

    @property
    def required_integrations(self) -> tuple[str, ...]:
        return tuple(self.to_dict()["required_integrations"])


@dataclass(frozen=True, slots=True)
class ProtectedContent:
    """Safe metadata plus a separate payload. ``to_dict`` never includes bytes."""

    status: ProtectionStatus
    mode: str
    original_digest: str | None
    metadata: Mapping[str, Any]
    protected_bytes: bytes | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "mode": self.mode,
            "original_digest": self.original_digest,
            "metadata": dict(self.metadata),
        }


class ContentProtector:
    """Bounded synchronous protection; transform errors become content loss.

    Unknown roles are omitted. No transform, hash or payload length is produced
    for omissions. Redaction needs an explicit per-role customer function; no
    generic detector or silent fallback is supplied. Token keys remain in memory
    and must be independently generated with >=32 bytes of entropy.
    """

    def __init__(
        self,
        policy: DeploymentPolicy,
        *,
        redactors: Mapping[str, Callable[[bytes], bytes]] | None = None,
        tokenization_key: bytes | None = None,
        payload_max_bytes: int = 1024 * 1024,
    ) -> None:
        if not isinstance(policy, DeploymentPolicy):
            raise ValueError("content protection requires a DeploymentPolicy")
        _positive(payload_max_bytes, _MAX_PAYLOAD)
        self.policy = policy
        self.payload_max_bytes = payload_max_bytes
        self._redactors = dict(redactors or {})
        roles = policy.privacy
        if any(
            roles.get(role) != "redact" or not callable(fn) or inspect.iscoroutinefunction(fn)
            for role, fn in self._redactors.items()
        ):
            raise ValueError("redactors must match explicitly redacted roles")
        if any(mode == "redact" and role not in self._redactors for role, mode in roles.items()):
            raise ValueError("redact mode requires an explicit customer redactor for each role")
        if tokenization_key is not None and (
            not isinstance(tokenization_key, bytes) or len(tokenization_key) < _MIN_KEY_BYTES
        ):
            raise ValueError("tokenization requires a key of at least 32 bytes")
        if "tokenize" in roles.values() and tokenization_key is None:
            raise ValueError("tokenize mode requires a caller-supplied key")
        self._key = tokenization_key
        self._modes = dict(roles)
        self._scope = {
            "schema_version": "fabric.token/v1",
            "policy_digest": policy.digest,
            "tenant_id": policy.tenant_id,
            "workload_id": policy.workload_id,
        }

    def protect(self, role: str, data: bytes) -> ProtectedContent:  # noqa: PLR0911
        """No exception text or rejected bytes are retained on failure."""
        mode = self._modes.get(role, "omit") if isinstance(role, str) else "omit"
        metadata: dict[str, Any] = {"policy_digest": self.policy.digest}

        def result(
            status: ProtectionStatus,
            reason: str,
            payload: bytes | None = None,
            original_digest: str | None = None,
        ) -> ProtectedContent:
            return ProtectedContent(
                status,
                mode,
                original_digest,
                MappingProxyType({**metadata, "reason": reason}),
                payload,
            )

        if mode == "omit":
            return result("withheld", "omitted_by_policy")
        if not isinstance(data, bytes):
            return result("unsupported", "unsupported_input_type")
        if mode == "metadata_only":
            metadata["source_byte_length"] = len(data)
            return result("withheld", "metadata_only")
        if len(data) > self.payload_max_bytes:
            return result("lost", "payload_too_large")
        try:
            if mode == "retain_original":
                metadata["source_byte_length"] = len(data)
                return result(
                    "retained",
                    "original_retained",
                    data,
                    "sha256:" + hashlib.sha256(data).hexdigest(),
                )
            if mode == "redact":
                payload = self._redactors[role](data)
                if not isinstance(payload, bytes):
                    if inspect.iscoroutine(payload):
                        payload.close()
                    return result("unsupported", "unsupported_transform_output")
                if len(payload) > self.payload_max_bytes:
                    return result("lost", "protected_payload_too_large")
                metadata["transform"] = "customer_redactor"
                return result("redacted", "redacted_by_customer", payload)
            if mode == "tokenize" and self._key is not None:
                scope = _canonical({**self._scope, "role": role})
                message = (
                    len(scope).to_bytes(4, "big") + scope + len(data).to_bytes(8, "big") + data
                )
                token = hmac.new(self._key, message, hashlib.sha256).hexdigest()
                payload = ("fabric.token.v1:" + token).encode("ascii")
                if len(payload) > self.payload_max_bytes:
                    return result("lost", "protected_payload_too_large")
                metadata["transform"] = "hmac_sha256_whole_object_v1"
                return result("tokenized", "tokenized_by_policy", payload)
        except Exception:
            return result("lost", "protection_failed")
        return result("unsupported", "unsupported_protection_mode")
