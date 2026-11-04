# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Explicit, opt-in content-v2 byte evidence capture.

The default is a bounded process-memory handoff. An explicitly configured
DurableByteSpool adds encrypted protected-byte admission and restartable replay;
passive capture still returns pending, never a durability acknowledgement.
This is not automatic terminal/SSH/database interception. Callers must publish and
reconcile the returned descriptors through their own evidence pipeline.
Only a caller-reported provenance is supportable from this SDK surface.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import queue
import re
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import InitVar, dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

from ._sequence import (
    EmittedIds,
    IdentityMode,
    check_id_key,
    emitted_ids,
    id_key_from_env,
    identity_mode_from_env,
)
from .byte_spool import ByteSpoolAdmissionError, DurableByteSpool
from .content_store.base import ByteEvidenceStore, check_safe_identifier
from .deployment_policy import ContentProtector, DeploymentPolicy
from .redaction import (
    RedactionClient,
    RedactionService,
    Transformation,
    refuse_removed,
    resolve_service,
)

_ROLES = frozenset(
    {
        "model.request.instructions",
        "model.request.messages",
        "model.request.tool_definitions",
        "model.request.parameters",
        "model.output.messages",
        "tool.definition",
        "tool.call.arguments",
        "tool.call.result",
        "retrieval.query",
        "retrieval.results",
        "memory.write.content",
        "memory.read.content",
        "side_effect.request",
        "side_effect.result",
        "context.file",
        "interaction.payload",
        "terminal.argv",
        "terminal.stdin",
        "terminal.stdout",
        "terminal.stderr",
        "remote.request",
        "remote.result",
        "remote.stream",
        "database.query",
        "database.parameters",
        "database.rows",
        "database.mutation",
        "network.request",
        "network.response",
        "network.stream",
        "sandbox.config",
        "sandbox.output",
        "artifact.before",
        "artifact.after",
        "service.receipt",
    }
)
_BOUNDARIES = frozenset(
    {"caller", "provider_bound", "tool", "terminal", "sandbox", "remote", "host", "service"}
)
_MEDIA_TYPE_RE = re.compile(r"^[a-zA-Z0-9!#$&^_.+-]+/[a-zA-Z0-9!#$&^_.+-]+$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_MEDIA_TYPE_MAX_LENGTH = 128
# Deployment modes whose stored object is a derivative (to the review store).
_DERIVED = frozenset({"redact", "masked_only", "tokenize"})
# A byte privacy mode as the capture policy names it (spec 050 §3.10 config check).
_CAPTURE_POLICY_MODE = {"original": "retain_original"}
_OPAQUE_ID_MAX_LENGTH = 128
# Spec 049 §7.7 rule 3 / content-v2 2.2.0: every object stored under a masked mode records
# the policy id, version and digest. Caller-supplied ``role_policies`` have no deployment
# policy, so they are bound by an implicit one (like ``fabric.local-default``) whose digest
# binds each role's mode and transformation identity and version.
ROLE_POLICIES_ID = "fabric.role-policies"
_MASKED_MODES = frozenset({"masked_only", "original_plus_masked"})
_LOG = logging.getLogger("fabric.byte_evidence")


def _production_marked(policy: object) -> bool:
    return isinstance(policy, DeploymentPolicy) and policy.deployment["profile"] == "production"


def content_gate(
    deployment_policy: DeploymentPolicy | None, id_key: bytes | None,
    *stores: ByteEvidenceStore | None,
) -> tuple[str, str | None]:  # fmt: skip
    """Spec 049 §7.3 on the explicit (records) input, as on the wire (§7.7 "both
    inputs"): ``(profile, reason)``. The ``production`` profile (the deployment policy, or
    a store's own policy, is marked production) needs the capture policy and the id key
    (``FABRIC_WIRE_ID_KEY``); a missing one disables content capture with that reason
    (metadata continues). The optional durable spool is always sealed (AES-256-GCM, a
    customer key), so it never lacks the spool envelope. ``local`` needs nothing."""
    marked = _production_marked(deployment_policy) or any(
        _production_marked(getattr(store, "policy", None)) for store in stores
    )
    if not marked:
        return "local", None
    if deployment_policy is None:
        return "production", "missing_capture_policy"
    if id_key is None:
        return "production", "missing_id_key"
    return "production", None


def _validate_capture_args(
    data: bytes,
    *,
    role: str,
    boundary: str,
    source_id: str,
    source_epoch: int,
    source_sequence: int,
    media_type: str,
    run_id: str | None,
    operation_id: str | None,
    attempt_id: str | None,
    stream_id: str | None,
    chunk_index: int | None,
) -> None:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes; no implicit text conversion")
    if role not in _ROLES:
        raise ValueError("role is not a content-v2 role")
    if boundary not in _BOUNDARIES:
        raise ValueError("boundary is not a content-v2 boundary")
    for name, value in (
        ("source_id", source_id),
        ("run_id", run_id),
        ("operation_id", operation_id),
        ("attempt_id", attempt_id),
        ("stream_id", stream_id),
    ):
        if value is not None and (
            not isinstance(value, str)
            or len(value) > _OPAQUE_ID_MAX_LENGTH
            or not _ID_RE.fullmatch(value)
        ):
            raise ValueError(f"{name} must be a content-v2 opaque identifier")
    if not source_id:
        raise ValueError("source_id is required")
    for counter_name, counter_value in (
        ("source_epoch", source_epoch),
        ("source_sequence", source_sequence),
    ):
        if (
            not isinstance(counter_value, int)
            or isinstance(counter_value, bool)
            or counter_value < 0
        ):
            raise ValueError(f"{counter_name} must be a non-negative integer")
    if chunk_index is not None:
        if stream_id is None:
            raise ValueError("chunk_index requires stream_id")
        if not isinstance(chunk_index, int) or isinstance(chunk_index, bool) or chunk_index < 0:
            raise ValueError("chunk_index must be a non-negative integer")
    if (
        not isinstance(media_type, str)
        or len(media_type) > _MEDIA_TYPE_MAX_LENGTH
        or not _MEDIA_TYPE_RE.fullmatch(media_type)
    ):
        raise ValueError("media_type must be a valid MIME type")


@dataclass(frozen=True, slots=True)
class BytePrivacyPolicy:
    """Customer-approved content handling; masking runs behind the handoff.

    The masked copy of ``masked_only`` and ``original_plus_masked`` is made by the
    customer-run redaction service (``ByteEvidenceConfig.redaction``, else
    ``FABRIC_REDACTION_ENDPOINT``; ``contracts/redaction/v1``), called on the recorder's
    worker, never the caller's thread, with this transformation identity and version.
    Fabric runs no customer code and ships no PII detector. A failed, timed-out,
    oversized or saturated call withholds the object (and a review copy) as
    ``protection_failed`` (spec 049 §7.7 rule 4).
    Masked descriptors omit the original digest to avoid revealing low-entropy original
    values. Raw queued memory stays inside the customer's approved capture boundary.
    """

    mode: str = "original"
    transformation_id: str | None = None
    transformation_version: str | None = None
    transform: InitVar[object] = None  # a module reference: removed, refused with the docs

    def __post_init__(self, transform: object) -> None:
        refuse_removed(transform=transform)
        if self.mode not in {"original", "omit", "masked_only", "original_plus_masked"}:
            raise ValueError("unsupported byte privacy mode")
        masked = self.mode in {"masked_only", "original_plus_masked"}
        for value in (self.transformation_id, self.transformation_version):
            if masked and (
                not isinstance(value, str)
                or len(value) > _OPAQUE_ID_MAX_LENGTH
                or not _ID_RE.fullmatch(value)
            ):
                raise ValueError("masked modes require opaque transformation identity and version")
        if not masked and any(
            value is not None for value in (self.transformation_id, self.transformation_version)
        ):
            raise ValueError("transformation settings require a masked mode")

    @property
    def transformation(self) -> Transformation | None:
        """The masked modes' transformation identity, sent to the redaction service."""
        if self.transformation_id is None or self.transformation_version is None:
            return None
        return Transformation(self.transformation_id, self.transformation_version)


def _role_policies_block(policies: Mapping[str, BytePrivacyPolicy]) -> dict[str, Any]:
    """The implicit ``fabric.role-policies`` identity (version 1) of a role-policy table."""
    privacy = {
        role: {
            "mode": policy.mode,
            "transformation_id": policy.transformation_id,
            "transformation_version": policy.transformation_version,
        }
        for role, policy in sorted(policies.items())
    }
    doc = {"policy_id": ROLE_POLICIES_ID, "policy_version": 1, "privacy": privacy}
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    return {
        "policy_id": ROLE_POLICIES_ID,
        "policy_version": 1,
        "policy_digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
    }


def _validate_store_separation(original: ByteEvidenceStore, review: ByteEvidenceStore) -> None:
    probe = "00000000-0000-4000-8000-000000000000"
    original_ref = original.evidence_ref_for(probe)
    review_ref = review.evidence_ref_for(probe)
    if original_ref == review_ref:
        raise ValueError("original and review store namespaces must differ")
    # Distinct refs are insufficient when one configured resolver can read the
    # other's nested namespace. Arbitrary customer stores still need IAM proof.
    for store, other_ref in ((original, review_ref), (review, original_ref)):
        owns_uri = getattr(store, "owns_uri", None)
        if callable(owns_uri) and owns_uri(other_ref):
            raise ValueError("original and review store resolver namespaces must not overlap")


@dataclass(frozen=True, slots=True)
class ByteEvidenceConfig:
    """An explicit role policy and bounded, asynchronous byte destination."""

    store: ByteEvidenceStore
    roles: frozenset[str]
    payload_max_bytes: int = 1024 * 1024
    queue_max_items: int = 64
    max_records: int = 4096
    role_policies: Mapping[str, BytePrivacyPolicy] | None = None
    review_store: ByteEvidenceStore | None = None
    deployment_policy: DeploymentPolicy | None = None
    content_protector: ContentProtector | None = None
    durable_spool: DurableByteSpool | None = None
    # The id key (049 §7.3; FABRIC_WIRE_ID_KEY when unset): the production profile needs
    # it before any content is captured. A secret: never in repr or logs.
    id_key: bytes | None = field(default=None, repr=False)
    # The customer-run redaction service for masked role policies (contracts/redaction/v1;
    # FABRIC_REDACTION_ENDPOINT when unset).
    redaction: RedactionService | None = None
    # 049 §2.9 rule 7 (FABRIC_IDENTITY_MODE when unset): caller ids leave as keyed
    # pseudonyms (``pseudonymous``, the default) or as given (``clear``).
    identity_mode: IdentityMode | None = None

    def __post_init__(self) -> None:  # noqa: PLR0912
        if self.redaction is not None and not isinstance(self.redaction, RedactionService):
            raise ValueError("redaction must be a RedactionService")
        if not isinstance(self.store, ByteEvidenceStore) or not self.store.tenant_id:
            raise ValueError("byte evidence requires a tenant-scoped byte evidence store")
        check_safe_identifier("tenant_id", self.store.tenant_id)
        if self.durable_spool is not None and (
            not isinstance(self.durable_spool, DurableByteSpool)
            or self.durable_spool.tenant_id != self.store.tenant_id
        ):
            raise ValueError("durable byte spool must match the byte store tenant")
        if not self.roles or not isinstance(self.roles, frozenset) or self.roles - _ROLES:
            raise ValueError("roles must be a non-empty frozenset of content-v2 roles")
        check_id_key(self.id_key)
        if self.identity_mode not in (None, "pseudonymous", "clear"):
            raise ValueError("identity_mode must be 'pseudonymous' or 'clear'")
        if self.content_protector is not None and self.deployment_policy is None:
            object.__setattr__(self, "deployment_policy", self.content_protector.policy)
        if self.deployment_policy is not None:
            deployment = self.deployment_policy
            if (
                not isinstance(deployment, DeploymentPolicy)
                or deployment.tenant_id != self.store.tenant_id
            ):
                raise ValueError("deployment policy must match byte store tenant")
            if self.role_policies:
                raise ValueError("deployment_policy and role_policies cannot be combined")
            protector = self.content_protector or ContentProtector(
                deployment, payload_max_bytes=self.payload_max_bytes, redaction=self.redaction
            )
            if protector.policy.digest != deployment.digest:
                raise ValueError("content protector must match deployment policy")
            object.__setattr__(self, "content_protector", protector)
            if any(deployment.privacy.get(role) in _DERIVED for role in self.roles):
                if (
                    not isinstance(self.review_store, ByteEvidenceStore)
                    or self.review_store.tenant_id != self.store.tenant_id
                ):
                    raise ValueError("deployment derivatives require a same-tenant review store")
                _validate_store_separation(self.store, self.review_store)
        policies = dict(self.role_policies or {})
        if policies.keys() - self.roles or any(
            not isinstance(policy, BytePrivacyPolicy) for policy in policies.values()
        ):
            raise ValueError(
                "role_policies must contain enabled roles and BytePrivacyPolicy values"
            )
        object.__setattr__(self, "role_policies", MappingProxyType(policies))
        if any(policy.mode == "original_plus_masked" for policy in policies.values()):
            if (
                not isinstance(self.review_store, ByteEvidenceStore)
                or self.review_store.tenant_id != self.store.tenant_id
            ):
                raise ValueError(
                    "original_plus_masked requires a separate same-tenant review store"
                )
            _validate_store_separation(self.store, self.review_store)
        for name, value, maximum in (
            ("payload_max_bytes", self.payload_max_bytes, 16 * 1024 * 1024),
            ("queue_max_items", self.queue_max_items, 65536),
            ("max_records", self.max_records, 1000000),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= maximum:
                raise ValueError(f"{name} must be between 1 and {maximum}")


class ByteEvidenceRecorder:
    """Record explicitly observed bytes; never place content on OTLP.

    ``capture`` returns an initial descriptor. ``get`` returns its latest
    settlement. Both the queue and retained record index are bounded;
    overflow is reported as ``dropped``. ``flush`` only confirms local store
    settlement, not downstream receipt or immutable retention.
    """

    def __init__(self, config: ByteEvidenceConfig) -> None:
        self._config = config
        self._queue: queue.Queue[tuple[str, bytes, str | None]] = queue.Queue(
            maxsize=config.queue_max_items
        )
        self._records: dict[str, dict[str, Any]] = {}
        self._condition = threading.Condition()
        self._closed = False
        self._pending = 0
        self._unretained_drops = 0
        self._spool = config.durable_spool
        self._policy_block = _role_policies_block(config.role_policies or {})
        # One connection pool to the redaction service for masked role policies (049
        # §7.7 rule 3), used only on this recorder's worker.
        self._redaction: RedactionClient | None = None
        if any(policy.transformation is not None
               for policy in (config.role_policies or {}).values()):  # fmt: skip
            service = resolve_service(config.redaction, os.environ)
            if service is None:
                raise ValueError(
                    "masked modes require a redaction service endpoint (FABRIC_REDACTION_ENDPOINT)"
                )
            self._redaction = RedactionClient(service, max_output_bytes=config.payload_max_bytes)
        # 049 §7.3: never blocked, but not silent; a malformed id key still raises here.
        id_key = config.id_key if config.id_key is not None else id_key_from_env(os.environ)
        self._profile, self._gate_reason = content_gate(
            config.deployment_policy, id_key, config.store, config.review_store
        )
        if self._gate_reason is not None:
            self._log_gate()
        # 049 §2.9: caller ids leave as keyed pseudonyms, or, in production without the id
        # key (rule 5), as generated ids; as given only in the clear mode (or local, no key).
        mode = config.identity_mode or identity_mode_from_env(os.environ)
        self._emitted_ids = emitted_ids(self._profile, id_key, mode)
        if self._spool is not None:
            recovered_ids = self._spool.object_ids()
            if len(recovered_ids) > config.max_records:
                raise ValueError("recovered byte spool exceeds recorder index capacity")
            for key in recovered_ids:
                recovered = self._spool.descriptor(key)
                if recovered is not None:
                    self._records[key] = recovered
            self._spool.bind(config.store, config.review_store)
        self._worker = threading.Thread(target=self._run, name="fabric-byte-evidence", daemon=True)
        self._worker.start()

    def _log_gate(self) -> None:
        """The disabled state, by reason only (class-only text, never a value)."""
        _LOG.warning(
            "fabric.byte_evidence: content capture disabled (%s, %s profile); "
            "metadata capture continues",
            self._gate_reason,
            self._profile,
        )

    def status(self) -> dict[str, Any]:
        """The content state of this recorder (049 §7.3): profile, ``content_capture`` and
        its reason, and whether a sealed durable spool is used. Values only."""
        return {
            "profile": self._profile,
            "content_capture": "enabled" if self._gate_reason is None else "disabled",
            "content_capture_reason": self._gate_reason,
            "spool_encrypted": self._spool is not None,
        }

    def redaction_stats(self) -> dict[str, int]:
        """The redaction service counters (never a value): calls that timed out, were
        refused at the in-flight bound, or failed otherwise."""
        if self._redaction is not None:
            return self._redaction.stats()
        if (protector := self._config.content_protector) is not None:
            return protector.stats()
        return dict.fromkeys(("redaction_timeouts", "redaction_saturated", "redaction_failures"), 0)

    def capture_policy_conflicts(self, capture_mode: Callable[[str], str]) -> list[str]:
        """The roles whose configured privacy mode (``role_policies``, or the deployment
        policy's ``privacy`` for an enabled role) disagrees with ``capture_mode`` (the
        install's capture policy, spec 050 §3.10), sorted. ``original`` is the capture
        policy's ``retain_original``. Roles this config does not name are not compared."""
        config = self._config
        if config.deployment_policy is not None:
            configured = {role: mode for role, mode in config.deployment_policy.privacy.items()
                          if role in config.roles}  # fmt: skip
        else:
            configured = {role: _CAPTURE_POLICY_MODE.get(policy.mode, policy.mode)
                          for role, policy in (config.role_policies or {}).items()}  # fmt: skip
        return sorted(role for role, mode in configured.items() if capture_mode(role) != mode)

    def check_capture_policy(self, capture_mode: Callable[[str], str]) -> None:
        """Spec 050 §3.10: in records mode the install's capture policy governs the bodies
        through the shared PROTECT stage, so a byte config whose role policies disagree
        with it is malformed configuration (``ValueError``, fixed text naming roles only)."""
        conflicts = self.capture_policy_conflicts(capture_mode)
        if conflicts:
            raise ValueError(
                "byte evidence role policies disagree with the capture policy for: "
                + ", ".join(conflicts)
            )

    @property
    def emitted_ids(self) -> EmittedIds | None:
        """How caller ids are emitted (049 §2.9): keyed pseudonyms, generated ids (the
        production profile without the id key, rule 5), or ``None`` (as given)."""
        return self._emitted_ids

    def emitted_run_id(self, run_id: str) -> str:
        """``run_id`` as this recorder emits it (epoch 0): the id a source spool or a
        qualified-run expectation for this run is keyed by. Never the clear value unless
        ids are emitted as given. The result is an :class:`fabric._sequence.EmittedId`:
        passed back to this recorder it is kept as is, while a plain string is always
        caller input and mapped again."""
        ids = self._emitted_ids
        return run_id if ids is None else ids.run(run_id, 0)

    def emitted_source_id(self, source_id: str) -> str:
        """``source_id`` as this recorder emits it, like :meth:`emitted_run_id`."""
        ids = self._emitted_ids
        return source_id if ids is None else ids.source(source_id)

    @property
    def tenant_id(self) -> str:
        """Tenant bound to the configured content store."""
        tenant_id = self._config.store.tenant_id
        if tenant_id is None:
            raise ValueError("byte evidence store lost its tenant binding")
        return tenant_id

    def capture(  # noqa: PLR0912, PLR0915
        self,
        data: bytes,
        *,
        role: str,
        boundary: str,
        source_id: str,
        source_epoch: int,
        source_sequence: int,
        media_type: str = "application/octet-stream",
        run_id: str | None = None,
        operation_id: str | None = None,
        attempt_id: str | None = None,
        stream_id: str | None = None,
        chunk_index: int | None = None,
    ) -> dict[str, Any]:
        """Handoff one exact byte buffer; return a copy of initial status.

        Invalid API arguments raise before any mutation. Resource failures
        and a closed writer become explicit non-stored descriptors.
        """
        _validate_capture_args(
            data,
            role=role,
            boundary=boundary,
            source_id=source_id,
            source_epoch=source_epoch,
            source_sequence=source_sequence,
            media_type=media_type,
            run_id=run_id,
            operation_id=operation_id,
            attempt_id=attempt_id,
            stream_id=stream_id,
            chunk_index=chunk_index,
        )

        if (ids := self._emitted_ids) is not None:  # 049 §2.9: no clear caller id leaves
            source_id = ids.source(source_id)
            run_id = ids.run(run_id, source_epoch) if run_id is not None else None
            operation_id, attempt_id, stream_id = (
                ids.other(value) if value is not None else None
                for value in (operation_id, attempt_id, stream_id)
            )
        object_id = str(uuid.uuid4())
        policy = (self._config.role_policies or {}).get(role, BytePrivacyPolicy())
        # 049 §7.3: content disabled, metadata only (logged at construction, never here:
        # nothing on the caller's path may wait on a log handler).
        gated = self._gate_reason is not None
        enabled = role in self._config.roles and policy.mode != "omit" and not gated
        protected = None
        protector = self._config.content_protector
        # Customer redaction never runs on the caller's thread (spec 049 §7.1, §7.7): it
        # is deferred to the worker, before persistence; failure there withholds.
        deferred = protector is not None and enabled and protector.needs_redaction_service(role)
        if protector is not None and not gated and not deferred:
            # Fabric's own protection runs before the handoff: only permitted bytes queue.
            protected = protector.protect(role if enabled else "", data)
            enabled = enabled and protected.protected_bytes is not None
        # Neither omitted nor masked-only content exposes the original fingerprint.
        digest = (
            "sha256:" + hashlib.sha256(data).hexdigest()
            if protected is None and enabled and policy.mode != "masked_only" and not deferred
            else None
        )
        descriptor: dict[str, Any] = {
            "schema_version": "fabric.content-object/v2",
            "object_id": object_id,
            "tenant_id": self._config.store.tenant_id,
            "role": role,
            "media_type": media_type,
            "encoding": "binary",
            "representation": "exact" if digest is not None else "unavailable",
            "transformations": [],
            "provenance": "caller_reported",
            "boundary": boundary,
            "source_id": source_id,
            "source_epoch": source_epoch,
            "source_sequence": source_sequence,
            "captured_at": datetime.now(UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "status": "pending",
        }
        if role in (self._config.role_policies or {}):
            descriptor["privacy_mode"] = policy.mode
        if enabled and policy.mode in _MASKED_MODES:
            descriptor.update(
                self._policy_block,
                protection_status="redacted" if policy.mode == "masked_only" else "retained",
            )
        if enabled and protected is None and policy.mode != "masked_only" and not deferred:
            # masked_only keeps no digest or length of the original (content-v2 2.2.0).
            descriptor["source_byte_length"] = len(data)
        if enabled and policy.mode == "masked_only":
            descriptor.update(
                representation="redacted",
                transformations=["redact"],
                transformation_id=policy.transformation_id,
                transformation_version=policy.transformation_version,
            )
        if digest is not None:
            descriptor["source_byte_length"] = len(data)
            descriptor["source_sha256"] = digest
        if deferred:  # pending the worker's redaction: no digest or length of the original
            deployment = self._config.deployment_policy
            transformation = protector.transformation(role) if protector is not None else None
            if deployment is None or transformation is None:  # validated configuration
                raise ValueError("missing deployment policy")
            descriptor.update(
                workload_id=deployment.workload_id,
                policy_digest=deployment.digest,
                policy_id=deployment.policy_id,
                policy_version=deployment.policy_version,
                privacy_mode=deployment.privacy[role],
                protection_status="redacted",
                representation="redacted",
                transformations=["redact"],
                transformation_id=transformation.transformation_id,
                transformation_version=transformation.version,
            )
        if protected is not None:
            deployment = self._config.deployment_policy
            if deployment is None:  # validated configuration
                raise ValueError("missing deployment policy")
            descriptor.update(
                workload_id=deployment.workload_id,
                policy_digest=deployment.digest,
                policy_id=deployment.policy_id,
                policy_version=deployment.policy_version,
                privacy_mode=protected.mode,
                protection_status=protected.status,
            )
            if "source_byte_length" in protected.metadata:
                descriptor["source_byte_length"] = protected.metadata["source_byte_length"]
            if protected.original_digest is not None:
                descriptor.update(source_sha256=protected.original_digest, representation="exact")
            if protected.status in {"redacted", "tokenized"}:
                descriptor.update(
                    representation=protected.status,
                    transformations=["redact" if protected.status == "redacted" else "tokenize"],
                )
            if protected.protected_bytes is not None:
                data = protected.protected_bytes
        for key, value in (
            ("run_id", run_id),
            ("operation_id", operation_id),
            ("attempt_id", attempt_id),
            ("stream_id", stream_id),
        ):
            if value is not None:
                descriptor[key] = value
        if chunk_index is not None:
            descriptor["chunk_index"] = chunk_index
        with self._condition:
            required_slots = 2 if enabled and policy.mode == "original_plus_masked" else 1
            if len(self._records) + required_slots > self._config.max_records:
                descriptor.update(
                    status="dropped",
                    representation="unavailable",
                    status_reason="record_index_full",
                )
                self._unretained_drops += 1
                return copy.deepcopy(descriptor)
            if gated:
                descriptor.update(
                    status="not_captured",
                    representation="unavailable",
                    status_reason=self._gate_reason,
                )
            elif not enabled and protected is not None:
                descriptor.update(
                    status={"lost": "failed", "unsupported": "unsupported"}.get(
                        protected.status, "not_captured"
                    ),
                    representation="unavailable",
                    status_reason=protected.metadata["reason"],
                )
            elif not enabled:
                descriptor.update(
                    status="not_captured",
                    representation="unavailable",
                    status_reason="privacy_omitted"
                    if policy.mode == "omit"
                    else "outside_capture_policy",
                )
            elif len(data) > self._config.payload_max_bytes:
                descriptor.update(
                    status="dropped",
                    representation="unavailable",
                    status_reason="payload_too_large",
                )
            elif self._closed:
                descriptor.update(
                    status="failed", representation="unavailable", status_reason="recorder_closed"
                )
            else:
                try:
                    self._enqueue(descriptor, data, policy)
                except Exception:
                    # Prospective refs may authenticate a short-lived capability.
                    # Failure before admission must remain a passive evidence gap,
                    # with no stale ref or customer exception text retained.
                    descriptor.pop("ref", None)
                    descriptor.update(
                        status="failed",
                        representation="unavailable",
                        status_reason="store_reference_failed",
                    )
            self._records[object_id] = descriptor
            return copy.deepcopy(descriptor)

    def _enqueue(self, descriptor: dict[str, Any], data: bytes, policy: BytePrivacyPolicy) -> None:
        object_id = descriptor["object_id"]
        store = self._config.store
        if self._config.deployment_policy is not None and descriptor.get("protection_status") in {
            "redacted",
            "tokenized",
        }:
            store = self._config.review_store or store
        descriptor["ref"] = store.evidence_ref_for(object_id)
        derivative_id = None
        if policy.mode == "original_plus_masked":
            derivative_id = str(uuid.uuid4())
            review_store = self._config.review_store
            if review_store is None:  # Configuration was validated before worker startup.
                raise ValueError("missing review store")
            derivative = {
                **descriptor,
                "object_id": derivative_id,
                "ref": review_store.evidence_ref_for(derivative_id),
                "representation": "redacted",
                "transformations": ["redact"],
                "transformation_id": policy.transformation_id,
                "transformation_version": policy.transformation_version,
                "protection_status": "redacted",
                "links": [{"relation": "derived_from", "object_id": object_id}],
            }
            # The review copy keeps no digest or length of the original (§7.5).
            derivative.pop("source_sha256", None)
            derivative.pop("source_byte_length", None)
            self._records[derivative_id] = derivative
        try:
            self._queue.put_nowait((object_id, data, derivative_id))
        except queue.Full:
            descriptor.pop("ref")
            descriptor.update(
                status="dropped", representation="unavailable", status_reason="queue_full"
            )
            if derivative_id is not None:
                self._fail_record(derivative_id, "queue_full", status="dropped")
        else:
            self._pending += 1

    def derivatives(self, object_id: str) -> list[dict[str, Any]]:
        """Return linked review objects separately from the original descriptor."""
        with self._condition:
            return [
                self.get(record["object_id"]) or copy.deepcopy(record)
                for record in self._records.values()
                if {"relation": "derived_from", "object_id": object_id} in record.get("links", [])
            ]

    def get(self, object_id: str) -> dict[str, Any] | None:
        """Read the latest local settlement without exposing stored bytes."""
        if self._spool is not None:
            recovered = self._spool.descriptor(object_id)
            if recovered is not None:
                return recovered
        with self._condition:
            descriptor = self._records.get(object_id)
            return copy.deepcopy(descriptor) if descriptor is not None else None

    def drain_settled(self) -> list[dict[str, Any]]:
        """Remove terminal records for publication by the caller."""
        with self._condition:
            if self._spool is not None:
                for key in self._spool.object_ids():
                    recovered = self._spool.descriptor(key)
                    if recovered is not None and key in self._records:
                        self._records[key] = recovered
            settled = [key for key, value in self._records.items() if value["status"] != "pending"]
            return [copy.deepcopy(self._records.pop(key)) for key in settled]

    @property
    def unretained_drops(self) -> int:
        """Number of overflow descriptors returned but absent from ``get``."""
        with self._condition:
            return self._unretained_drops

    def flush(self, timeout_s: float = 10.0) -> bool:
        """Wait for the local byte store to settle all accepted writes."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        with self._condition:
            while self._pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            if self._spool is None:
                return True
        return self._spool.flush(max(0.0, deadline - time.monotonic()))

    def wait_durable(self, timeout_s: float = 10.0) -> bool:
        """Wait for protected local admission, independent of destination outage.

        False means timeout, absent durable configuration, or known admission
        loss. True does not prove all physical source events were captured.
        """
        if self._spool is None:
            return False
        deadline = time.monotonic() + max(0.0, timeout_s)
        with self._condition:
            while self._pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            if self._unretained_drops or any(
                row["status"] in {"failed", "dropped"} for row in self._records.values()
            ):
                return False
            required = [key for key, row in self._records.items() if row["status"] == "pending"]
        return self._spool.all_durable(required, max(0.0, deadline - time.monotonic()))

    def delivery_state(self, object_id: str) -> dict[str, Any]:
        """Separate passive pending, fsynced durable, delivered and loss states.

        Delivered is the configured store's acknowledgement, not an independent
        Node/destination receipt or an immutable-retention claim.
        """
        if self._spool is not None:
            state = self._spool.state(object_id)
            if state["state"] != "unknown":
                return state
        with self._condition:
            row = self._records.get(object_id)
            if row is None:
                return {"state": "unknown", "durable": False}
            state_name = {
                "pending": "pending",
                "stored": "delivered",
                "redacted": "delivered",
                "failed": "lost",
                "dropped": "lost",
            }.get(row["status"], "not_captured")
            return {"state": state_name, "durable": False, "reason": row.get("status_reason")}

    def spool_health(self) -> dict[str, Any]:
        """Read bounded replay health without revealing content or exception text."""
        return self._spool.health() if self._spool is not None else {"enabled": False}

    def close(self, timeout_s: float = 10.0) -> bool:
        """Settle accepted writes, stop the worker, close the redaction service
        connections (the role policies' and the content protector's) and the durable
        spool, all within ``timeout_s``."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        with self._condition:
            self._closed = True
        complete = self.flush(max(0.0, deadline - time.monotonic()))
        self._worker.join(max(0.0, deadline - time.monotonic()))
        if self._redaction is not None:
            self._redaction.close()
        if self._config.content_protector is not None:
            self._config.content_protector.close()
        if self._spool is not None:
            spooled = self._spool.close(max(0.0, deadline - time.monotonic()))
            return complete and spooled and not self._worker.is_alive()
        return complete

    def _run(self) -> None:
        while True:
            try:
                object_id, data, derivative_id = self._queue.get(timeout=0.1)
            except queue.Empty:
                with self._condition:
                    if self._closed and self._pending == 0:
                        return
                continue
            try:
                self._process(object_id, data, derivative_id)
            except Exception as exc:
                # Do not log bytes, URIs, or exception text (which may include sensitive paths).
                with self._condition:
                    for record_id in (object_id, derivative_id):
                        if (
                            record_id is not None
                            and self._records.get(record_id, {}).get("status") == "pending"
                        ):
                            self._fail_record(
                                record_id,
                                exc.reason
                                if isinstance(exc, ByteSpoolAdmissionError)
                                else "store_write_failed",
                            )
            finally:
                with self._condition:
                    self._pending -= 1
                    self._condition.notify_all()
                self._queue.task_done()

    def _process(self, object_id: str, data: bytes, derivative_id: str | None) -> None:
        with self._condition:
            role = self._records[object_id]["role"]
        if self._config.deployment_policy is not None:
            mode = self._config.deployment_policy.privacy.get(role, "omit")
            store = self._config.review_store if mode in _DERIVED else self._config.store
            if store is None:
                raise ValueError("missing deployment content store")
            payload = self._deferred_protection(object_id, role, data)
            if payload is not None:
                self._write_record(object_id, payload, store)
            return
        policy = (self._config.role_policies or {}).get(role, BytePrivacyPolicy())
        transformed = None
        if policy.transformation is not None:
            transformed = self._role_transform(role, policy, data)
            if transformed is None:
                # Spec 049 §7.7 rule 4: a failed transformation withholds; never raw bytes.
                with self._condition:
                    for record_id in (object_id, derivative_id):
                        if record_id is not None:
                            self._withhold(record_id)
                return
        payload = transformed if policy.mode == "masked_only" else data
        if payload is None:
            raise ValueError("missing transformed content")
        self._write_record(object_id, payload, self._config.store)
        if derivative_id is not None:
            if transformed is None or self._config.review_store is None:
                raise ValueError("missing transformed content or review store")
            self._write_record(derivative_id, transformed, self._config.review_store)

    def _role_transform(self, role: str, policy: BytePrivacyPolicy, data: bytes) -> bytes | None:
        """A role policy's masked copy from the redaction service; ``None`` when the call
        failed, timed out, was refused at the in-flight bound or returned too much."""
        transformation = policy.transformation
        if transformation is None or self._redaction is None:
            return None
        return self._redaction.transform(
            data, transformation=transformation, role=role, mode="masked_only"
        )

    def _deferred_protection(self, object_id: str, role: str, data: bytes) -> bytes | None:
        """The bytes to persist under a deployment policy. A customer redaction deferred
        from :meth:`capture` runs here (bounded, on its own thread), before persistence;
        any failure withholds the object (spec 049 §7.7 rule 4) and returns ``None``."""
        protector = self._config.content_protector
        if protector is None or not protector.needs_redaction_service(role):
            return data  # already protected before the handoff
        protected = protector.protect(role, data)
        if protected.status != "redacted" or protected.protected_bytes is None:
            with self._condition:
                self._withhold(object_id)
            return None
        if len(protected.protected_bytes) > self._config.payload_max_bytes:
            # The recorder's own cap, as before deferral (a supplied protector may allow
            # more): dropped, nothing stored (Sol P0-A round 2 #4).
            with self._condition:
                self._fail_record(object_id, "payload_too_large", status="dropped")
            return None
        return protected.protected_bytes

    def _fail_record(self, object_id: str, reason: str, *, status: str = "failed") -> None:
        descriptor = self._records[object_id]
        for key in ("ref", "stored_byte_length", "stored_sha256"):
            descriptor.pop(key, None)
        descriptor.update(status=status, status_reason=reason, representation="unavailable")

    def _withhold(self, object_id: str) -> None:
        """A descriptor-only ``not_captured(protection_failed)``: no bytes, no digest or
        length of the original, protection outcome ``withheld``."""
        descriptor = self._records[object_id]
        for key in ("ref", "stored_byte_length", "stored_sha256"):
            descriptor.pop(key, None)
        for key in ("source_sha256", "source_byte_length"):
            descriptor.pop(key, None)
        descriptor.update(
            status="not_captured",
            status_reason="protection_failed",
            representation="unavailable",
            transformations=[],
            protection_status="withheld",
        )

    def _write_record(self, object_id: str, data: bytes, store: ByteEvidenceStore) -> None:
        with self._condition:
            descriptor = self._records[object_id]
            stored = {
                **descriptor,
                "status": "redacted"
                if descriptor["representation"] in {"redacted", "tokenized"}
                else "stored",
                "stored_byte_length": len(data),
                "stored_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
            }
        if self._spool is not None:
            self._spool.admit(
                stored, data, route="review" if store is self._config.review_store else "original"
            )
            return
        result = store.put_bytes_object(stored, data)
        if (
            result.uri != stored["ref"]
            or result.content_hash != stored["stored_sha256"].split(":", 1)[1]
        ):
            raise ValueError("byte store returned a mismatched content reference")
        with self._condition:
            self._records[object_id] = stored
