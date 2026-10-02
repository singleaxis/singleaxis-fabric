# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Opt-in configured capture through the existing CallRecorder production path.

Configuration is validated before monitoring starts. Recording failures preserve
application behavior. This helper never grants capabilities or enforces actions.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from opentelemetry import trace

from .byte_evidence import ByteEvidenceConfig, ByteEvidenceRecorder
from .call_otlp import call_batch_manifest, project_call_snapshot_batches
from .call_recorder import CallRecorder
from .content_store.base import ByteEvidenceStore
from .control_evidence import ControlObservation
from .deployment_policy import ContentProtector, DeploymentPolicy
from .source_spool import SyntheticSourceSpool

if TYPE_CHECKING:
    from .byte_spool import DurableByteSpool

_MAX_CONTROLS = 1024


class PolicyCaptureSession:
    """One explicitly instrumented source under immutable deployment policy.

    Call ``calls.call/acall/stream/astream`` around the final dispatch boundary.
    Separate verified stores are supplied by the customer; this class does not
    create credentials, grant access, configure SSO, or install global hooks.
    Customer redactors execute synchronously before queue admission and must be
    bounded/nonblocking. Passive means no action gating, not zero CPU overhead.
    """

    def __init__(
        self,
        *,
        policy: DeploymentPolicy,
        store: ByteEvidenceStore,
        run_id: str,
        source_id: str,
        agent_id: str,
        derivative_store: ByteEvidenceStore | None = None,
        redactors: Mapping[str, Callable[[bytes], bytes]] | None = None,
        tokenization_key: bytes | None = None,
        source_spool: SyntheticSourceSpool | None = None,
        durable_spool: DurableByteSpool | None = None,
        queue_max_items: int = 64,
        max_records: int = 4096,
        tracer: trace.Tracer | None = None,
    ) -> None:
        self.policy = policy
        values = policy.to_dict()
        for target in (store, derivative_store):
            if target is not None:
                bound_policy = getattr(target, "policy", None)
                if (
                    not isinstance(bound_policy, DeploymentPolicy)
                    or bound_policy.digest != policy.digest
                ):
                    raise ValueError("capture store deployment policy mismatch")
        protector = ContentProtector(
            policy,
            redactors=redactors or {},
            tokenization_key=tokenization_key,
        )
        self.writer = ByteEvidenceRecorder(
            ByteEvidenceConfig(
                store=store,
                review_store=derivative_store,
                roles=frozenset(values["privacy"]),
                deployment_policy=policy,
                content_protector=protector,
                queue_max_items=queue_max_items,
                max_records=max_records,
                durable_spool=durable_spool,
            )
        )
        self.calls = CallRecorder(
            self.writer,
            run_id=run_id,
            source_id=source_id,
            agent_id=agent_id,
            source_spool=source_spool,
            max_events=max_records,
            tracer=tracer,
        )
        self._durable_spool = durable_spool
        self._controls: list[dict[str, Any]] = []
        self._control_gaps = 0

    def observe_external_control(self, observation: ControlObservation) -> None:
        """Record bounded metadata from a separate controller; never execute it."""
        if not isinstance(observation, ControlObservation):
            raise TypeError("external control observation must be validated")
        if len(self._controls) >= _MAX_CONTROLS:
            self._control_gaps += 1
            return
        self._controls.append(observation.to_dict())

    def report(self) -> dict[str, Any]:
        snapshot = self.calls.snapshot()
        content_states: dict[str, int] = {}
        persistence_states: dict[str, int] = {}
        for event in snapshot["events"]:
            descriptor = event.get("descriptor", {})
            status = descriptor.get("protection_status", event.get("status", "unknown"))
            content_states[status] = content_states.get(status, 0) + 1
            settled = event.get("status", "unknown")
            persistence_states[settled] = persistence_states.get(settled, 0) + 1
        return {
            "schema_version": "fabric.policy-capture-report/v1",
            "policy_scope": "capture_configuration",
            "policy_digest": self.policy.digest,
            "tenant_id": self.policy.to_dict()["tenant_id"],
            "workload_id": self.policy.to_dict()["workload_id"],
            "content_states": content_states,
            "persistence_states": persistence_states,
            "source_snapshot": snapshot,
            "byte_delivery": self.writer.spool_health()
            if self._durable_spool is not None
            else {"durable_spool_enabled": False, "pre_admission_unknown": True},
            "batch_manifest": call_batch_manifest(snapshot),
            "external_controls": list(self._controls),
            "external_control_gaps": self._control_gaps,
            "external_control_coverage": "unverified" if self._controls else "not_observed",
            "action_enforcement": "external_not_implemented",
            "original_reconstruction": "not_qualified",
            "production_verdict": "NO_GO",
            "limits": [
                "explicit_dispatch_only",
                "single_source_scope",
                "pre_spool_crash_window",
                "external_issuers_unqualified",
                "ordinary_otel_exporters_not_covered_by_this_session",
            ],
        }

    def metadata_batches(self, *, batch_size: int = 4096) -> list[tuple[bytes, list[str]]]:
        return project_call_snapshot_batches(self.calls.snapshot(), batch_size=batch_size)

    def close(self, timeout_s: float = 10.0) -> bool:
        """Return whether byte writes settled within the timeout.

        A false result leaves unsettled writes observable through ``report``;
        it does not establish delivery or terminate a blocked store operation.
        The caller owns source journal and store lifetimes.
        """
        return self.writer.close(timeout_s=timeout_s)
