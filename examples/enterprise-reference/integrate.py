#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Two application touch points: initialize once, wrap the shared final dispatch.

The runnable demo uses synthetic bytes and loopback HTTP only. Keys are ephemeral
and are never written; real applications must supply stable managed keys across
restarts. This example does not configure a remote destination or prove delivery.
"""

from __future__ import annotations

import argparse
import json
import secrets
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.sampling import ALWAYS_ON

from fabric.byte_spool import DurableByteSpool
from fabric.coverage_manifest import inspect_integrations
from fabric.deployment_policy import DeploymentPolicy
from fabric.enterprise import PolicyCaptureSession
from fabric.governed_store import GovernedLocalContentStore, LocalCapabilityAuthority
from fabric.http_dispatch import FinalHTTPAdapter, IndependentHTTPWitness
from fabric.source_spool import SyntheticSourceSpool

_T = TypeVar("_T")


@dataclass
class AppCapture:
    """Small application-owned lifecycle helper, using the public SDK interfaces."""

    session: PolicyCaptureSession
    journal: SyntheticSourceSpool
    store: GovernedLocalContentStore
    _journal_stopped: bool = False
    _store_closed: bool = False

    def dispatch(
        self,
        payload: bytes,
        send: Callable[[bytes], _T],
        *,
        kind: str,
        operation_id: str,
        attempt_id: str,
        parent_call_id: str | None = None,
    ) -> _T:
        """Use at final serialization/physical dispatch, once per actual retry."""
        return self.session.calls.call(
            payload,
            send,
            kind=kind,
            operation_id=operation_id,
            attempt_id=attempt_id,
            parent_call_id=parent_call_id,
        )

    def close(self, timeout_s: float = 10.0) -> bool:
        """Stop producers first. False means shutdown/evidence is still unsettled."""
        stopped = self.session.close(timeout_s=timeout_s)
        if not self._journal_stopped:
            self._journal_stopped = self.journal.close(timeout_s=timeout_s)
        if stopped and not self._store_closed:
            self.store.close()
            self._store_closed = True
        return stopped and self._journal_stopped


def initialize_capture(
    root: Path,
    *,
    policy: DeploymentPolicy,
    authority_key: bytes,
    storage_key: bytes,
    spool_key: bytes,
    run_id: str = "integration-run",
    source_id: str = "integration-source",
    agent_id: str = "application-agent",
    tracer: trace.Tracer | None = None,
) -> AppCapture:
    """Application startup only; credentials come from the application's key provider.

    This small demo supports retain_original, metadata_only and omit. Redaction
    or tokenization needs explicitly configured transforms/derivative storage;
    use PolicyCaptureSession's corresponding arguments rather than raw fallback.
    """
    if any(mode in {"redact", "tokenize"} for mode in policy.privacy.values()):
        raise ValueError(
            "example requires explicit customization for transformed content"
        )
    root = root.absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    journal_root = root / "journal"
    journal_root.mkdir(mode=0o700, exist_ok=True)
    authority = LocalCapabilityAuthority(authority_key)
    capability = authority.issue(
        policy=policy,
        subject_id=agent_id,
        permissions={"write_original"},
        ttl_seconds=3600,
    )
    store = GovernedLocalContentStore(
        root / "content",
        policy=policy,
        authority=authority,
        capability=capability,
        encryption_key=storage_key,
    )
    journal = None
    spool = None
    try:
        journal = SyntheticSourceSpool(
            str(journal_root), tenant_id=policy.tenant_id, run_id=run_id
        )
        spool = DurableByteSpool(
            root / "byte-spool", tenant_id=policy.tenant_id, encryption_key=spool_key
        )
        session = PolicyCaptureSession(
            policy=policy,
            store=store,
            source_spool=journal,
            durable_spool=spool,
            run_id=run_id,
            source_id=source_id,
            agent_id=agent_id,
            tracer=tracer,
        )
        return AppCapture(session, journal, store)
    except BaseException:
        if spool is not None:
            spool.close()
        if journal is not None:
            journal.close()
        store.close()
        raise


def run(output: Path, *, policy_path: Path | None = None) -> dict[str, Any]:
    """Execute real loopback model/tool dispatch and explicit background parent linkage."""
    output = output.absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    policy_path = policy_path or Path(__file__).with_name("policy.integration.json")
    policy = DeploymentPolicy.from_dict(json.loads(policy_path.read_text()))
    provider = TracerProvider(sampler=ALWAYS_ON)
    capture = initialize_capture(
        output,
        policy=policy,
        authority_key=secrets.token_bytes(32),
        storage_key=secrets.token_bytes(32),
        spool_key=secrets.token_bytes(32),
        tracer=provider.get_tracer("fabric.integration-example"),
    )
    result: dict[str, Any] = {}
    try:
        with IndependentHTTPWitness(output / "witness") as witness:
            transport = FinalHTTPAdapter(declared_url=witness.url)
            with ThreadPoolExecutor(max_workers=1) as background:

                def model_send(payload: bytes) -> bytes:
                    response = transport.request(
                        "POST",
                        witness.url,
                        payload,
                        operation_id="model-1",
                        attempt_id="model-attempt-1",
                    ).body
                    # Capture context before crossing a thread/queue/process boundary.
                    parent = capture.session.calls.current_call_id
                    child = background.submit(
                        capture.dispatch,
                        b"synthetic-tool-input",
                        lambda data: transport.request(
                            "POST",
                            witness.url,
                            data,
                            operation_id="tool-1",
                            attempt_id="tool-attempt-1",
                        ).body,
                        kind="tool",
                        operation_id="tool-1",
                        attempt_id="tool-attempt-1",
                        parent_call_id=parent,
                    )
                    child.result()  # Application owns background joins and errors.
                    return response

                response = capture.dispatch(
                    b"synthetic-model-input",
                    model_send,
                    kind="model",
                    operation_id="model-1",
                    attempt_id="model-attempt-1",
                )
            # Offline, after all work joined. A seal is not a completeness receipt.
            source_seal = capture.session.calls.seal_source()
            snapshot = capture.session.calls.snapshot()
            calls = snapshot["calls"]
            model = next(row for row in calls if row["kind"] == "model")
            tool = next(row for row in calls if row["kind"] == "tool")
            result = {
                "schema_version": "fabric.integration-example/v1",
                "response_preserved": response == b"ok",
                "background_parent_linked": tool["parent_call_id"] == model["call_id"],
                "call_count": len(calls),
                "coverage": inspect_integrations(
                    required=policy.required_integrations, only=[]
                ).to_dict(),
                "http_boundary": transport.reconcile(witness.inventory()),
                "byte_delivery": capture.session.writer.spool_health(),
                "journal_health": capture.journal.health(),
                "source_seal": source_seal,
                "production_qualified": False,
                "destination_delivery": "not_configured",
                "key_custody": "ephemeral_demo_only_not_restart_recoverable",
            }
            (output / "snapshot.json").write_text(json.dumps(snapshot, indent=2) + "\n")
            (output / "scope.json").write_text(
                json.dumps(
                    {
                        "source_ids": ["integration-source"],
                        "source_epochs": [0],
                        "expected_max_records": 4096,
                        "expected_max_object_bytes": 16777216,
                    },
                    indent=2,
                )
                + "\n"
            )
    finally:
        result["shutdown_settled"] = capture.close()
        provider.shutdown()
    (output / "integration-report.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", required=True, type=Path, help="new private demo directory"
    )
    parser.add_argument(
        "--policy",
        type=Path,
        help="local capture policy; demo default retains synthetic bytes",
    )
    args = parser.parse_args()
    result = run(args.output, policy_path=args.policy)
    passed = (
        result["response_preserved"]
        and result["background_parent_linked"]
        and result["shutdown_settled"]
        and result["http_boundary"]["status"] == "complete"
        and result["journal_health"]["failed"]
        == result["journal_health"]["dropped"]
        == 0
        and result["byte_delivery"]["lost"]
        == result["byte_delivery"]["corrupt_entries"]
        == 0
    )
    print(
        json.dumps(
            {
                "local_integration_passed": passed,
                "production_qualified": False,
                "report": str(args.output / "integration-report.json"),
            }
        )
    )
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
