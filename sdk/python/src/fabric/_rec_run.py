# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Run-level records (spec 051 §4.3.2): ``record_run_context``, fields C30-C33.

A run annotation is a records-input record with ``fabric.step.kind=run`` that is **not a
step**: the verifier merges it into the run's fields (051 §4.13 rule 1). It is sequenced
like any record. The declared execution mode, approval policy, permissions and agent policy
are what the customer *reports*; they are recorded, never enforced or checked. The
permission lists never reach telemetry: only their leaf count does
(``fabric.run.permissions.count``); the lists are the ``run.permissions`` content body,
retained only as the capture policy allows. A later call in the same run is a new
observation (a configuration change), not a conflict. Run annotations default their actor
to ``unknown`` (051 D-12).

Pulled forward by spec 057 OD-15. Spec 057 §5.2 (WP7-1): ``permissions=`` is mapped into
a minimal declared ``fabric.grant-snapshot/v1`` document, so the annotation is also a
declared grant snapshot (``grt-`` id, counts; trigger ``run_start``) and its
``run.permissions`` body is the structurally pseudonymised document. A name of the form
``<group>.<list>`` that names a list of the document (``tools.allow|deny|ask``,
``filesystem.roots|read|write|deny``, ``network.allow|deny``, ``models.allow|deny``)
fills that list; any other name is kept verbatim under ``x-permissions``.
``fabric.run.permissions.count`` stays the number of leaf entries.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ._capture_types import misuse
from ._rec_grant import check_document, emit_grant
from ._records_api import current_records, emit, never_raises
from ._sequence import operator_label
from .records._handles import RecordHandle
from .records._vocab import APPROVAL_POLICIES, EXECUTION_MODES, normalise

_DIGEST = re.compile(r"(?:sha256:)?([0-9a-f]{64})")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
_MAX_VERSION = 2**31
MAX_PERMISSION_ENTRIES = 4096


@dataclass(frozen=True, slots=True)
class AgentPolicyRef:
    """The customer's agent policy identity (C33): an operator label id (emitted ``lbl-``
    unless ``FABRIC_WIRE_LABELS=clear``), a version (int ≥ 1) and a ``sha256:`` digest.
    Not the recorder's capture policy (X31)."""

    id: str
    version: int | None = None
    digest: str | None = None


def _permission_count(permissions: object) -> int | None:
    """The number of leaf entries of ``{name: [str, ...]}``; ``None`` (dropped, counted)
    for any other shape."""
    if not isinstance(permissions, Mapping):
        misuse("permissions must be a mapping of lists")
        return None
    total = 0
    for name, entries in permissions.items():
        if (
            type(name) is not str
            or isinstance(entries, (str, bytes))
            or not isinstance(entries, Sequence)
        ):
            misuse("permissions must be a mapping of lists")
            return None
        if not all(type(entry) is str for entry in entries):
            misuse("permission entries must be str")
            return None
        total += len(entries)
        if total > MAX_PERMISSION_ENTRIES:
            misuse("more than 4096 permission entries")
            return None
    return total


_GROUPS = {
    "tools": ("allow", "deny", "ask"), "filesystem": ("roots", "read", "write", "deny"),
    "network": ("allow", "deny"), "models": ("allow", "deny"),
}  # fmt: skip


def declared_document(
    permissions: Mapping[str, Sequence[str]], execution_mode: object, approval_policy: object,
) -> dict[str, Any]:  # fmt: skip
    """The minimal declared grant document of ``permissions=`` (spec 057 §5.2)."""
    doc: dict[str, Any] = {"schema_version": "fabric.grant-snapshot/v1", "basis": "declared",
                           "source": {"boundary": "api"}}  # fmt: skip
    if isinstance(execution_mode, str):
        doc["execution_mode"] = execution_mode
    if isinstance(approval_policy, str):
        doc["approval_policy"] = approval_policy
    other: dict[str, list[str]] = {}
    for name, entries in permissions.items():
        group, _, leaf = name.partition(".")
        if leaf in _GROUPS.get(group, ()):
            values = list(entries)
            if group == "tools":
                doc.setdefault("tools", {})[leaf] = [{"rule": v} for v in values]
            else:
                doc.setdefault(group, {})[leaf] = values
        else:
            other[name] = list(entries)
    if other:
        doc["x-permissions"] = other
    return doc


def _agent_policy(records: Any, policy: object) -> dict[str, Any]:
    if not isinstance(policy, AgentPolicyRef):
        misuse("agent_policy must be an AgentPolicyRef")
        return {}
    out: dict[str, Any] = {}
    if isinstance(policy.id, str) and _LABEL.fullmatch(policy.id):
        clear = getattr(records, "_labels", "pseudonymous") == "clear"
        out["fabric.run.agent_policy_id"] = operator_label(
            policy.id, getattr(records, "_key", None), clear=clear
        )
    else:
        misuse("agent_policy id")
    version = policy.version
    if version is not None:
        if type(version) is int and 1 <= version <= _MAX_VERSION:
            out["fabric.run.agent_policy_version"] = version
        else:
            misuse("agent_policy version")
    if policy.digest is not None:
        match = _DIGEST.fullmatch(policy.digest) if isinstance(policy.digest, str) else None
        if match is None:
            misuse("agent_policy digest")
        else:
            out["fabric.run.agent_policy_digest"] = "sha256:" + match.group(1)
    return out


@never_raises(RecordHandle.unrecorded)
def record_run_context(
    *, execution_mode: str | None = None, approval_policy: str | None = None,
    permissions: Mapping[str, Sequence[str]] | None = None,
    agent_policy: AgentPolicyRef | None = None,
) -> RecordHandle:  # fmt: skip
    """Record the run's declared execution mode (C30), approval policy (C31), permissions
    (C32: the count on telemetry, the lists as ``run.permissions`` content) and agent
    policy (C33). Passive: returns a handle (ids only) and never raises."""
    records = current_records()
    if records is None:
        return RecordHandle.unrecorded()
    attrs: dict[str, Any] = {}
    if execution_mode is not None:
        attrs["fabric.run.execution_mode"] = normalise(execution_mode, EXECUTION_MODES,
                                                       "execution mode")  # fmt: skip
    if approval_policy is not None:
        attrs["fabric.run.approval_policy"] = normalise(approval_policy, APPROVAL_POLICIES,
                                                        "approval policy")  # fmt: skip
    if agent_policy is not None:
        attrs.update(_agent_policy(records, agent_policy))
    if permissions is not None:
        count = _permission_count(permissions)
        if count is not None:
            attrs["fabric.run.permissions.count"] = count
            document = check_document(declared_document(
                permissions, attrs.get("fabric.run.execution_mode"),
                attrs.get("fabric.run.approval_policy")))  # fmt: skip
            if document is not None:
                return emit_grant(records, document, trigger="run_start", attrs=attrs)[0]
    return emit("run", attrs=attrs, records=records, name_hint="fabric.activity",
                default_actor="unknown")  # fmt: skip


__all__ = ["AgentPolicyRef", "record_run_context"]
