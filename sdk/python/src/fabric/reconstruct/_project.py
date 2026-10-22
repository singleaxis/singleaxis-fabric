# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric.step-projection/v1`` (spec 050 §3.13): steps, aliases, parents, field wrappers
and the R1-R6 / RR1-RR7 verdict tables, written next to the run-reconstruction report.

The projection is the verifier's second document. It is built offline from the report, the
per-run segment graphs (WP-31) and what a :class:`ProjectionCollector` gathered while the
verifier ran (the observations with their spans, each exchange's verified bodies and stitch
view, the manifests). It never reads a byte the verifier did not verify, never dereferences
an asset reference and never inlines CONTENT (``content_inline`` is always false in P1).

**Steps** (one per ``attempt_id``, spec 049 §2.3):

- a wire exchange: ``attempt_id`` = ``exchange_id`` (a pre-uuid4 exchange id gets a derived
  uuid4-format id and keeps the original as the alias ``wire.exchange_id``); its model-call
  fields come from ``_fields_model`` over the stored, reassembled bytes. Its parent is the
  records step whose span is the exchange's OTel parent (the ``records.span_id`` alias), else
  its run-scope step. ``event_ids`` is the span's ``fabric.event_id``; a pre-P1 span without
  one lists its ``exchange_id`` (the only Fabric-minted, persisted identity that record has)
  and reports X02 ``unsupported(unsupported_version)``;
- a records-input attempt (``fabric.attempt.uid``): every record of the attempt merged;
  ``event_ids`` lists at most the first 64 by ``(source, epoch, sequence)`` and the
  ``event_id`` wrapper carries ``collection {completeness, observed_count}`` (R15); the full
  membership is the attempt's sequence set in the report. Evidence objects are decoded by
  ``_evidence`` (R7); a windowed producer's ``continuation`` indexes give the evidence fields
  their own ``collection``;
- a run scope: ``run:`` + ``scope_id``, ``attempt_id`` = ``scope_id``, S34 from its
  ``run_end``. Its position is the first sequence its window can hold (``run_start``
  ``last_sequence`` + 1); a scope whose markers carry no event id (pre-P1) is no step;
- children of a model call, parsed from its response: hosted tool items (``provider_tool_call``),
  ``computer_call`` items (``ui_action``) and unknown items (``extension``,
  ``x-<provider>.<type>``, ``unsupported(unsupported_api)``, never coerced). They take their
  parent's position with a ``subindex`` and a uuid4-format id derived from the parent's
  attempt id and the item's locator (reproducible, like an inferred step's);
- inferred ``input`` steps (``new_user_message``, tentative): a user message a request adds
  after the exchange it continues by prefix. Their id is :func:`inferred_step_id` of the
  evidence locator.

**Fields.** Every R field the registry assigns to the step (unconditionally, by its kind, or
by a condition that holds: timed, on error, streamed, split side, scope, in a segment) gets a
wrapper; O fields appear only when supplied. A field without evidence takes its status from
the governing manifest's row of the capture point that would supply it: active and listing
the field -> the field is missing from the record (``not_captured(caller_omitted)`` for a
reporting point, else the registry's "if hook absent" status, ``unknown`` for ``always``);
active without it -> ``unsupported(unsupported_version)``; inactive, disabled, unsupported or
failed -> that state with the row's reason; no manifest -> ``unknown``; no point that can
supply it for this kind of step -> ``unsupported(unsupported_version)``. Model-call fields of
a side whose bytes are unavailable take that side's status (049 §6.3: never ``absent``).

**Verdicts** are the 049 §6.2 tables as data (:data:`STEP_RULES`, :data:`RUN_RULES`), first
matching row wins. A step's layer verdict counts its R fields of that layer (cross-cutting
fields carry no layer verdict). Every step gets verdicts; a run aggregates only the steps of
the kinds its coverage profile names, plus the profile's run-level fields as one pseudo-step.
A pre-P1 run (no segments) is ``not_resumable_unclosed`` (G8: no terminal, not resumable).

The field-registry rows the projection uses are a runtime twin of
``contracts/coverage/v1/registry/field-registry-v1.json`` (:data:`FIELD_ROWS`), pinned by
``tests/test_reconstruct_project.py``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import re
import uuid
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Final, cast

from fabric._manifest_fields_generated import FIELD_REGISTRY_REVISION
from fabric._model_names import HASHED_MODEL_RE, expose_model
from fabric._sequence import key_id
from fabric._version import __version__

from ._evidence import EVIDENCE_TYPES, EvidenceDecode, decode_evidence
from ._fields_model import (
    _ALL_FIELD_IDS,
    _REQUEST_FIELDS,
    FieldValue,
    ModelFields,
    extract_model_fields,
)
from ._inputs import (
    ExchangeObs,
    HeartbeatObs,
    ManifestObs,
    Observation,
    ReconstructInputError,
    RecordObs,
    SpanRecord,
)
from ._report import format_datetime

if TYPE_CHECKING:
    from ._graph import RunGraph
    from ._objects import ObjectResult
    from ._stitch import WireApi
    from ._stitch_check import StitchView

SCHEMA_VERSION = "fabric.step-projection/v1"
PROJECTION_REVISION = 1
DEFAULT_COVERAGE_PROFILE = "fabric.profile.model-calls/v1"
#: R15: a step lists at most this many event ids (the schema's ``event_ids`` bound).
MAX_EVENT_IDS = 64
REGISTRY_REVISION = int(FIELD_REGISTRY_REVISION.rsplit("@", 1)[1])
LAYERS: Final = ("cross_cutting", "context", "structure", "content", "decisions_effects")
VERDICT_LAYERS: Final = ("context", "structure", "content", "decisions_effects")

_UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_POINT_RE = re.compile(r"^[a-z][a-z0-9_.]*(@[0-9A-Za-z.+-]{1,32})?$")
_VERSION_RE = re.compile(r"^[0-9A-Za-z.+-]{1,32}$")
_ROLE_RE = re.compile(r"^[a-z][a-z_]*(\.[a-z_]+)+$")
_EXTENSION_RE = re.compile(r"^x-[a-z0-9-]+\.[a-z0-9_.]+$")
_ALIAS_MAX = 160
_VALUE_MAX = 256
_POINTER_MAX = 1024
_NS = 1_000_000_000
_HTTP_OK, _HTTP_ERROR = 200, 400
_EVIDENCE_MAX_BYTES = 1 << 20


def inferred_step_id(locator: str) -> str:
    """The attempt id of an inferred step (§3.13): a uuid4-*format* id from SHA-256 of the
    evidence locator with the version and variant bits set (RFC 9562 §5.4 layout), so a
    regenerated projection gives the same id. Never uuid5. The one reviewed exception to
    R2's "minted once"."""
    digest = hashlib.sha256(locator.encode("utf-8", "surrogatepass")).digest()[:16]
    return str(uuid.UUID(bytes=digest, version=4))


# --------------------------------------------------------------------------
# The registry twin (pinned to field-registry-v1.json by test)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FieldRow:
    """One registry row: its projection keys, whether it is ``R`` (in any form), the
    registry's "if hook absent" status (normalised: ``status`` or ``status(reason)``,
    ``always``) and the capture points that observe it."""

    field_id: str
    keys: tuple[str, ...]
    required: bool
    absent: str
    observed_by: tuple[str, ...]

    @property
    def layer(self) -> str:
        return _LAYER_OF_PREFIX[self.field_id[0]]


_LAYER_OF_PREFIX: Mapping[str, str] = {
    "X": "cross_cutting", "C": "context", "S": "structure", "N": "content",
    "D": "decisions_effects",
}  # fmt: skip
_WIRE = ("wire.py.httpx", "wire.py.aiohttp")
_ROWS: tuple[tuple[str, tuple[str, ...], bool, str, tuple[str, ...]], ...] = (
    ("X01", ("schema_version",), True, "always", ("fabric.self",)),
    ("X02", ("event_id",), True, "always", ("fabric.self",)),
    ("X05", ("agent_id", "system_id", "deployment_id", "release_id", "environment",
             "workload_id"), False, "not_captured(not_configured)", ("install.config",)),
    ("X06", ("input", "source_id", "source_epoch", "source_sequence"), True, "always",
     ("fabric.self",)),
    ("X07", ("sequence_unit",), True, "always", ("fabric.self",)),
    ("X08", ("run_id",), True, "always", ("run.scope", *_WIRE)),
    ("X09", ("scope_id",), False, "not_applicable", ("run.scope",)),
    ("X13", ("session_id",), False, "not_captured(caller_omitted)", ("run.scope", "sdk.records")),
    ("X14", ("user_id",), False, "not_captured(caller_omitted)", ("run.scope", "sdk.records")),
    ("X17", ("step_id",), True, "always", ("fabric.self",)),
    ("X18", ("parent_step_id",), False, "absent", ("fabric.self", "explicit.call_recorder")),
    ("X19", ("attempt_id",), True, "always", ("fabric.self",)),
    ("X22", ("started_at", "ended_at"), True, "not_captured(caller_omitted)",
     (*_WIRE, "sdk.records", "explicit.call_recorder")),
    ("X23", ("timing_basis",), True, "always", ("fabric.self",)),
    ("X26", ("capture_point",), True, "always", ("fabric.self",)),
    ("X27", ("provenance",), True, "always", ("fabric.self", "reconstruct.parse")),
    ("X34", ("manifest_id",), True, "always", ("fabric.self",)),
    ("X40", ("store_reason",), True, "always", _WIRE),
    ("X43", ("segment_id",), True, "always", ("run.scope",)),
    ("X48", ("content_object_ids",), False, "absent", ("fabric.self",)),
    ("C01", ("trigger.kind",), True, "not_captured(not_instrumented)", ("sdk.records",)),
    ("C08", ("input.kind",), True, "not_captured(not_instrumented)",
     ("sdk.records", "reconstruct.infer")),
    ("C11", ("input.payload",), True, "not_captured(caller_omitted)",
     ("sdk.records", "reconstruct.parse")),
    ("C19", ("instructions",), True, "not_captured(not_instrumented)",
     ("reconstruct.parse", "explicit.call_recorder")),
    ("C20", ("instructions.digest",), True, "not_captured(not_instrumented)",
     ("reconstruct.parse",)),
    ("C21", ("tools_offered",), True, "not_captured(not_instrumented)",
     ("reconstruct.parse", "explicit.call_recorder")),
    ("C22", ("tools_offered.digest", "tools_offered.count"), True,
     "not_captured(not_instrumented)", ("reconstruct.parse",)),
    ("C23", ("tools_changed",), False, "unknown", ("reconstruct.infer",)),
    ("C34", ("model.provider", "model.api"), True, "not_captured(not_instrumented)", _WIRE),
    ("C35", ("model.endpoint_id",), True, "not_captured(not_instrumented)", _WIRE),
    ("C36", ("model.requested",), True, "not_captured(not_instrumented)", ("reconstruct.parse",)),
    ("C37", ("model.served",), True, "not_captured(provider_not_returned)",
     (*_WIRE, "reconstruct.parse")),
    ("C38", ("model.parameters",), True, "not_captured(not_instrumented)",
     ("reconstruct.parse",)),
    ("C39", ("context_dependencies",), True, "not_captured(not_instrumented)",
     ("reconstruct.parse", "reconstruct.infer")),
    ("C40", ("provider_request_id",), False, "not_captured(hook_disabled)", _WIRE),
    ("S01", ("step.kind",), True, "always", ("fabric.self", "reconstruct.parse")),
    ("S02", ("step.label",), False, "absent", ("sdk.records",)),
    ("S03", ("actor.type",), True, "always", ("fabric.self", "sdk.records", "reconstruct.parse")),
    ("S04", ("actor.id",), False, "not_captured(caller_omitted)", ("sdk.records",)),
    ("S07", ("lifecycle.state",), True, "unknown",
     (*_WIRE, "sdk.records", "explicit.call_recorder")),
    ("S08", ("result_status",), True, "unknown", (*_WIRE, "sdk.records", "explicit.call_recorder")),
    ("S09", ("error.domain",), True, "unknown", (*_WIRE, "sdk.records")),
    ("S10", ("error.type",), True, "unknown", (*_WIRE, "sdk.records", "explicit.call_recorder")),
    ("S11", ("error.code",), False, "absent", (*_WIRE, "reconstruct.parse")),
    ("S12", ("error.message", "error.stack", "error.cause"), False,
     "not_captured(caller_omitted)", ("sdk.records", "reconstruct.parse")),
    ("S13", ("attempt.kind",), False, "unknown", ("sdk.records", "reconstruct.infer")),
    ("S29", ("stream.state",), True, "not_captured(not_instrumented)", _WIRE),
    ("S30", ("stream.first_chunk_offset_ns",), False, "absent", _WIRE),
    ("S34", ("scope.exit_status",), True, "not_captured(not_instrumented)", ("run.scope",)),
    ("N01", ("model.exchange.request", "model.exchange.response"), True,
     "not_captured(not_instrumented)",
     (*_WIRE, "wire.ts.undici", "explicit.call_recorder", "explicit.byte_boundary")),
    ("N02", ("model.exchange.parts",), True, "not_applicable", _WIRE),
    ("N03", ("input.messages",), True, "not_captured(not_instrumented)",
     ("reconstruct.parse", "explicit.call_recorder")),
    ("N04", ("output.messages",), True, "not_captured(not_instrumented)",
     ("reconstruct.parse", "explicit.call_recorder")),
    ("N05", ("content.parts",), True, "not_captured(not_instrumented)", ("reconstruct.parse",)),
    ("N06", ("refusal",), False, "absent", ("reconstruct.parse",)),
    ("N07", ("finish_reasons",), True, "not_captured(not_instrumented)",
     (*_WIRE, "reconstruct.parse")),
    ("N08", ("reasoning.format",), True, "not_applicable", ("reconstruct.parse",)),
    ("N09", ("reasoning.text",), True, "not_applicable",
     ("reconstruct.parse", "explicit.call_recorder")),
    ("N10", ("reasoning.summary",), False, "absent", ("reconstruct.parse",)),
    ("N11", ("reasoning.object",), False, "absent", ("reconstruct.parse",)),
    ("N12", ("tool_call.id",), True, "not_captured(not_instrumented)", ("reconstruct.parse",)),
    ("N13", ("tool_call.name", "tool_call.type"), True, "not_captured(not_instrumented)",
     ("reconstruct.parse", "sdk.records")),
    ("N14", ("tool_call.arguments",), True, "not_captured(not_instrumented)",
     ("reconstruct.parse", "sdk.records")),
    ("N15", ("tool_call.result_as_fed",), True, "not_captured(not_exposed)",
     ("reconstruct.parse",)),
    ("N17", ("tool.execution.arguments", "tool.execution.result"), True,
     "not_captured(not_instrumented)", ("sdk.records", "explicit.call_recorder")),
    ("N18", ("tool.execution_side",), True, "unknown", ("reconstruct.parse", "sdk.records")),
    ("N19", ("provider_tool.kind",), True, "not_captured(not_instrumented)",
     ("reconstruct.parse",)),
    ("N20", ("provider_tool.status",), True, "unknown", ("reconstruct.parse",)),
    ("N21", ("provider_tool.inputs", "provider_tool.outputs", "provider_tool.citations",
             "provider_tool.files"), False, "absent", ("reconstruct.parse",)),
    ("N32", ("terminal.argv", "terminal.context"), True, "not_captured(not_instrumented)",
     ("exec.subprocess", "exec.audit", "explicit.byte_boundary", "explicit.subprocess_artifact")),
    ("N33", ("terminal.stdin",), False, "not_captured(hook_disabled)",
     ("exec.subprocess", "explicit.byte_boundary", "explicit.subprocess_artifact")),
    ("N34", ("terminal.stdout", "terminal.stderr"), True, "not_captured(not_exposed)",
     ("exec.subprocess", "explicit.byte_boundary", "explicit.subprocess_artifact")),
    ("N35", ("terminal.exit_code", "terminal.signal", "terminal.pid"), True,
     "not_captured(not_instrumented)", ("exec.subprocess", "explicit.subprocess_artifact")),
    ("N43", ("http.method", "http.status", "http.host"), True, "not_captured(not_instrumented)",
     ("http.nonmodel", "explicit.final_http")),
    ("N44", ("http.target", "http.request_body", "http.response_body", "http.redirects"), False,
     "not_captured(hook_disabled)", ("http.nonmodel", "explicit.final_http")),
    ("N45", ("file.operation", "file.path_hash", "file.byte_range"), True,
     "not_captured(not_instrumented)", ("sdk.records", "file.audit")),
    ("N46", ("file.path",), False, "not_captured(hook_disabled)", ("sdk.records", "file.audit")),
    ("N47", ("file.before", "file.after"), False, "not_captured(not_exposed)",
     ("explicit.byte_boundary", "explicit.subprocess_artifact")),
    ("N51", ("asset.reference",), False, "absent", ("reconstruct.parse", "sdk.records")),
    ("N53", ("computer.requested_action",), True, "not_captured(not_instrumented)",
     ("reconstruct.parse",)),
    ("N55", ("computer.snapshot",), False, "not_captured(not_exposed)",
     ("reconstruct.parse", "sdk.records", "ui.automation")),
    ("N58", ("application_message",), True, "not_captured(caller_omitted)", ("sdk.records",)),
    ("N59", ("output.payload",), True, "not_captured(not_instrumented)", ("sdk.records",)),
    ("N60", ("embedding.input", "embedding.dimensions"), True, "not_captured(not_instrumented)",
     ("reconstruct.parse",)),
    ("D17", ("context.history_rewritten",), False, "unknown", ("reconstruct.infer",)),
    ("D21", ("effect.request", "effect.result"), False, "not_captured(caller_omitted)",
     ("sdk.records",)),
    ("D30", ("run.outcome", "run.stop_reason"), True, "unknown", ("sdk.records",)),
    ("D31", ("usage.input_tokens", "usage.output_tokens"), True,
     "not_captured(provider_not_returned)", (*_WIRE, "reconstruct.parse")),
    ("D32", ("usage.cache_read", "usage.cache_creation", "usage.reasoning_tokens"), False,
     "absent", ("reconstruct.parse",)),
    ("D33", ("usage.media_units", "usage.hosted_tool_calls"), False, "absent",
     ("reconstruct.parse",)),
    ("D34", ("usage.basis",), True, "always", ("fabric.self",)),
)  # fmt: skip
FIELD_ROWS: Mapping[str, FieldRow] = {row[0]: FieldRow(*row) for row in _ROWS}
#: Projection key -> its row (keys are unique across the registry, 049 §3).
KEY_ROWS: Mapping[str, FieldRow] = {key: row for row in FIELD_ROWS.values() for key in row.keys}

#: R fields on every step (049 §3 ``Req`` ``R`` without a parenthesis; the source-, epoch-,
#: segment- and document-level rows X01, X25, X33, X35, X36, X39, X41, X42, X44, X45, X47,
#: X49, C16 and S31 are reported where they live, never repeated per step).
STEP_REQUIRED: tuple[str, ...] = (
    "X02", "X06", "X07", "X08", "X17", "X19", "X26", "X27", "X34", "S01", "S03", "S07", "S08",
)  # fmt: skip
#: R fields by step kind (the ``Req`` parenthesis). Kinds without a P1 producer carry only
#: the step-wide fields.
KIND_REQUIRED: Mapping[str, tuple[str, ...]] = {
    "model_call": ("C19", "C20", "C21", "C22", "C34", "C35", "C36", "C37", "C38", "C39",
                   "N01", "N03", "N04", "N05", "N07", "N08", "N09", "N12", "N13", "N14",
                   "D31", "D34"),
    "embedding": ("N60",),
    "provider_tool_call": ("N18", "N19", "N20"),
    "ui_action": ("N53",),
    "tool_call": ("N17", "N18"),
    "input": ("C11",),
    "terminal": ("N32", "N34", "N35"),
    "network": ("N43",),
    "file": ("N45",),
    "message": ("N58",),
    "outcome": ("N59",),
}  # fmt: skip
#: R fields under a condition (``R (timed steps)``, ``R (on error)``, ...).
CONDITIONAL_REQUIRED: Mapping[str, str] = {
    "X22": "timed", "X23": "timed", "X40": "not_stored", "X43": "segment", "S09": "on_error",
    "S10": "on_error", "S29": "streamed", "S34": "scope", "N02": "split",
}  # fmt: skip
#: The registry's coverage profiles, ``extends`` resolved: step kinds and run fields.
PROFILES: Mapping[str, tuple[frozenset[str], tuple[str, ...]]] = {
    "fabric.profile.model-calls/v1": (
        frozenset({"model_call", "embedding", "provider_tool_call"}),
        ("X01", "X02", "X06", "X08", "S34"),
    ),
    "fabric.profile.agent-run/v1": (
        frozenset({"model_call", "embedding", "provider_tool_call", "tool_call", "input",
                   "outcome", "side_effect", "control", "delegation", "context_change"}),
        ("X01", "X02", "X06", "X08", "S34", "C01", "C05", "D30"),
    ),
    "fabric.profile.execution/v1": (
        frozenset({"model_call", "embedding", "provider_tool_call", "tool_call", "input",
                   "outcome", "side_effect", "control", "delegation", "context_change",
                   "terminal", "database", "network", "file", "mcp_call", "remote_exec"}),
        ("X01", "X02", "X06", "X08", "S34", "C01", "C05", "D30"),
    ),
    "fabric.profile.full/v1": (
        frozenset({"run", "model_call", "embedding", "input", "message", "tool_call",
                   "provider_tool_call", "mcp_call", "retrieval", "memory", "terminal",
                   "remote_exec", "database", "network", "file", "ui_action", "media_stream",
                   "delegation", "workflow_node", "checkpoint", "control", "context_change",
                   "selection", "side_effect", "outcome", "hook", "skill", "interaction",
                   "extension"}),
        ("X01", "X02", "X06", "X08", "S34", "C01", "C05", "D30"),
    ),
}  # fmt: skip
#: Content roles a records body projects into (the registry's ``lives in`` ``C`` roles).
ROLE_FIELDS: Mapping[str, str] = {
    "model.exchange.request": "model.exchange.request",
    "model.exchange.response": "model.exchange.response",
    "model.request.instructions": "instructions",
    "model.request.tool_definitions": "tools_offered",
    "model.request.messages": "input.messages",
    "model.output.messages": "output.messages",
    "model.output.reasoning": "reasoning.text",
    "tool.call.arguments": "tool.execution.arguments",
    "tool.call.result": "tool.execution.result",
    "terminal.argv": "terminal.argv",
    "terminal.context": "terminal.context",
    "terminal.stdin": "terminal.stdin",
    "terminal.stdout": "terminal.stdout",
    "terminal.stderr": "terminal.stderr",
    "network.request": "http.request_body",
    "network.response": "http.response_body",
    "artifact.before": "file.before",
    "artifact.after": "file.after",
    "artifact.locator": "file.path",
    "interaction.payload": "application_message",
    "run.outcome": "output.payload",
    "run.input": "input.payload",
    "side_effect.request": "effect.request",
    "side_effect.result": "effect.result",
}
STEP_KINDS: frozenset[str] = PROFILES["fabric.profile.full/v1"][0] | {"agent_turn"}

# Field classes and coverage reasons (049 §2.6).
_WITHHELD_REDACTED = frozenset({"privacy_policy", "provider_redacted", "provider_encrypted"})
_WITHHELD_NOT_CAPTURED = frozenset(
    {"privacy_policy", "provider_summarised", "provider_not_returned", "explicit_withheld"}
)
_UNCERTAIN_REASONS = frozenset({"clock_uncertain", "source_unauthenticated"})
REASONS: frozenset[str] = frozenset({
    "not_instrumented", "hook_disabled", "not_configured", "unsupported_api",
    "unsupported_runtime", "unsupported_version", "parse_failed", "body_cap", "part_cap",
    "inflight_budget", "queue_full", "disk_full", "shutdown", "internal_error", "span_dropped",
    "store_failed", "destination_rejected", "transport_incomplete", "stream_closed_early",
    "privacy_policy", "protection_failed", "missing_capture_policy", "missing_id_key",
    "missing_spool_key", "provider_redacted", "provider_encrypted", "provider_summarised",
    "provider_not_returned", "provider_held", "caller_omitted", "deferred_to_explicit",
    "explicit_withheld", "not_exposed", "source_lost", "segment_missing", "segment_conflict",
    "run_unterminated", "post_terminal_activity", "clock_uncertain", "source_unauthenticated",
    "unsealed_epoch", "seal_mismatch", "uninstrumented_client", "sampling",
    "retention_expired", "deleted",
})  # fmt: skip
# Descriptor-only producer reasons (049 §2.6) and how they project.
_DESCRIPTOR_REASONS: Mapping[str, tuple[str, str]] = {
    "payload_too_large": ("not_captured", "body_cap"),
    "parse_failed": ("not_captured", "parse_failed"),
    "encoding_failed": ("not_captured", "parse_failed"),
    "not_exact_bytes": ("unsupported", "unsupported_api"),
}
# Report gap types and the coverage reason each states at run level (RR1, RR3a).
_GRAPH_GAPS: Mapping[str, str] = {
    "segment_missing": "segment_missing", "segment_conflict": "segment_conflict",
    "post_terminal_activity": "post_terminal_activity", "seal_mismatch": "seal_mismatch",
    "unsealed_segment": "source_lost", "unsealed_epoch": "unsealed_epoch",
}  # fmt: skip
_UNVERIFIED_GAPS: Mapping[str, str] = {
    "source_unauthenticated": "source_unauthenticated", "clock_uncertain": "clock_uncertain",
    "manifest_gap": "source_lost", "unparsed_exchange": "parse_failed",
    "seal_mismatch": "seal_mismatch",
}  # fmt: skip
_GRAPH_REASONS = frozenset({"segment_missing", "segment_conflict", "post_terminal_activity"})
_HOSTED_KINDS = {"computer": "ui_action"}
_PROVIDER_TOOL_RESULTS: Mapping[str, tuple[str, str]] = {
    "reported_completed": ("completed", "ok"),
    "reported_failed": ("completed", "error"),
    "in_progress": ("running", "unknown"),
}
_RESPONSE_FIELDS_ORIGIN = frozenset({
    "model.served", "output.messages", "refusal", "finish_reasons", "reasoning.format",
    "reasoning.text", "reasoning.summary", "reasoning.object", "usage.input_tokens",
    "usage.output_tokens", "usage.cache_read", "usage.cache_creation", "usage.reasoning_tokens",
    "usage.media_units", "usage.hosted_tool_calls", "error.code", "tool_call.id",
    "tool_call.name", "tool_call.type",
})  # fmt: skip
# Model-call fact keys that become child steps, not fields of the model call.
_CHILD_FACT_KEYS = frozenset({
    "tool.execution_side", "provider_tool.kind", "provider_tool.status", "provider_tool.inputs",
    "computer.requested_action",
})  # fmt: skip


def _version(value: str) -> str | None:
    return value if _VERSION_RE.fullmatch(value) else None


_PARSER_VERSION = __version__ if re.fullmatch(r"^[0-9A-Za-z.+-]{1,64}$", __version__) else "0"


def _point(name: str, version: str | None = None) -> str:
    """A capture point string ``id@version`` (``id`` alone without a valid version)."""
    text = f"{name}@{version}" if version is not None and _version(version) else name
    return text if _POINT_RE.fullmatch(text) else "fabric.self"


_PARSE = _point("reconstruct.parse", __version__)
_INFER = _point("reconstruct.infer", __version__)


# --------------------------------------------------------------------------
# Collection while the verifier runs
# --------------------------------------------------------------------------


@dataclass(slots=True)
class _Exchange:
    """One exchange: its observation and span, its sides' verification results (without
    their bytes), its stitch view and its model-call fields, parsed while the run's bodies
    were in memory (``request_parsed``/``response_parsed``: the side's verified bytes were
    there to parse)."""

    obs: ExchangeObs
    span: SpanRecord | None
    request: ObjectResult | None = None
    response: ObjectResult | None = None
    view: StitchView | None = None
    model: ModelFields | None = None
    request_parsed: bool = False
    response_parsed: bool = False


class ProjectionCollector:
    """The verifier's projection sink (``_verify.ProjectionSink``): it keeps references to
    what the verifier already holds, never copies of bytes beyond one run's bodies."""

    def __init__(self) -> None:
        self.exchanges: dict[str, _Exchange] = {}
        self.records: dict[str, dict[RecordObs, SpanRecord]] = defaultdict(dict)
        self.markers: dict[str, dict[HeartbeatObs, SpanRecord]] = defaultdict(dict)
        self.records_by_span: dict[tuple[str, str], str] = {}
        self.verifier: Any = None

    def observed(self, obs: Observation, span: SpanRecord) -> None:
        if isinstance(obs, ExchangeObs):
            self.exchanges.setdefault(obs.exchange_id, _Exchange(obs, span))
        elif isinstance(obs, RecordObs):
            self.records[obs.attempt_uid].setdefault(obs, span)
            self.records_by_span.setdefault((obs.source_id, span.span_id), obs.attempt_uid)
        elif (
            isinstance(obs, HeartbeatObs) and obs.kind in ("run_start", "run_end")
            and obs.scope_id is not None
        ):  # fmt: skip
            self.markers[obs.scope_id].setdefault(obs, span)

    def attach(self, verifier: Any) -> None:
        self.verifier = verifier

    def exchange_read(
        self, exchange: ExchangeObs, request: ObjectResult, response: ObjectResult | None,
        view: StitchView,
    ) -> None:  # fmt: skip
        """Parse the exchange's model-call fields now, from its verified (and reassembled)
        bytes, and keep the results without the bytes: the projection holds one run's
        bodies at most, as the verifier does."""
        entry = self.exchanges.get(exchange.exchange_id)
        if entry is None:
            entry = self.exchanges[exchange.exchange_id] = _Exchange(exchange, None)
        req = request.data if request.verification == "verified" else None
        resp = response.data if response is not None and response.verification == "verified" \
            else None  # fmt: skip
        key = getattr(self.verifier, "key", None)
        entry.model = extract_model_fields(
            cast("WireApi", exchange.api), request=req, response=resp,
            request_encoding=request.content_encoding,
            response_encoding=response.content_encoding if response is not None else None,
            request_media_type=request.media_type,
            response_media_type=response.media_type if response is not None else None,
            id_key=key,
        ) if exchange.api else None  # fmt: skip
        entry.obs, entry.view = exchange, view
        entry.request = dataclasses.replace(request, data=None)
        entry.response = None if response is None else dataclasses.replace(response, data=None)
        entry.request_parsed, entry.response_parsed = req is not None, resp is not None


# --------------------------------------------------------------------------
# Field wrappers and classes
# --------------------------------------------------------------------------


def _scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, bool))


def _json_value(value: Any) -> Any:
    """A wrapper ``value`` (scalar or a list of at most 256 scalars), else ``_NO_VALUE``
    (``None`` is no value: a parser's "nothing here" is never shown as a JSON null)."""
    if value is None:
        return _NO_VALUE
    if _scalar(value) and not isinstance(value, float):
        return value
    if isinstance(value, (list, tuple)) and all(_scalar(v) for v in value):
        return list(value)[:_VALUE_MAX]
    return _NO_VALUE


_NO_VALUE: Any = object()


def wrapper(
    status: str, *, provenance: str, point: str, reason: str | None = None,
    value: Any = _NO_VALUE, refs: Sequence[Mapping[str, Any]] = (), **extra: Any,
) -> dict[str, Any]:  # fmt: skip
    """One ``$defs/field`` wrapper; a value or locator only for a captured-class status."""
    out: dict[str, Any] = {"status": status, "provenance": provenance, "capture_point": point}
    if reason is not None and status in ("not_captured", "redacted", "truncated", "unsupported"):
        out["reason"] = reason if reason in REASONS else "internal_error"
    carries = status not in ("absent", "not_applicable", "unknown", "conflict")
    if carries and value is not _NO_VALUE:
        shown = _json_value(value)
        if shown is not _NO_VALUE:
            out["value"] = shown
    if carries and refs:
        if len(refs) == 1:
            out["ref"] = dict(refs[0])
        else:
            out["refs"] = [dict(ref) for ref in refs[:4096]]
    if status == "absent":
        out["parse"] = "parsed"
    out.update({key: item for key, item in extra.items() if item is not None})
    return out


def _parsed_status(text: str) -> tuple[str, str | None]:
    if "(" in text and text.endswith(")"):
        status, reason = text[:-1].split("(", 1)
        return status, reason
    return text, None


def field_class(field_wrapper: Mapping[str, Any]) -> str:  # noqa: PLR0911 - one per class
    """049 §2.6 field class: ok, withheld, gap, unsupported or uncertain."""
    status, reason = field_wrapper["status"], field_wrapper.get("reason")
    if reason in _UNCERTAIN_REASONS or status == "unknown":
        return "uncertain"
    if status == "captured":
        return "uncertain" if field_wrapper.get("confidence") == "tentative" else "ok"
    if status in ("absent", "not_applicable"):
        return "ok"
    if status == "unsupported":
        return "unsupported"
    if status == "redacted" and reason in _WITHHELD_REDACTED:
        return "withheld"
    if status == "not_captured" and reason in _WITHHELD_NOT_CAPTURED:
        return "withheld"
    return "gap"


# --------------------------------------------------------------------------
# The verdict tables (049 §6.2), as data
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StepEval:
    """What R1-R6 read for one step and layer: whether a manifest governs the step's
    window, and the class and reason of each R field of the layer."""

    governed: bool
    fields: tuple[tuple[str, str | None], ...]  # (class, reason) per R field

    @property
    def classes(self) -> set[str]:
        return {cls for cls, _ in self.fields}

    def reasons(self, *classes: str) -> list[str]:
        return sorted({r for cls, r in self.fields if cls in classes and r is not None})


Rule = tuple[str, Callable[[Any], bool], str, Callable[[Any], list[str]]]
STEP_RULES: tuple[Rule, ...] = (
    ("R1", lambda e: not e.governed, "unverified", lambda e: ["source_lost"]),
    ("R2", lambda e: "uncertain" in e.classes, "unverified", lambda e: e.reasons("uncertain")),
    ("R3", lambda e: bool(e.fields) and e.classes == {"unsupported"}, "unsupported",
     lambda e: e.reasons("unsupported")),
    ("R4", lambda e: "gap" in e.classes or ("unsupported" in e.classes and len(e.classes) > 1),
     "partial", lambda e: e.reasons("gap", "unsupported")),
    ("R5", lambda e: "withheld" in e.classes, "captured_with_withholding",
     lambda e: e.reasons("withheld")),
    ("R6", lambda e: True, "captured_for_declared_fields", lambda e: []),
)  # fmt: skip


@dataclass(frozen=True, slots=True)
class RunEval:
    """What RR1-RR7 read for one run and layer."""

    integrity: str
    run_state: str
    steps: tuple[tuple[str, tuple[str, ...]], ...]  # in-profile (verdict, reasons)
    observed_steps: bool  # an in-profile step that is not a tentative inference exists
    run_level: tuple[str, tuple[str, ...]] | None  # the run-level pseudo-step, if any
    integrity_reasons: tuple[str, ...] = ()
    graph_reasons: tuple[str, ...] = ()
    unauthenticated: bool = False
    none_reasons: tuple[str, ...] = ()

    def verdicts(self) -> list[tuple[str, tuple[str, ...]]]:
        return [*self.steps, *([self.run_level] if self.run_level is not None else [])]

    def reasons_of(self, *verdicts: str) -> list[str]:
        return sorted({r for v, rs in self.verdicts() if v in verdicts for r in rs})

    def unsupported_mixed(self) -> bool:
        kinds = {v for v, _ in self.verdicts()}
        return "unsupported" in kinds and len(kinds) > 1


RUN_RULES: tuple[Rule, ...] = (
    ("RR1", lambda e: e.integrity == "unverified" or any(v == "unverified" for v, _ in e.steps),
     "unverified",
     lambda e: sorted({*e.integrity_reasons,
                       *(r for v, rs in e.steps if v == "unverified" for r in rs)})),
    ("RR1a", lambda e: e.unauthenticated, "unverified", lambda e: ["source_unauthenticated"]),
    ("RR2", lambda e: e.run_level is not None and e.run_level[0] == "unverified", "unverified",
     lambda e: sorted(e.run_level[1])),
    ("RR3", lambda e: not e.observed_steps and e.run_level is None, "none_observed",
     lambda e: sorted(e.none_reasons)),
    ("RR3a", lambda e: bool(e.graph_reasons) or e.run_state == "conflicted", "partial",
     lambda e: sorted(e.graph_reasons) or ["segment_conflict"]),
    ("RR3b", lambda e: e.run_state == "deadline_uncertain", "unverified",
     lambda e: ["clock_uncertain"]),
    ("RR3c", lambda e: e.run_state == "unterminated", "partial", lambda e: ["run_unterminated"]),
    ("RR4", lambda e: bool(e.verdicts()) and all(v == "unsupported" for v, _ in e.verdicts()),
     "unsupported", lambda e: e.reasons_of("unsupported")),
    ("RR5", lambda e: e.integrity == "partial" or any(v == "partial" for v, _ in e.verdicts())
     or e.unsupported_mixed(), "partial", lambda e: e.reasons_of("partial", "unsupported")),
    ("RR5a", lambda e: e.run_state == "open", "open", lambda e: []),
    ("RR6", lambda e: any(v == "captured_with_withholding" for v, _ in e.verdicts()),
     "captured_with_withholding", lambda e: e.reasons_of("captured_with_withholding")),
    ("RR7", lambda e: True, "captured_for_declared_fields", lambda e: []),
)  # fmt: skip


def decide(rules: Sequence[Rule], evaluation: Any) -> tuple[str, str, list[str]]:
    """``(row id, verdict, reasons)`` of the first matching row."""
    for row_id, applies, verdict, reasons in rules:
        if applies(evaluation):
            return row_id, verdict, reasons(evaluation)
    raise AssertionError("the last row always applies")  # pragma: no cover


def _verdict_json(verdict: str, reasons: Iterable[str]) -> dict[str, Any]:
    shown = sorted({r for r in reasons if r in REASONS})
    return {"verdict": verdict, "reasons": shown} if shown else {"verdict": verdict}


# --------------------------------------------------------------------------
# Per-step field sets
# --------------------------------------------------------------------------


@dataclass(slots=True)
class _StepContext:
    """What a field without evidence is decided from: the governing manifest, the step's
    capture point and the points that can supply fields to it."""

    manifest: ManifestObs | None
    point_id: str
    points: frozenset[str]
    kind: str


class _Fields:
    """One step's (or run's) layered field set."""

    def __init__(self) -> None:
        self.layers: dict[str, dict[str, dict[str, Any]]] = {}

    def put(self, key: str, value: dict[str, Any], layer: str | None = None) -> None:
        row = KEY_ROWS.get(key)
        where = layer or (row.layer if row is not None else "content")
        self.layers.setdefault(where, {})[key] = value

    def has(self, key: str) -> bool:
        return any(key in fieldset for fieldset in self.layers.values())

    def get(self, key: str) -> dict[str, Any] | None:
        for fieldset in self.layers.values():
            if key in fieldset:
                return fieldset[key]
        return None

    def to_json(self) -> dict[str, Any]:
        return {layer: dict(sorted(self.layers[layer].items()))
                for layer in LAYERS if self.layers.get(layer)}  # fmt: skip


def _manifest_row(manifest: ManifestObs | None, point: str) -> Mapping[str, Any] | None:
    if manifest is None:
        return None
    for row in manifest.document.get("capture_points", ()):
        if isinstance(row, Mapping) and row.get("id") == point:
            return row
    return None


def _manifest_point(manifest: ManifestObs | None, point: str) -> str:
    row = _manifest_row(manifest, point)
    version = row.get("version") if row is not None else None
    return _point(point, version if isinstance(version, str) else None)


_STATE_STATUS: Mapping[str, tuple[str, str]] = {
    "installed_inactive": ("not_captured", "not_instrumented"),
    "disabled": ("not_captured", "hook_disabled"),
    "unsupported": ("unsupported", "unsupported_version"),
    "failed": ("not_captured", "internal_error"),
}


def unobserved(  # noqa: PLR0911 - one return per manifest case
    row: FieldRow, step: _StepContext
) -> tuple[str, str | None, str]:
    """``(status, reason, capture point)`` of an R field the record does not carry, from
    the governing manifest (049 §2.6 "When a capture point is absent", 050 §3.13)."""
    if step.manifest is None:
        return "unknown", None, row.observed_by[0]
    candidates = [p for p in row.observed_by if p in step.points]
    candidates.sort(key=lambda p: p != step.point_id)
    if not candidates:
        return "unsupported", "unsupported_version", row.observed_by[0]
    for point in candidates:
        manifest_row = _manifest_row(step.manifest, point)
        if manifest_row is None:
            continue
        shown = _manifest_point(step.manifest, point)
        state = manifest_row.get("state")
        if state != "active":
            inactive, why = _STATE_STATUS.get(str(state), ("not_captured", "not_instrumented"))
            declared = manifest_row.get("reason")
            return inactive, declared if isinstance(declared, str) else why, shown
        if row.field_id not in manifest_row.get("fields", ()):
            return "unsupported", "unsupported_version", shown
        if manifest_row.get("kind") == "R":
            return "not_captured", "caller_omitted", shown
        status, reason = _parsed_status(row.absent)
        return ("unknown", None, shown) if status == "always" else (status, reason, shown)
    return "unsupported", "unsupported_runtime", candidates[0]


def complete_required(
    fields: _Fields, step: _StepContext, kind: str, flags: Iterable[str], provenance: str
) -> None:
    """Give every applicable R field the step does not carry its manifest-driven status (a
    statement of the manifest's, never an inference: ``observed`` for an inferred step)."""
    provenance = "observed" if provenance == "inferred" else provenance
    for field_id in required_fields(kind, flags):
        row = FIELD_ROWS[field_id]
        for key in row.keys:
            if fields.has(key):
                continue
            status, reason, point = unobserved(row, step)
            fields.put(key, wrapper(status, provenance=provenance, point=point, reason=reason))


def required_fields(kind: str, flags: Iterable[str]) -> tuple[str, ...]:
    """The R field ids that apply to a step of ``kind`` under ``flags``."""
    held = set(flags)
    conditional = tuple(i for i, flag in CONDITIONAL_REQUIRED.items() if flag in held)
    return tuple(dict.fromkeys((*STEP_REQUIRED, *KIND_REQUIRED.get(kind, ()), *conditional)))


def step_layer_verdicts(
    fields: _Fields, kind: str, flags: Iterable[str], governed: bool,
    extra: Mapping[str, Iterable[str]] | None = None,
) -> tuple[dict[str, Any], dict[str, tuple[str, str, list[str]]]]:  # fmt: skip
    """The step's ``layer_verdicts`` and, per layer, the deciding ``(row, verdict, reasons)``.
    ``extra`` adds keys counted in a layer (an extension step's ``x-`` field)."""
    keys = [k for i in required_fields(kind, flags) for k in FIELD_ROWS[i].keys]
    decided: dict[str, tuple[str, str, list[str]]] = {}
    for layer in VERDICT_LAYERS:
        fieldset = fields.layers.get(layer, {})
        counted = [k for k in keys if KEY_ROWS[k].layer == layer]
        counted += list((extra or {}).get(layer, ()))
        evaluation = StepEval(governed, tuple(
            (field_class(fieldset[k]), fieldset[k].get("reason")) for k in counted
            if k in fieldset
        ))  # fmt: skip
        decided[layer] = decide(STEP_RULES, evaluation)
    return {layer: _verdict_json(v, r) for layer, (_, v, r) in decided.items()}, decided


# --------------------------------------------------------------------------
# The document
# --------------------------------------------------------------------------


def _profile(coverage_profile: str) -> tuple[frozenset[str], tuple[str, ...]]:
    try:
        return PROFILES[coverage_profile]
    except KeyError:
        raise ReconstructInputError(
            "--coverage-profile names a profile this verifier does not know"
        ) from None


def build_projection(
    report: Mapping[str, Any], *, graphs: Sequence[RunGraph], reconstruction_sha256: str,
    evaluated_at: datetime, coverage_profile: str = DEFAULT_COVERAGE_PROFILE,
    inline_content: bool = False, collector: ProjectionCollector | None = None,
) -> dict[str, Any] | None:  # fmt: skip
    """The projection document of ``report`` (``None`` when there is nothing to project:
    no run, or no collector, which alone holds what steps are built from)."""
    runs = report.get("runs") or []
    if collector is None or collector.verifier is None or not runs:
        return None
    if inline_content:
        raise ReconstructInputError("inline content is not offered by this verifier")
    profile = _profile(coverage_profile)
    builder = _Builder(report, collector, {graph.run_id: graph for graph in graphs}, profile)
    projected_runs, steps = [], []
    roots: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for run in runs:
        run_doc, run_steps, root = builder.run(run)
        projected_runs.append(run_doc)
        steps.extend(run_steps)
        if root is not None:
            roots[root[0]].append((run["run_id"], root[1]))
    _same_as_by_trace(roots)
    verifier = collector.verifier
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "projection_revision": PROJECTION_REVISION,
        "generated_at": report.get("generated_at") or format_datetime(evaluated_at),
        "parser": {"name": "fabric.reconstruct", "version": _PARSER_VERSION},
        "field_registry": {"schema_version": "fabric.field-registry/v1",
                           "registry_revision": REGISTRY_REVISION},
        "coverage_profile": coverage_profile,
        "inputs": {
            "reconstruction_sha256": reconstruction_sha256,
            "manifests": builder.manifest_inputs(steps),
            "telemetry_origin": report.get("inputs", {}).get("telemetry_origin", "imported"),
        },
        "pseudonym_mode": "keyed" if verifier.key else "unkeyed",
        "content_inline": False,
        "runs": projected_runs,
        "steps": steps,
        "evaluated_at": format_datetime(evaluated_at),
    }  # fmt: skip
    if verifier.key:
        document["key_id"] = key_id(verifier.key)
    return document


_TRACE_RE = re.compile(r"^[0-9a-f]{32}$")
_MAX_LINKS = 1024
_PAIR = 2


def _same_as_by_trace(roots: Mapping[str, Sequence[tuple[str, dict[str, Any]]]]) -> None:
    """049 §2.5: runs whose root steps share a W3C trace id are linked ``same_as``, inferred
    by ``trace_id_match``, tentative; never merged."""
    for members in roots.values():
        if len({run_id for run_id, _ in members}) < _PAIR:
            continue
        for run_id, step in members:
            links = step.setdefault("links", [])
            for other, _ in members:
                if other == run_id or len(links) >= _MAX_LINKS:
                    continue
                links.append({"type": "same_as", "target": {"namespace": "run", "id": other},
                              "provenance": "inferred", "method": "trace_id_match",
                              "confidence": "tentative", "state": "resolved"})  # fmt: skip


class _Builder:
    """Builds the runs and steps of one projection."""

    def __init__(
        self, report: Mapping[str, Any], collector: ProjectionCollector,
        graphs: Mapping[str, RunGraph], profile: tuple[frozenset[str], tuple[str, ...]],
    ) -> None:  # fmt: skip
        self.report = report
        self.collector = collector
        self.verifier = collector.verifier
        self.graphs = graphs
        self.kinds, self.run_fields = profile
        self.known_responses = {
            entry["response_id"] for run in report.get("runs", ())
            for entry in run.get("exchanges", ()) if isinstance(entry.get("response_id"), str)
        }  # fmt: skip

    # -- manifests -------------------------------------------------------------

    def governing(self, key: tuple[str, int], sequence: int) -> ManifestObs | None:
        """The manifest that governs ``sequence`` of ``key`` (049 §2.4): the last of the
        chain whose ``after_source_sequence`` is below it, outside every manifest-less
        window (rule R1), and never one of two documents claiming one ``manifest_seq``."""
        source = self.verifier.sources.get(key)
        if source is None:
            return None
        for low, high, _ in source.manifestless:
            if low <= sequence and (high is None or sequence <= high):
                return None
        chosen: list[ManifestObs] = []
        for manifest in source.manifests:
            if manifest.after_source_sequence < sequence:
                if chosen and chosen[0].manifest_seq != manifest.manifest_seq:
                    chosen = []
                chosen.append(manifest)
        if len(chosen) != 1:
            return None
        return chosen[0]

    def manifest_inputs(self, steps: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
        """Every manifest of the record, by id and digest; at most 4096, the ones a step
        names first."""
        named = {step["source"]["manifest_id"] for step in steps
                 if "manifest_id" in step.get("source", {})}  # fmt: skip
        everything = {
            (m.manifest_id, m.sha256)
            for source in self.verifier.sources.values() for m in source.manifests
        }  # fmt: skip
        ordered = sorted(everything, key=lambda m: (m[0] not in named, m))
        return [{"manifest_id": mid, "sha256": digest} for mid, digest in ordered[:4096]]

    # -- one run ---------------------------------------------------------------

    def run(
        self, run: Mapping[str, Any]
    ) -> tuple[dict[str, Any], list[dict[str, Any]], tuple[str, dict[str, Any]] | None]:
        """The run's document, its steps and ``(trace id, root step)`` when the run's root
        step names a W3C trace."""
        run_id = run["run_id"]
        graph = self.graphs.get(run_id)
        member_ids = set(graph.member_run_ids()) if graph is not None else {run_id}
        builder = _RunSteps(self, run, member_ids)
        steps = builder.build()
        return self._run_document(run, graph, steps), steps, builder.root_trace()

    def _run_document(
        self, run: Mapping[str, Any], graph: RunGraph | None, steps: Sequence[Mapping[str, Any]]
    ) -> dict[str, Any]:
        state, resumable = "not_resumable_unclosed", False
        if graph is not None and graph.run_state is not None:
            state, resumable = graph.run_state, bool(graph.resumable)
        out: dict[str, Any] = {"run_id": run["run_id"]}
        scope_ids = [s["scope_id"] for s in run.get("scopes", ())
                     if _UUID4.fullmatch(s["scope_id"])]  # fmt: skip
        if scope_ids:
            out["scope_ids"] = scope_ids
        out["integrity_verdict"] = run["verdict"]
        run_fields, governed = _RunFields(self, run, steps).build()
        verdicts, none_seen = self._run_verdicts(run, state, steps, run_fields, governed)
        out["layer_verdicts"] = verdicts
        if none_seen:
            out["kinds_none_observed"] = none_seen
        out["fields"] = run_fields.to_json()
        out["run_state"] = state
        out["resumable"] = resumable
        if graph is not None and graph.open_run_deadline_s is not None:
            out["open_run_deadline_s"] = max(60, graph.open_run_deadline_s)
        aliases = list(run.get("run_aliases", ()))[:64]
        if aliases:
            out["run_aliases"] = aliases
        out["segments"] = [dict(segment) for segment in run.get("segments", ())][:4096]
        if graph is not None and graph.deadline_at is not None:
            out["deadline_at"] = format_datetime(graph.deadline_at)
        return out

    def _run_verdicts(
        self, run: Mapping[str, Any], state: str, steps: Sequence[Mapping[str, Any]],
        run_fields: _Fields, governed: bool,
    ) -> tuple[dict[str, Any], list[str]]:  # fmt: skip
        in_profile = [s for s in steps if s["step_kind"] in self.kinds]
        observed = [s for s in in_profile if s.get("confidence") != "tentative"]
        gap_types = {gap["gap_type"]: gap for gap in run.get("gaps", ())}
        unverified_gaps = {gap["gap_type"] for gap in run.get("gaps", ())
                           if gap.get("effect") == "unverified"}  # fmt: skip
        partial_gaps = {gap["gap_type"] for gap in run.get("gaps", ())
                        if gap.get("effect") == "partial"}  # fmt: skip
        integrity_reasons = {_UNVERIFIED_GAPS[t] for t in unverified_gaps if t in _UNVERIFIED_GAPS}
        graph_reasons = {_GRAPH_GAPS[t] for t in partial_gaps if t in _GRAPH_GAPS}
        conflicted = state == "conflicted"
        integrity_reasons = {
            r
            for r in integrity_reasons
            if r != "clock_uncertain" or state in ("conflicted", "deadline_uncertain")
        }
        graph_reasons = {r for r in graph_reasons if r not in _GRAPH_REASONS or conflicted}
        out: dict[str, Any] = {}
        none_seen = False
        run_keys = [k for i in self.run_fields if i in FIELD_ROWS for k in FIELD_ROWS[i].keys]
        for layer in VERDICT_LAYERS:
            layer_steps = tuple(
                (s["layer_verdicts"][layer]["verdict"],
                 tuple(s["layer_verdicts"][layer].get("reasons", ())))
                for s in in_profile
            )  # fmt: skip
            run_level = self._run_level(run_fields, run_keys, layer, governed)
            evaluation = RunEval(
                integrity=run["verdict"], run_state=state, steps=layer_steps,
                observed_steps=bool(observed), run_level=run_level,
                integrity_reasons=tuple(sorted(integrity_reasons)),
                graph_reasons=tuple(sorted(graph_reasons)),
                unauthenticated="source_unauthenticated" in gap_types,
                none_reasons=tuple(self._none_reasons(in_profile)),
            )  # fmt: skip
            _, verdict, reasons = decide(RUN_RULES, evaluation)
            none_seen = none_seen or verdict == "none_observed"
            out[layer] = _verdict_json(verdict, reasons)
        seen_kinds = {s["step_kind"] for s in observed}
        missing = sorted(self.kinds - seen_kinds) if none_seen else []
        return out, missing

    @staticmethod
    def _run_level(
        run_fields: _Fields, keys: Sequence[str], layer: str, governed: bool
    ) -> tuple[str, tuple[str, ...]] | None:
        fieldset = run_fields.layers.get(layer, {})
        counted = [k for k in keys if KEY_ROWS[k].layer == layer and k in fieldset]
        if not counted:
            return None
        evaluation = StepEval(governed, tuple(
            (field_class(fieldset[k]), fieldset[k].get("reason")) for k in counted
        ))  # fmt: skip
        _, verdict, reasons = decide(STEP_RULES, evaluation)
        return verdict, tuple(reasons)

    def _none_reasons(self, steps: Sequence[Mapping[str, Any]]) -> list[str]:
        """RR3's manifest states: the reasons of supplying wire points declared not active."""
        if steps:
            return []
        reasons: set[str] = set()
        for source in self.verifier.sources.values():
            for manifest in source.manifests:
                for point in _WIRE:
                    row = _manifest_row(manifest, point)
                    if row is not None and row.get("state") != "active":
                        reason = row.get("reason")
                        reasons.add(reason if isinstance(reason, str) else "not_instrumented")
        return sorted(reasons & REASONS)


# --------------------------------------------------------------------------
# Run-level fields (the profile's run_fields, evaluated as one pseudo-step)
# --------------------------------------------------------------------------


class _RunFields:
    def __init__(
        self, builder: _Builder, run: Mapping[str, Any], steps: Sequence[Mapping[str, Any]]
    ) -> None:
        self.builder = builder
        self.run = run
        self.steps = steps

    def _root(self) -> Mapping[str, Any] | None:
        runs = [s for s in self.steps if s["step_kind"] == "run" and "parent_step_id" not in s]
        runs.sort(key=lambda s: (s["source"]["source_id"], s["source"]["source_epoch"],
                                 s["source"]["source_sequence"]))  # fmt: skip
        return runs[0] if runs else None

    def build(self) -> tuple[_Fields, bool]:
        """The run's fields and whether a manifest governs its root window (R1)."""
        fields = _Fields()
        root = self._root()
        anchor = root or next((s for s in self.steps if "source" in s), None)
        manifest = None
        if anchor is not None:
            source = anchor["source"]
            manifest = self.builder.governing(
                (source["source_id"], source["source_epoch"]), source["source_sequence"]
            )
        self_point = _manifest_point(manifest, "fabric.self")
        scope_point = root["capture_point"] if root is not None else _manifest_point(
            manifest, "run.scope")  # fmt: skip
        fields.put("run_id", wrapper("captured", provenance="observed", point=scope_point,
                                     value=self.run["run_id"]))  # fmt: skip
        fields.put(
            "schema_version",
            wrapper(
                "captured",
                provenance="observed",
                point=self_point,
                value=self.builder.report.get("schema_version"),
            ),
        )
        self._root_identity(fields, root, self_point)
        self._exit_status(fields, scope_point)
        step = _StepContext(manifest, "run.scope", frozenset({"run.scope", "sdk.records",
                                                             "fabric.self"}), "run")  # fmt: skip
        for field_id in self.builder.run_fields:
            row = FIELD_ROWS.get(field_id)
            if row is None or field_id == "C05":  # C05 only once a trigger is recorded (P2)
                continue
            self._run_field(fields, row, step, root)
        return fields, manifest is not None

    def _root_identity(self, fields: _Fields, root: Mapping[str, Any] | None, point: str) -> None:
        if root is None:
            fields.put("event_id", wrapper("not_applicable", provenance="observed", point=point))
            for key in FIELD_ROWS["X06"].keys:
                fields.put(key, wrapper("not_applicable", provenance="observed", point=point))
            return
        fields.put("event_id", wrapper("captured", provenance="observed", point=point,
                                       value=root["event_ids"][0]))  # fmt: skip
        source = root["source"]
        for key in FIELD_ROWS["X06"].keys:
            fields.put(key, wrapper("captured", provenance="observed", point=point,
                                    value=source[key]))  # fmt: skip

    def _exit_status(self, fields: _Fields, point: str) -> None:
        """S34 over the run's ended scopes: their exit statuses; ``not_applicable`` with no
        scope or no ended scope (an unclosed scope is the integrity verdict's and the run
        state's to report); ``unsupported(unsupported_version)`` for run_end markers that
        predate ``fabric.run.scope_status``."""
        statuses: list[str] = []
        ended = False
        for step in self.steps:
            if step["step_kind"] != "run":
                continue
            exit_status = step["layers"].get("structure", {}).get("scope.exit_status", {})
            if exit_status.get("status") == "captured":
                ended = True
                statuses.append(exit_status["value"])
            elif exit_status.get("status") == "unsupported":
                ended = True
        if statuses:
            fields.put(
                "scope.exit_status",
                wrapper(
                    "captured", provenance="reported", point=point, value=sorted(set(statuses))
                ),
            )
        elif ended:
            fields.put(
                "scope.exit_status",
                wrapper(
                    "unsupported", provenance="reported", point=point, reason="unsupported_version"
                ),
            )
        else:
            fields.put("scope.exit_status", wrapper("not_applicable", provenance="reported",
                                                    point=point))  # fmt: skip

    def _run_field(
        self, fields: _Fields, row: FieldRow, step: _StepContext, root: Mapping[str, Any] | None
    ) -> None:
        for key in row.keys:
            if fields.has(key):
                continue
            value = None if root is None else _root_value(root, key)
            if value is not None:
                fields.put(key, wrapper("captured", provenance="reported",
                                        point=root["capture_point"] if root else "run.scope",
                                        value=value))  # fmt: skip
                continue
            status, reason, point = unobserved(row, step)
            fields.put(key, wrapper(status, provenance="reported", point=point, reason=reason))


# --------------------------------------------------------------------------
# Steps of one run
# --------------------------------------------------------------------------


def _uuid_or_derived(value: str, locator: str) -> tuple[str, bool]:
    """``value`` when it is a uuid4, else a reproducible uuid4-format id of ``locator``."""
    return (value, False) if _UUID4.fullmatch(value) else (inferred_step_id(locator), True)


def _bounded(text: str, limit: int = _ALIAS_MAX) -> str:
    return text if len(text) <= limit else text[:limit]


def _str_attr(attrs: Mapping[str, Any], key: str) -> str | None:
    value = attrs.get(key)
    return value if isinstance(value, str) and value else None


_LIFECYCLES = frozenset(
    {"queued", "running", "suspended", "deferred", "completed", "cancelled", "unknown"}
)
_RESULTS = frozenset({"ok", "error", "cancelled", "timeout", "unknown"})
_ACTORS = frozenset({
    "user", "agent", "sub_agent", "human_approver", "human_operator", "system", "scheduler",
    "external_service", "provider", "unknown",
})  # fmt: skip


def _actor(attrs: Mapping[str, Any]) -> str:
    """S03 (049 §2.3): the record's ``fabric.actor.type``, else the SDK default ``agent``;
    a value outside the vocabulary is ``unknown`` (imported spans are never trusted)."""
    actor = _str_attr(attrs, "fabric.actor.type")
    if actor is None:
        return "agent"
    return actor if actor in _ACTORS else "unknown"


def _int_attr(attrs: Mapping[str, Any], key: str) -> int | None:
    value = attrs.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


class _RunSteps:
    """The steps of one report run."""

    def __init__(self, builder: _Builder, run: Mapping[str, Any], members: set[str]) -> None:
        self.builder = builder
        self.collector = builder.collector
        self.verifier = builder.verifier
        self.run = run
        self.run_id: str = run["run_id"]
        self.members = members
        self.steps: list[dict[str, Any]] = []
        self.scope_steps: dict[str, str] = {}
        self.exchange_steps: dict[str, dict[str, Any]] = {}
        self.record_steps: dict[str, str] = {}  # attempt uid -> step id
        gaps = run.get("gaps", ())
        self.prefix_breaks = {
            gap["exchange_id"]
            for gap in gaps
            if gap.get("gap_type") == "prefix_break" and "exchange_id" in gap
        }
        self.entries = {entry["exchange_id"]: entry for entry in run.get("exchanges", ())}
        self.traces: dict[str, str] = {}  # attempt id -> the W3C trace id of its record
        self.record_attempts: set[str] = set()

    def root_trace(self) -> tuple[str, dict[str, Any]] | None:
        """The run's root step (its outermost first scope, else its first exchange, else its
        first records attempt) and the W3C trace id of the record it came from."""
        top = [s for s in self.steps if s["step_kind"] == "run" and "parent_step_id" not in s]
        wire = [s for s in self.steps if s.get("source", {}).get("input") == "wire"
                and s["step_kind"] in ("model_call", "embedding")]  # fmt: skip
        records = [s for s in self.steps if s["attempt_id"] in self.record_attempts]
        for candidates in (top, wire, records):
            if candidates:
                trace = self.traces.get(candidates[0]["attempt_id"])
                return None if trace is None else (trace, candidates[0])
        return None

    def build(self) -> list[dict[str, Any]]:
        for scope in run_scopes(self.run):
            self._scope_step(scope)
        self._link_scopes()
        for attempt in self.run.get("attempts", ()):
            self._records_step(attempt["attempt_uid"])
        for entry in self.run.get("exchanges", ()):
            self._wire_step(entry)
        return self.steps

    # -- shared ---------------------------------------------------------------

    def _context(
        self, key: tuple[str, int], sequence: int, point_id: str, kind: str,
        extra_points: Iterable[str] = (),
    ) -> _StepContext:  # fmt: skip
        manifest = self.builder.governing(key, sequence)
        points = frozenset({point_id, "fabric.self", "install.config", "run.scope",
                            *extra_points})  # fmt: skip
        return _StepContext(manifest, point_id, points, kind)

    def _common(self, fields: _Fields, step: dict[str, Any], ctx: _StepContext) -> None:
        """The step-wide cross-cutting and structure facts every step states."""
        self_point = _manifest_point(ctx.manifest, "fabric.self")
        put = fields.put
        if not fields.has("event_id"):
            put("event_id", wrapper("captured", provenance="observed", point=self_point,
                                    value=step["event_ids"][0]))  # fmt: skip
        source = step.get("source")
        positional = (*FIELD_ROWS["X06"].keys, "sequence_unit", "manifest_id")
        for key in positional:
            if source is None:  # an inferred step has no source position
                put(key, wrapper("not_applicable", provenance="observed", point=self_point))
            elif key in source:
                put(key, wrapper("captured", provenance="observed", point=self_point,
                                 value=source[key]))  # fmt: skip
        put("run_id", wrapper("captured", provenance="observed", point=self_point,
                              value=self.run_id))  # fmt: skip
        put("step_id", wrapper("captured", provenance="observed", point=self_point,
                               value=step["step_id"]))  # fmt: skip
        put("attempt_id", wrapper("captured", provenance="observed", point=self_point,
                                  value=step["attempt_id"]))  # fmt: skip
        put("capture_point", wrapper("captured", provenance="observed", point=self_point,
                                     value=step["capture_point"]))  # fmt: skip
        put("provenance", wrapper("captured", provenance="observed", point=self_point,
                                  value=step["provenance"]))  # fmt: skip
        for key, value in (("scope_id", step.get("scope_id")),
                           ("segment_id", step.get("segment_id")),
                           ("parent_step_id", step.get("parent_step_id"))):  # fmt: skip
            if value is not None:
                put(key, wrapper("captured", provenance="observed", point=self_point,
                                 value=value))  # fmt: skip
        put("step.kind", fields.get("step.kind") or wrapper(
            "captured", provenance=step["provenance"], point=self_point,
            value=step["step_kind"]))  # fmt: skip
        if "actor" in step and not fields.has("actor.type"):
            put("actor.type", wrapper("captured", provenance="observed", point=self_point,
                                      value=step["actor"]["type"]))  # fmt: skip
        timing = step.get("timing")
        if timing is not None:
            put("timing_basis", wrapper("captured", provenance="observed", point=self_point,
                                        value=timing["basis"]))  # fmt: skip
            for key, ns in (("started_at", timing.get("started_at_ns")),
                            ("ended_at", timing.get("ended_at_ns"))):  # fmt: skip
                if ns is not None:
                    put(key, wrapper("captured", provenance=step["provenance"],
                                     point=step["capture_point"], value=ns))  # fmt: skip

    def _source(
        self, input_name: str, key: tuple[str, int], sequence: int, manifest: ManifestObs | None,
        subindex: int | None = None,
    ) -> dict[str, Any]:  # fmt: skip
        unit = manifest.document.get("sequence_unit") if manifest is not None else None
        if unit not in ("exchange", "record"):
            unit = "exchange" if input_name == "wire" and manifest is None else "record"
        out: dict[str, Any] = {"input": input_name, "source_id": key[0], "source_epoch": key[1],
                               "source_sequence": sequence, "sequence_unit": unit}  # fmt: skip
        if subindex is not None:
            out["subindex"] = subindex
        if manifest is not None:
            out["manifest_id"] = manifest.manifest_id
        return out

    def _finish(
        self, step: dict[str, Any], fields: _Fields, ctx: _StepContext, flags: Iterable[str],
        extra: Mapping[str, Iterable[str]] | None = None,
    ) -> dict[str, Any]:  # fmt: skip
        held = tuple(flags)
        self._common(fields, step, ctx)
        complete_required(fields, ctx, step["step_kind"], held, step["provenance"])
        step["layers"] = fields.to_json()
        step["layer_verdicts"], _ = step_layer_verdicts(
            fields, step["step_kind"], held, ctx.manifest is not None, extra
        )
        self.steps.append(step)
        return step

    # -- run scopes -------------------------------------------------------------

    def _scope_step(self, scope: Mapping[str, Any]) -> None:
        scope_id = scope["scope_id"]
        markers = self.collector.markers.get(scope_id, {})
        starts = sorted((m for m in markers if m.kind == "run_start"),
                        key=lambda m: m.last_sequence)  # fmt: skip
        ends = [m for m in markers if m.kind == "run_end"]
        event_ids = [m.info.event_id for m in [*starts, *ends]
                     if m.info is not None and m.info.event_id is not None]  # fmt: skip
        if not starts or not event_ids or not _UUID4.fullmatch(scope_id):
            return  # a pre-P1 scope: no record identity to list
        start = starts[0]
        key = (start.source_id, start.source_epoch)
        span = markers[start]
        point_attr = _str_attr(span.attributes, "fabric.capture.point")
        sequence = start.last_sequence + 1
        ctx = self._context(key, sequence, "run.scope", "run")
        point = point_attr if point_attr and _POINT_RE.fullmatch(point_attr) else (
            _manifest_point(ctx.manifest, "run.scope"))  # fmt: skip
        end = ends[0] if len(ends) == 1 else None
        step: dict[str, Any] = {
            "attempt_id": scope_id, "step_id": f"run:{scope_id}", "step_kind": "run",
            "run_id": self.run_id, "scope_id": scope_id,
        }  # fmt: skip
        if start.segment_id is not None:
            step["segment_id"] = start.segment_id
        step["source"] = self._source("records", key, sequence, ctx.manifest)
        step["event_ids"] = list(dict.fromkeys(event_ids))[:MAX_EVENT_IDS]
        step["capture_point"] = point
        step["provenance"] = "reported"
        step["actor"] = {"type": "agent"}
        timing: dict[str, Any] = {"basis": "measured", "clock_domain": "wall_utc",
                                  "started_at_ns": span.start_ns}  # fmt: skip
        if end is not None:
            timing["ended_at_ns"] = max(markers[end].start_ns, span.start_ns)
        step["timing"] = timing
        state = scope.get("state")
        status = end.info.scope_status if end is not None and end.info is not None else None
        step["lifecycle_state"] = {"closed": "completed", "open": "running"}.get(
            str(state), "unknown"
        )
        step["result_status"] = status or "unknown"
        fields = _Fields()
        self._scope_fields(fields, step, end, status, point)
        self.scope_steps[scope_id] = step["step_id"]
        if _TRACE_RE.fullmatch(span.trace_id) and span.trace_id != "0" * 32:
            self.traces[scope_id] = span.trace_id
        opener = 0 if start.info is not None and start.info.predecessors else 1
        step["_window"] = (key, start.last_sequence, scope.get("end_sequence"),
                           (span.start_ns, opener))  # fmt: skip
        self._finish(step, fields, ctx, ("timed", "scope", *self._segment_flag(step)))

    @staticmethod
    def _segment_flag(step: Mapping[str, Any]) -> tuple[str, ...]:
        return ("segment",) if "segment_id" in step else ()

    @staticmethod
    def _scope_fields(
        fields: _Fields, step: Mapping[str, Any], end: HeartbeatObs | None, status: str | None,
        point: str,
    ) -> None:  # fmt: skip
        lifecycle = step["lifecycle_state"]
        if lifecycle != "unknown":
            fields.put("lifecycle.state", wrapper("captured", provenance="reported", point=point,
                                                  value=lifecycle))  # fmt: skip
        if status is not None:
            fields.put("result_status", wrapper("captured", provenance="reported", point=point,
                                                value=status))  # fmt: skip
            fields.put("scope.exit_status", wrapper("captured", provenance="reported",
                                                    point=point, value=status))  # fmt: skip
        elif end is not None:  # a run_end without fabric.run.scope_status: pre-P1 marker
            fields.put(
                "scope.exit_status",
                wrapper(
                    "unsupported", provenance="reported", point=point, reason="unsupported_version"
                ),
            )
        if end is not None and end.info is not None:
            for key, value in (("run.outcome", end.info.outcome),
                               ("run.stop_reason", end.info.stop_reason)):  # fmt: skip
                if value is not None:
                    fields.put(key, wrapper("captured", provenance="reported", point=point,
                                            value=value))  # fmt: skip

    def _link_scopes(self) -> None:
        """A scope's parent is the innermost other scope of the run on its source whose
        window contains its own (an inner ``with run()`` block): it starts no later, ends no
        earlier (an open scope never ends), and, on a tie, its ``run_start`` came first."""
        windows = [(s, s.pop("_window")) for s in self.steps if "_window" in s]
        for step, mine in windows:
            containers = [(theirs, other["step_id"]) for other, theirs in windows
                          if other is not step and _contains(theirs, mine)]  # fmt: skip
            if not containers:
                continue
            _, parent = max(containers, key=lambda c: (c[0][1], -_end(c[0]), c[0][3]))
            step["parent_step_id"] = parent
            cross = step["layers"].setdefault("cross_cutting", {})
            point = cross["step_id"]["capture_point"]
            cross["parent_step_id"] = wrapper("captured", provenance="observed", point=point,
                                              value=parent)  # fmt: skip

    # -- records-input attempts -------------------------------------------------

    def _records_step(self, attempt_uid: str) -> None:
        held = self.collector.records.get(attempt_uid, {})
        records = sorted(
            ((obs, span) for obs, span in held.items() if obs.run_id in self.members),
            key=lambda pair: (pair[0].source_id, pair[0].source_epoch, pair[0].source_sequence),
        )
        if not records:
            return
        first, first_span = records[0]
        last_attrs = records[-1][1].attributes
        attrs = first_span.attributes
        key = first.source
        kind = _str_attr(attrs, "fabric.step.kind")
        kind = kind if kind in STEP_KINDS else "interaction"
        point_attr = _str_attr(attrs, "fabric.capture.point")
        point = point_attr if point_attr and _POINT_RE.fullmatch(point_attr) else "sdk.records"
        point_id = point.split("@", 1)[0]
        ctx = self._context(key, first.source_sequence, point_id, kind, ("sdk.records",))
        provenance = _str_attr(attrs, "fabric.capture.source")
        provenance = provenance if provenance in ("observed", "reported") else "reported"
        logical = _str_attr(attrs, "fabric.step.id")
        step_id = (_bounded(f"records:{first.source_id}:{logical}") if logical is not None
                   else attempt_uid)  # fmt: skip
        step: dict[str, Any] = {"attempt_id": attempt_uid, "step_id": step_id,
                                "step_kind": kind, "run_id": self.run_id}  # fmt: skip
        parent = _str_attr(attrs, "fabric.step.parent_id")
        if parent is not None:
            step["parent_step_id"] = _bounded(f"records:{first.source_id}:{parent}")
        elif first.scope_id is not None and first.scope_id in self.scope_steps:
            step["parent_step_id"] = self.scope_steps[first.scope_id]
        if first.scope_id is not None:
            step["scope_id"] = first.scope_id
        aliases = self._record_aliases(first.source_id, attrs, first_span)
        if aliases:
            step["aliases"] = aliases
        step["source"] = self._source("records", key, first.source_sequence, ctx.manifest)
        event_ids = list(dict.fromkeys(obs.event_id for obs, _ in records))
        step["event_ids"] = event_ids[:MAX_EVENT_IDS]
        step["capture_point"] = point
        step["provenance"] = provenance
        step["actor"] = {"type": _actor(attrs)}
        step["timing"] = {
            "started_at_ns": min(span.start_ns for _, span in records),
            "ended_at_ns": max(max(span.end_ns, span.start_ns) for _, span in records),
            "basis": "reported" if provenance == "reported" else "measured",
            "clock_domain": "wall_utc",
        }
        lifecycle, result = _record_outcome(last_attrs)
        step["lifecycle_state"], step["result_status"] = lifecycle, result
        if first.segment_id is not None:
            step["segment_id"] = first.segment_id
        fields = _Fields()
        self._record_fields(fields, step, records, ctx)
        flags = ["timed", *self._segment_flag(step)]
        if result == "error":
            flags.append("on_error")
        self._note_attempt(attempt_uid, step_id, first_span)
        self._finish(step, fields, ctx, flags)

    def _note_attempt(self, attempt_uid: str, step_id: str, span: SpanRecord) -> None:
        self.record_steps[attempt_uid] = step_id
        self.record_attempts.add(attempt_uid)
        if _TRACE_RE.fullmatch(span.trace_id) and span.trace_id != "0" * 32:
            self.traces[attempt_uid] = span.trace_id

    @staticmethod
    def _record_aliases(
        source_id: str, attrs: Mapping[str, Any], span: SpanRecord
    ) -> dict[str, str]:
        out: dict[str, str] = {}
        for alias, key in (("records.step_id", "fabric.step.id"),
                           ("records.step_attempt_id", "fabric.step.attempt_id")):  # fmt: skip
            value = _str_attr(attrs, key)
            if value is not None:
                out[alias] = _bounded(f"{source_id}/{value}")
        if span.span_id:
            out["records.span_id"] = _bounded(f"{source_id}/{span.span_id}")
        return out

    def _record_fields(
        self, fields: _Fields, step: Mapping[str, Any],
        records: Sequence[tuple[RecordObs, SpanRecord]], ctx: _StepContext,
    ) -> None:  # fmt: skip
        point, provenance = step["capture_point"], step["provenance"]
        self_point = _manifest_point(ctx.manifest, "fabric.self")
        total = len({obs.event_id for obs, _ in records})
        fields.put("event_id", wrapper(
            "captured", provenance="observed", point=self_point, value=step["event_ids"],
            collection={"completeness": "complete" if total <= MAX_EVENT_IDS else "partial",
                        "observed_count": total},
        ))  # fmt: skip
        last = records[-1][1].attributes
        for key, value in (
            ("step.kind", step["step_kind"]), ("actor.type", step["actor"]["type"]),
            ("lifecycle.state", step["lifecycle_state"]), ("result_status", step["result_status"]),
            ("error.domain", _str_attr(last, "fabric.error.domain")),
        ):  # fmt: skip
            if value is None or value == "unknown":
                continue  # no value: the manifest decides
            fields.put(key, wrapper("captured", provenance=provenance, point=point, value=value))
        if step["lifecycle_state"] in ("queued", "running", "suspended"):
            # 049 §6.3: no end observed, so no outcome (never the caller's omission).
            fields.put("result_status", wrapper("unknown", provenance=provenance, point=point))
        object_ids = [oid for _, span in records
                      for oid in _object_ids(span.attributes)]  # fmt: skip
        if object_ids:
            listed = len(object_ids) <= _VALUE_MAX
            fields.put("content_object_ids", wrapper(
                "captured", provenance="observed", point=self_point, value=object_ids,
                collection=None if listed else {"completeness": "partial",
                                                "observed_count": len(object_ids)},
            ))  # fmt: skip
        identity_mode = (ctx.manifest.document.get("identity_mode", "pseudonymous")
                         if ctx.manifest is not None else "pseudonymous")  # fmt: skip
        _RecordBodies(self.verifier, fields, point, provenance, str(identity_mode)).add(records)

    # -- wire exchanges -----------------------------------------------------------

    def _wire_step(self, entry: Mapping[str, Any]) -> None:
        data = self.collector.exchanges.get(entry["exchange_id"])
        if data is None:
            return
        _WireStep(self, entry, data).build()

    def parent_of_span(self, source_id: str, parent_span_id: str | None) -> str | None:
        """The step whose record span is ``parent_span_id`` (its ``records.span_id``)."""
        if parent_span_id is None:
            return None
        attempt = self.collector.records_by_span.get((source_id, parent_span_id))
        return None if attempt is None else self.record_steps.get(attempt)


_Window = tuple[tuple[str, int], int, int | None, tuple[int, int]]


def _end(window: _Window) -> int:
    return (1 << 63) if window[2] is None else window[2]


def _contains(outer: _Window, inner: _Window) -> bool:
    """``outer``'s scope window holds ``inner``'s: same source, no later start, no earlier
    end, and on an identical window the earlier ``run_start`` (at one time, the one that
    opened the segment: an inner block's ``run_start`` names no predecessors)."""
    if outer[0] != inner[0] or outer[1] > inner[1] or _end(outer) < _end(inner):
        return False
    if (outer[1], _end(outer)) == (inner[1], _end(inner)):
        return outer[3] < inner[3]
    return True


def run_scopes(run: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """The report run's scopes, by source window start."""
    return sorted(run.get("scopes", ()), key=lambda s: (s.get("source_id", ""),
                                                        s.get("source_epoch", 0),
                                                        s.get("start_sequence", -1),
                                                        s["scope_id"]))  # fmt: skip


def _object_ids(attrs: Mapping[str, Any]) -> list[str]:
    ids = attrs.get("fabric.content.object_ids")
    if not isinstance(ids, list):
        return []
    return [oid for oid in ids if isinstance(oid, str) and _UUID4.fullmatch(oid)][:8]


def _record_outcome(attrs: Mapping[str, Any]) -> tuple[str, str]:
    """Lifecycle and result of an attempt from its last record (049 §2.3): a missing end is
    never an outcome (``running``/``unknown``)."""
    lifecycle = _str_attr(attrs, "fabric.step.lifecycle_state")
    result = _str_attr(attrs, "fabric.step.status")
    lifecycle = lifecycle if lifecycle in _LIFECYCLES else "unknown"
    result = result if result in _RESULTS else "unknown"
    if lifecycle in ("queued", "running", "suspended", "unknown"):
        result = "unknown"  # a start without an end is never an outcome
    return lifecycle, result


# --------------------------------------------------------------------------
# Records bodies and evidence objects
# --------------------------------------------------------------------------


class _RecordBodies:
    """Projects a records attempt's content objects (by role) and decodes its evidence
    objects, reading descriptors and evidence bytes from the verifier's store (R9: an
    evidence object over 1 MiB is never read)."""

    def __init__(
        self, verifier: Any, fields: _Fields, point: str, provenance: str, identity_mode: str
    ) -> None:
        self.store = verifier.store
        self.tenant = getattr(verifier.reader, "tenant_id", None)
        self.fields = fields
        self.point = point
        self.provenance = provenance
        self.identity_mode = identity_mode
        self.by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.evidence: list[EvidenceDecode] = []

    def add(self, records: Sequence[tuple[RecordObs, SpanRecord]]) -> None:
        for _, span in records:
            for object_id in _object_ids(span.attributes):
                self._object(object_id)
        for key, wrappers in self.by_key.items():
            self.fields.put(key, _merge(wrappers))
        self._evidence_fields()

    def _descriptor(self, object_id: str) -> Mapping[str, Any] | None:
        if self.store is None:
            return None
        try:
            descriptor = self.store.read_descriptor(self.store.evidence_ref_for(object_id))
        except ImportError:
            raise
        except Exception:
            return None
        if (
            not isinstance(descriptor, Mapping) or descriptor.get("object_id") != object_id
            or descriptor.get("tenant_id") != self.tenant
        ):  # fmt: skip
            return None
        return descriptor

    def _object(self, object_id: str) -> None:
        descriptor = self._descriptor(object_id)
        if descriptor is None:
            return
        role = descriptor.get("role")
        if role == "record.evidence":
            self._evidence_object(object_id, descriptor)
            return
        key = ROLE_FIELDS.get(str(role))
        if key is None:
            return
        self.by_key[key].append(
            object_wrapper(
                descriptor, object_id, str(role), provenance=self.provenance, point=self.point
            )
        )

    def _evidence_object(self, object_id: str, descriptor: Mapping[str, Any]) -> None:
        stored = descriptor.get("stored_sha256")
        length = descriptor.get("stored_byte_length")
        if descriptor.get("status") != "stored" or not isinstance(stored, str):
            return  # a descriptor-only evidence object: its fields stay manifest-driven
        if not isinstance(length, int) or length > _EVIDENCE_MAX_BYTES:
            self.evidence.append(EvidenceDecode("parse_failed"))
            return
        try:
            data = self.store.read(str(self.store.evidence_ref_for(object_id)))
        except ImportError:
            raise
        except Exception:
            return
        if not isinstance(data, bytes | bytearray) or len(data) > _EVIDENCE_MAX_BYTES:
            self.evidence.append(EvidenceDecode("parse_failed"))
            return
        if "sha256:" + hashlib.sha256(bytes(data)).hexdigest() != stored:
            return
        self.evidence.append(decode_evidence(
            bytes(data), evidence_types=EVIDENCE_TYPES, provenance=self.provenance,
            capture_point=self.point, identity_mode=self.identity_mode,
        ))  # fmt: skip

    def _evidence_fields(self) -> None:
        """Every decoded object's fields, merged over the attempt's records in order; a
        windowed producer's ``continuation`` indexes give each field its ``collection``."""
        merged: dict[str, tuple[str, list[Any], bool]] = {}
        windows: set[int] = set()
        final: int | None = None
        for decoded in self.evidence:
            if decoded.continuation is not None:
                windows.add(decoded.continuation[0])
                if decoded.continuation[1]:
                    final = decoded.continuation[0]
            for name, value in decoded.fields.items():
                layer, values, failed = merged.get(name, (name.split(".", 1)[0], [], False))
                values.extend(value.value or [])
                merged[name] = (layer, values, failed or value.status != "captured")
        for name, (layer, values, failed) in merged.items():
            key = name.split(".", 1)[1]
            collection: dict[str, Any] | None = None
            complete = len(values) <= _VALUE_MAX
            if windows:
                expected = None if final is None else final + 1
                complete = complete and expected == len(windows) == max(windows) + 1
                collection = {"completeness": "complete" if complete else "partial",
                              "observed_count": len(windows)}  # fmt: skip
                if expected is not None:
                    collection["expected_count"] = expected
            elif not complete:
                collection = {"completeness": "partial", "observed_count": len(values)}
            status = ("not_captured", "parse_failed") if failed else ("captured", None)
            self.fields.put(key, wrapper(status[0], provenance=self.provenance, point=self.point,
                                         reason=status[1], value=values,
                                         collection=collection), layer)  # fmt: skip


def _merge(wrappers: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """One field from several objects of one role: their locators when every one is
    captured, else the first that is not."""
    for item in wrappers:
        if item["status"] != "captured":
            return item
    refs = [item["ref"] for item in wrappers if "ref" in item]
    merged = dict(wrappers[0])
    merged.pop("ref", None)
    if len(refs) == 1:
        merged["ref"] = refs[0]
    elif refs:
        merged["refs"] = refs
    return merged


def object_wrapper(  # noqa: PLR0911 - one return per content-v2 status
    descriptor: Mapping[str, Any], object_id: str, role: str, *, provenance: str, point: str
) -> dict[str, Any]:
    """A content object's coverage status (049 §2.6 mapping from content-v2 statuses)."""
    status = descriptor.get("status")
    reason = descriptor.get("status_reason")
    stored = descriptor.get("stored_sha256")
    ref: dict[str, Any] = {"object_id": object_id, "role": role}
    if isinstance(stored, str):
        ref["sha256"] = stored
    if not _ROLE_RE.fullmatch(role):
        ref = {}
    refs = (ref,) if ref else ()
    if status == "stored":
        protection = descriptor.get("protection_status")
        if protection in ("redacted", "tokenized"):
            return wrapper("redacted", provenance=provenance, point=point,
                           reason="privacy_policy", refs=refs)  # fmt: skip
        if protection == "withheld":
            return wrapper("not_captured", provenance=provenance, point=point,
                           reason="privacy_policy")  # fmt: skip
        return wrapper("captured", provenance=provenance, point=point, refs=refs)
    if status == "truncated":
        return wrapper("truncated", provenance=provenance, point=point, reason="body_cap",
                       refs=refs)  # fmt: skip
    if status == "redacted":
        return wrapper("redacted", provenance=provenance, point=point, reason="privacy_policy")
    if isinstance(reason, str) and reason in _DESCRIPTOR_REASONS:
        mapped, mapped_reason = _DESCRIPTOR_REASONS[reason]
        return wrapper(mapped, provenance=provenance, point=point, reason=mapped_reason)
    if status == "unsupported":
        return wrapper("unsupported", provenance=provenance, point=point,
                       reason=reason if reason in REASONS else "unsupported_api")  # fmt: skip
    return wrapper("not_captured", provenance=provenance, point=point,
                   reason=reason if reason in REASONS else "store_failed")  # fmt: skip


# --------------------------------------------------------------------------
# A wire exchange and the steps parsed from it
# --------------------------------------------------------------------------


def _side_status(
    result: ObjectResult | None, obs: ExchangeObs, store_reason: str
) -> tuple[str, str | None]:
    """A side's N01 status when its bytes are not ``verified``: the store reason when
    content is not recorded by configuration; ``unknown`` when the verifier was given no
    store; a response the exchange never received is ``transport_incomplete``."""
    if obs.store_status == "disabled":
        return "not_captured", store_reason
    if result is None:  # only the response side is ever absent
        received = obs.response_state in ("complete", "closed_early", "abandoned")
        if received or obs.http_status is not None:
            return "not_captured", "store_failed"
        return "not_captured", "transport_incomplete"
    if result.verification == "not_checked":
        return "unknown", None  # the verifier was given no store: nothing is established
    return "not_captured", "store_failed"


class _WireStep:
    def __init__(self, steps: _RunSteps, entry: Mapping[str, Any], data: _Exchange) -> None:
        self.steps = steps
        self.entry = entry
        self.data = data
        self.obs = data.obs
        self.attrs: Mapping[str, Any] = data.span.attributes if data.span is not None else {}
        self.fields = _Fields()
        self.point = "wire.py.httpx"
        self.span_model: str | None = None
        self.model: ModelFields | None = None

    def build(self) -> None:
        obs, attrs = self.obs, self.attrs
        attempt_id, derived = _uuid_or_derived(
            obs.exchange_id, f"wire:{obs.source_id}/{obs.exchange_id}"
        )
        kind = "embedding" if obs.api == "openai.embeddings" else "model_call"
        point_attr = _str_attr(attrs, "fabric.capture.point")
        point_id = point_attr.split("@", 1)[0] if point_attr else "wire.py.httpx"
        ctx = self.steps._context(
            obs.source,
            obs.source_sequence,
            point_id,
            kind,
            ("reconstruct.parse", "reconstruct.infer"),
        )
        point = point_attr if point_attr and _POINT_RE.fullmatch(point_attr) else (
            _manifest_point(ctx.manifest, point_id))  # fmt: skip
        provenance = _str_attr(attrs, "fabric.capture.source")
        provenance = provenance if provenance in ("observed", "reported") else "observed"
        event = _str_attr(attrs, "fabric.event_id")
        event_ids = [event] if event is not None and _UUID4.fullmatch(event) else [attempt_id]
        step: dict[str, Any] = {"attempt_id": attempt_id, "step_id": attempt_id,
                                "step_kind": kind, "run_id": self.steps.run_id}  # fmt: skip
        parent = self.steps.parent_of_span(obs.source_id, self._parent_span())
        if parent is None and obs.scope_id is not None:
            parent = self.steps.scope_steps.get(obs.scope_id)
        if parent is not None:
            step["parent_step_id"] = parent
        if obs.scope_id is not None:
            step["scope_id"] = obs.scope_id
        if obs.segment_id is not None:
            step["segment_id"] = obs.segment_id
        aliases: dict[str, str] = {}
        if obs.span_id is not None:
            aliases["wire.span_id"] = _bounded(f"{obs.source_id}/{obs.span_id}")
        if derived:
            aliases["wire.exchange_id"] = _bounded(f"{obs.source_id}/{obs.exchange_id}")
        if aliases:
            step["aliases"] = aliases
        step["source"] = self.steps._source("wire", obs.source, obs.source_sequence,
                                            ctx.manifest)  # fmt: skip
        step["event_ids"] = event_ids
        step["capture_point"] = self.point = point
        step["provenance"] = provenance
        step["actor"] = {"type": _actor(attrs)}
        step["timing"] = {"started_at_ns": obs.start_ns, "ended_at_ns": obs.end_ns,
                          "basis": "measured", "clock_domain": "wall_utc"}  # fmt: skip
        lifecycle, result = self._outcome()
        step["lifecycle_state"], step["result_status"] = lifecycle, result
        links = self._links()
        if links:
            step["links"] = links
        if event is None:
            self.fields.put("event_id", wrapper(
                "unsupported", provenance="observed", reason="unsupported_version",
                point=_manifest_point(ctx.manifest, "fabric.self")))  # fmt: skip
        flags = self._wire_fields(step, ctx)
        self.steps.exchange_steps[obs.exchange_id] = step
        if obs.trace_id is not None:
            self.steps.traces[attempt_id] = obs.trace_id
        self.steps._finish(step, self.fields, ctx, flags)
        self._children(step, ctx)
        self._inferred_inputs(step, ctx)

    def _parent_span(self) -> str | None:
        span = self.data.span
        return span.parent_span_id if span is not None else None

    def _outcome(self) -> tuple[str, str]:
        """Lifecycle and result: the span's S07/S08 (WP-14), else the legacy mapping (049
        §2.3): complete with HTTP 2xx -> ok, error -> error, closed_early -> cancelled,
        abandoned -> unknown."""
        attrs, obs = self.attrs, self.obs
        lifecycle = _str_attr(attrs, "fabric.step.lifecycle_state")
        result = _str_attr(attrs, "fabric.step.status")
        if lifecycle in _LIFECYCLES and result in _RESULTS:
            return str(lifecycle), str(result)
        status = obs.http_status
        if obs.response_state == "closed_early":
            return "cancelled", "cancelled"
        if obs.response_state == "error" or (status is not None and status >= _HTTP_ERROR):
            return "completed", "error"
        if obs.response_state == "complete" and status is not None and status >= _HTTP_OK:
            return "completed", "ok"
        return "completed", "unknown"

    def _links(self) -> list[dict[str, Any]]:
        links: list[dict[str, Any]] = []
        continued = self.entry.get("continues_exchange_id")
        if isinstance(continued, str):
            method = ("previous_response_id" if "previous_response_id" in self.entry
                      else "prefix_digest")  # fmt: skip
            links.append({"type": "continues",
                          "target": {"namespace": "exchange", "id": continued},
                          "provenance": "inferred", "method": method, "confidence": "certain",
                          "state": "resolved"})  # fmt: skip
        retried = self._retried()
        if retried is not None:
            links.append({"type": "retries",
                          "target": {"namespace": "attempt", "id": retried},
                          "provenance": "inferred", "method": "identical_request_after_error",
                          "confidence": "tentative", "state": "resolved"})  # fmt: skip
        return links

    def _retried(self) -> str | None:
        """S13 (049 §2.5): the latest earlier exchange of the run with the same request
        digest that ended in an error."""
        obs = self.obs
        if obs.request_sha256 is None:
            return None
        for exchange_id in reversed(list(self.steps.exchange_steps)):
            earlier = self.steps.exchange_steps[exchange_id]
            data = self.steps.collector.exchanges.get(exchange_id)
            if data is None or data.obs.request_sha256 != obs.request_sha256:
                continue
            if earlier["result_status"] == "error":
                return str(earlier["attempt_id"])
            return None
        return None

    # -- fields -------------------------------------------------------------------

    def _store_reason(self) -> str:
        reason = _str_attr(self.attrs, "fabric.wire.store_reason")
        if reason == "no_store" or reason is None:
            return "not_configured"
        return reason if reason in REASONS else "not_configured"

    def _wire_fields(self, step: Mapping[str, Any], ctx: _StepContext) -> list[str]:
        point, provenance = step["capture_point"], step["provenance"]
        flags = ["timed", *self.steps._segment_flag(step)]
        if step["result_status"] == "error":
            flags.append("on_error")
        if self.obs.store_status != "stored":
            flags.append("not_stored")
            self.fields.put(
                "store_reason",
                wrapper("captured", provenance=provenance, point=point, value=self._store_reason()),
            )
        self._span_fields(point, provenance)
        sides = self._sides(point, provenance)
        if self._streamed():
            flags.append("streamed")
            self.fields.put(
                "stream.state",
                wrapper(
                    "captured", provenance=provenance, point=point, value=self.obs.response_state
                ),
            )
        if any(side is not None and side.split is not None for side in sides):
            flags.append("split")
        self._model_fields(step, ctx, sides)
        self._inferred_fields(step)
        return flags

    def _span_fields(self, point: str, provenance: str) -> None:
        attrs, put = self.attrs, self.fields.put
        allowlist = self.steps.verifier.allowlist
        provider = _str_attr(attrs, "gen_ai.provider.name")
        for key, value in (
            ("model.provider", provider), ("model.api", self.obs.api or None),
            ("model.endpoint_id", _str_attr(attrs, "fabric.wire.endpoint_id")),
            ("provider_request_id", _str_attr(attrs, "fabric.wire.provider_request_id")),
            ("stream.first_chunk_offset_ns",
             _int_attr(attrs, "fabric.wire.first_chunk_offset_ns")),
            ("lifecycle.state", _str_attr(attrs, "fabric.step.lifecycle_state")),
            ("result_status", _str_attr(attrs, "fabric.step.status")),
            ("error.domain", _str_attr(attrs, "fabric.error.domain")),
            ("error.type", _str_attr(attrs, "error.type")),
            ("step.kind", _str_attr(attrs, "fabric.step.kind")),
            ("actor.type", _str_attr(attrs, "fabric.actor.type")),
            ("session_id", _str_attr(attrs, "fabric.session_id")),
            ("user_id", _str_attr(attrs, "fabric.user_id")),
        ):  # fmt: skip
            if value is not None:
                put(key, wrapper("captured", provenance=provenance, point=point, value=value))
        for key in FIELD_ROWS["X05"].keys:
            value = _str_attr(attrs, f"fabric.{key}")
            if value is not None:
                put(key, wrapper("captured", provenance=provenance, point=point, value=value))
        lifecycle, result = self._outcome()
        if not self.fields.has("lifecycle.state"):
            put("lifecycle.state", wrapper("captured", provenance=provenance, point=point,
                                           value=lifecycle))  # fmt: skip
        if not self.fields.has("result_status") and result != "unknown":
            put("result_status", wrapper("captured", provenance=provenance, point=point,
                                         value=result))  # fmt: skip
        if self.obs.model is not None:
            self.span_model = (self.obs.model if HASHED_MODEL_RE.fullmatch(self.obs.model)
                               else expose_model(self.obs.model, allowlist))  # fmt: skip

    def _streamed(self) -> bool:
        response = self.data.response
        media = response.media_type if response is not None else None
        return isinstance(media, str) and media.split(";", 1)[0].strip() == "text/event-stream"

    def _sides(
        self, point: str, provenance: str
    ) -> tuple[ObjectResult | None, ObjectResult | None]:
        """N01: each side's object and its coverage status."""
        request, response = self.data.request, self.data.response
        reason = self._store_reason()
        for key, result, role, digest in (
            ("model.exchange.request", request, "model.exchange.request",
             self.obs.request_sha256),
            ("model.exchange.response", response, "model.exchange.response",
             self.obs.response_sha256),
        ):  # fmt: skip
            if result is not None and result.verification == "verified":
                ref = self._ref(result.object_id, role, digest)
                status, why = ("truncated", "body_cap") if result.truncated else ("captured", None)
                self.fields.put(key, wrapper(status, provenance=provenance, point=point,
                                             reason=why, refs=ref))  # fmt: skip
                continue
            status, why = _side_status(result, self.obs, reason)
            self.fields.put(key, wrapper(status, provenance=provenance, point=point, reason=why))
        return request, response

    @staticmethod
    def _ref(object_id: str | None, role: str, digest: str | None) -> tuple[dict[str, Any], ...]:
        if object_id is None or not _UUID4.fullmatch(object_id):
            return ()
        ref: dict[str, Any] = {"object_id": object_id, "role": role}
        if digest:
            ref["sha256"] = digest if digest.startswith("sha256:") else "sha256:" + digest
        return (ref,)

    def _side_objects(self) -> Mapping[str, tuple[str | None, str]]:
        request, response = self.data.request, self.data.response
        return {
            "request": (request.object_id if request is not None else None,
                        "model.exchange.request"),
            "response": (response.object_id if response is not None else None,
                         "model.exchange.response"),
        }  # fmt: skip

    def _locators(self, texts: Iterable[str]) -> list[dict[str, Any]]:
        """``request:<pointer>`` / ``response:<pointer>`` locators (``response:final...`` and
        ``response:event/<n>...`` address a stream's terminal document or a data event, kept
        verbatim) as schema locators into the side's stored object."""
        sides = self._side_objects()
        out: list[dict[str, Any]] = []
        for text in texts:
            side, _, pointer = text.partition(":")
            object_id, role = sides.get(side, (None, ""))
            if object_id is None or not _UUID4.fullmatch(object_id):
                continue
            locator: dict[str, Any] = {"object_id": object_id, "role": role}
            if pointer:
                locator["pointer"] = pointer[:_POINTER_MAX]
            out.append(locator)
        return out

    def _model_fields(
        self, step: Mapping[str, Any], ctx: _StepContext,
        sides: tuple[ObjectResult | None, ObjectResult | None],
    ) -> None:  # fmt: skip
        request, response = sides
        provenance = step["provenance"]
        model = self.model = self.data.model
        side_status = {
            "request": self._unavailable("model.exchange.request", request,
                                         self.data.request_parsed),
            "response": self._unavailable("model.exchange.response", response,
                                          self.data.response_parsed),
        }  # fmt: skip
        fields = dict(model.fields) if model is not None else {}
        for key in _ALL_FIELD_IDS:
            if key in _CHILD_FACT_KEYS or key == "usage" or key not in KEY_ROWS:
                continue
            side = "request" if key in _REQUEST_FIELDS else "response"
            value = fields.get(key)
            missing = side_status[side]
            if value is None or (
                missing is not None
                and value.status in ("absent", "not_captured")
                and not value.locators
            ):
                if missing is None:
                    continue
                status, reason = missing
                self.fields.put(key, wrapper(status, provenance=provenance, point=_PARSE,
                                             reason=reason))  # fmt: skip
                continue
            self._model_field(key, value, side, provenance)
        self._served(provenance)

    def _unavailable(
        self, key: str, result: ObjectResult | None, parsed: bool
    ) -> tuple[str, str | None] | None:
        """Why a side's model-call fields cannot be parsed (049 §6.3), ``None`` when its
        bytes are verified: a truncated side's fields are ``truncated(body_cap)``."""
        if parsed:
            return ("truncated", "body_cap") if result is not None and result.truncated else None
        status = self.fields.get(key)
        if status is None:
            return "unknown", None
        return status["status"], status.get("reason")

    def _model_field(self, key: str, value: FieldValue, side: str, provenance: str) -> None:
        origin = "provider" if key in _RESPONSE_FIELDS_ORIGIN else None
        status = value.status
        if status == "absent" and side == "request" and self._side_truncated(side):
            status = "truncated"
        reason = value.reason if status != "truncated" else "body_cap"
        shown: Any = value.value
        if key == "model.requested":
            shown = expose_model(value.value, self.steps.verifier.allowlist)
        if key == "context_dependencies":
            self._dependencies(value, provenance)
            return
        refs = self._locators(value.locators)
        if key in ("input.messages", "output.messages", "tools_offered", "instructions"):
            shown = _NO_VALUE
        self.fields.put(
            key,
            wrapper(
                status,
                provenance=provenance,
                point=_PARSE,
                reason=reason,
                value=shown,
                refs=refs,
                assertion_origin=origin,
            ),
        )

    def _side_truncated(self, side: str) -> bool:
        result = self.data.request if side == "request" else self.data.response
        return result is not None and result.truncated

    def _dependencies(self, value: FieldValue, provenance: str) -> None:
        """C39 (049 §6.3): ``resolved`` only when the named response is in the record, else
        ``unresolved`` and the field is ``not_captured(provider_held)``."""
        if value.status != "captured" or not isinstance(value.value, list):
            self.fields.put(
                "context_dependencies",
                wrapper(value.status, provenance=provenance, point=_PARSE, reason=value.reason),
            )
            return
        items: list[dict[str, Any]] = []
        unresolved = False
        for dependency in value.value[:4096]:
            resolution = dependency.get("resolution", "unknown")
            provider_id = dependency.get("provider_id")
            if (
                dependency.get("kind") == "previous_response_id"
                and provider_id in self.steps.builder.known_responses
            ):
                resolution = "resolved"
            unresolved = unresolved or resolution != "resolved"
            item = {"kind": wrapper("captured", provenance=provenance, point=_PARSE,
                                    value=dependency.get("kind")),
                    "resolution": wrapper("captured", provenance=provenance, point=_PARSE,
                                          value=resolution)}  # fmt: skip
            if isinstance(provider_id, str):
                item["provider_id"] = wrapper("captured", provenance=provenance, point=_PARSE,
                                              value=provider_id)  # fmt: skip
            items.append(item)
        status, reason = ("not_captured", "provider_held") if unresolved else ("captured", None)
        self.fields.put(
            "context_dependencies",
            wrapper(status, provenance=provenance, point=_PARSE, reason=reason, items=items),
        )

    def _served(self, provenance: str) -> None:
        """C37: the parsed response model and the span's (provider assertions); when both
        are present and differ, a ``conflict`` that keeps both and chooses neither."""
        parsed = self.fields.get("model.served")
        span_model = self.span_model
        allowlist = self.steps.verifier.allowlist
        if parsed is not None and parsed["status"] == "captured" and "value" in parsed:
            parsed["value"] = expose_model(parsed["value"], allowlist) or parsed["value"]
        if span_model is None:
            return
        if parsed is None or parsed["status"] != "captured":
            self.fields.put("model.served", wrapper(
                "captured", provenance=provenance, point=self.point,
                value=span_model, assertion_origin="provider"))  # fmt: skip
            return
        if parsed.get("value") != span_model:
            self.fields.put("model.served", wrapper(
                "conflict", provenance=provenance, point=_PARSE,
                evidence=[
                    {"capture_point": self.point, "provenance": provenance,
                     "assertion_origin": "provider", "value": span_model},
                    {"capture_point": _PARSE, "provenance": provenance,
                     "assertion_origin": "provider", "value": parsed.get("value")},
                ],
            ))  # fmt: skip

    def _inferred_fields(self, step: Mapping[str, Any]) -> None:
        """D17 (``prefix_break``, tentative), C23 (``tools_digest_change``, certain) and S13
        (``identical_request_after_error``, tentative)."""
        if self.obs.exchange_id in self.steps.prefix_breaks:
            self.fields.put("context.history_rewritten", wrapper(
                "captured", provenance="inferred", point=_INFER, value=True,
                method="prefix_break", confidence="tentative"))  # fmt: skip
        if any(link["type"] == "retries" for link in step.get("links", ())):
            self.fields.put("attempt.kind", wrapper(
                "captured", provenance="inferred", point=_INFER, value="retry",
                method="identical_request_after_error", confidence="tentative"))  # fmt: skip
        continued = self.entry.get("continues_exchange_id")
        earlier = self.steps.exchange_steps.get(continued) if isinstance(continued, str) else None
        mine = self.fields.get("tools_offered.digest")
        theirs = (earlier.get("layers", {}).get("context", {}).get("tools_offered.digest")
                  if earlier is not None else None)  # fmt: skip
        parsed = ("captured", "absent")
        if (
            mine is not None
            and theirs is not None
            and {mine["status"], theirs["status"]} <= set(parsed)
        ):
            self.fields.put("tools_changed", wrapper(
                "captured", provenance="inferred", point=_INFER,
                value=mine.get("value") != theirs.get("value"), method="tools_digest_change",
                confidence="certain"))  # fmt: skip

    # -- child and inferred steps ---------------------------------------------------

    def _children(self, parent: Mapping[str, Any], ctx: _StepContext) -> None:
        model = self.model
        if model is None:
            return
        subindex = 0
        for tool in model.provider_tools:
            subindex += 1
            self._child(parent, ctx, subindex, tool)
        for item in model.extension_items:
            subindex += 1
            self._extension(parent, ctx, subindex, item)

    @staticmethod
    def _child_step(
        parent: Mapping[str, Any], subindex: int, kind: str, locator: str
    ) -> dict[str, Any]:
        attempt_id = inferred_step_id(f"{parent['attempt_id']}#{locator}")
        step: dict[str, Any] = {
            "attempt_id": attempt_id, "step_id": attempt_id, "step_kind": kind,
            "run_id": parent["run_id"], "parent_step_id": parent["step_id"],
        }  # fmt: skip
        for key in ("scope_id", "segment_id"):
            if key in parent:
                step[key] = parent[key]
        step["source"] = dict(parent["source"], subindex=subindex)
        step["event_ids"] = list(parent["event_ids"])
        step["capture_point"] = _PARSE
        step["provenance"] = parent["provenance"]
        step["actor"] = {"type": "provider"}
        return step

    def _child(
        self, parent: Mapping[str, Any], ctx: _StepContext, subindex: int, tool: Mapping[str, Any]
    ) -> None:
        kind = _HOSTED_KINDS.get(str(tool.get("kind")), "provider_tool_call")
        pointer = str(tool.get("pointer", ""))
        step = self._child_step(parent, subindex, kind, pointer)
        lifecycle, result = _PROVIDER_TOOL_RESULTS.get(
            str(tool.get("status")), ("unknown", "unknown")
        )
        step["lifecycle_state"], step["result_status"] = lifecycle, result
        fields = _Fields()
        provenance = parent["provenance"]
        _outcome_fields(fields, lifecycle, result, provenance)
        refs = self._locators([pointer]) if pointer else []
        if kind == "ui_action":
            fields.put("computer.requested_action", wrapper(
                "captured" if refs else "unknown", provenance=provenance, point=_PARSE,
                refs=refs))  # fmt: skip
        else:
            fields.put(
                "tool.execution_side",
                wrapper("captured", provenance=provenance, point=_PARSE, value="provider"),
            )
            fields.put(
                "provider_tool.kind",
                wrapper(
                    "captured",
                    provenance=provenance,
                    point=_PARSE,
                    value=tool.get("kind"),
                    assertion_origin="provider",
                ),
            )
            fields.put(
                "provider_tool.status",
                wrapper(
                    "captured",
                    provenance=provenance,
                    point=_PARSE,
                    value=tool.get("status"),
                    assertion_origin="provider",
                ),
            )
            if refs:
                fields.put(
                    "provider_tool.inputs",
                    wrapper("captured", provenance=provenance, point=_PARSE, refs=refs),
                )
        flags = self.steps._segment_flag(step)
        self.steps._finish(step, fields, ctx, flags)

    def _extension(
        self, parent: Mapping[str, Any], ctx: _StepContext, subindex: int, item: FieldValue
    ) -> None:
        """An unknown provider item (049 §5 rule 6): an ``extension`` step, never coerced."""
        name = item.field_id
        if not _EXTENSION_RE.fullmatch(name):
            namespace = "anthropic" if self.obs.api.startswith("anthropic") else "openai"
            item_type = re.sub(r"[^a-z0-9_.]", "_", name.lower()).strip(".") or "item"
            name = f"x-{namespace}.{item_type}"[:96]
        namespace = name[2:].split(".", 1)[0]
        locator = item.locators[0] if item.locators else name
        step = self._child_step(parent, subindex, "extension", locator)
        step["step_kind_extension"] = name
        # The item's own semantics are unknown; its lifecycle is the response that carried it.
        lifecycle, result = parent["lifecycle_state"], parent["result_status"]
        step["lifecycle_state"], step["result_status"] = lifecycle, result
        fields = _Fields()
        _outcome_fields(fields, lifecycle, result, parent["provenance"])
        fields.put(
            f"x-{namespace}.result",
            wrapper(
                "unsupported",
                provenance=parent["provenance"],
                point=_PARSE,
                reason="unsupported_api",
                refs=self._locators(item.locators),
            ),
            "content",
        )
        flags = self.steps._segment_flag(step)
        self.steps._finish(step, fields, ctx, flags, {"content": [f"x-{namespace}.result"]})

    def _inferred_inputs(self, parent: Mapping[str, Any], ctx: _StepContext) -> None:
        """Inferred ``input`` steps (``new_user_message``, tentative): the user messages a
        request adds after the exchange it continues. Only when the request's messages and
        their digests align one to one; never from a stream or an unparsed exchange."""
        model = self.model
        view = self.data.view
        continued = self.entry.get("continues_exchange_id")
        if model is None or view is None or not view.parsed or not isinstance(continued, str):
            return
        messages = model.fields.get("input.messages")
        if messages is None or not isinstance(messages.value, list):
            return
        if "previous_response_id" in self.entry:
            prefix = 0
        else:
            earlier = self.steps.collector.exchanges.get(continued)
            if earlier is None or earlier.view is None or len(messages.value) != len(view.request):
                return
            prefix = len(earlier.view.continuation)
        for message in messages.value:
            if message.get("role") != "user" or message.get("index", -1) < prefix:
                continue
            locator = str(message.get("pointer", ""))
            self._inferred_input(parent, ctx, locator)

    def _inferred_input(self, parent: Mapping[str, Any], ctx: _StepContext, locator: str) -> None:
        attempt_id = inferred_step_id(f"{parent['attempt_id']}/{locator}")
        step: dict[str, Any] = {
            "attempt_id": attempt_id, "step_id": attempt_id, "step_kind": "input",
            "run_id": parent["run_id"], "parent_step_id": parent["step_id"],
            "event_ids": list(parent["event_ids"]), "capture_point": _INFER,
            "provenance": "inferred", "method": "new_user_message", "confidence": "tentative",
            "lifecycle_state": "completed", "result_status": "unknown",
            "links": [{"type": "derived_from",
                       "target": {"namespace": "exchange", "id": self.obs.exchange_id},
                       "provenance": "inferred", "method": "new_user_message",
                       "confidence": "tentative", "state": "resolved"}],
        }  # fmt: skip
        fields = _Fields()
        refs = self._locators([locator])
        provenance = parent["provenance"]
        fields.put(
            "input.payload",
            wrapper(
                "captured" if refs else "unknown", provenance=provenance, point=_PARSE, refs=refs
            ),
        )
        # The step's existence is tentative (its provenance, method and confidence say so);
        # its fields are classified normally (049 §6.2): the message is literally a user
        # message the request carried, and an input has no outcome of its own.
        step["actor"] = {"type": "user"}
        for key, value in (("step.kind", "input"), ("actor.type", "user"),
                           ("lifecycle.state", "completed")):  # fmt: skip
            fields.put(key, wrapper("captured", provenance=provenance, point=_PARSE, value=value))
        fields.put("result_status", wrapper("not_applicable", provenance=provenance,
                                            point=_PARSE))  # fmt: skip
        self.steps._finish(step, fields, ctx, ())


def _outcome_fields(fields: _Fields, lifecycle: str, result: str, provenance: str) -> None:
    """S07/S08 of a step parsed from a response: provider assertions; ``unknown`` (no
    value) when the response does not establish them."""
    for key, value in (("lifecycle.state", lifecycle), ("result_status", result)):
        if value == "unknown":
            fields.put(key, wrapper("unknown", provenance=provenance, point=_PARSE))
        else:
            fields.put(key, wrapper("captured", provenance=provenance, point=_PARSE, value=value,
                                    assertion_origin="provider"))  # fmt: skip


def _root_value(root: Mapping[str, Any], key: str) -> Any:
    """D30 ``run.outcome``/``run.stop_reason`` from the root scope's ``run_end``."""
    found = root.get("layers", {}).get("decisions_effects", {}).get(key)
    return found.get("value") if isinstance(found, Mapping) else None


__all__ = [
    "DEFAULT_COVERAGE_PROFILE",
    "FIELD_ROWS",
    "KEY_ROWS",
    "MAX_EVENT_IDS",
    "PROFILES",
    "PROJECTION_REVISION",
    "ROLE_FIELDS",
    "RUN_RULES",
    "SCHEMA_VERSION",
    "STEP_RULES",
    "FieldRow",
    "ProjectionCollector",
    "RunEval",
    "StepEval",
    "build_projection",
    "decide",
    "field_class",
    "inferred_step_id",
    "object_wrapper",
    "required_fields",
    "unobserved",
    "wrapper",
]  # fmt: skip
