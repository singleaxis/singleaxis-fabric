# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Content-Governance + GDPR Data-Subject-Request Agent — instrumented with SingleAxis Fabric.

Scenario
--------
A social platform runs an AI content-governance agent. Two things happen in
one operational "case":

1. **Moderation sweep.** A batch of three user-generated posts flows through
   the platform's moderation policy engine and a safety guardrail rail:
     * an egregious post (CSAM-adjacent solicitation) is **hard-blocked** at
       the guardrail and the policy engine **denies** it;
     * a borderline post (heated but not rule-breaking) gets a policy **warn**
       and a **synchronous human escalation** (a moderator blocks for a live
       verdict before the post is published);
     * a post carrying a user's email/phone PII is policy-**redacted** so the
       contact details are stripped before the post goes live.

2. **GDPR right-to-erasure.** A data-subject request comes in for a departed
   user: the agent emits an **erase** marker for that user's stored profile
   memory (``decision.forget(..., tenant_scope=...)``) and writes a fresh
   "erasure receipt" record that **invalidates** the old profile key
   (``decision.remember(..., invalidates=...)``) so the Decision Graph has a
   lineage edge from the superseded key to the receipt.

Crucially, the raw flagged post bodies and the raw moderation-policy inputs
never land on the trace stream. A **ContentStore** (the dual-pipeline) is
configured on the Fabric client, so ``guard_input`` and ``evaluate_policy``
stash the raw payload off-trace and stamp only a ``content_ref`` *locator URI*
(plus the SHA-256) onto the events. An auditor resolves the URI out-of-band;
the trace itself stays hash-only.

Everything here is *emit-only*: Fabric never runs the moderation engine, the
guardrail rail, or the erasure — the tenant agent does. Fabric records the
hash-only, allow-listed evidence as OpenTelemetry spans/events.

Fabric primitives demonstrated
------------------------------
* ``Fabric`` / ``FabricConfig`` (+ ``content_store=``)  — client wired to a
  dual-pipeline ``LocalFilesystemContentStore``
* ``Fabric.execution(...)`` / ``Fabric.decision(...)``   — case + turn spans
* ``decision.guard_input(...)``                          — guarded intake that
  stamps ``fabric.guardrail.content_ref`` (off-trace payload pointer)
* ``Fabric.guardrail_chain.check(...)`` + ``decision.record_block`` /
  ``raise_for_block``                                    — the canonical HARD
  guardrail block (the documented host pattern for obtaining the
  ``GuardrailResult`` to record)
* ``decision.evaluate_policy(...)``                      — the 5-value policy
  vocabulary exercised as **deny**, **warn**, and **redact**, each stamping
  ``fabric.policy.input_content_ref`` (off-trace payload pointer)
* ``decision.request_escalation(EscalationSummary(mode="sync"))`` +
  ``raise_for_escalation``                               — SYNCHRONOUS human-in-
  the-loop (moderator blocks for a verdict), distinct from async/deferred
* ``decision.forget(MemoryKind..., key, tenant_scope=...)`` — GDPR right-to-
  erasure marker (``fabric.memory.direction='erase'`` +
  ``fabric.memory_erase_count``)
* ``decision.remember(..., invalidates="old:key")``      — supersession lineage
  edge (``fabric.memory.invalidates``)

Telemetry shape (what the asserts verify)
-----------------------------------------
``fabric.execution`` / ``fabric.decision`` spans; span events
``fabric.guardrail`` (with ``fabric.guardrail.content_ref``),
``fabric.policy.evaluation`` (with ``fabric.policy.decision`` ∈
{deny,warn,redact} and ``fabric.policy.input_content_ref``),
``fabric.escalation`` (``mode='sync'``), ``fabric.memory``
(``direction='erase'`` with ``tenant_scope`` and ``direction='write'`` with
``invalidates``); decision-span attributes ``fabric.blocked``,
``fabric.escalated``, ``fabric.memory_erase_count``.

How to run
----------
    python3.13 -m venv .venv
    .venv/bin/pip install -e path/to/singleaxis-fabric/sdk/python
    .venv/bin/python content_governance_agent.py

Runs fully OFFLINE: a deterministic stub LLM, an in-process safety rail, an
in-process moderation engine, and a real ``LocalFilesystemContentStore`` rooted
at a temp dir — no API key, no sidecar, no network. It prints the captured
audit trail and asserts the emitted telemetry is correct (the asserts ARE the
test). A real OpenAI-compatible provider hook is documented in ``classify``'s
sibling ``call_llm`` (set ``FABRIC_EXAMPLE_USE_REAL_LLM=1`` +
``FABRIC_EXAMPLE_LLM_API_KEY``); the offline path is the committed one.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import textwrap

from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from fabric import (
    CheckerVerdict,
    EngineVerdict,
    EscalationRequested,
    EscalationSummary,
    Fabric,
    FabricConfig,
    GuardrailBlocked,
    LocalFilesystemContentStore,
    MemoryKind,
    install_default_provider,
)

# ---------------------------------------------------------------------------
# Tenant-side stubs. These stand in for systems the platform already runs (a
# safety classifier rail, a moderation policy engine). Fabric does NOT ship
# these — it only records the evidence they produce.
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_PHONE_RE = re.compile(r"\b(?:\+?\d[\d -]{7,}\d)\b")

# Deterministic markers that route each post to its archetype outcome. In a
# real deployment these are a classifier's labels, not substring matches.
_EGREGIOUS_MARKER = "[[egregious]]"
_BORDERLINE_MARKER = "[[borderline]]"


class SafetyRailChecker:
    """A minimal :class:`fabric.GuardrailChecker` — the platform's safety rail.

    Real deployments wire Lakera / NeMo over a Unix-domain socket via
    ``Fabric.from_env()``. For a sidecar-free, offline example we implement the
    same protocol (``name`` / ``check`` -> ``CheckerVerdict`` / ``close``)
    directly. It HARD-BLOCKS egregious solicitation and otherwise allows
    (PII handling here is the *policy* engine's job, shown separately).
    """

    name = "platform-safety-rail"

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        if _EGREGIOUS_MARKER in value:
            return CheckerVerdict(
                action="block",
                reason="csam_solicitation",
                rail="child_safety",
            )
        return CheckerVerdict(action="allow")

    def close(self) -> None:  # pragma: no cover - nothing to release
        pass


class ModerationPolicyEngine:
    """Stand-in :class:`fabric.PolicyEngine` for the content-moderation policy.

    Mirrors how a tenant wraps OPA / Cedar / an internal trust-and-safety
    service. Returns the 5-value ``PolicyDecision`` vocabulary; every non-allow
    verdict carries a reason (required by the contract). Drives three outcomes:

        * egregious post   -> ``deny``   (rule violation)
        * borderline post  -> ``warn``   (publish, but flag for review)
        * PII-bearing post -> ``redact`` (strip contact details, then publish)
    """

    engine_name = "content-moderation-v4"

    def evaluate(
        self, *, policy_id: str, input: dict[str, object], timeout_seconds: float
    ):
        body = str(input.get("post_body", ""))
        if _EGREGIOUS_MARKER in body:
            return EngineVerdict(
                decision="deny",
                policy_version="2026-05-20",
                reason="violates_child_safety_policy",
            )
        if _BORDERLINE_MARKER in body:
            return EngineVerdict(
                decision="warn",
                policy_version="2026-05-20",
                reason="heated_tone_borderline_harassment",
            )
        if _EMAIL_RE.search(body) or _PHONE_RE.search(body):
            return EngineVerdict(
                decision="redact",
                policy_version="2026-05-20",
                reason="contact_pii_must_be_stripped_before_publish",
            )
        return EngineVerdict(
            decision="allow",
            policy_version="2026-05-20",
            reason="clean",
        )

    def close(self) -> None:  # pragma: no cover
        pass


# ---------------------------------------------------------------------------
# LLM call. Deterministic STUB by default so the example runs offline with no
# API key. The real-provider path is documented and gated behind an env var.
# (The agent uses an LLM to draft the moderator-facing rationale; the verdicts
# themselves come from the deterministic policy engine, so the asserts are
# stable regardless of which LLM path runs.)
# ---------------------------------------------------------------------------


def call_llm(*, system: str, user: str, model: str) -> dict[str, object]:
    """Return an assistant rationale plus token usage.

    Offline default: a deterministic stub. Real provider (OpenAI-compatible,
    e.g. Fireworks): set ``FABRIC_EXAMPLE_USE_REAL_LLM=1`` and
    ``FABRIC_EXAMPLE_LLM_API_KEY``. Build CLEAN message dicts (role + content
    only) — some gateways reject echoed refusal/annotations/audio fields::

        from openai import OpenAI
        client = OpenAI(
            base_url="https://api.fireworks.ai/inference/v1",
            api_key=os.environ["FABRIC_EXAMPLE_LLM_API_KEY"],
        )
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        msg = resp.choices[0].message
        return {"content": msg.content,
                "input_tokens": resp.usage.prompt_tokens,
                "output_tokens": resp.usage.completion_tokens}
    """
    if os.environ.get("FABRIC_EXAMPLE_USE_REAL_LLM") == "1":  # pragma: no cover
        from openai import OpenAI  # imported lazily; not a hard dependency

        client = OpenAI(
            base_url=os.environ.get(
                "FABRIC_EXAMPLE_LLM_BASE_URL",
                "https://api.fireworks.ai/inference/v1",
            ),
            api_key=os.environ["FABRIC_EXAMPLE_LLM_API_KEY"],
        )
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        usage = resp.usage
        return {
            "content": resp.choices[0].message.content or "",
            "input_tokens": usage.prompt_tokens,
            "output_tokens": usage.completion_tokens,
        }

    # --- deterministic offline stub -------------------------------------
    return {
        "content": "Rationale drafted for moderator review.",
        "input_tokens": 64,
        "output_tokens": 18,
    }


# ---------------------------------------------------------------------------
# The instrumented workflow.
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are a content-moderation assistant. Draft a concise moderator rationale."
)
MODEL = os.environ.get("FABRIC_EXAMPLE_MODEL", "accounts/fireworks/models/kimi-k2p6")


def moderate_post(
    fab: Fabric,
    *,
    raw_post_body: str,
    post_id: str,
    author_id: str,
    session_id: str,
) -> dict[str, object]:
    """Moderate ONE user-generated post end-to-end, fully instrumented.

    Opens a ``fabric.decision`` inside the active ``fabric.execution`` so the
    whole governance case correlates. Returns a small outcome dict for the
    printed summary.
    """
    with fab.decision(
        session_id=session_id,
        request_id=f"req-{post_id}",
        user_id=author_id,
        attributes={"fabric.example.post_id": post_id},
    ) as decision:
        outcome: dict[str, object] = {
            "decision_id": decision.decision_id,
            "post_id": post_id,
        }

        # 1) GUARDED INTAKE -----------------------------------------------
        # guard_input runs the safety rail and (because a ContentStore is
        # configured on the client) stashes the raw post body off-trace and
        # stamps fabric.guardrail.content_ref. We capture the redacted string.
        safe_body = decision.guard_input(raw_post_body)

        # 1b) HARD GUARDRAIL BLOCK ----------------------------------------
        # guard_input only returns the redacted string. To obtain the
        # GuardrailResult needed for the canonical record_block, run the
        # configured chain directly — the documented host pattern — then
        # record it as THE block for this decision and abort via the
        # exception-style flow.
        chain_result = fab.guardrail_chain.check(
            phase="input", path="input", value=raw_post_body
        )
        if chain_result.blocked:
            decision.record_block(chain_result)
            # Still run the moderation policy so the audit trail shows the
            # engine's matching 'deny' verdict alongside the rail block.
            _evaluate(decision, post_id, raw_post_body)
            outcome["status"] = "blocked"
            outcome["policies_fired"] = chain_result.policies_fired
            try:
                decision.raise_for_block()
            except GuardrailBlocked as blocked:
                outcome["block_response"] = blocked.result.block_response
            return outcome

        # 2) MODERATION POLICY --------------------------------------------
        # The 5-value verdict drives flow. evaluate_policy also stashes the
        # raw serialized input off-trace and stamps
        # fabric.policy.input_content_ref.
        evaluation = _evaluate(decision, post_id, raw_post_body)
        outcome["policy_decision"] = evaluation.decision

        # 3) DRAFT A MODERATOR RATIONALE (LLM) ----------------------------
        with decision.llm_call(
            system="openai-compatible",
            model=MODEL,
            temperature=0.0,
            step_id="draft-rationale",
        ) as call:
            result = call_llm(system=SYSTEM_PROMPT, user=safe_body, model=MODEL)
            call.set_usage(
                input_tokens=int(result["input_tokens"]),
                output_tokens=int(result["output_tokens"]),
                finish_reason="stop",
            )
        outcome["rationale"] = str(result["content"])

        if evaluation.decision == "warn":
            # 4) SYNCHRONOUS ESCALATION -----------------------------------
            # Borderline content: a moderator must give a LIVE verdict before
            # the post publishes. mode="sync" means the human blocks the turn
            # (distinct from async/deferred review-after-the-fact). Record all
            # evidence first, then raise the flow-control signal.
            decision.request_escalation(
                EscalationSummary(
                    reason=evaluation.reason
                    or "borderline content needs a live moderator verdict",
                    rubric_id="borderline-harassment",
                    mode="sync",
                )
            )
            outcome["status"] = "escalated_sync"
            outcome["escalation_payload"] = decision.escalation.to_payload()
            decision.raise_for_escalation()
        elif evaluation.decision == "redact":
            # PII stripped by policy; the cleaned body publishes.
            published = _PHONE_RE.sub("<PHONE>", _EMAIL_RE.sub("<EMAIL>", safe_body))
            outcome["published_body"] = published
            outcome["status"] = "published_redacted"
        else:  # allow (none of the sample posts hit this branch)
            outcome["status"] = "published"
        return outcome


def _evaluate(decision, post_id: str, raw_post_body: str):
    """Run the moderation policy engine on a post (shared by block + normal paths)."""
    return decision.evaluate_policy(
        ModerationPolicyEngine(),
        policy_id="content-moderation",
        input={"post_id": post_id, "post_body": raw_post_body},
    )


def handle_erasure_request(
    fab: Fabric,
    *,
    subject_user_id: str,
    session_id: str,
) -> dict[str, object]:
    """Handle a GDPR right-to-erasure / data-subject request, instrumented.

    Emits an erase marker for the subject's stored profile memory and writes an
    erasure-receipt record that invalidates (supersedes) the old profile key.
    Fabric only emits these markers — the commercial Decision Graph acts on
    them and purges the referenced memory.
    """
    with fab.decision(
        session_id=session_id,
        request_id=f"dsr-{subject_user_id}",
        user_id=subject_user_id,
        attributes={"fabric.example.request_type": "gdpr_erasure"},
    ) as decision:
        old_key = f"profile:{subject_user_id}"

        # ERASE marker — tenant-wide right-to-erasure (purge everything for
        # this subject). Emits fabric.memory.direction='erase' + bumps
        # fabric.memory_erase_count; references a key, never content.
        decision.forget(
            MemoryKind.SEMANTIC,
            old_key,
            tenant_scope=True,
        )

        # SUPERSESSION — write an erasure receipt that invalidates the old
        # profile key, giving the Decision Graph a lineage edge.
        decision.remember(
            kind=MemoryKind.SEMANTIC,
            content=f"GDPR erasure executed for {subject_user_id} on 2026-06-01",
            key=f"erasure-receipt:{subject_user_id}",
            tags=["gdpr", "erasure", "receipt"],
            invalidates=old_key,
        )
        return {
            "decision_id": decision.decision_id,
            "status": "erased",
            "subject": subject_user_id,
            "invalidated_key": old_key,
        }


# ---------------------------------------------------------------------------
# Telemetry inspection helpers + assertions (the test).
# ---------------------------------------------------------------------------


def _span_by_name(spans: list[ReadableSpan], name: str) -> ReadableSpan:
    for span in spans:
        if span.name == name:
            return span
    raise AssertionError(f"no span named {name!r}; saw {[s.name for s in spans]}")


def _events(span: ReadableSpan, name: str):
    return [e for e in span.events if e.name == name]


def _event(span: ReadableSpan, name: str):
    evs = _events(span, name)
    if not evs:
        raise AssertionError(
            f"no event {name!r} on {span.name}; saw {[e.name for e in span.events]}"
        )
    return evs[0]


def print_audit_trail(spans: list[ReadableSpan]) -> None:
    """Pretty-print the captured Fabric telemetry — the audit trail."""
    print("=" * 78)
    print("CAPTURED FABRIC TELEMETRY  (the audit trail an auditor would read)")
    print("=" * 78)
    for span in spans:
        attrs = dict(span.attributes or {})
        print(f"\n[SPAN] {span.name}")
        for key in sorted(attrs):
            if key.startswith(("fabric.", "gen_ai.")):
                print(f"        {key} = {attrs[key]!r}")
        for event in span.events:
            ev = dict(event.attributes or {})
            highlights = {k: v for k, v in ev.items() if k != "fabric.schema_version"}
            shown = ", ".join(f"{k}={v!r}" for k, v in list(highlights.items())[:8])
            print(f"   - event: {event.name}  {{{shown}}}")
    print("\n" + "=" * 78)


def run_assertions(spans: list[ReadableSpan], content_root: str) -> None:
    """Assert the emitted spans/events are correct. These ARE the test."""
    # --- execution span correlates the case --------------------------------
    execution = _span_by_name(spans, "fabric.execution")
    assert execution.attributes["fabric.execution_id"] == "gov-case-5501"

    decisions = [
        s
        for s in spans
        if s.name == "fabric.decision"
        and s.attributes.get("fabric.execution_id") == "gov-case-5501"
    ]
    # three moderated posts + one GDPR erasure decision
    assert len(decisions) == 4, f"expected 4 decisions, got {len(decisions)}"

    # Classify the four decisions by their captured evidence.
    blocked = next(d for d in decisions if d.attributes.get("fabric.blocked"))
    escalated = next(d for d in decisions if d.attributes.get("fabric.escalated"))
    erasure = next(
        d for d in decisions if d.attributes.get("fabric.memory_erase_count")
    )
    redacted = next(
        d
        for d in decisions
        if d not in (blocked, escalated, erasure)
        and any(
            e.name == "fabric.policy.evaluation"
            and e.attributes["fabric.policy.decision"] == "redact"
            for e in d.events
        )
    )

    # --- every decision carries the canonical identity ---------------------
    for d in decisions:
        assert d.attributes["fabric.decision_id"], "decision span missing decision_id"
        assert d.attributes["fabric.tenant_id"] == "globochat"
        assert d.attributes["fabric.agent_id"] == "content-governance-agent"
        assert d.attributes["fabric.execution_id"] == "gov-case-5501"

    # === GAP 1: content_ref (dual-pipeline off-trace pointers) =============
    # guard_input stamped fabric.guardrail.content_ref on a guardrail event,
    # and evaluate_policy stamped fabric.policy.input_content_ref. Verify the
    # URIs point into the configured ContentStore root and resolve to bytes.
    guard_refs = [
        e.attributes.get("fabric.guardrail.content_ref")
        for d in decisions
        for e in _events(d, "fabric.guardrail")
        if e.attributes.get("fabric.guardrail.content_ref")
    ]
    assert guard_refs, "no fabric.guardrail.content_ref stamped"
    policy_refs = [
        e.attributes.get("fabric.policy.input_content_ref")
        for d in decisions
        for e in _events(d, "fabric.policy.evaluation")
        if e.attributes.get("fabric.policy.input_content_ref")
    ]
    assert policy_refs, "no fabric.policy.input_content_ref stamped"
    sample_ref = guard_refs[0]
    assert sample_ref.startswith("file://"), sample_ref
    # The URI resolves to a real off-trace file under the store root.
    resolved = sample_ref[len("file://") :]
    assert content_root in resolved, (resolved, content_root)
    with open(resolved, encoding="utf-8") as fh:
        assert fh.read(), "content_ref target is empty"

    # === GAP 3: HARD guardrail block ======================================
    guard_ev = _event(blocked, "fabric.guardrail")
    assert guard_ev.attributes["fabric.guardrail.phase"] == "input"
    # The rail also produced a content_ref on the block path.
    assert guard_ev.attributes.get("fabric.guardrail.content_ref", "").startswith(
        "file://"
    )
    assert blocked.attributes["fabric.blocked"] is True
    assert blocked.status.status_code.name == "ERROR"
    assert blocked.status.description == "guardrail_blocked"
    # === GAP 4a: policy DENY on the blocked post ==========================
    pd = _event(blocked, "fabric.policy.evaluation")
    assert pd.attributes["fabric.policy.decision"] == "deny"
    assert pd.attributes["fabric.policy.reason"] == "violates_child_safety_policy"
    assert pd.attributes["fabric.policy.engine"] == "content-moderation-v4"
    assert len(pd.attributes["fabric.policy.input_hash"]) == 64

    # === GAP 4b: policy WARN + GAP 5: SYNC escalation =====================
    pw = _event(escalated, "fabric.policy.evaluation")
    assert pw.attributes["fabric.policy.decision"] == "warn"
    assert pw.attributes["fabric.policy.reason"] == "heated_tone_borderline_harassment"
    esc = _event(escalated, "fabric.escalation")
    assert esc.attributes["fabric.escalation.mode"] == "sync", esc.attributes
    assert esc.attributes["fabric.escalation.rubric_id"] == "borderline-harassment"
    assert escalated.attributes["fabric.escalated"] is True
    assert escalated.status.description == "escalation_requested"

    # === GAP 4c: policy REDACT ============================================
    pr = _event(redacted, "fabric.policy.evaluation")
    assert pr.attributes["fabric.policy.decision"] == "redact"
    assert (
        pr.attributes["fabric.policy.reason"]
        == "contact_pii_must_be_stripped_before_publish"
    )

    # all three non-allow verdicts present across the case
    seen_decisions = {
        e.attributes["fabric.policy.decision"]
        for d in decisions
        for e in _events(d, "fabric.policy.evaluation")
    }
    assert {"deny", "warn", "redact"} <= seen_decisions, seen_decisions

    # === GAP 2: memory ERASE + INVALIDATE (GDPR) ==========================
    mem_evs = _events(erasure, "fabric.memory")
    erase_ev = next(
        e for e in mem_evs if e.attributes["fabric.memory.direction"] == "erase"
    )
    assert erase_ev.attributes["fabric.memory.tenant_scope"] is True
    assert erase_ev.attributes["fabric.memory.key"] == "profile:user-departed-88"
    assert erasure.attributes["fabric.memory_erase_count"] == 1
    # the erase marker references a key, never content (no hash on erase)
    assert "fabric.memory.content_hash" not in erase_ev.attributes
    write_ev = next(
        e for e in mem_evs if e.attributes["fabric.memory.direction"] == "write"
    )
    assert (
        write_ev.attributes["fabric.memory.invalidates"] == "profile:user-departed-88"
    )
    assert write_ev.attributes["fabric.memory.content_hash"], (
        "write should hash content"
    )

    print("ALL ASSERTIONS PASSED — the captured audit trail is correct.\n")


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def main() -> None:
    # 1) Install a real OTel provider with an in-memory exporter so the
    #    example reads back exactly what it emitted. SimpleSpanProcessor
    #    flushes on span end (no batching delay), so spans are readable
    #    immediately — install_default_provider wraps a BatchSpanProcessor,
    #    so we wire our own SimpleSpanProcessor for the in-memory exporter.
    exporter = InMemorySpanExporter()
    provider = install_default_provider(service_name="content-governance-agent")
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    # 2) Stand up a real dual-pipeline ContentStore rooted at a temp dir, and
    #    wire it onto the Fabric client. guard_input / evaluate_policy now
    #    stash raw payloads here and stamp content_ref URIs onto events; the
    #    trace stream itself stays hash-only.
    content_root = tempfile.mkdtemp(prefix="fabric-content-")
    content_store = LocalFilesystemContentStore(root=content_root)

    config = FabricConfig(tenant_id="globochat", agent_id="content-governance-agent")
    fab = Fabric(
        config,
        guardrail_checkers=[SafetyRailChecker()],
        content_store=content_store,
    )

    # 3) One execution ("case") spans the whole governance run: three moderated
    #    posts (deny+block / warn+sync-escalate / redact) and one GDPR erasure.
    out_blocked = out_escalated = out_redacted = out_erasure = None
    with fab.execution(execution_id="gov-case-5501"):
        # (a) Egregious post -> safety rail HARD BLOCK + policy DENY.
        out_blocked = moderate_post(
            fab,
            raw_post_body="Looking to meet minors privately, DM me [[egregious]]",
            post_id="post-9001",
            author_id="user-bad-1",
            session_id="sess-a",
        )

        # (b) Borderline post -> policy WARN + SYNCHRONOUS escalation.
        try:
            moderate_post(
                fab,
                raw_post_body="You people are pathetic and should be ashamed [[borderline]]",
                post_id="post-9002",
                author_id="user-heated-2",
                session_id="sess-b",
            )
            out_escalated = {"status": "escalated_sync"}
        except EscalationRequested as exc:
            # Host catches the flow-control signal and blocks for a live verdict.
            out_escalated = {"status": "escalated_sync", "reason": exc.summary.reason}

        # (c) PII-bearing post -> policy REDACT, then publish cleaned body.
        out_redacted = moderate_post(
            fab,
            raw_post_body="Contact me at jane.doe@example.com or +1 415 555 0100 for tickets",
            post_id="post-9003",
            author_id="user-seller-3",
            session_id="sess-c",
        )

        # (d) GDPR data-subject request -> erase marker + supersession edge.
        out_erasure = handle_erasure_request(
            fab,
            subject_user_id="user-departed-88",
            session_id="sess-dsr",
        )

    fab.close()

    # 4) Read back the captured spans and show + verify the audit trail.
    spans = list(exporter.get_finished_spans())
    print_audit_trail(spans)

    print("Outcomes:")
    print(f"  egregious post   -> {out_blocked['status']}  (rail+policy: deny)")
    print(f"  borderline post  -> {out_escalated['status']}  (sync human verdict)")
    print(f"  pii post         -> {out_redacted['status']}")
    print(textwrap.indent(json.dumps(out_erasure, indent=2, default=str), "  "))
    print(f"\n  content_ref store root: {content_root}\n")

    run_assertions(spans, content_root)


if __name__ == "__main__":
    main()
