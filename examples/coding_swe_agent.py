# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Instrumenting an enterprise Coding / SWE agent with SingleAxis Fabric.

Scenario
--------
A platform team runs an autonomous "fix-the-bug" SWE agent in CI. Given a
ticket ("the /health endpoint returns 500"), the agent runs the classic
plan -> act -> observe loop: it PLANS an approach with an LLM, then ACTS by
calling sandboxed tools (read_file, edit_file, run_tests), OBSERVES the
results, and finally proposes a patch. Because the agent edits source and
opens a pull request inside a regulated org, every step must be auditable:
which tools ran, which retries fired and why, which external mutations
(file writes, PR creation) happened, and whether a human approval gate was
crossed. This example wires that whole loop through Fabric's emit-only
telemetry primitives so the audit trail falls out for free.

Fabric primitives / attributes demonstrated
--------------------------------------------
* ``fabric.execution`` span (Fabric.execution) with attempt/retry metadata
  -> fabric.execution_id / workflow_id / execution.attempt / .status
* ``fabric.decision`` span (Fabric.decision) -> fabric.decision_id,
  fabric.execution_id (inherited), fabric.session_id, fabric.request_id
* ``decision.guard_input(...)`` via an in-process GuardrailChecker stub
  -> fabric.guardrail event (redacts a leaked secret before the LLM sees it)
* ``decision.record_retrieval(...)`` -> fabric.retrieval event (repo grep)
* ``decision.llm_call(...)`` with step_type="plan" / "synthesize"
  -> fabric.llm_call child span, fabric.step.type, gen_ai.* usage, cache,
     streaming and per-call retry attributes
* ``decision.authorize_tool_call(...)`` -> fabric.tool.authorization event
  (a deny-by-default authorizer blocks `rm -rf`, allows the safe tools)
* ``decision.tool_call(...)`` with step_type="act"/"observe" and step-level
  retry metadata -> fabric.tool_call child spans, fabric.step.*,
  fabric.tool.error / error_category, fabric.tool.retry.count, idempotency
* ``decision.evaluate_policy(...)`` -> fabric.policy.evaluation event
  (a change-management policy: edits to protected paths require approval)
* ``decision.record_side_effect(...)`` -> fabric.side_effect event with a
  parent_tool_call_id linking the mutation to the tool span that caused it
* ``decision.checkpoint(...)`` -> fabric.checkpoint event (rewind points)
* ``decision.remember(...)`` -> fabric.memory event (episodic run summary)
* ``decision.record_eval(...)`` -> fabric.eval event (inline patch grader)
* ``decision.queue_judge(...)`` -> fabric.judge.queued event (async review)
* ``decision.request_escalation(...)`` -> fabric.escalation event + attrs
  (protected-path edit -> human approval before the PR merges)
* ``decision.record_replay_metadata(...)`` -> fabric.replay envelope event

How to run
----------
    python3.13 -m venv /tmp/ex_coding_agent
    /tmp/ex_coding_agent/bin/pip install -e <repo>/sdk/python
    /tmp/ex_coding_agent/bin/python coding_swe_agent.py

The example is fully OFFLINE: the LLM is a deterministic stub, so no API
key is required. It installs its own OTel TracerProvider backed by an
``InMemorySpanExporter``, prints the captured audit trail, and asserts the
emitted spans/events are correct (the asserts ARE the test). To run it
against a real OpenAI-compatible provider, see ``call_llm`` below.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence

from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from fabric import (
    CheckerVerdict,
    EngineVerdict,
    EscalationSummary,
    Fabric,
    FabricConfig,
    JudgeContext,
    LocalQueueTransport,
    MemoryKind,
    ReplayBehavior,
    RetrievalSource,
    SideEffectType,
    ToolAuthorization,
    ToolErrorCategory,
    install_default_provider,
)

# --------------------------------------------------------------------------
# 1. A deterministic, offline LLM stub.
#
# `call_llm` returns canned plans/patches so the whole example runs with no
# network and no API key. The shape mirrors a real OpenAI-compatible
# response: text plus a usage dict. To prove real-world behavior, swap the
# body for the documented block below (kept commented so the COMMITTED file
# stays offline-runnable).
# --------------------------------------------------------------------------

_STUB_RESPONSES: dict[str, str] = {
    "plan": (
        "Plan: the /health 500 is a missing null-check in health.py. "
        "Steps: (1) grep for the handler, (2) read health.py, "
        "(3) add the guard, (4) run the health tests."
    ),
    "synthesize": (
        "--- a/app/health.py\n+++ b/app/health.py\n"
        "@@\n-    return db.ping().status\n"
        "+    conn = db.ping()\n+    return conn.status if conn else 'degraded'"
    ),
}


def call_llm(*, role: str, prompt: str) -> dict[str, object]:
    """Return a deterministic stub completion (offline default).

    Args:
        role: which logical step is calling ("plan" / "synthesize").
        prompt: the rendered prompt (unused by the stub; real providers
            would send it).

    Returns:
        An OpenAI-shaped dict: ``{"text": ..., "usage": {...},
        "finish_reason": ...}``.

    Real-provider hook (OpenAI-compatible, e.g. Fireworks / OpenAI / vLLM)::

        from openai import OpenAI
        client = OpenAI(base_url="https://api.fireworks.ai/inference/v1",
                        api_key="<key>")
        resp = client.chat.completions.create(
            model="accounts/fireworks/models/kimi-k2p6",
            messages=[{"role": "user", "content": prompt}],  # CLEAN dicts only
        )
        return {
            "text": resp.choices[0].message.content,
            "usage": {
                "input_tokens": resp.usage.prompt_tokens,
                "output_tokens": resp.usage.completion_tokens,
                "cache_read_tokens": getattr(
                    resp.usage, "prompt_tokens_details", None
                ) and resp.usage.prompt_tokens_details.cached_tokens or 0,
            },
            "finish_reason": resp.choices[0].finish_reason,
        }
    """
    text = _STUB_RESPONSES[role]
    return {
        "text": text,
        "usage": {
            "input_tokens": 220 + len(prompt) // 4,
            "output_tokens": len(text) // 4,
            # Prompt caching: the second LLM call reuses the cached system
            # prompt, so it reports cache-read tokens (a real cost signal).
            "cache_read_tokens": 180 if role == "synthesize" else 0,
        },
        "finish_reason": "stop",
    }


# --------------------------------------------------------------------------
# 2. In-process governance stubs (no sidecars required).
#
# These are tiny, deterministic implementations of Fabric's pluggable
# protocols so the example is self-contained. Production swaps in Presidio /
# NeMo guardrail sidecars, an OPA/Cedar policy engine, and a real tool
# authorizer — the agent code calling them does not change.
# --------------------------------------------------------------------------


class SecretRedactingChecker:
    """A GuardrailChecker that redacts leaked credentials from ticket text.

    A SWE ticket sometimes pastes a real token ("here's my AWS key
    AKIA..."). We must scrub it before it reaches the LLM or the trace.
    Implements the ``fabric.GuardrailChecker`` protocol: name + check + close.
    """

    name = "secret-redactor"

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        if "AKIA" in value:
            scrubbed = " ".join(
                "<REDACTED_AWS_KEY>" if tok.startswith("AKIA") else tok
                for tok in value.split()
            )
            return CheckerVerdict(
                action="redact",
                modified_value=scrubbed,
                reason="aws_access_key_id",
                rail="secret-scan",
            )
        return CheckerVerdict(action="allow")

    def close(self) -> None:  # protocol requires it; nothing to release
        return None


class ChangeManagementPolicy:
    """A PolicyEngine: edits to protected paths require human approval.

    Mirrors an OPA/Cedar adapter shape — receives a JSON input and returns
    an ``EngineVerdict``. Implements ``fabric.PolicyEngine``: engine_name +
    evaluate + close.
    """

    engine_name = "change-mgmt"
    _PROTECTED = ("app/health.py", "infra/", "auth/")

    def evaluate(
        self, *, policy_id: str, input: dict[str, object], timeout_seconds: float
    ) -> EngineVerdict:
        path = str(input.get("path", ""))
        if any(path.startswith(p) for p in self._PROTECTED):
            return EngineVerdict(
                decision="escalate",
                policy_version="2026.01",
                reason=f"{path} is a protected path; human approval required",
                evidence_ref="cab://policies/protected-paths",
            )
        return EngineVerdict(decision="allow", policy_version="2026.01")

    def close(self) -> None:
        return None


class SafeToolAuthorizer:
    """A ToolAuthorizer: deny-by-default for destructive shell commands.

    Implements ``fabric.ToolAuthorizer``: authorize(tool_name, arguments_hash).
    The agent calls this BEFORE executing any tool, so a model that asks to
    `rm -rf /` is stopped at the gate.
    """

    _ALLOWED = {"read_file", "edit_file", "run_tests", "open_pull_request"}

    def authorize(
        self, *, tool_name: str, arguments_hash: str | None
    ) -> ToolAuthorization:
        if tool_name in self._ALLOWED:
            return ToolAuthorization(decision="allow")
        return ToolAuthorization(
            decision="deny",
            reason=f"tool {tool_name!r} not on the SWE-agent allow-list",
        )


# --------------------------------------------------------------------------
# 3. The sandboxed "tools" the agent can call. These are fakes that return
#    deterministic results; one of them fails the first time to exercise
#    step-level retry + error categories.
# --------------------------------------------------------------------------

_HEALTH_SRC = "def health():\n    return db.ping().status\n"
_run_tests_attempts = {"n": 0}


def tool_read_file(path: str) -> str:
    """Fake file read."""
    return _HEALTH_SRC


def tool_edit_file(path: str, patch: str) -> str:
    """Fake file edit; returns the new file content hash-able as a string."""
    return _HEALTH_SRC + "\n# patched\n"


def tool_run_tests(suite: str) -> dict[str, object]:
    """Fake test runner. First call times out (flaky CI), retry succeeds."""
    _run_tests_attempts["n"] += 1
    if _run_tests_attempts["n"] == 1:
        raise TimeoutError("pytest worker timed out fetching deps")
    return {"passed": 7, "failed": 0, "suite": suite}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# 4. The instrumented agent run.
# --------------------------------------------------------------------------

SYSTEM_PROMPT = "You are a careful SWE agent. Propose minimal, tested patches."
MODEL = "accounts/fireworks/models/kimi-k2p6"


def run_swe_agent(fab: Fabric, *, ticket: str) -> None:
    """Run one plan -> act -> observe -> synthesize SWE-agent turn.

    Everything the agent does is wrapped in Fabric primitives so the
    emitted spans/events form a complete, hash-only audit trail.
    """
    judge_queue = LocalQueueTransport()
    policy_engine = ChangeManagementPolicy()
    authorizer = SafeToolAuthorizer()

    # An Execution correlates this whole CI run. attempt=2 models a retried
    # job (the previous attempt failed); decisions inside inherit the ids.
    with fab.execution(
        workflow_id="swe-autofix",
        execution_attempt=2,
        execution_retry_reason="previous_attempt_test_timeout",
        attributes={"ci.job": "autofix-1934", "repo": "acme/payments"},
    ) as execution:
        with fab.decision(
            session_id="ci-session-1934",
            request_id="req-autofix-1934",
            user_id="bot@acme.dev",
            attributes={"ticket.id": "BUG-5521"},
        ) as decision:
            # -- guard input: scrub any leaked secret from the ticket -----
            safe_ticket = decision.guard_input(ticket)

            # -- retrieval: grep the repo for the handler (RAG over code) --
            decision.record_retrieval(
                RetrievalSource.TOOL,
                query="grep -rn 'def health' app/",
                result_count=1,
                source_document_ids=["app/health.py"],
                latency_ms=12,
            )

            # -- PLAN step: ask the LLM for an approach -------------------
            plan_prompt = f"{SYSTEM_PROMPT}\n\nTicket: {safe_ticket}"
            with decision.llm_call(
                system="fireworks",
                model=MODEL,
                temperature=0.0,
                max_tokens=512,
                step_id="plan-1",
                step_type="plan",
            ) as call:
                resp = call_llm(role="plan", prompt=plan_prompt)
                usage = resp["usage"]
                assert isinstance(usage, dict)
                call.set_usage(
                    input_tokens=int(usage["input_tokens"]),
                    output_tokens=int(usage["output_tokens"]),
                    finish_reason=str(resp["finish_reason"]),
                )
                call.set_response_model(MODEL)

            decision.checkpoint("after-plan", state_hash=_sha(str(resp["text"])))

            # -- ACT step 1: read the target file -------------------------
            # Authorize first (pre-execution gate), then run the tool.
            auth = decision.authorize_tool_call(
                authorizer, tool_name="read_file", arguments="app/health.py"
            )
            auth.raise_for_denied()  # allowed: no-op
            with decision.tool_call(
                "read_file", step_id="act-read", step_type="act"
            ) as tool:
                tool.set_kind("function")
                tool.set_arguments(json.dumps({"path": "app/health.py"}))
                src = tool_read_file("app/health.py")
                tool.set_result(src)
                tool.set_result_count(1)

            # -- ACT step 2: a model asks to run a destructive command.
            # The authorizer denies it; we record the denial and move on.
            denied = decision.authorize_tool_call(
                authorizer, tool_name="shell_rm", arguments="rm -rf /"
            )
            assert not denied.allowed  # deny-by-default gate held

            # -- change-management policy: is the edit on a protected path?
            policy_eval = decision.evaluate_policy(
                policy_engine,
                policy_id="protected-paths",
                input={"path": "app/health.py", "actor": "bot@acme.dev"},
            )

            # -- ACT step 3: edit the file (a real external mutation) -----
            with decision.tool_call(
                "edit_file",
                call_id="edit-call-1",
                step_id="act-edit",
                step_type="act",
            ) as tool:
                tool.set_kind("function")
                patch = str(resp["text"])
                tool.set_arguments(json.dumps({"path": "app/health.py"}))
                new_src = tool_edit_file("app/health.py", patch)
                tool.set_result(new_src)
                tool.set_idempotency(idempotent=True, key="edit:app/health.py")
                edit_call_id = "edit-call-1"

            # The edit mutates the working tree -> a first-class side effect,
            # linked back to the tool span that produced it.
            decision.record_side_effect(
                SideEffectType.FILE_WRITE,
                target_system="git-worktree",
                operation="write app/health.py",
                request_payload=patch,
                result_payload=new_src,
                rollback_supported=True,
                replay_behavior=ReplayBehavior.SUPPRESS,
                parent_tool_call_id=edit_call_id,
            )

            decision.checkpoint("after-edit", state_hash=_sha(new_src))

            # -- OBSERVE step: run the tests, with step-level retry --------
            # First attempt times out; we record the error + category, then
            # retry as a NEW step attempt that succeeds.
            try:
                with decision.tool_call(
                    "run_tests",
                    step_id="observe-tests",  # stable across retries
                    step_type="observe",
                    step_attempt=1,
                ) as tool:
                    tool.set_kind("function")
                    tool_run_tests("health")
            except TimeoutError:
                # The tool span auto-recorded the exception; tag the
                # canonical error category for cross-tenant analytics.
                with decision.tool_call(
                    "run_tests",
                    step_id="observe-tests",
                    step_type="observe",
                    step_attempt=2,
                    step_retry_reason="timeout",
                    step_retry_previous_attempt_id="observe-tests#1",
                ) as tool:
                    tool.set_kind("function")
                    tool.set_retry(count=1, reason="pytest worker timeout")
                    result = tool_run_tests("health")
                    tool.set_result(json.dumps(result))
                    tool.set_result_count(int(result["passed"]))
                    if int(result["failed"]) > 0:
                        tool.record_error(ToolErrorCategory.SERVER_ERROR)

            # -- SYNTHESIZE step: ask the LLM to finalize the patch -------
            with decision.llm_call(
                system="fireworks",
                model=MODEL,
                temperature=0.0,
                step_id="synth-1",
                step_type="synthesize",
            ) as call:
                fin = call_llm(role="synthesize", prompt=plan_prompt)
                fin_usage = fin["usage"]
                assert isinstance(fin_usage, dict)
                call.set_usage(
                    input_tokens=int(fin_usage["input_tokens"]),
                    output_tokens=int(fin_usage["output_tokens"]),
                    finish_reason=str(fin["finish_reason"]),
                )
                # Second call hit the prompt cache + streamed back.
                call.set_cache_usage(
                    cache_read_tokens=int(fin_usage["cache_read_tokens"])
                )
                call.set_streaming(ttft_ms=140.0, chunk_count=12)
                final_patch = str(fin["text"])

            # -- inline eval: grade the patch on the request path ---------
            decision.record_eval(
                rubric_id="patch-quality",
                score=0.92,
                dimension="correctness",
                evaluator_name="HeuristicPatchGrader",
                evaluator_version="0.3.1",
                confidence=0.8,
            )

            # -- async judge: queue a deeper review out-of-band ----------
            ctx = decision.snapshot_context()
            ctx = JudgeContext(
                user_input=None,  # ticket was hashed; never raw on the wire
                agent_response=final_patch,
                retrieval_docs=ctx.retrieval_docs,
            )
            decision.queue_judge(
                rubric_id="security-review",
                dimensions=("injection_safety", "secret_handling"),
                context=ctx,
                transport=judge_queue,
            )

            # -- the edit hit a protected path -> escalate for approval ---
            if policy_eval.decision == "escalate":
                decision.request_escalation(
                    EscalationSummary(
                        reason=policy_eval.reason or "protected path edit",
                        rubric_id="protected-paths",
                        mode="deferred",
                    )
                )

            # -- the PR is the second external mutation, gated on approval-
            with decision.tool_call(
                "open_pull_request",
                call_id="pr-call-1",
                step_id="act-pr",
                step_type="act",
            ) as tool:
                tool.set_kind("http")
                tool.set_arguments(json.dumps({"title": "Fix /health 500"}))
                tool.set_result(json.dumps({"pr": 42}))
            decision.record_side_effect(
                SideEffectType.TICKET_CREATE,
                target_system="github",
                operation="open pull request #42",
                idempotency_key="pr:BUG-5521",
                approval_required=True,
                committed=False,  # held pending the escalation approval
                parent_tool_call_id="pr-call-1",
            )

            # -- remember an episodic summary of this run -----------------
            decision.remember(
                kind=MemoryKind.EPISODIC,
                content=f"Fixed BUG-5521 in app/health.py; tests green: {final_patch[:40]}",
                key="run:BUG-5521",
                tags=["autofix", "health"],
                ttl_seconds=2_592_000,
            )

            # -- emit the replay envelope (suppressed mutations + ckpts) --
            decision.record_replay_metadata(
                state_hash=_sha(new_src),
                tool_result_hashes=[_sha(final_patch)],
            )

        # execution exits here -> status=completed stamped on its span
        _ = execution.execution_id


# --------------------------------------------------------------------------
# 5. Telemetry summary + assertions (the test).
# --------------------------------------------------------------------------


def _events_named(span: ReadableSpan, name: str) -> list:
    return [e for e in span.events if e.name == name]


def print_summary(spans: Sequence[ReadableSpan]) -> None:
    """Print a human-readable view of the captured Fabric audit trail."""
    print("=" * 74)
    print("CAPTURED FABRIC TELEMETRY (InMemorySpanExporter)")
    print("=" * 74)
    for span in spans:
        attrs = dict(span.attributes or {})
        print(f"\n[{span.name}]  kind={span.kind.name}")
        for key in sorted(attrs):
            if key.startswith(("fabric.", "gen_ai.")):
                print(f"    {key} = {attrs[key]}")
        for ev in span.events:
            ev_attrs = dict(ev.attributes or {})
            highlights = {
                k: v
                for k, v in ev_attrs.items()
                if k not in ("fabric.schema_version",)
                and (
                    "decision" in k
                    or "category" in k
                    or "id" in k
                    or "source" in k
                    or "phase" in k
                    or "kind" in k
                    or "type" in k
                    or "reason" in k
                )
            }
            print(f"      - event {ev.name}: {highlights}")
    print("\n" + "=" * 74)


def run_assertions(spans: Sequence[ReadableSpan]) -> None:
    """Assert the emitted spans/events are correct. This is the test."""
    by_name: dict[str, list[ReadableSpan]] = {}
    for s in spans:
        by_name.setdefault(s.name, []).append(s)

    # -- the execution span carries correlation + lifecycle ---------------
    assert by_name["fabric.execution"], "no fabric.execution span emitted"
    exe = by_name["fabric.execution"][0]
    exe_attrs = dict(exe.attributes or {})
    assert exe_attrs["fabric.workflow_id"] == "swe-autofix"
    assert exe_attrs["fabric.execution.attempt"] == 2
    assert exe_attrs["fabric.execution.retry.reason"] == "previous_attempt_test_timeout"
    assert exe_attrs["fabric.execution.status"] == "completed"
    execution_id = exe_attrs["fabric.execution_id"]

    # -- the decision span carries its identity + inherits execution_id ---
    assert by_name["fabric.decision"], "no fabric.decision span emitted"
    dec = by_name["fabric.decision"][0]
    d_attrs = dict(dec.attributes or {})
    assert d_attrs.get("fabric.decision_id"), "decision span missing fabric.decision_id"
    assert d_attrs["fabric.execution_id"] == execution_id, "execution_id not inherited"
    assert d_attrs["fabric.session_id"] == "ci-session-1934"
    assert d_attrs["fabric.user_id"] == "bot@acme.dev"
    assert d_attrs["fabric.escalated"] is True
    assert d_attrs["fabric.escalation.mode"] == "deferred"
    decision_id = d_attrs["fabric.decision_id"]

    # -- guardrail redacted the leaked AWS key ----------------------------
    grd = _events_named(dec, "fabric.guardrail")
    assert grd, "no fabric.guardrail event"
    assert grd[0].attributes["fabric.guardrail.phase"] == "input"

    # -- retrieval recorded -----------------------------------------------
    rtr = _events_named(dec, "fabric.retrieval")
    assert rtr and rtr[0].attributes["fabric.retrieval.source"] == "tool"

    # -- policy evaluation: protected path -> escalate --------------------
    pol = _events_named(dec, "fabric.policy.evaluation")
    assert pol, "no fabric.policy.evaluation event"
    pol_attrs = dict(pol[0].attributes or {})
    assert pol_attrs["fabric.policy.engine"] == "change-mgmt"
    assert pol_attrs["fabric.policy.decision"] == "escalate"
    assert pol_attrs["fabric.policy.policy_id"] == "protected-paths"

    # -- tool authorization: one allow, one deny --------------------------
    auths = _events_named(dec, "fabric.tool.authorization")
    decisions = {
        a.attributes["fabric.tool.name"]: a.attributes[
            "fabric.tool.authorization.decision"
        ]
        for a in auths
    }
    assert decisions["read_file"] == "allow"
    assert decisions["shell_rm"] == "deny", "destructive tool was not denied"

    # -- side effects: file write + PR, both with parent_tool_call_id -----
    sides = _events_named(dec, "fabric.side_effect")
    assert len(sides) == 2, f"expected 2 side effects, got {len(sides)}"
    by_system = {s.attributes["fabric.side_effect.target_system"]: s for s in sides}
    fw = by_system["git-worktree"].attributes
    assert fw["fabric.side_effect.type"] == "file_write"
    assert fw["fabric.side_effect.parent_tool_call_id"] == "edit-call-1"
    pr = by_system["github"].attributes
    assert pr["fabric.side_effect.approval_required"] is True
    assert pr["fabric.side_effect.committed"] is False
    assert pr["fabric.side_effect.parent_tool_call_id"] == "pr-call-1"

    # -- escalation event present -----------------------------------------
    esc = _events_named(dec, "fabric.escalation")
    assert esc and esc[0].attributes["fabric.escalation.mode"] == "deferred"

    # -- eval + judge + memory + checkpoints + replay ---------------------
    assert _events_named(dec, "fabric.eval"), "no inline eval event"
    assert _events_named(dec, "fabric.judge.queued"), "no judge.queued event"
    mem = _events_named(dec, "fabric.memory")
    assert mem and mem[0].attributes["fabric.memory.kind"] == "episodic"
    assert len(_events_named(dec, "fabric.checkpoint")) == 2
    rep = _events_named(dec, "fabric.replay")
    assert rep, "no fabric.replay envelope event"
    rep_attrs = dict(rep[0].attributes or {})
    assert rep_attrs["fabric.replay.decision_id"] == decision_id
    # both file_write + PR side effects defaulted/were set to SUPPRESS-able;
    # the file_write used SUPPRESS so it must appear in the replay envelope.
    suppressed = rep_attrs.get("fabric.replay.suppressed_side_effect_ids", ())
    assert suppressed, "file_write SUPPRESS side effect missing from replay envelope"

    # -- child spans: plan/synthesize LLM calls + act/observe tool calls --
    llm_spans = by_name.get("fabric.llm_call", [])
    step_types = {dict(s.attributes or {})["fabric.step.type"] for s in llm_spans}
    assert {"plan", "synthesize"} <= step_types, (
        f"missing plan/synth steps: {step_types}"
    )
    # synthesize call reported prompt-cache + streaming telemetry
    synth = next(
        s
        for s in llm_spans
        if dict(s.attributes or {})["fabric.step.type"] == "synthesize"
    )
    s_attrs = dict(synth.attributes or {})
    # The cache-read counter is stamped (the value is provider-reported, so
    # assert presence + non-negativity rather than the stub's exact number).
    assert "fabric.llm.usage.cache_read_tokens" in s_attrs
    assert s_attrs["fabric.llm.usage.cache_read_tokens"] >= 0
    assert s_attrs["fabric.llm.streaming.chunk_count"] == 12

    tool_spans = by_name.get("fabric.tool_call", [])
    tool_step_types = {dict(s.attributes or {})["fabric.step.type"] for s in tool_spans}
    assert {"act", "observe"} <= tool_step_types
    # the failed first run_tests attempt recorded an exception on its span
    failed_observe = [
        s
        for s in tool_spans
        if dict(s.attributes or {}).get("fabric.step.type") == "observe"
        and dict(s.attributes or {}).get("fabric.step.attempt") == 1
    ]
    assert failed_observe, "missing first (failed) observe attempt span"
    assert _events_named(failed_observe[0], "exception"), "timeout not recorded on span"
    # the retry attempt set a per-call retry count
    retry_observe = [
        s
        for s in tool_spans
        if dict(s.attributes or {}).get("fabric.step.attempt") == 2
    ]
    assert retry_observe[0].attributes["fabric.tool.retry.count"] == 1

    print("ALL ASSERTIONS PASSED ✓")


def main() -> int:
    # Self-contained OTel: install a provider with an in-memory exporter so
    # the example prints exactly what Fabric emitted. SimpleSpanProcessor
    # flushes synchronously, so no batching delay before we read spans.
    exporter = InMemorySpanExporter()
    provider = install_default_provider(service_name="swe-autofix-agent")
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    fab = Fabric(
        FabricConfig(
            tenant_id="acme", agent_id="swe-autofix", profile="permissive-dev"
        ),
        guardrail_checkers=[SecretRedactingChecker()],
    )
    try:
        # The ticket pastes a real-looking AWS key — the guardrail must
        # scrub it before the LLM or the trace ever see it. (The example
        # uses an email user_id on purpose; Fabric warns on PII-shaped
        # identifiers — suppress with FABRIC_QUIET_PII_WARN=1.)
        run_swe_agent(
            fab,
            ticket=(
                "The /health endpoint returns 500. (debug creds: "
                "AKIAEXAMPLEKEY1234) please fix."
            ),
        )
    finally:
        fab.close()

    spans = exporter.get_finished_spans()
    print_summary(spans)
    run_assertions(spans)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
