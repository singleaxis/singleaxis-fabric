# What your auditor will ask — and what Fabric captures

A practical checklist for proving that an AI agent did what it did, saw
what it saw, and was authorized to do it. Each question is mapped to what
the open-source substrate captures today versus what the Commercial tier
adds.

This document is intended for use with your security, risk, and
compliance teams. It doubles as a self-assessment against SOC 2, the EU
AI Act (Art. 12 record-keeping and Art. 14 human oversight), HIPAA
§164.312(b) audit controls, SR 11-7 model risk management, and the NIST
AI Risk Management Framework (MEASURE / MANAGE).

## Status key

Each row is labelled with one of the following:

| Label | Meaning |
|---|---|
| **OSS** | Shipped in `singleaxis-fabric` (Apache 2.0) |
| **OSS (partial)** | Capability present, with a documented limitation |
| **Commercial** | Provided by the SingleAxis Commercial tier |
| **External** | Outside Fabric's scope (your identity provider or model provider) |

## 1. Identity and accountability

| # | Question | Coverage |
|---|---|---|
| 1 | Which agent made this decision? | **OSS** — `fabric.agent_id` |
| 2 | Which tenant or customer did this affect? | **OSS** — `fabric.tenant_id` |
| 3 | Which user did the agent act on behalf of? | **OSS (partial)** — captured per decision; not propagated cross-service |
| 4 | Which session or conversation thread? | **OSS** — `fabric.session_id` |
| 5 | Which workflow, execution, and retry attempt? | **OSS** — `fabric.workflow_id`, `execution_id`, attempt metadata |
| 6 | Which service account or OAuth identity did the agent use at each external call? | **External** — resides in your authorization layer |

## 2. Input provenance

| # | Question | Coverage |
|---|---|---|
| 7 | What was the original input the user sent? | **OSS (partial)** — hashed on the span; raw content flows out of band to the ContentStore (privacy contract) |
| 8 | What did the model actually see, after redaction? | **OSS** — redacted content captured |
| 9 | Where did the input originate (email, chat, webhook, queue)? | **OSS (partial)** — not first-class; add as a custom attribute |
| 10 | What PII was detected and removed? | **OSS** — guardrail event with entity categories |
| 11 | Which input-side guardrails fired, and what action did they take? | **OSS** — `fabric.guardrail` event (layer, action, policy_id) |

## 3. Reasoning and model

| # | Question | Coverage |
|---|---|---|
| 12 | Which model produced this output? | **OSS** — `gen_ai.request.model` |
| 13 | Which provider-side model version hash? | **External** — not exposed by providers |
| 14 | What system prompt and instructions shaped the output? | **OSS (partial)** — not first-class today |
| 15 | What tools were defined to the model? | **OSS** — MCP inventory hashes each tool definition (`fabric.mcp.inventory`); definition drift is detectable |
| 16 | What was the raw output? | **OSS (partial)** — hashed on the span; raw content to the ContentStore |
| 17 | How many tokens, what cost, what latency? | **OSS** — `gen_ai.usage.*`, `fabric.llm.*` |
| 18 | Did streaming occur? Time to first token? Chunk count? | **OSS** — `fabric.llm.streaming.*` (v0.6) |
| 19 | Did the call retry, and why? | **OSS** — `fabric.llm.retry.*` |

## 4. Retrieval and RAG context

| # | Question | Coverage |
|---|---|---|
| 20 | Which documents were retrieved? | **OSS** — `source_document_ids` |
| 21 | What was the query? | **OSS** — query hash |
| 22 | Which backend served it (vector, knowledge graph, SQL)? | **OSS** — retrieval source class |
| 23 | Was any retrieved document user-authored (an indirect-injection surface)? | **OSS (partial)** — not yet first-class |
| 24 | What memory was recalled or written? | **OSS** — `fabric.memory` events with kind and content hash |

## 5. Actions and tool calls

| # | Question | Coverage |
|---|---|---|
| 25 | Which tools were called? | **OSS** — `fabric.tool.name` |
| 26 | What arguments were passed? | **OSS** — argument hash; raw to the ContentStore |
| 27 | What did each tool return? | **OSS** — result hash; raw to the ContentStore |
| 28 | Was the call authorized, by whom, and under what policy? | **OSS** — `fabric.tool.authorization` event |
| 29 | Did the side effect execute, or was it suppressed during replay? | **OSS** — `fabric.side_effect` event with suppression state |
| 30 | What was the idempotency key? | **OSS** — `fabric.tool.idempotency_key` |
| 31 | Retries and error category? | **OSS** — `fabric.tool.retry.*`, `error_category` (v0.6) |
| 32 | Did the agent invoke another agent? | **OSS** — `Decision.delegate` emits `fabric.delegation` (to_agent, protocol, depth); `parent_agent_id` propagates to the child |

## 6. Policy enforcement

| # | Question | Coverage |
|---|---|---|
| 33 | Which engine evaluated the policy? | **OSS** — `fabric.policy.engine` |
| 34 | Which policy bundle (version and digest)? | **OSS** — `fabric.policy.policy_version`, bundle digest |
| 35 | At which enforcement point (input, tool call, output, egress)? | **OSS** — all four points instrumented |
| 36 | What was the verdict and reason? | **OSS** — `fabric.policy.decision`, `fabric.policy.reason` |
| 37 | What input was the policy applied to? | **OSS** — input hash only (raw never on the span) |

## 7. Evaluation (judge layer)

| # | Question | Coverage |
|---|---|---|
| 38 | Was this decision evaluated? | **OSS** — `fabric.judge.queued`, `record_eval` |
| 39 | Against which rubric (id and version)? | **OSS** — `fabric.judge.rubric_id`, version |
| 40 | By which judge model? | **OSS** — `fabric.judge.judge_model` |
| 41 | What was the score? | **OSS** — `fabric.judge.score` |
| 42 | How confident was the judge? | **OSS (partial)** — not standardized |
| — | A judge fleet running rubrics continuously | **Commercial** — Judge Workers |

## 8. Human review (human-in-the-loop)

| # | Question | Coverage |
|---|---|---|
| 43 | Was this decision escalated to a human? | **OSS** — `fabric.escalation` event |
| 44 | What was the trigger? | **OSS** — `fabric.escalation.trigger` |
| 45 | Who reviewed it? | **OSS (partial)** — captured |
| 46 | What was the verdict? | **OSS (partial)** — captured |
| 47 | Was the verdict cryptographically signed and verifiable? | **OSS (partial)** — HMAC scaffold in OSS; the Ed25519 signed-verdict flow is **Commercial** |

## 9. Side effects (what actually changed in the world)

| # | Question | Coverage |
|---|---|---|
| 48 | What external mutations were attempted, suppressed, or executed? | **OSS** — `fabric.side_effect` event with stable `side_effect_id` |
| 49 | What is the replay-safety state, so we can re-run safely? | **OSS** — versioned `ReplayMetadata` envelope |

## 10. Temporal and configuration provenance

| # | Question | Coverage |
|---|---|---|
| 50 | Exactly when did this happen? | **OSS** — native OpenTelemetry timestamps |
| 51 | What was the configuration snapshot at decision time (model, policy bundle, prompt, rubric version)? | **OSS (partial)** — policy bundle digest and model name captured; system prompt and variables not yet captured |

## 11. Integrity and non-repudiation

This layer is what makes sections 1–10 legally usable as evidence.

| # | Question | Coverage |
|---|---|---|
| 52 | Is the record tamper-evident? | **Commercial** |
| 53 | Is it signed by the operator under a published trust anchor? | **Commercial** |
| 54 | Is it hash-chained to adjacent records (Merkle-style)? | **Commercial** |
| 55 | Is it WORM-stored for long retention with verified storage? | **Commercial** |

## 12. Reproducibility

| # | Question | Coverage |
|---|---|---|
| 56 | Can we replay this decision without re-firing side effects? | **OSS (partial)** — metadata envelope and suppression contract in OSS; the replay engine is **Commercial** |
| 57 | Can we compare what the agent would do now against what it did then? | **Commercial** |

---

## Summary scorecard

| Category | Covered by OSS | OSS gaps | Requires Commercial |
|---|---|---|---|
| Identity and accountability | 4/6 | 1 (`user_id` cross-service propagation) | — |
| Input provenance | 3/5 | 1 (input source / channel) | — |
| Reasoning and model | 5/8 | 1 (system prompt) | — |
| Retrieval and RAG | 3/5 | 1 (user-authored document marking) | — |
| Actions and tools | 8/8 | — | — |
| Policy enforcement | 5/5 | — | — |
| Evaluation | 4/5 | — | 1 (continuous judge fleet) |
| Human review | 3/5 | — | 1 (Ed25519 signed-verdict pipeline) |
| Side effects | 2/2 | — | — |
| Temporal and configuration | 1/2 | 1 (system prompt versioning) | — |
| Integrity (52–55) | 0/4 | — | 4 (the integrity layer in full) |
| Reproducibility | 1/2 | — | 1 (diff against current behaviour) |

Approximately 38 of 57 audit questions are answerable from the
open-source layer today. That covers the majority of what an internal
audit and a SOC 2, GDPR, HIPAA, or SOX reasonable-care review will ask
for. The integrity layer (questions 52–55) is the legally load-bearing
gap, and the capability the Commercial tier exists to provide.

## Mapping to the major regimes

- **EU AI Act, high-risk systems (Art. 12, record-keeping):** covered
  technically by the open-source layer. Art. 14 (human oversight)
  requires the signed-verdict pipeline, which is Commercial.
- **HIPAA §164.312(b), audit controls:** the open-source layer covers
  the audit log contents; long-term tamper-evident storage is
  Commercial.
- **SR 11-7, model risk management:** the open-source layer covers the
  per-decision evidence; the model-change attestation workflow is
  Commercial.
- **NIST AI RMF, MEASURE / MANAGE:** the open-source layer supplies the
  telemetry these functions build on; ongoing evaluation orchestration
  and governance are Commercial.

See [`compliance/mappings/`](compliance/mappings/) for the per-regime
control matrices.
