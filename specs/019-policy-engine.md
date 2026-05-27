---
title: Policy Engine — Decision-level policy evaluation primitive
status: draft
revision: 1
last_updated: 2026-05-27
owner: project-lead
---

# 019 — Policy Engine

> **Scope split.** This spec covers two layers that ship in different
> tiers:
>
> - **L1 OSS — `decision.evaluate_policy()` primitive + reference
>   adapters (this repo).** The SDK method, the
>   `fabric.policy.evaluation` event shape, the `PolicyEngine`
>   protocol, and three reference adapters (`OPAAdapter`,
>   `CedarAdapter`, `HTTPPolicyAdapter`) ship in `sdk/python/`.
>   Operators get a uniform way to consult any policy engine and
>   record the decision on the decision span.
>
> - **L2 commercial — Signed policy bundles + lineage analytics +
>   governance workflows.** The signed-bundle distribution mechanism,
>   policy version drift detection, cross-decision policy lineage,
>   and the governance UI live in the SingleAxis commercial control
>   plane (`singleaxis-fabric-internal`). Sections "Signed policy
>   bundles" and "Lineage and governance" below describe that L2
>   pipeline as design of record; they are not implemented in the OSS
>   distribution.

## Summary

Production agents make decisions whose acceptability depends on
declarative business rules: refund caps, region-scoped redaction
requirements, role-based tool access, content-type restrictions.
Encoding these rules in agent code makes them invisible to auditors
and impossible to update without a redeploy. Encoding them in a
policy engine (OPA, Cedar, or a custom service) externalizes the
rules but leaves a different problem: there is no shared way for
the agent to report which rule fired and why.

Spec 019 defines the SDK surface that closes that loop. The agent
calls `decision.evaluate_policy(engine, policy_id, input)`. The SDK
forwards the call to a `PolicyEngine` adapter, gets back a normalized
verdict, and emits a `fabric.policy.evaluation` span event the
Decision Graph and judge workers can consume.

The PRD (spec 012 §6 Policy enforcement) and the PRD principle
"Integrate commodity engines, own the semantics" frame the design:
the SDK does not embed a policy engine. It standardizes the event
shape, the decision vocabulary, and the engine-agnostic adapter
protocol.

## Goals

| Goal | Description |
|---|---|
| Single SDK surface for any policy engine | `decision.evaluate_policy()` works the same against OPA, Cedar, or a custom HTTP service |
| Normalize the verdict vocabulary | Five values shared across engines: `allow`, `deny`, `warn`, `escalate`, `redact` |
| First-class lineage | Every policy evaluation is a span event with engine, policy_id, version, decision, reason, evidence_ref |
| Audit-safe | `reason` is required when decision is not `allow`; silent denies are not permitted |
| Reference adapters in OSS | OPA (sidecar HTTP), Cedar (embedded), generic HTTP |
| Signed bundles as a commercial extension point | The event carries an optional `bundle_signature` field the OSS adapter records but never produces or verifies |

## Non-goals

- Embedding a policy engine inside the SDK.
- Authoring a policy DSL.
- Calibrating policy outcomes across engines (commercial concern).
- Defining the meaning of `policy_id` — that is up to the tenant.
- Cross-decision policy lineage queries (Decision Graph, commercial).
- Policy bundle signing (commercial).

## The `decision.evaluate_policy()` primitive

```python
class Decision:
    def evaluate_policy(
        self,
        engine: PolicyEngine,
        *,
        policy_id: str,
        input: dict[str, Any],
        timeout_seconds: float = 1.0,
    ) -> PolicyEvaluation:
        """Forward to the engine, normalize the verdict, emit a span event."""
```

Required keyword arguments:

- `engine` — a `PolicyEngine` adapter instance. Same instance can be
  shared across decisions; thread-safety is the adapter's contract.
- `policy_id` — opaque to the SDK. The tenant decides naming
  (`finance.refund.cap`, `eu.pii.redaction`, etc.). The Decision
  Graph keys on this value for lineage queries; consistency across
  decisions matters.
- `input` — the JSON-serializable input the engine evaluates against.
  The SDK does not inspect the contents; it hashes the payload to
  `input_hash` for the span event so the raw payload never lands on
  the trace stream.

Optional:

- `timeout_seconds` — engine-side timeout. The adapter is expected
  to honor it; the SDK does not enforce.

Return: a `PolicyEvaluation` record. Caller decides what to do with
the verdict (block execution, redact, escalate, continue). The SDK
only emits the event; enforcement is the caller's responsibility.

## The `PolicyEvaluation` event shape

Emitted as a span event named `fabric.policy.evaluation` on the
parent decision span:

```python
@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    evaluation_id: UUID
    decision_id: str
    engine: str                   # "opa", "cedar", "custom:<name>"
    policy_id: str
    policy_version: str | None
    decision: PolicyDecision      # see vocabulary below
    reason: str | None            # required if decision != "allow"
    evidence_ref: str | None      # tenant-side URI for engine proof artifacts
    input_hash: str               # SHA-256 of the input payload
    latency_ms: float
    bundle_signature: str | None  # commercial-signed bundles only; OSS sets None
```

Span event attributes (the wire shape OTel exporters see):

| Attribute | Type | Description |
|---|---|---|
| `fabric.policy.evaluation_id` | string (UUID) | Unique per evaluation |
| `fabric.policy.engine` | string | One of `opa`, `cedar`, `custom:<name>` |
| `fabric.policy.policy_id` | string | Opaque to SDK |
| `fabric.policy.policy_version` | string \| absent | Engine-reported version |
| `fabric.policy.decision` | string | One of the 5 vocabulary values |
| `fabric.policy.reason` | string \| absent | Required when decision != allow |
| `fabric.policy.evidence_ref` | string \| absent | Tenant-controlled URI |
| `fabric.policy.input_hash` | string | SHA-256 hex of input payload |
| `fabric.policy.latency_ms` | float | Engine round-trip latency |
| `fabric.policy.bundle_signature` | string \| absent | Commercial signed bundles only |

Aggregation on the parent decision span:

- `fabric.policy_evaluation_count` (int)
- `fabric.policy_engines` (tuple of strings, distinct engine names used)
- `fabric.policy_decisions_fired` (tuple of strings,
  `<policy_id>:<decision>` pairs for non-allow outcomes only)

## Decision vocabulary

Five values normalized across engines:

```python
PolicyDecision = Literal["allow", "deny", "warn", "escalate", "redact"]
```

Lives in `sdk/python/src/fabric/policy.py` (new in v0.4).

| Value | Meaning | Continues execution? |
|---|---|---|
| `allow` | The policy explicitly permitted the action | Yes |
| `deny` | The policy refused; caller emits canned response or stops | No |
| `warn` | The policy fired but did not block; flagged for review | Yes |
| `escalate` | The policy defers to a human reviewer (HITL) | Paused |
| `redact` | The policy permitted the action with field-level redaction | Yes (with rewritten value) |

### Relationship to `GuardrailAction`

`PolicyDecision` and `GuardrailAction` (`sdk/python/src/fabric/guardrails.py`,
extended in spec 016) share four of five values. The only divergence
is the refusal term:

- `GuardrailAction` uses **`block`** — security/guardrail convention
  ("I refuse to forward this content").
- `PolicyDecision` uses **`deny`** — policy-engine convention (OPA,
  Cedar, XACML all use "deny" for explicit refusal).

The two are semantically equivalent — a `policy.evaluation.decision="deny"`
fed into a guardrail enforcement layer becomes a `guardrail.action="block"`.
Keeping the two literal types distinct lets each layer use its native
vocabulary without cross-coupling.

### Vocabulary enforcement

The SDK enforces the vocabulary at the adapter boundary. An adapter
that returns a value not in this set raises `PolicyAdapterError`;
the SDK fails closed (treats the evaluation as `deny` with
`reason="adapter returned invalid decision"`).

## The `PolicyEngine` protocol

```python
@runtime_checkable
class PolicyEngine(Protocol):
    """Adapter contract for any policy engine."""

    def evaluate(
        self,
        *,
        policy_id: str,
        input: dict[str, Any],
        timeout_seconds: float,
    ) -> EngineVerdict:
        """Return the engine-native verdict. The SDK normalizes."""

    def close(self) -> None:
        """Release any held resources (HTTP session, embedded process, etc.)."""


@dataclass(frozen=True, slots=True)
class EngineVerdict:
    """Adapter return shape — engine-native, before SDK normalization."""

    decision: PolicyDecision      # one of the 5 vocabulary values
    policy_version: str | None
    reason: str | None
    evidence_ref: str | None
    bundle_signature: str | None = None  # OSS adapters always None
```

The adapter's job is to call the engine, parse the response, and
return an `EngineVerdict` with the decision already mapped to the
shared vocabulary. The SDK does not see engine-native shapes.

## Adapter pattern

Three reference adapters ship in OSS. Each is a thin wrapper around
a real engine; the IP is not the adapter but the engine itself.

### `OPAAdapter` — sidecar OPA over HTTP

File: `sdk/python/src/fabric/policy_adapters/opa.py`
Extra: `[opa]` — pins `httpx>=0.27`.

```python
class OPAAdapter:
    def __init__(
        self,
        base_url: str = "http://localhost:8181",
        *,
        timeout_seconds: float = 1.0,
        decision_path_prefix: str = "v1/data",
    ) -> None: ...
```

Wire shape — calls OPA's standard data API:

```
POST {base_url}/{decision_path_prefix}/{policy_id}
Content-Type: application/json
{ "input": <input> }
```

OPA returns a `result` object. The adapter expects the policy to
emit `{ "decision": "<one of vocabulary>", "reason": "...", ... }`.
Policies that return only a boolean are coerced (`true` → `allow`,
`false` → `deny` with `reason="policy returned false"`).

### `CedarAdapter` — embedded Cedar via Python bindings

File: `sdk/python/src/fabric/policy_adapters/cedar.py`
Extra: `[cedar]` — pins `cedarpy>=0.4` or equivalent.

```python
class CedarAdapter:
    def __init__(
        self,
        policy_store_path: str,
        entities_path: str | None = None,
    ) -> None: ...
```

Cedar's native verdict is `Allow` / `Deny`. The adapter maps:

- Cedar `Allow` + no annotations → `allow`
- Cedar `Allow` + annotation `redact=true` → `redact`
- Cedar `Allow` + annotation `warn=true` → `warn`
- Cedar `Deny` + annotation `escalate=true` → `escalate`
- Cedar `Deny` otherwise → `deny`

Annotations are read from the policy effect block. Cedar policy
authors can opt into the richer vocabulary by adding the annotations;
default Cedar policies remain allow/deny.

### `HTTPPolicyAdapter` — generic JSON-over-HTTP

File: `sdk/python/src/fabric/policy_adapters/http.py`
No extra; uses `urllib` from stdlib.

```python
class HTTPPolicyAdapter:
    def __init__(
        self,
        endpoint: str,
        *,
        timeout_seconds: float = 1.0,
        headers: dict[str, str] | None = None,
    ) -> None: ...
```

Wire shape:

```
POST {endpoint}
Content-Type: application/json
{ "policy_id": "<id>", "input": <input> }
```

Response shape (required):

```json
{
  "decision": "allow|deny|warn|escalate|redact",
  "reason": "<string, optional>",
  "policy_version": "<string, optional>",
  "evidence_ref": "<string, optional>"
}
```

Adapter validates the response shape; missing `decision` or a value
not in the vocabulary raises `PolicyAdapterError`.

## Signed policy bundles (commercial extension point)

OSS Cedar and OPA adapters record `bundle_signature=None`. The
commercial control plane distributes policy bundles signed by
SingleAxis; tenants verify the signature locally before loading the
bundle into the engine, and the adapter records the verified
signature on every evaluation event.

The OSS `PolicyEvaluation` schema reserves the `bundle_signature`
field so the wire shape is forward-compatible with commercial
deployments. Auditors querying the Decision Graph can filter for
`bundle_signature IS NOT NULL` to see only evaluations against
signed policies.

Bundle signing logic, key management, and bundle distribution are
out of OSS scope. They live in
`singleaxis-fabric-internal/components/policy-bundle-service/`
(future component).

## Lineage and governance (commercial)

The Decision Graph (commercial) consumes `fabric.policy.evaluation`
events from the OTel stream and indexes them for cross-decision
queries:

- "Which policies fired on this customer's last 100 turns?"
- "Show me every decision in Q2 where policy `finance.refund.cap`
  returned `escalate` and the human reviewer overrode to `allow`."
- "Which policy_ids have had a verdict drift > 10% in the last 30
  days?"

These queries require persistent storage of policy evaluations
across decisions, which is Decision Graph territory and not in OSS
scope.

Governance workflows — rubric-style mappings from policy outcomes
to escalation runbooks ("if policy R returns escalate, route to
reviewer pool X under SLA Y") — live in the commercial governance
engine.

## Concurrency and error semantics

- `decision.evaluate_policy()` is synchronous. Async variants are
  out of scope for v0.4.
- The adapter's `evaluate()` call is wrapped in a try/except by the
  SDK. Any exception is converted to a `PolicyEvaluation` with
  `decision="deny"`, `reason=f"adapter raised: {type(e).__name__}"`,
  `latency_ms=<elapsed>`. The exception is also recorded as an
  `exception` event on the span per OTel conventions.
- Adapter `close()` is called when `Fabric.close()` runs. Adapters
  that hold long-lived resources (HTTP session, embedded process)
  are responsible for cleanup.
- Adapters are expected to be thread-safe at the `evaluate()` level.
  The OSS reference adapters are.

## Privacy posture

- The raw `input` payload is hashed (`input_hash`); the raw value
  never lands on the span. This is consistent with spec 005's
  hash-by-default redaction posture.
- `reason` is a free-text field. Adapters MUST NOT echo the input
  payload into the reason. The reason is meant for auditor-readable
  explanation ("amount exceeds tier-1 cap"), not for the input
  itself.
- `evidence_ref` points to a tenant-side URI. The SDK never
  dereferences it. Auditors with access to the tenant content store
  can resolve the ref to engine-side proof artifacts (Rego
  evaluation tree, Cedar entity store snapshot, etc.).
- `bundle_signature` is a public-key signature; safe to log.

## Examples

Minimal OPA evaluation:

```python
from fabric import Fabric, FabricConfig
from fabric.policy_adapters import OPAAdapter

fabric = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))
opa = OPAAdapter(base_url="http://opa-sidecar:8181")

with fabric.decision(session_id="s", request_id="r") as decision:
    verdict = decision.evaluate_policy(
        opa,
        policy_id="finance.refund.cap",
        input={"amount": 1500, "tier": "tier-1"},
    )
    if verdict.decision == "deny":
        raise PolicyDenied(verdict.reason)
    elif verdict.decision == "escalate":
        decision.request_escalation(
            EscalationSummary(reason=verdict.reason or "policy escalation")
        )
```

Generic HTTP policy service:

```python
from fabric.policy_adapters import HTTPPolicyAdapter

http_policy = HTTPPolicyAdapter(
    endpoint="https://policies.internal/evaluate",
    headers={"Authorization": "Bearer ..."},
)
with fabric.decision(session_id="s", request_id="r") as decision:
    verdict = decision.evaluate_policy(
        http_policy,
        policy_id="eu.pii.redaction",
        input={"text_lang": "fr", "destination": "log"},
    )
```

## Open questions

- **Multi-policy evaluation in one call.** Some engines support
  evaluating N policies in a single round-trip. Should
  `decision.evaluate_policy()` accept `policy_ids: list[str]`? Or
  should the caller loop? Recommendation: loop in v0.4, batch API
  in v0.5 if measured pressure warrants it.
- **Async policy evaluation.** Long-running policies (queued
  external review) are escalations, not policy evaluations. Caller
  uses `decision.request_escalation()` for those. Recommendation:
  keep `evaluate_policy()` synchronous; reject async as a separate
  primitive.
- **Engine discovery / configuration.** Should `Fabric.from_env()`
  auto-construct a default policy engine from
  `FABRIC_POLICY_OPA_URL` etc.? Recommendation: no — keep policy
  engine wiring explicit. Auto-construction obscures which engine
  was consulted.
- **Default timeout.** 1.0s is generous for OPA (typical p99 < 5ms)
  but tight for embedded Cedar with cold caches. Should the default
  be per-adapter? Recommendation: keep the SDK-level default at 1.0s
  and let adapter constructors override.

## References

- Open Policy Agent (OPA): <https://www.openpolicyagent.org/>
- AWS Cedar: <https://www.cedarpolicy.com/>
- Spec 005 — Inline guardrails (PII redaction posture)
- Spec 007 — Escalation workflow (HITL primitive used by `escalate`)
- Spec 012 — OSS commercialization strategy (commercial vs OSS
  scope split)
- Spec 016 — Foundational fixes (the `GuardrailAction` /
  `PolicyDecision` 5-value vocabulary lives here)
