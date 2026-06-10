# Capturing every interaction

Fabric logs every way an agent touches the outside world — not just LLM and
tool calls, but MCP servers, skills, sub-agents, hooks, file access, and *any*
other interaction you can name. Each is captured with **metadata + hashes,
never raw data** (the same privacy contract as the rest of the SDK), so your
telemetry is never a data-leak surface.

> Specs: [022 — Surface Logging](../specs/022-surface-logging.md) ·
> [023 — Generic Interaction Capture](../specs/023-generic-interaction-capture.md)

## The one principle

Every interaction becomes a `fabric.*` span event carrying metadata and
SHA-256 hashes. Raw payloads, file contents, and (optionally) sensitive
targets/paths stay out of the span — only their hashes are emitted. All of
this is **additive**: existing traces are byte-identical; the wire
`fabric.schema_version` stays `1.0`.

## First-class surfaces

### MCP servers — inventory + tool-definition drift

Beyond tracing MCP tool *calls*, you can snapshot what an MCP server *exposes*
and detect when its tool definitions change underneath the agent (the
"tool poisoning" / shadowing signal).

```python
from fabric.integrations import InstrumentedMCPSession

session = InstrumentedMCPSession(real_mcp_session, decision, server_name="weather", transport="stdio")
inv = await session.snapshot_inventory()   # emits fabric.mcp.inventory
# fabric.mcp.tools = ("get_weather:75ed1d95c9de", "add:b07e3fe8e43c")
# fabric.mcp.tools_hash = <hash of the whole tool list>
# If a tool's def_hash changes between snapshots, the tool definition changed.
```

### Skills / plugins

```python
decision.record_skill(
    "medical-affairs", "2.1.0",
    source="registry://acme/skills",
    manifest_hash="sha256:…",   # hash of the prompt+tools bundle
    signed=True,                 # was the manifest signature valid?
)   # → fabric.skill event + rolling fabric.skill_count
```

### Sub-agent delegation

First-class "agent A invoked agent B", with the parent identity propagated to
the child so its spans link back.

```python
with decision.delegate("claims-agent", protocol="a2a") as sub:
    # sub.carrier is already injected with this decision's context +
    # parent_agent_id — pass it straight to the downstream agent.
    call_other_agent(headers=sub.carrier)
# → fabric.delegation event (to_agent, protocol, depth) + fabric.delegation_count
```

### Hooks / middleware

```python
decision.record_hook(
    "pre_model_guard", "pre_model",   # phase ∈ pre_model|post_model|pre_tool|post_tool|pre_decision|post_decision
    modified=True,
    input_hash="sha256:…", output_hash="sha256:…",  # differing = context was altered
)   # → fabric.hook event + fabric.hook_count
```

### File access — names + hash, never the data

```python
decision.record_file_access(
    "/patients/jane/record.pdf", "read",   # operation ∈ read|write|delete|append
    content_hash="sha256:…", size_bytes=44210,
    redact_path=True,            # hash the path too (sensitive paths)
)   # → fabric.file event + fabric.file_access_count
```

The file's *contents* are never on the span — only a hash. With
`redact_path=True` the path is hashed as well (`fabric.file.path_hash`).

## The universal primitive — capture *anything*

For any interaction without a first-class method (HTTP, DB, queue, shell,
browser, gRPC, …), use `record_interaction`. Nothing is hard-coded; the `kind`
is free-form.

```python
decision.record_interaction(
    "http.request", "https://api.example.com/v1/orders",
    direction="outbound",
    payload_hash="sha256:…",
    metadata={"status": 200, "method": "POST"},   # allowlisted scalars
    redact_target=True,         # hash the target if it carries secrets (tokens in URLs)
)   # → fabric.interaction event + rolling fabric.interaction_count / _kinds
```

A recommended (open) `kind` convention keeps data queryable across teams:
`network.* · storage.* · model.* · tool.* · agent.* · compute.*`.

## The improvement loop — coverage signal

The first time Fabric sees a *new* interaction `kind` via `record_interaction`,
it emits a one-shot `fabric.coverage` event — a signal that an interaction type
is being captured generically, so you know what to give first-class support,
a baseline, or tags. Coverage converges toward "captures everything."

## Generic capabilities (work on *any* surface)

These three are cross-cutting — pass them to any `record_*` call (and
`record_interaction`).

### Baseline — "is this what we approved?"

```python
from fabric import Baseline, BaselineCheck

bl = Baseline.load("approved-tools.json")        # name -> approved_hash (any hashed thing)
bl.check("get_weather", observed_hash)           # "match" | "deviation" | "unknown"

decision.record_interaction(
    "mcp.tool", "weather",
    baseline=BaselineCheck(bl, "get_weather", observed_hash),
)   # stamps fabric.baseline.name + fabric.baseline.status
```

Works on *any* hash — MCP tool sets, skill manifests, approved endpoints, file
paths, prompt templates.

### Tags — any taxonomy (MITRE ATLAS, OWASP LLM, your own)

```python
decision.record_interaction(
    "tool.exec", "send_email",
    tags=["atlas:AML.T0051", "owasp-llm:LLM01", "myco:risk-high"],   # arbitrary allowed
)   # → fabric.tags
```

Reference taxonomies (**MITRE ATLAS**, **OWASP LLM Top 10**) ship as data under
`fabric/taxonomies/`. Add a new framework by dropping a JSON file in — **zero
code change** (`Taxonomy.load("nist-ai-rmf")` then works). Arbitrary tags are
always allowed.

> **Privacy note:** tags are open-vocabulary and **readable** (not hashed) — do
> not place secrets in tag values.

### Signature verification — any artifact

```python
from fabric import verify_signature, SignatureCheck

res = verify_signature(artifact_hash, signature, public_key, scheme="ed25519")
res.verified   # True/False — never raises on a bad signature; ValueError only on bad scheme

decision.record_skill(
    "medical-affairs", "2.1.0",
    signature=SignatureCheck(artifact_hash, signature, public_key, scheme="ed25519"),
)   # stamps fabric.signature.verified / .scheme / .key_id
```

Schemes: `ed25519` (requires the `[signing]` extra; degrades to
`verified=False` with a warning if `cryptography` is absent) and `hmac-sha256`
(stdlib). Works on *any* artifact — manifests, skill bundles, policy bundles,
server identities.

## What's OSS vs. Commercial

This page is all **OSS** — *capturing and logging* every interaction. The
*analysis* on top — detecting a poisoned tool, scoring risk, correlating across
decisions, blocking in real time — is the Commercial Surface Audit. OSS
captures; Commercial governs.

## See also

- [Auditor checklist](auditor-checklist.md) — what an auditor asks, mapped to what Fabric captures
- [Architecture](architecture.md) · [Quickstart](quickstart.md)
