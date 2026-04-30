<div align="center">

# SingleAxis Fabric

**Open-source observability and control plane for AI agents.**

Decision-span tracing, fail-loud guardrails, and a human-in-the-loop
primitive — OpenTelemetry-native, with adapters for LangGraph,
Microsoft Agent Framework, and CrewAI. Hardened defaults for regulated
environments: the `eu-ai-act-high-risk` Helm profile ships today;
full audit-trail evidence generation lands with the SingleAxis control
plane.

[![PyPI](https://img.shields.io/pypi/v/singleaxis-fabric.svg)](https://pypi.org/project/singleaxis-fabric/)
[![Python](https://img.shields.io/pypi/pyversions/singleaxis-fabric.svg)](https://pypi.org/project/singleaxis-fabric/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/singleaxis/singleaxis-fabric/actions/workflows/ci.yml/badge.svg)](https://github.com/singleaxis/singleaxis-fabric/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/singleaxis/singleaxis-fabric/badge)](https://securityscorecards.dev/viewer/?uri=github.com/singleaxis/singleaxis-fabric)

[Quickstart](docs/quickstart.md) ·
[Architecture](docs/architecture.md) ·
[Deployment](docs/deployment.md) ·
[Reference agent](examples/reference-agent/) ·
[Specs](specs/)

</div>

---

## Why Fabric

Teams shipping LLM agents into regulated environments — banks, hospitals,
insurers, public sector — keep building the same five things in-house:

1. A way to record what the agent **decided** and **why**, so auditors and
   incident responders can reconstruct a turn months later.
2. Inline **PII redaction** and **policy rails** that fail loud instead of
   silently leaking or complying.
3. A **human-in-the-loop** primitive that pauses an agent turn, routes it
   to a reviewer, and resumes with a signed verdict.
4. **Retrieval provenance** — which documents were pulled, what was
   hashed, what the agent saw vs. what it ignored.
5. A deployment shape that doesn't make the agent request path wait on
   any of it.

Fabric ships all five as a drop-in library, sidecars, and a Helm chart.
Apache-2.0. Zero-signup. Works offline.

## What you get

- **Decision spans** — one OpenTelemetry span per agent turn, tagged
  with tenant / agent / session / request / user, plus span events for
  every retrieval, guardrail check, memory write, and escalation.
- **Inline guardrails** — [Presidio](https://microsoft.github.io/presidio/)
  for PII redaction and [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails)
  for Colang policy rails, both exposed over Unix domain sockets
  (sub-millisecond transport, no TCP hop).
- **Escalation primitive** — `decision.request_escalation(...)` returns a
  framework-agnostic payload you hand to whatever HITL mechanism your
  orchestrator exposes (LangGraph `interrupt()`, MAF `request_info`,
  CrewAI `human_feedback`, or your own queue).
- **Retrieval + memory recording** — SHA-256-hashed locally (raw text
  never leaves the span), allowlisted attributes, rolling counters on
  the decision span. Maps cleanly onto a provenance graph.
- **OTel Collector distribution** — preconfigured with the Fabric
  processor chain (tail sampling, attribute allowlisting, tenant
  scoping). Fans out to Langfuse, Tempo, Jaeger, Honeycomb, Datadog —
  anything that speaks OTLP.
- **Helm chart with regulatory profiles** — `permissive-dev` for
  evaluation and `eu-ai-act-high-risk` for production under the EU AI
  Act ship today. NIST AI RMF, ISO/IEC 42001, SR 11-7, and HIPAA
  profiles are roadmap (see [`specs/008-deployment-model.md`](specs/008-deployment-model.md)).
- **First-class adapters** — [LangGraph](https://langchain-ai.github.io/langgraph/),
  [Microsoft Agent Framework](https://learn.microsoft.com/en-us/agent-framework/),
  and [CrewAI](https://www.crewai.com/). Installed via extras; core
  stays framework-neutral.

### One principle makes all of this practical

> **The agent request path never blocks on a Fabric HTTP call.**

SDK work is in-process (target `<1ms` P99). Guardrail sidecars run
over a Unix domain socket (target `<100ms` P99 budget per check).
Everything else — judges, escalation bookkeeping, provenance writes,
evidence generation — happens asynchronously off the OTel stream.
Security tooling that blocks request paths gets ripped out; Fabric
stays in the path only where latency budgets justify it. Numbers
above are design budgets enforced by component readiness probes;
benchmark suites against representative workloads land in a
follow-up release.

## Install

```bash
pip install singleaxis-fabric                        # core SDK
pip install "singleaxis-fabric[otlp]"                # + OTLP/HTTP exporter
pip install "singleaxis-fabric[langgraph]"           # + LangGraph adapter
pip install "singleaxis-fabric[agent-framework]"     # + Microsoft Agent Framework
pip install "singleaxis-fabric[crewai]"              # + CrewAI adapter
```

Python 3.11+ (the rest of the repo targets 3.12).

## 60-second example

```python
# Requires the [otlp] extra for OTLPSpanExporter:
#   pip install "singleaxis-fabric[otlp]"
import os
from fabric import Fabric, FabricConfig, install_default_provider
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

# One-time: point the SDK at your OTel Collector (or any OTLP sink).
install_default_provider(
    service_name="support-bot",
    exporter=OTLPSpanExporter(endpoint=os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"]),
)

# Tenant + agent identity are required. Either pass them explicitly:
fabric = Fabric(FabricConfig(tenant_id="acme-prod", agent_id="support-bot"))
# ...or set FABRIC_TENANT_ID and FABRIC_AGENT_ID and call Fabric.from_env().

with fabric.decision(
    session_id="sess-1",
    request_id="req-1",
    user_id="user-42",
) as decision:
    safe_input = decision.guard_input("hello")               # Presidio rail

    # Wrap the LLM call in a child span so the trace tree captures
    # gen_ai.* semantic conventions (model, token counts, finish
    # reason) — Phoenix's LLM view, Langfuse cost dashboards, and
    # any backend keyed on either namespace render natively.
    with decision.llm_call(system="anthropic", model="claude-opus-4-7") as call:
        answer = "..."  # call your LLM
        call.set_usage(input_tokens=42, output_tokens=210, finish_reason="stop")

    safe_answer = decision.guard_output_final(answer)        # Presidio + NeMo
```

That's the full wrapping. One span lands in your collector per agent
turn, tagged with everything a reviewer or auditor needs to
reconstruct the decision. Drop `guard_input` / `guard_output_final`
if you haven't wired the sidecars yet — the calls fail loud with
`GuardrailNotConfiguredError` by design, so compliance never silently
regresses.

**Prefer to see it run first?** The reference agent exercises every
SDK surface in one turn, offline, no API keys:

```bash
git clone https://github.com/singleaxis/singleaxis-fabric.git
cd singleaxis-fabric/examples/reference-agent
uv sync
uv run fabric-reference-agent --prompt "Hello"
uv run fabric-reference-agent --prompt "Hello" --low-score   # escalation path
```

Output shape: `{"response": "...", "escalated": bool, "blocked": bool,
"trace_id": "<32-hex>"}`.

## Deploy the control plane

For any cluster that will take real traffic, install the umbrella
Helm chart. Regulatory profiles preset safe defaults.

```bash
git clone https://github.com/singleaxis/singleaxis-fabric.git
cd singleaxis-fabric/charts/fabric
helm dependency build

# Dev / evaluation cluster:
helm install fabric . \
    --namespace fabric-system --create-namespace \
    --values profiles/permissive-dev.yaml

# EU AI Act high-risk workloads:
helm install fabric . \
    --namespace fabric-system --create-namespace \
    --values profiles/eu-ai-act-high-risk.yaml \
    --set tenant.id=<uuid>
```

The `otel-collector` subchart also publishes as an OCI artifact at
`oci://ghcr.io/singleaxis/charts/otel-collector` for teams that only
want the collector distribution. Umbrella-chart OCI publishing lands
in a following release.

Chart contents, profiles, and latency posture: [`charts/fabric/README.md`](charts/fabric/README.md).
Full deployment guide including HA, DR, and upgrade posture:
[`docs/deployment.md`](docs/deployment.md).

## How it fits together

```text
      agent pod
  ┌─────────────────────────────────────────────┐
  │  your agent code                            │
  │      │                                      │
  │      ▼                                      │
  │  fabric.Decision  ──UDS──▶  Presidio sidecar│
  │      │                                      │
  │      ├──UDS─────────────▶  NeMo Guardrails  │
  │      │                                      │
  │      └─ async OTLP ─┐                       │
  └─────────────────────┼───────────────────────┘
                        ▼
                 OTel Collector  ──▶  Langfuse / Tempo / Jaeger /
                                      Honeycomb / Datadog / your sink
```

Three layers you actually touch: **SDK** (in-process), **sidecars**
(same pod, UDS), **collector** (cluster-level). Everything else —
judge workers, escalation service, provenance graph, evidence
bundles — runs asynchronously off the OTel stream.

Two-page mental model: [`docs/architecture.md`](docs/architecture.md).
Authoritative design: [`specs/002-architecture.md`](specs/002-architecture.md).

## Status

**Beta — Phase 1a shipping.** The `specs/` directory is the
design of record. What's in this repo runs and is tested; anything
marked "Phase 2" or "roadmap" is explicitly called out. We'd rather
under-document than overclaim.

See [`CHANGELOG.md`](CHANGELOG.md) for what's in the current release.

## What this OSS distribution covers

The open-source Fabric (this repository) is the **collection
infrastructure** plus the **inline control plane** for an AI agent:

- **Collection** — decision spans, guardrail events, retrieval
  hashes, escalation records, judge-score attributes. Standardised
  OTel shape; hardened defaults; tenant-scoped.
- **Control** — fail-loud guardrail sidecars, the human-in-the-loop
  escalation primitive, deny-by-default policy gates, the
  signed-manifest update channel.

It is a substrate, not a compliance product. **Fabric does not issue
certifications, generate evidence bundles, or produce signed audit
trails on its own.** The artefacts an external auditor asks for —
queryable evidence bundles, immutable retention, regulator-shaped
mappings — are produced by the SingleAxis commercial control plane on
top of this collection layer (Context Graph, evidence builder,
escalation service, judge workers).

If your team operates the collection infrastructure yourselves and
builds your own audit trail on top of it, the OSS distribution is
sufficient. If you need the audit trail itself as a managed product,
that's the SingleAxis control plane.

Control mappings (Fabric artifact → regulatory control) are roadmap.
The structure each mapping will follow is captured in
[`specs/009-compliance-mapping.md`](specs/009-compliance-mapping.md);
nothing authoritative ships in this release. Initial targets are the
EU AI Act, NIST AI RMF, and ISO/IEC 42001; SR 11-7, HIPAA, and GDPR
follow.

## Documentation

| If you want to... | Read |
|-------------------|------|
| Install the SDK and instrument one agent turn in 5 minutes | [`docs/quickstart.md`](docs/quickstart.md) |
| Understand the 3-layer mental model and the latency principle | [`docs/architecture.md`](docs/architecture.md) |
| Deploy the Helm chart with a regulatory profile | [`docs/deployment.md`](docs/deployment.md) |
| See every SDK surface exercised in one runnable file | [`examples/reference-agent/`](examples/reference-agent/) |
| Read the authoritative design of record | [`specs/`](specs/) |
| Look up an SDK symbol or environment variable | [`sdk/python/README.md`](sdk/python/README.md) |
| Plan a disaster-recovery exercise | [`docs/operations/dr.md`](docs/operations/dr.md) |

## Contributing

Contributions are welcome — patches, issues, RFCs against the specs.
Read [`CONTRIBUTING.md`](CONTRIBUTING.md) first. Fabric uses the
[Developer Certificate of Origin](https://developercertificate.org/)
(DCO): every commit must be signed off with `git commit -s`. Project
decisions follow [`GOVERNANCE.md`](GOVERNANCE.md).

Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
(Contributor Covenant 2.1).

## Security

To report a vulnerability, follow the private disclosure process in
[`SECURITY.md`](SECURITY.md). **Do not** open a public issue for
security findings. We acknowledge receipt within 3 business days and
follow a 90-day coordinated disclosure default.

## Community and support

- **Issues** — bug reports, feature requests:
  [GitHub Issues](https://github.com/singleaxis/singleaxis-fabric/issues)
- **Discussions** — questions, show-and-tell, design RFCs:
  [GitHub Discussions](https://github.com/singleaxis/singleaxis-fabric/discussions)
- **Commercial support** — for regulated deployments and managed
  operations: [singleaxis.ai](https://singleaxis.ai)

## Governance

Fabric is maintained by **AI5Labs Research OPC Private Limited**
(SingleAxis) as an open project. Maintainer appointment, release
processes, and trademark policy: [`GOVERNANCE.md`](GOVERNANCE.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See
[`NOTICE`](NOTICE).

SingleAxis, SASF, and the Fabric word mark are trademarks of AI5Labs
Research OPC Private Limited. The trademarks are **not** licensed under
Apache-2.0; see [`GOVERNANCE.md`](GOVERNANCE.md) for the trademark policy.
