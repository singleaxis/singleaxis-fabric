# docs/

User-facing documentation for Fabric. The authoritative design of
record lives in [`../specs/`](../specs/); these pages are the
shorter, action-oriented doors in.

## Start here

- [**Quickstart**](quickstart.md) — 5-minute walkthrough: install
  the SDK, wrap one agent turn, see telemetry.
- [**Architecture**](architecture.md) — the 3-layer mental model
  (SDK / sidecars / collector) and the "never block the agent
  request path" principle. Links to the authoritative specs.
- [**Deployment**](deployment.md) — Helm chart, the
  `permissive-dev` and `eu-ai-act-high-risk` profiles, and the
  L1-OSS / L2-control-plane boundary.

## Reference surfaces

- [**Operations — Disaster recovery**](operations/dr.md) — DR
  posture and pointers to the chart + bootstrap Job.

Compliance control mappings (Fabric artifact → regulatory control)
are roadmap; the structure is captured in
[`specs/009-compliance-mapping.md`](../specs/009-compliance-mapping.md).

## Status

Phase 1a. The docs cover the surfaces the OSS code ships today.
Anything marked "Roadmap / not yet shipping" in the spec or
component README is called out explicitly in the docs too — we'd
rather under-document than overclaim.

Longer-form reference material (component READMEs, SDK API docs)
still lives alongside the code in [`../components/`](../components/)
and [`../sdk/`](../sdk/). A generated static site (MkDocs + Material)
is a Phase 2 deliverable; until then, browse the Markdown directly
on GitHub.
