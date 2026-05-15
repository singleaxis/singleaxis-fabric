---
title: Overview & Conventions
status: accepted
revision: 1
last_updated: 2026-04-18
owner: project-lead
---

# 000 — Overview & Conventions

This spec is meta: it describes how other specs are written and what
conventions apply across the `specs/` directory.

## Purpose of specs

Specs capture **load-bearing decisions** — product positioning,
architecture, data contracts, cross-component interfaces, security
boundaries, release policies.

Specs do **not** capture:

- Ephemeral implementation details (those live in code and component-level
  READMEs)
- Task tracking (issues)
- Tutorials or how-tos (those live in `docs/`)

If in doubt: write a spec if a future contributor, auditor, or enterprise
reviewer would need to understand the *why*, not just the *what*.

## File format

Every spec is a Markdown file with YAML front-matter:

```yaml
---
title: Short human title
status: draft | accepted | implemented | deprecated | superseded
revision: 1          # increments with each material change
last_updated: YYYY-MM-DD
owner: <maintainer handle or team>
supersedes: 0NN      # optional, if this replaces a prior spec
superseded_by: 0NN   # optional, populated on the old spec
---
```

## Required sections

At minimum, every non-trivial spec should contain:

1. **Summary** — one paragraph, what and why.
2. **Goals** — what this spec commits to.
3. **Non-goals** — what this spec explicitly excludes, to prevent scope
   creep.
4. **Design** — the load-bearing content.
5. **Security considerations** — threats, mitigations, trust boundaries.
6. **Operational considerations** — latency, throughput, failure modes,
   upgrade/migration.
7. **Open questions** — decisions deferred; each should name a resolver
   and a deadline.
8. **References** — prior art, related specs, upstream standards.

Smaller specs may omit sections where there is genuinely nothing to say,
but should explicitly note the omission rather than silently drop the
section.

## Authoring style

- **Opinionated and direct.** Fabric is an opinionated project. Waffling
  in a spec signals a decision was not actually made.
- **Write for the enterprise reviewer.** Imagine a CISO, an auditor, or
  a platform engineering lead who has never seen the project. The spec
  should answer their questions without hand-waving.
- **Show the boundaries.** Draw diagrams with
  [Mermaid](https://mermaid.js.org/) or ASCII. Name every interface.
- **Cite upstream standards.** If the design conforms to OTel semantic
  conventions, NIST AI RMF, ISO 42001, EU AI Act, cite it inline.

## Diagrams

Prefer Mermaid for anything that must render on GitHub. ASCII is
acceptable for simple flow. Don't embed binary images — they're
unreviewable.

## Review expectations

A spec is "good" when:

- It compiles in a reviewer's head without ambiguity.
- It closes more questions than it opens.
- It would be useful to someone encountering the project cold.
- It is falsifiable — a future test or audit can determine whether
  the implementation conforms.

## Glossary

Shared vocabulary used across specs:

| Term | Definition |
|------|------------|
| **Fabric** | This project in its entirety |
| **Fabric Control Plane** | The `fabric-system` namespace running Fabric's managed components in a tenant VPC |
| **Tenant** | An organization running Fabric in their own infrastructure |
| **Audit Bridge** / **Telemetry Bridge** | The single egress component that sends sanitized data to SingleAxis SaaS |
| **SASF** | SingleAxis Assessment Framework — the human-in-the-loop evaluation service |
| **Decision Graph** | The unified per-decision provenance artifact |
| **Decision** | A single agent turn that produces an observable output |
| **Rubric** | A versioned, signed judgement specification used by L6 |
| **Regulatory Profile** | A named `values.yaml` preset that configures Fabric for a specific regulation |
