# OSS and commercial boundary

The split follows the customer's trust boundary and can be explained in one
sentence:

> Keep capture, export protection, delivery interoperability, and local
> verification open; commercialize fleet operations, calibrated evaluation,
> investigations, enterprise workflows, and regulatory content.

## Product separation

| Product | Responsibilities | Runs where |
|---|---|---|
| Fabric OSS | `CAPTURE -> PROTECT -> DELIVER` | Customer-controlled data plane |
| SingleAxis Platform | `MONITOR -> EVALUATE -> GOVERN` | SingleAxis SaaS, customer private deployment, or hybrid |
| Optional later Control Runtime | `ENFORCE` customer-approved decisions | Deliberately placed in request/tool path |

Fabric OSS does not require the Platform. The Platform consumes the same public
record a customer-owned backend can consume.

## Open trust-boundary components

- Activity, connector, recorder, privacy, and delivery contracts;
- Python and TypeScript capture SDKs;
- Fabric Node OTLP receiver and exact metadata protection;
- persistent queue and customer-selected OTLP delivery;
- `fabricctl` local setup, validation, diagnostics, and receipts;
- release checksums, provenance, image SBOM attestation, and conformance tests.

These parts remain open because customers must be able to audit what observes
their systems and what crosses their boundary.

## Commercial capabilities

- fleet inventory and coverage management;
- continuous monitoring and alerting at enterprise scale;
- calibrated judges, evaluation workers, and campaign orchestration;
- Decision Graph materialization and cross-run analytics;
- incidents, investigations, evidence workflows, and replay orchestration;
- approvals, policy authoring, rollout, and reviewer workflows;
- regulatory mappings, proprietary rubrics, and industry content;
- enterprise connectors, deployment overlays, support, and managed operations.

Commercial services may be deployed by SingleAxis or privately for the
customer. Commercial logic does not become a hidden dependency of local
recording.

## Optional enforcement

PII blocking, prompt guardrails, policy authorization, human approval, and tool
blocking become enforcement only when deliberately placed in an agent's model,
tool, retrieval, or side-effect path. They are not part of passive shadow
monitoring and are never activated by installing recorder v1.

Fabric can still record outcomes produced by a customer's existing control
systems. Recording an observed decision is not the same as owning or executing
that decision.

## Repository migration

This public repository predates the recorder-first boundary. Historical source
for judges, sidecars, policy, assurance, management, or Relay may remain visible
while migration is completed. Recorder-v1 qualification must prove that such
source is not compiled into the Fabric Node, bundled in the Helm chart, exposed
as a stable SDK API, included in public contract archives, or published as a
recorder runtime artifact.

The authoritative release scope is [spec 027](../specs/027-recorder-v1.md).
