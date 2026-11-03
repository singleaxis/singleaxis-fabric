> **Archived; not part of recorder v1 documentation.** Superseded by
> [Architecture](../architecture.md). Kept for history only; it may not match the current code.

# OSS and commercial boundary

The split follows the customer's trust boundary: capture, export
protection, delivery interoperability and local verification are open.

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
- `fabricctl` local initialization, configuration validation and digesting;
  its initialization receipt says only that local preparation occurred, not
  that a deployment or destination durably received evidence;
- release checksums, provenance, image SBOM attestation, and conformance tests.

These parts remain open because customers must be able to audit what observes
their systems and what crosses their boundary.

## Outside Fabric OSS

Monitoring, evaluation, governance and the other uses that consume the
record are outside Fabric OSS; [AGENTS.md](../../AGENTS.md) states the
boundary. They never become a hidden dependency of local recording.

## Optional enforcement

PII blocking, prompt guardrails, policy authorization, human approval, and tool
blocking become enforcement only when deliberately placed in an agent's model,
tool, retrieval, or side-effect path. They are not part of passive shadow
monitoring and are never activated by installing recorder v1.

Fabric can still record outcomes produced by a customer's existing control
systems. Recording an observed decision is not the same as owning or executing
that decision.

## Release boundary

This public repository predates the recorder-first boundary. Historical source
for judges, sidecars, policy, assurance, management, and Relay was removed from
the working tree; its design history remains in Git. Artifact-content tests
must continue to prove that none of those capabilities is compiled into Fabric
Node, bundled in the Helm chart, exposed as a stable SDK API, included in
public contract archives, or published as a recorder runtime artifact.

The authoritative release scope is [spec 027](../../specs/027-recorder-v1.md).
