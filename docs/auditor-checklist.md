# Recorder v1 auditor checklist

Fabric OSS supplies evidence inputs for reconstruction. It does not decide
whether an agent was safe, compliant, authorized, or correct. Those conclusions
belong to customer controls or a governance platform consuming the record.

Use this checklist to assess a specific deployment, not the repository in the
abstract.

## Capture coverage

| Auditor question | Recorder v1 evidence | Required qualification |
|---|---|---|
| Which workload emitted the activity? | Tenant, service, agent, deployment, trace, span, and parent identities when supplied | Prove identities are authenticated, stable, and mapped to the deployment inventory |
| What observable operations occurred? | Instrumented model, tool, retrieval, memory, delegation, side-effect, failure, retry, and generic interaction metadata | Publish a connector capability manifest and document blind spots |
| In what order did they occur? | Native OTLP trace topology and timestamps; Activity Envelope v2 defines richer ordering for adapters that implement it | Test clock behavior, retries, fan-out, and source sequencing for the chosen connector |
| What content was used? | Hashes or governed references when the integration supplies them | Prove hash generation, object authorization, retention, and referential availability |
| Can hidden reasoning be reconstructed? | No | Do not represent unobserved internal reasoning as captured fact |

## Export protection

| Auditor question | Recorder v1 evidence | Required qualification |
|---|---|---|
| Can raw prompts or tool payloads leave by default? | Fabric Node's exact allowlist rejects unapproved fields | Run adversarial payload tests through the exact production image and configuration |
| Is PII automatically identified? | No semantic PII engine is included | Classify allowed metadata and use opaque identifiers; add customer-approved controls if required |
| Can credentials be exported? | Credential-shaped fields are outside the allowlist | Test headers, tokens, URLs, errors, baggage, resource attributes, and custom adapter fields |
| Can production weaken the allowlist? | The named production profile rejects extensions | Restrict Helm overrides and changes through customer approval controls |
| Is a privacy assertion proof of de-identification? | No; it is an interoperability record of an applied policy | Obtain independent evidence when legal de-identification is required |

## Delivery and retention

| Auditor question | Recorder v1 evidence | Required qualification |
|---|---|---|
| Is telemetry buffered during an outage? | Persistent Collector sending queue in the production profile | Size storage, test saturation and restart, and monitor queue health |
| Is delivery exactly once? | No; delivery is at least once | Deduplicate at the destination using stable event or trace/span identity |
| Does a successful export prove retention? | No; it proves only the acknowledgement represented by that destination | Define and collect destination-specific durable-persistence evidence |
| Is traffic authenticated and encrypted? | Production requires mTLS ingress and authenticated HTTPS egress | Operate certificate and credential lifecycle and validate external network controls |
| Is evidence immutable? | Not in Fabric Node | Configure destination retention, WORM/immutability, access control, and legal hold as needed |

## Operations and supply chain

- Verify the image, chart, CLI, SDK, and contract digests against the release.
- Review SBOM, provenance, signatures, vulnerability results, and license report.
- Record the exact chart values, Secret references, image digest, storage class,
  destination, connector version, and capability manifest used.
- Test backup, restore, certificate expiry, credential revocation, queue outage,
  destination outage, duplicate delivery, and rollback.
- Confirm only designated administrators can change capture, protection, and
  export configuration.
- Preserve the release qualification report and customer acceptance evidence.

## Questions answered elsewhere

Authorization verdicts, policy versions, judge scores, red-team results,
incidents, approvals, evidence bundles, regulatory mappings, and Decision Graph
queries are downstream control or governance records. They may correlate with
the same trace identity, but their engines are not part of recorder v1.
