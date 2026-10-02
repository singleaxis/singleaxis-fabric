# Finite authenticated distributed closure

`fabric.distributed_closure` is an optional Python reference closure verifier
within CAPTURE → PROTECT → DELIVER. It does not add an enforcement runtime,
automatically instrument workers, or make a production-completeness promise.
The existing `qualified_run` verifier keeps its one-source, epoch-zero contract.
Distributed closure is an additional evidence gate, not a replacement for byte
readback, delivery receipts, boundary coverage or privacy qualification.

## Evidence and trust boundary

An owner configures a `ClosureScope` with tenant, run, scope digest, root source,
registry issuer, witness issuer and a fresh challenge. The scope/challenge is
bound into every signed document. Registry, witness and each source must have
separate issuer identities and public keys. The verifier uses the existing
`EvidenceTrustKey` and Ed25519 attestation verifier, including explicit key
validity, revocation, issuer authority and statement expiry. Private signing keys
are never handled or persisted by the closure module.

- The registry signs `SourceRegistration` documents. Exactly one declared root
  and one registered source per expected child context must exist.
- A registered parent signs `PropagatedContext`, binding the intended child,
  parent call and exact parent source/epoch/sequence anchor. A child can call
  `authenticate_propagated_context` before accepting this correlation. This
  authenticates identity only; it does not authorize an application action.
- A source signs immutable `SourceEpoch` evidence. Sequence positions must be
  unique and contiguous from zero. Epochs must be contiguous from zero with
  exact previous-document hash links. Earlier epochs are explicitly recovered;
  the final epoch must be completed. A prior completed epoch cannot silently
  grow into another epoch. Unknown or lost records prevent completion.
- Each parent declares every expected child exactly once and joins every child
  exactly once, referring to the child's actual final completed epoch hash.
  A parent's application success alone does not close an unjoined child.
- A separately trusted witness signs `ClosureWitness`: its exact control
  inventory, independently observed source record identities/positions/digests,
  and a closed inventory with zero unknown sources/unresolved children. Every
  supplied document and source record must reconcile exactly.

Timestamps validate signature freshness only. They never establish execution
order, substitute for source positions, or invent causal edges between workers.
Exact duplicated transport proofs are idempotent. Different signed envelopes
at the same identity remain conservative conflicts. Do not persist provisional
running snapshots as final epoch manifests and later overwrite them.

A valid signature cannot prove that a witness was operationally independent or
honest. The witness must obtain source/lifecycle truth independently of recorder
snapshots and freeze that inventory under the owner's fresh challenge. Signing
a copied recorder list does not establish this. Undeclared routes, workers
outside that witness's observation, and pre-fsync events absent from all
independent truth remain outside the evidence. An offline verifier cannot
discover facts withheld from every supplied authority.

## Public API

Import the optional module directly. Its public building blocks are:

- `ClosureScope`, `SourceRegistration`, `PropagatedContext`
- `EpochRecord`, `SourceEpoch`, `ChildJoin`
- `ClosureReference`, `WitnessRecord`, `ClosureWitness`
- `SignedClosureDocument`, `ClosureVerification`
- `closure_document_bytes`, `closure_document_id`, `closure_sha256`
- `closure_expectation` for the existing external signing API
- `authenticate_propagated_context`, `verify_distributed_closure`
- `source_epoch_records`, `ClosureEvidenceStore`

`source_epoch_records` hashes exact source-journal metadata using its canonical
encoding. Obtain source records from fresh journal readback. This helper does
not establish independent source truth or promise that an input snapshot was
durable.

`verify_distributed_closure` returns `complete`, fixed-code `reasons`, source,
epoch and record counts, and `production_qualified=False`. A complete result
means only that this declared authenticated closure inventory reconciled.

`ClosureEvidenceStore` is an explicit, fsynced control-evidence store, not a
background writer on the application path. Use an absolute owner-controlled
mode-0700 directory. It returns `durable` only after file and directory fsync,
replays exact signed bytes across restart, retains conflicting versions, and
refuses corrupted/incomplete or unsafe entries. The caller must handle store
errors as unresolved evidence. It stores opaque metadata and signatures in
mode-0600 files; it does not encrypt this control metadata, retain signing keys,
rotate keys, implement retention, or provide legal hold/deletion. The customer
controls directory protection, filesystem durability and lifecycle.

## Executable local campaign

From the repository root with the Python SDK and signing dependencies installed:

```sh
python examples/enterprise-reference/closure_campaign.py --output /tmp/closure-UNIQUE
python -m pytest sdk/python/tests/test_distributed_closure.py --no-cov
```

The main `examples/enterprise-reference/run.py` also invokes
`run_closure_campaign(output / "closure")`.

The campaign fsyncs a finite coordinator plan before starting the sources. It
runs parent/worker journals in separate OS processes, terminates worker epoch
zero after fsync without graceful shutdown, and recovers it in a new process
for epoch one. Source manifests use actual fresh journal readbacks. The witness
uses its separately persisted, pre-source plan and the coordinator's observed
child process/join barriers, never a recorder-generated expected-record list.
The persisted report distinguishes this same-host, shared-administrator trust
boundary from independent production infrastructure.

The clean case verifies two sources across three total source epochs. Late,
unjoined and dead-child variants withhold completion. Tests additionally cover
missing/orphan children, duplicate/overlapping/missing epochs and sequences,
record tails, pre-fsync unknowns, replay, fsync failure, persisted conflicts,
corruption, forged/wrong-audience context, cross-tenant/run/scope substitution,
stale/revoked witnesses and clock skew. These local tests do not qualify a cloud
scheduler, remote worker system, external source witness, IAM/KMS or production
storage. Any launch claiming those must supply its own target evidence.
