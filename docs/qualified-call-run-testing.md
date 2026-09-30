# Qualified custom-agent evidence testing

This optional offline check combines the recorded timeline, protected original
data, independent operation records and separate delivery proofs. It is not a
judge, evaluation service or production approval system. Fabric still does
CAPTURE -> PROTECT -> DELIVER.

## What is implemented

- `fabric.qualified_run.verify_qualified_call_run` compares each physical
  operation, attempt, outcome, required original byte object and ordered chunk
  against raw signed independent feeds. Parent-child links are checked against
  the saved source records; this does not establish hidden provider state.
- Fresh journal readback checks the saved source seal, exact record set and
  terminal sequence. It does not rely on the recorder's cached seal.
- `fabric.receipt_sets` checks four distinct signed exact sets: source saved,
  Node accepted, destination accepted, destination durably read back.
- Source identity and declared route closure require purpose-specific statements
  from owner-configured authorities. An unobserved reachable route prevents
  completeness even when the route declaration is signed.
- `fabric.independent_store.LocalIndependentFeedResolver` reads only approved
  tenant/issuer-owned local witness files. It rejects unsafe paths, links,
  public permissions, oversized files and files changed during reading.

The first qualified interface deliberately handles **one source, epoch zero,
and one tenant/run**. Additional source epochs, multi-source aggregation and
additional live adapter families are not qualified by this interface. Parallel
calls inside the declared source keep their own call/attempt identities.

## Reproduce the bounded end-to-end test

Use a new empty parent directory you own; substitute its absolute path below.
Do not reuse an old evidence directory. Run these commands from repository root:

```sh
python -m build --outdir /path/to/new-parent/dist sdk/python
python -m venv /path/to/new-parent/venv
/path/to/new-parent/venv/bin/python -m pip install '/path/to/new-parent/dist/singleaxis_fabric-0.8.0rc1-py3-none-any.whl[otlp,signing]' pytest
/path/to/new-parent/venv/bin/python scripts/qualification/run_qualified_call_pilot.py --fixture-only --evidence-dir /path/to/new-parent/pilot
/path/to/new-parent/venv/bin/python -m pytest -q -o addopts= sdk/python/tests/test_qualified_run.py sdk/python/tests/test_receipt_sets.py sdk/python/tests/test_independent_store.py sdk/python/tests/test_source_spool_readback.py sdk/python/tests/test_route_closure_attestation.py
```

The pilot requires an installed wheel. It runs a loopback HTTP model endpoint,
an actual no-shell subprocess, a binary file artifact, and a second model call.
Service/delegate observations populate separate native witness ledgers and
owner-only byte files. Expected operations, roles and terminal cursors come
from the specified workload, not from the recorder snapshot. It checks four
calls and fifteen required original objects, including ordered model chunks
and explicitly empty stderr. Individual signature, feed, object, source record,
source seal and receipt omissions/substitutions must never preserve a complete
verdict. No private signing key is saved or printed.

`summary.json`, `positive.json` and `negative-tests.json` are metadata-only.
Exact authorized originals are in the dedicated captured/native stores. Keep
the directory protected: it is synthetic test evidence, not a public upload
bundle. The Linux workflow publishes only its non-secret summary and artifact
identities, not the byte stores or signing material.

## Meaning of the result

`verified_complete_for_declared_scope` means every required submitted proof and
exact comparison passed under the separately supplied trust registry and scope.
`partial` means a known omission, contradiction or loss was detected.
`unverified` means required authority or evidence could not be established.
A missing proof cannot be replaced by a caller flag, another stage's receipt,
an aggregate count, a masked derivative or an OTLP success response.

The pilot's stage signatures are **fixture assertions**. It does not obtain
signed live Node receipts or qualify real storage durability. Its positive
verification is accompanied by `production_status: NO_GO`. The existing
production-profile Kubernetes job independently tests actual Node delivery,
TLS failures, outages and controlled-sink readback using frozen artifacts; its
passing result is not silently converted into these fixture stage statements.

## Required inputs for a real deployment

The deployment owner supplies the signed scope and out-of-band key registry,
an independent native ledger with terminal checkpoints for each declared
route, and qualified issuer/readback integrations for all four receipt stages.
Source and destination sets include original content readback; the first
combined durable-set issuer must be authorized for both the selected metadata
destination and protected original storage. A signer cannot derive destination
durability merely by copying `qualified_receipt_expectations` from the source.

Actual route restrictions, issuer independence, encryption/KMS/IAM, retention,
restore, key rotation and deployment acceptance require their own live tests.
No production issuer is created or trusted automatically by installing the
recorder. The [qualification status](recorder-v1-qualification-status.md)
records executed checks separately from these remaining gates.
