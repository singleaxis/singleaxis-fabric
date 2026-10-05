# Evidence qualification map

Fabric's supported promise is CAPTURE -> PROTECT -> DELIVER for declared,
observable boundaries. This map separates source implementation, local fixture
evidence and customer target qualification. No local result establishes universal
capture, hidden model context, deterministic replay or a production approval.

The machine-readable [C0–C10 matrix](../qualification/capture-level-matrix.json)
records expected actions, actual capture boundaries, identity/causality, privacy,
independent truth, observed results, omissions and status for every level. Its
scenario execution status is deliberately `unexecuted` until a concrete run is
bound to artifacts; existing source/test references are not substituted for runs.
The [product audit](../qualification/cloud-audit-product.json) separately records
per-path hashes and review methods. Hash inventory and lexical scans are not
textual review or runtime qualification.

| Level | Declared surface | Qualification boundary |
| --- | --- | --- |
| C0 | Agent input/output, exception, cancellation, serialization | Explicit root wrapper; root return does not close producers |
| C1 | Model physical attempts/retries/streams | Actual wrapped transport bytes; hidden retries/context remain unknown |
| C2 | Tools and existing permissions | Arguments/results/errors and separately observed attempted/granted/exercised facts; no authorization engine |
| C3 | Remote effects | Requested/acknowledged/committed/unknown; authoritative service readback required for commit |
| C4 | Retrieval/memory/context | Actual supplied results/context and provenance; no inferred hidden provider context |
| C5 | Delegated/parallel/background work | Supplied causal links plus registered sources/epochs/joins; missing or late producer withholds closure |
| C6 | Shell and descendants | Bounded explicit subprocess support; general PTY/detached descendants unqualified |
| C7 | Files and stores | Explicit observed content and independent state readback; partial writes/renames need dedicated cases |
| C8 | Network | Scoped connection metadata versus application semantics; encrypted payloads not recovered by host sensing |
| C9 | Sandbox/container/restart/loss | Source epochs and loss accounting; actual target kernel/container lifecycle requires separate execution |
| C10 | Remote workers/delivery | Duplicate/partition handling, producer closure and independent destination readback; local fixture is not remote qualification |

## Run and export the acceptance fixtures

Use the SDK development environment with pytest and the SDK extras installed:

```sh
python scripts/qualification/run_capture_acceptance.py \
  --python /path/to/sdk-venv/bin/python \
  --evidence-dir /tmp/fabric-acceptance-UNIQUE
```

The directory must be new. The runner creates a private report directory and
exports `capture-matrix.json`, per-level commands, source hashes, command logs,
JUnit results and pytest fixture files. These fixtures use synthetic inputs only.
`LOCAL_FIXTURE_PASSED` credits precisely the selected assertions, not an entire
level; `not_implemented_scenarios` remains present even after those assertions
pass. Skips, malformed/missing JUnit and command errors cannot pass. C8 now has
a controlled application HTTP scenario; host and TLS coverage remains unimplemented. The runner
uses local tests, not a live model or cloud service, and always reports `NO_GO`.
Retain the whole directory with its exact source/artifact ledger for review.

## Controlled C8 application-network journey

```sh
python scripts/qualification/run_c8_network_journey.py \
  --evidence-dir /tmp/fabric-c8-UNIQUE
```

The new private directory retains `capture-matrix.json`, protected metadata,
encrypted derivative objects and an independent SQLite service ledger. The
actual Python HTTP adapter makes four requests: a 503 followed by an explicit
200 retry, a 400 response, and a request whose effect commits before its response
is lost. The caller's last outcome remains unknown; only the independent service
ledger establishes that the effect committed once. Evidence recovery starts a
fresh authorized reader and sends no HTTP request. Keep the generated key files
private; this fixture uses local capabilities, not production IAM or KMS.

The privacy check observes seven actual writer handoffs after DeploymentPolicy
redaction and searches retained files for the synthetic raw canary. The fresh
reader verifies seven redacted objects and denies wrong-tenant metadata. It does
not recover original content. Socket peer observations do not prove application
semantics; response IDs and fixture request IDs provide the scoped joins here.
No host packet sensing, TLS run, HTTP/2, SSH, uninstrumented plaintext recovery,
external destination durability or producer closure is credited. An explicit
HTTP adapter can observe application bytes before encryption; host connection
metadata alone cannot reveal encrypted request/response content.

## What counts as evidence

Keep source admission, durable source spool, Node acceptance, destination
acceptance and destination durable readback separate. Record unknown effects
when an acknowledgement is lost. Exact duplicates can be idempotent;
conflicting identities or missing positions are discrepancies. A hash proves
integrity of the bytes presented, not truth or completeness of unobserved actions.

Independent truth must come from the operation/effect authority or a separately
observing witness. A recorder-generated expected list signed by a fixture does
not become independent. Same-host fixtures share an administrator trust boundary.
Application root return, background producer closure and delivery completion are
three separate observations.

Do not promote `masked_only` into a pre-admission guarantee: the byte recorder's
`BytePrivacyPolicy` masking callback runs in its worker. `DeploymentPolicy` protection on the explicit
byte recorder is a distinct pre-queue path. All capture is opt-in at the declared
boundaries; existing host exporters remain host-owned. Python and TypeScript
capabilities must be reported separately using the [support matrix](sdk-support-matrix.md).

## Customer qualification packet

For each executed scenario retain the command, exact source/artifact hashes,
configuration and declared routes, independent expectation established before
capture, outcome, counterexamples, unknowns and report paths. Missing evidence
stays unexecuted/unverified; never fill a result from a passing neighboring test.
Collector/sink fixture evidence and host target evidence belong in their own run
reports. No portal, control runtime, private platform integration or future phase
is required to use the standalone recorder.
