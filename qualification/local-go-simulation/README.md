# Local production-GO rehearsal (synthetic only)

Status: **simulation, never a production GO or customer sign-off**. This
rehearsal uses the existing bounded model → no-shell terminal → binary file
artifact → model fixture and a disposable local kind namespace. Fabric OSS
remains passive CAPTURE → PROTECT → DELIVER; the fixture's reconciler is an
offline test consumer, not an OSS evaluation service.

## Pre-registered simulated scope

- Agent: `scripts/qualification/run_synthetic_agent_pilot.py` from the
  recorded clean Git commit, importing the wheel built and installed from
  that same commit. Python 3.11; no customer agent or provider credentials.
- Model route: fixture-owned loopback HTTP endpoint. Terminal route: bounded
  no-shell subprocess running `synthetic_agent_tool.py` under a new private
  work directory. File route: allowlisted `result.bin` before/after bytes.
- Required bytes: final visible model request/response and approved HTTP
  context; terminal argv, cwd context, stdin, ordered stdout/stderr and
  outcome; created/modified artifact bytes. `artifact.before` is conditional
  on a prior object. Source sequences, operation/attempt IDs and retries are
  required. Provider-hidden state and deterministic replay are not claimed.
- Limits: the provisional ceilings in `scope.v1.json` apply only to this
  fixture (1 MiB object, 8 MiB terminal output, 64 KiB stdin, 60 s tool and
  receiver-outage windows). They are not measured production capacity.
- Excluded routes: SSH, DB, browser/cloud, PTY, arbitrary subprocess/HTTP,
  background jobs and non-allowlisted files. They are **not proven
  unreachable** in a general Python process; the direct-provider bypass
  fixture must lower the verdict. This prevents promotion of the scope.
- Privacy: generated non-sensitive bytes only; the canary is allowed in the
  fixture's local governed-content store but forbidden in OTLP, sink files
  and Node logs. Local temporary files are not a customer retention policy.

## Simulated target and witnesses

Use a uniquely named namespace in an explicitly selected local kind cluster.
Build one Node image and wheel from the frozen commit, package one chart,
record their digests, and install the `shadow-production` profile with
test-only mTLS, export authentication, a persistent Node queue and a
controlled HTTPS sink that fsyncs requests before its test response. The
source spool and governed content objects live in separate private local
paths; the sink has its own PVC. The fixture's provider JSONL, terminal
JSONL and file pre/post inventory are truth inputs independent of recorder
events. Copy sink files out and reconcile each parsed record ID, role,
status, source sequence and digest—not counts alone.
The Node and sink run in Linux/arm64 containers, but this laptop script runs
the Python 3.11 agent fixture on the macOS host. It therefore cannot qualify
Linux agent-process behavior or kernel/host capture.
After the chart's namespace default-deny is installed, the simulation adds a
narrow sink-ingress policy allowing only the Fabric Node Pods to port 8443.
The first local attempt intentionally exposed this missing allowance: the
Node stayed healthy and queued records, but the sink stored none. The
rehearsal must verify that queued records arrive after the allowance; a
healthy Pod or policy object alone is insufficient.
The script also restarts its local port-forward after the deliberately
rejected unauthenticated TLS request; that handshake can end a port-forward
session without affecting the Collector Pod.

The actors below are **test roles, not people or signatures**:

| Role | Simulation actor | Missing customer proof |
| --- | --- | --- |
| Platform | Local kind operator | Approved target cluster, route inventory, enforced CNI and capacity |
| Storage/records | Local-path PVC and private directories | Customer IAM/KMS, retention, backup/restore, rotation and durable destination receipt |
| Privacy/security | Canary and negative-auth fixtures | Data classification, secret-finding disposition and policy approval |
| AI-system owner | Deterministic fixture controller | Pinned customer agent, endpoint and reachable tool inventory |
| Independent reviewer | Offline byte/operation/sink reconciler | Separately authenticated records and human reproduction/signature |
| Risk owner | None | Named decision authority and signed exact-scope packet |

## Acceptance and stop rule

Run clean, direct-bypass and missing-object cases. Require all clean fixture
operations/bytes and stored sink records to match independently, with no
privacy canary outside the content store. Bypass and missing object must be
`partial`; the clean case remains `unverified`, never
`verified_complete_for_declared_scope`, because source identity, pre-fsync
continuity and general durable receipts are absent. Any unexplained
discrepancy fails the rehearsal. The production decision is always
`NO_GO`; simulated approvals must never be presented as signatures.

This local kind release appears to enforce its namespace default-deny, but
the test does not qualify an intended customer's CNI or all policy routes.
Its local-path PVC is neither an encrypted customer content store nor a retention/backup
qualification. A successful rehearsal demonstrates the procedure and
identifies missing proofs; it does not satisfy spec 037–039 promotion gates.

## Reproduction

From a clean checkout of the candidate commit, run the local simulation
script with `FABRIC_SIM_KUBECONFIG` set to the dedicated kind kubeconfig and
`FABRIC_SIM_CLUSTER` set to its exact kind name. It refuses other contexts.
The script creates only a uniquely named namespace and temporary directory;
it does not delete a pre-existing cluster or volume. Evidence and test-only
private keys remain in the printed mode-0700 temporary directory. Protect or
delete that directory under the operator's local policy after review.

`scripts/qualification/run_local_go_simulation.sh` records exact commands,
artifact digests, source and sink reports, and a machine-readable simulated
decision in its output directory. Missing prerequisites or a failing check
stop the script and leave `NO_GO`.
