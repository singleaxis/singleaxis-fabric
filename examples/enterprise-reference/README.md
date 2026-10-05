# Durable enterprise capture reference

This reference binds the Python CAPTURE → PROTECT → DELIVER components into a
finite local deployment. It is a runnable qualification target, not a substitute
for the customer's production platform, cloud KMS or real OpenTelemetry Node.

The reference separates:

1. Passive application capture and privacy protection.
2. Encrypted restartable byte spool and fsynced source metadata journal.
3. Restartable immutable OTLP batches and acknowledged Node acceptance.
4. Independently persisted local HTTP ingress, destination acceptance and fresh
   destination readback, using separate issuer identities.
5. Explicit source/epoch/child closure and negative completeness decisions.

Durable admission is acknowledged only after fsync. Calls admitted before fsync
may be lost on process termination; independent source truth must account for
that window. Delivery acknowledgement is not destination durability. A process
that owns all reference keys can impersonate all reference roles: separate
production custody and authenticated workload identities are target gates.

Local keys are generated per run and retained only in the orchestrator's memory
or passed directly to child processes for the local fault campaign; they are not
production credentials. Durable state cannot be decrypted after losing the key.
No cloud credential, paid service, Docker daemon or native sensor is required.

Execution commands and measured results are added by the integration campaign.

## Run

From the repository root with the Python SDK and signing/test dependencies
installed (Python 3.11+):

```sh
python examples/enterprise-reference/run.py --output /tmp/fabric-reference-UNIQUE --iterations 20
```

Use a fresh output path. `report.json` contains independent exact-set readback,
per-stage delivery accounting, key/stage negatives, an explicit bypass mismatch,
crash/restart results and measured admission/recovery timing. The parent owns
both child-process handles; cleanup terminates only those service processes.

The campaign captures a real declared HTTP/1.1 body boundary using
`FinalHTTPAdapter`, with two digest-only receiver inventories. Baseline and
instrumented calls use separate receivers; a direct bypass is injected only
after the clean receiver set reconciles. Both request and response contain a
synthetic canary and use `masked_only` byte policy. The destination is stopped
while the application succeeds. Protected objects remain in an AES-256-GCM
spool, while metadata is accepted into the ingress process's persistent store.
The ingress is SIGKILLed and restarted, the application writers are reopened,
and all exact IDs/digests are checked against fresh destination inventory.
The destination is SIGKILLed/restarted again before another fresh readback.

The reference destination intentionally stores permitted derivatives without
claiming encryption or governed lifecycle. For retained originals use the
separately tested `GovernedLocalContentStore` and customer-governed production
destination adapters. Never point this reference service at real unapproved
content. Its ephemeral bearer tokens and keys are local test material. It uses
loopback HTTP and explicit tenant/run/scope binding, not production TLS/IAM.

## What the result means

`LOCAL_REFERENCE_CHECKS_PASS` means the finite checks in the report passed.
`production_verdict` remains `NO_GO`: no real OpenTelemetry Collector Node,
cloud IAM/KMS, native sensor, production route inventory or approved workload
budget was qualified by this command. A configured HTTP metadata transport can
send to a real Node, but the reference ingress is distinctly labeled and cannot
issue a destination-stage statement. Fresh exact receipts authenticate the
selected issuer's assertions; they do not make key custody independent.

Admission timing includes local HTTP work and in-process capture CPU, and is
reported separately from eventual recovery. The command does not apply an
invented performance threshold or claim cross-host benchmark comparability.
Pre-fsync admission remains unknown without independent source truth; the
sample never labels a restarted source journal complete merely because it
recovered available records.
