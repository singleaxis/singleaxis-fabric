# Production-profile synthetic kind qualification plan

Status: test plan implemented in `e2e-production-profile.yml`; Linux result
pending. This is an isolated, non-sensitive CI deployment proof for the
`shadow-production` Helm profile, not a customer production GO.
It extends the bounded model → terminal → artifact → model slice in spec 040.

## Topology and identity

- Run a disposable Linux kind cluster and namespace, with a uniquely named
  cluster and no existing volumes or customer data.
- Build Fabric Node once for the job, record its image ID; package and install
  the chart by SHA-256; build and install the Python wheel in a clean venv.
- Use an ephemeral test CA for a Node server certificate, an approved client
  certificate, and a separate HTTPS sink server certificate. Configure the
  production profile to require a client certificate, an explicit ingress
  peer, an HTTPS export endpoint with CA validation and bearer authentication,
  an explicit egress peer, and an fsync-enabled persistent queue.
- The fixture's single client certificate authenticates the TLS peer, **not**
  the tenant/source attributes inside OTLP. The test must not elevate those
  caller-supplied attributes to authenticated source identity.

## Acceptance

1. Verify chart render and installed Pod configuration retain the named
   secrets, receiver TLS/client CA, exporter TLS CA/auth, network-policy
   objects and persistent queue. The default kind CNI does not prove policy
   enforcement, so that remains a target-environment gate.
2. A valid client certificate can send the fixture. Missing/untrusted client
   certificate attempts fail and do not create a new fsynced sink record.
3. The deterministic installed-wheel agent fixture reconciles every expected
   provider, terminal and file byte object and outcome against independent
   fixture journals and filesystem inventory. Its offline AEEP projection is
   sent over loopback HTTPS with explicit CA and client certificate.
4. Copy the controlled sink's fsynced OTLP files from its Pod. Parse every
   AEEP log record; match record ID, event name, role, status,
   tenant/run/source/operation/attempt IDs and content digest exactly once.
   Neither canary nor local content refs may appear in sink bytes or Node
   logs. The direct-bypass and missing-object injections must remain
   `partial`, never complete.
5. Publish exact artifact IDs, discrepancy report, commands and skips. A
   failing or unrun gate retains `NO_GO`.

The first live run (`36324254204`) failed as intended: the generated auth
Secret included a trailing newline, so Go rejected the `Authorization` header
and all 78 required sink ID/digest checks failed. The fixture now writes the
header with no newline. A new Linux run must pass before this gate is marked
tested. Production Secret provisioning needs the same byte-level check; a
healthy Collector Pod is not delivery proof.

## Non-claims

The controlled sink's fsync readback is not an arbitrary customer's durable
receipt. This CI does not qualify source crash-before-fsync, passive
non-interference, real NetworkPolicy enforcement, tenant/certificate binding,
customer IAM/KMS/storage, retention/restore, host BPF, uninstrumented routes,
or a customer shadow pilot. No complete-run or compliance claim follows from
this test alone.
