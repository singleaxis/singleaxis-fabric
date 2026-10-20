# Privacy and security

Fabric's promise is to protect the record **before** it leaves the process
that captured it, keep it encrypted wherever Fabric stores it, and deliver
it only to a destination you choose. This page describes the controls that
v0.8 implements and what they do not cover. Source of truth: spec
[049](../specs/049-four-layer-capture-coverage.md) §7.

## Where data goes

```text
agent process                              Fabric Node                      your systems
model call bytes ─► PROTECT ─► spool ─────► otlp/content :4319 ─► fabriccontent ─► file dir or S3 (content)
(memory only)       (worker)  (encrypted)  otlp :4317/:4318 ─► fabricguard ─► OTLP destination (metadata)
```

- **Content** (request and response bodies, extracted parts) goes only to
  the content store. It never travels on telemetry.
- **Telemetry** carries ids, digests, sequence numbers, sizes, statuses and
  allowlisted metadata. No prompt, response, URL, query, header, path,
  error message or environment value.
- **HTTP headers, credentials and environment values are never captured.**
  Credentials inside a request body cannot be detected reliably; govern
  body roles with the capture policy.

## Profiles

| Profile | Selected by | Content capture needs | If something is missing |
|---|---|---|---|
| `production` | node mode (`FABRIC_WIRE_CONTENT_ENDPOINT` set), or `deployment.profile: production` in the capture policy | a capture policy (`FABRIC_CAPTURE_POLICY`), `FABRIC_WIRE_ID_KEY` (≥ 16 bytes) and, with a spool, `FABRIC_WIRE_SPOOL_KEY` | Content capture is **disabled**, metadata continues, and every exchange span carries `fabric.wire.store_reason` (`missing_capture_policy`, `missing_id_key`, `missing_spool_key`). The application is never blocked. |
| `local` | a `file://` store and no production marker | nothing: the implicit `fabric.local-default` policy keeps model exchanges as `retain_original` | Records are marked `profile: local` and are never production-qualified. |

Missing protection is not an error and never stops the application: autoload
and `install()` succeed, log the disabled state (reason only) at every
install, and `WireHandle.status()` reports it. A **malformed**
configuration (unreadable or invalid policy, key too short, invalid
endpoint, node mode without tenant or spool) raises at explicit `install()`;
autoload logs one warning and does not install.

## Protection modes (the PROTECT stage)

PROTECT runs on the capture worker thread, never on the application's
thread, **before** anything reaches the spool, a store or the network. Each
content role gets a mode from the capture policy (deployment-policy/v1); a
role the policy does not name is `omit`.

| Mode | What is stored | Digest of the original |
|---|---|---|
| `retain_original` | the exact bytes | yes |
| `redact` | the output of your transformation | no |
| `masked_only` | only the masked copy | no |
| `original_plus_masked` | the original, plus a separately referenced masked review copy | yes (original only) |
| `tokenize` | HMAC-SHA256 of the whole object with a tenant-scoped tokenization key (`FABRIC_TOKENIZATION_KEY`, ≥ 32 bytes, distinct from the id key) | no |
| `metadata_only` | a descriptor (role, length, status), no bytes | no |
| `omit` | nothing | no |

Wire-capture roles are `model.exchange.request`, `model.exchange.response`
and `model.exchange.part` (an extracted inline image, audio or file).
Example policy fragment:

```json
"privacy": {
  "model.exchange.request": "masked_only",
  "model.exchange.response": "retain_original",
  "model.exchange.part": "omit"
}
```

**Customer transformations.** `redact`, `masked_only` and the review copy of
`original_plus_masked` need your own transformation; Fabric ships no PII
detector. It is named by module reference (`"package.module:function"`,
bytes in, bytes out) and runs out of process: a separate `python -I` child
in Python (POSIX only; on Windows it always withholds), a `worker_threads`
Worker in TypeScript. In-process functions are refused. For wire capture the
transformation is configured only through
`fabric.wire.install(transformations={role: Transformation(transformation_id, version, ref, timeout_s)})`;
under zero-code autoload these modes withhold.

**Failure withholds, never leaks.** A transformation error, timeout
(default 5 s; the child is killed), non-bytes or oversized result,
saturation (more than two calls in flight), unsupported media or a missing
transformation produces a descriptor-only object (`not_captured`,
`protection_status: withheld`, reason `protection_failed`). There is no
fallback to raw bytes. A crash between capture and protection persists
nothing.

**Large requests.** A side up to `max_body_bytes` (default 32 MiB; at most
63 MiB in node mode) is stored whole. A larger JSON side, up to 64 MiB, is
split by typed extraction: each inline base64 part of at least 64 KiB
(OpenAI `image_url` data URLs, `input_audio`, files; Anthropic
`source.data`; Responses `input_image`/`input_file`; `b64_json`) becomes its
own `model.exchange.part` object and the rest is stored as a skeleton.
Each object is then protected separately. Under `retain_original` the
verifier reassembles the original and checks its digest; under masking
modes no original digest or byte range is kept. A part above
`max_body_bytes` is withheld; a side above 64 MiB or a non-JSON body is
truncated.

## Pseudonyms (keyed pseudonym v2)

Identifiers leave the process as keyed pseudonyms by default:

- wire capture: run ids (`r-`), source id (`s-`) and `service.name`
  (`svc-`) are `prefix` + 32 hex of HMAC-SHA256 keyed by
  `FABRIC_WIRE_ID_KEY`; model names outside the public allowlist become
  `m-` digests;
- decision API: `sess-`, `usr-`, `conv-`, `mkey-`, `agt-`, `tgt-` with a
  per-type subkey of the same key; without the key these ids are omitted.

In the production profile without `FABRIC_WIRE_ID_KEY`, nothing derived
from a caller- or host-supplied id leaves the process: the source id is
random per process and run ids fall back to generated values. In the local
profile without a key, wire labels use an **unkeyed** SHA-256, which anyone
who can guess the value can reverse; do not rely on it for privacy.
`FABRIC_WIRE_LABELS=clear` and `FABRIC_IDENTITY_MODE=clear` emit labels and
ids unchanged; use them only with values that are not personal data.

Keep the id key secret and stable: `fabric.reconstruct` needs it to match a
clear run id to its pseudonym.

## Encryption at rest

| Where | Mechanism | Key |
|---|---|---|
| Agent spool (`FABRIC_WIRE_SPOOL_DIR`) | AES-256-GCM envelope on every record | `FABRIC_WIRE_SPOOL_KEY` or `FABRIC_WIRE_SPOOL_KEY_FILE`: 32 bytes (base64, or raw in the file). Required in production. |
| Node content queue | `fabricenvelope` storage extension seals every queued value (AES-256-GCM) | Node-side key file (`FABRIC_CONTENT_KEY_FILE` in Compose, `content.encryption.keySecret` in Helm). Required in production. |
| Node file-backend store | `fabriccontent` `file.encryption_key_file` seals every object and descriptor | Same Node key. Required in production when the file backend is used. |
| S3 / S3-compatible store | Server-side encryption (`AES256` or `aws:kms`), always required by the exporter | Your S3/KMS configuration |
| Python explicit line (`DurableByteSpool`) | AES-256-GCM | Customer-supplied 32-byte key |

Fabric never stores a key; status and manifests name a key only by its
`kid-` id. With a spool key set, a plaintext spool record is never read: it
is quarantined (`*.corrupt`) and counted as a loss.
`FABRIC_WIRE_SPOOL_MIGRATE_PLAINTEXT=1` seals leftover plaintext records in
place, in the local profile only. Losing the Node key loses queued and
file-stored content; rotate it only with an empty queue.

Not encrypted by Fabric: the local-profile `file://` store, the auditd
logfile state, and the TypeScript content spool. Use encrypted volumes.

## Source authentication

In the production profile every agent batch is bound to one source:

- The Node's ingress accepts exactly one bearer token (a single-token
  `bearertokenauth`, shared by the `otlp` and `otlp/content` receivers;
  `fabric-gate` refuses any other receiver).
- `fabricguard` (`evidence_source_binding`) and `fabriccontent`
  (`source_binding`) require each record's tenant and `fabric.source_id` to
  equal the binding. A record naming another tenant or source is a forgery
  signal: the whole batch is refused with `INVALID_ARGUMENT`. A span naming
  no source is dropped on its own.
- The Node stamps `fabric.source.authenticated=true` on admitted spans and
  `source_authenticated: true` in every stored descriptor. It strips the
  span attribute when an agent supplies it, and refuses a content record
  that carries its own `source_authenticated` field.
- `fabric.reconstruct --profile production --trusted-source` reports a run
  `unverified` (`source_unauthenticated`) if any record or object lacks the
  stamp, or if the spans were imported from a file rather than read back
  from the Node's export or destination.

A stamp proves which ingress credential delivered a record, not that the
credential is held only by that agent; protect the token accordingly. One
production Node serves one agent source.

## Delivery and the Node

- `fabricguard` applies an exact-key allowlist to every span and log:
  unknown keys, maps, byte values, sensitive key names, log bodies, status
  messages and oversized values are removed; capture spans keep only their
  own closed key set and `service.name`.
- `fabric-gate`, the Node's entrypoint, refuses configurations that bypass
  this: a pipeline without `fabricguard`, an exporter that follows
  redirects, `--feature-gates`, `--set`, connectors, remote configuration,
  and in production any non-HTTPS or debug exporter.
- Content upload from the agent requires verified HTTPS, or plain HTTP to a
  loopback host only; redirects are never followed.
- Delivery is at least once. The Node does not prove that a destination
  durably stored a record.

## Python managed span export

`install_default_provider()` protects only the provider it installs: its
exporter removes content, exception text and event payloads and hashes
free-form strings. Exporters you configure yourself, and other
instrumentation libraries, are not changed by Fabric. Upstream
`capture_content=False` switches are not a privacy boundary: provider error
text can still reach spans through them. `capture_content=True` or
`FABRIC_CAPTURE_LLM_CONTENT=true` turns the protection off.

## Threat model

Fabric is designed to hold against:

- an agent, library or misconfiguration putting content on telemetry
  (allowlist at the SDK export and at the Node);
- a forged or misrouted batch claiming another tenant or source (binding);
- tampering with spool files, queue files or stored objects (envelopes and
  digests; the verifier reports `digest_mismatch` or `missing_object`);
- a downgrade by replacing spool records with plaintext (quarantine);
- a redirect or proxy sending content elsewhere (no redirects, verified
  TLS);
- a slow, crashing or malicious redaction function stalling the agent
  (out-of-process with timeout and capacity bounds).

Not covered:

- a compromised agent host or process: it sees the plaintext and holds the
  ingress token and keys;
- a compromised Node: it holds the content key and store credentials;
- correctness of your transformation, policy or classification of data;
  Fabric ships no PII detector and makes no de-identification claim;
- traffic Fabric does not capture (see [limitations](limitations-and-roadmap.md));
- your destination's access control, retention, residency and legal
  obligations.

Report vulnerabilities as described in [SECURITY.md](../SECURITY.md).
