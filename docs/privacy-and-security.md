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

**Customer transformations.** `redact`, `masked_only` and the review copy
of `original_plus_masked` need your own transformation, performed by your
[redaction service](#redaction-service). Fabric ships no PII detector.
`tokenize`, `omit`, `metadata_only` and `retain_original` need no service.

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

## Redaction service

Fabric never runs your code: no imported module, callable, child process or
worker thread. The masking for `redact`, `masked_only` and the review copy
of `original_plus_masked` is done by a **redaction service you run** beside
the application, and the recorder calls it. The protocol is
[`contracts/redaction/v1`](../contracts/redaction/v1/README.md) (a draft in
the repository, not in the published contracts archive): one
`POST /v1/transform` per object, with the raw bytes as the body and the
transformation id and version, role and mode as `X-Fabric-*` headers; a
`200` answer carries the masked bytes.
[`examples/redaction-service/`](../examples/redaction-service/README.md) is
a small standard-library reference service (regular-expression rules from a
JSON file) with a Dockerfile and Compose and Kubernetes sidecar snippets. It
is an example, not a PII detector, and not part of any release artifact.

```bash
export FABRIC_REDACTION_ENDPOINT=unix:///run/fabric/redaction.sock   # or http://127.0.0.1:8181
export FABRIC_REDACTION_TOKEN_FILE=/run/secrets/fabric-redaction-token  # optional
```

- **Endpoint.** Only `unix:///absolute/path` or a loopback address
  (`http://127.0.0.1:<port>`, `http://[::1]:<port>`) is accepted; anything
  else fails at `install()` or recorder construction. No TLS, no proxy, and
  a redirect is a failure.
- **Token.** Optional. `FABRIC_REDACTION_TOKEN_FILE` must be a regular
  file owned by the process user with mode `0600`, holding one printable
  ASCII token (at most 4096 bytes). It is read once, sent as
  `Authorization: Bearer`, and never logged.
- **Bounds.** Calls run only on the recorder's worker (the capture worker
  thread in Python, the recorder's asynchronous drain in Node.js), never on
  the application's thread or event loop. Each call has a 5 s timeout
  (`timeout_s` / `timeoutMs`, at most 300 s) and at most two calls are in
  flight per recorder (`max_in_flight` / `maxInFlight`, at most 64).
- **Failure withholds, never leaks.** A status other than 200, a redirect,
  a timeout, an answer above the object cap, a connection error, the
  in-flight bound reached, or (wire capture) a masking role with no
  transformation or no service, produces a descriptor-only object (`not_captured`,
  `protection_status: withheld`, reason `protection_failed`); wire spans
  carry `fabric.wire.store_reason=protection_failed`. There is no fallback
  to raw bytes and no error body or exception text is kept. `WireStats`
  counts `redaction_timeouts`, `redaction_saturated` and
  `redaction_failures`. A slow or absent service loses content; it never
  delays or fails the monitored call. A crash between capture and
  protection persists nothing.

Name the transformation per role in code. Fabric records its id and version
on every stored object and sends them with each call:

```python
import dataclasses
import os

from fabric import wire
from fabric.wire import Transformation
from fabric.wire._config import config_from_env

config, _ = config_from_env(os.environ)   # reads FABRIC_REDACTION_ENDPOINT
mask = Transformation("example-mask", "1")
wire.install(dataclasses.replace(config, transformations={
    "model.exchange.request": mask, "model.exchange.response": mask,
}))
```

The explicit APIs take the same identity:
`ContentProtector(policy, transformations={role: Transformation(...)}, redaction=RedactionService(...))`
or `BytePrivacyPolicy(mode="masked_only", transformation_id=..., transformation_version=...)`
in Python, and
`new ContentProtector(policy, { transformations: { role: { id, version } }, redaction: { endpoint } })`
in TypeScript. Without an explicit `redaction`, both SDKs read
`FABRIC_REDACTION_ENDPOINT`. An explicit `ContentProtector` whose policy
has a masking role raises (throws) at construction when that role has no
transformation or no service is configured. Zero-code autoload cannot name
a transformation, so under autoload the masking modes withhold.

Module references (`"package.module:function"`), callables and TypeScript
`{ module, exportName }` redactors, used by earlier v0.8 builds, raise or
throw at construction with a pointer to this section.

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

**Caller-supplied ids are always pseudonymised.** A plain string is caller
input and is mapped, whatever its shape, even a value that already looks
like `r-`, `s-` or `lbl-` + 32 hex; this includes `FABRIC_SOURCE_ID` (unless
`FABRIC_WIRE_LABELS=clear`). Only ids a recorder itself returned pass
through unchanged: they are typed values (Python `fabric._sequence.EmittedId`,
a `str` subclass; TypeScript `EmittedId`), recognised by type and issuer,
never by shape. An emitted id that is serialised and read back is a plain
string again and is mapped. For continuity across processes and hosts,
pass the **same clear id** with the same key (the keyed mapping is
deterministic), never an emitted value.

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
  equal the binding. For spans, a record naming another tenant or source is
  a forgery signal: the whole batch is refused with `INVALID_ARGUMENT`, and
  a span naming no source is dropped on its own. Content records are
  validated after the Node's queue accepts them, so a content upload is
  acknowledged with HTTP 200 and an invalid record (wrong source or tenant,
  forged stamp, bad descriptor, digest mismatch) is dropped afterwards and
  logged (`source_unbound`, `tenant_not_allowed`, `bad_descriptor`,
  `digest_mismatch`). It never reaches the store, and `fabric.reconstruct`
  reports the missing object as a gap, never as complete.
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
- a slow, failing or absent redaction service stalling the agent (calls
  only on the recorder's worker, with timeout and in-flight bounds; failure
  withholds).

Not covered:

- a compromised agent host or process: it sees the plaintext and holds the
  ingress token and keys;
- a compromised Node: it holds the content key and store credentials;
- correctness and security of your redaction service, policy or
  classification of data (it receives raw content; run it on the same host
  or Pod and restrict its socket);
  Fabric ships no PII detector and makes no de-identification claim;
- traffic Fabric does not capture (see [limitations](limitations-and-roadmap.md));
- your destination's access control, retention, residency and legal
  obligations.

Report vulnerabilities as described in [SECURITY.md](../SECURITY.md).
