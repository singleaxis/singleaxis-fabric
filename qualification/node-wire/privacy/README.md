# `ts-wire-privacy`: the Node privacy gate

Spec 055 §9.2. Proves that wire capture writes nothing a capture policy does
not authorize. CI runs it as the `ts-wire-privacy` job and fails the PR when a
check fails.

```sh
cd sdk/typescript && npm ci && cd ../..
node qualification/node-wire/privacy/run.mjs --out privacy.json
```

`run.mjs` bundles the capture and a Fabric worker running the capture pipeline
from the SDK source (`lib/build.mjs`; the packed package replaces it from unit
055-t14), compiles the native lock module with the maintainers' script, runs
each scenario in a fresh child process (`children/scenario.mjs`) and writes one
JSON report. It needs a C compiler.

## Canary scan

One scenario per privacy mode of the two exchange roles (`retain_original`,
`metadata_only`, `omit`, `redact`, `masked_only`, `tokenize`) and one with
content capture disabled (`missing_id_key`). Each scenario runs an agent that
makes five model calls through global `fetch` (JSON, SSE, a gzip response, a
transport error mid-response, an abort mid-stream) with canaries planted in:
the prompt, the tool schema, the response, the URL path and query, the request
headers (authorization, cookie, API key), the response headers (set-cookie,
request id), an abort reason's `Error.name` and message, the clear run id
(`FABRIC_RUN_ID`), the agent id, the service name, the resource attributes and
the environment.

The scanner reads every byte Fabric produced: every file under the spool
directory raw (records, temps, quarantine, locks, ledger), each record
decrypted (as bytes, then parsed: headers, descriptors and every body), and
the agent process's output. It fails when:

- a canary appears anywhere except inside a content object whose policy mode
  is `retain_original` (and there only the prompt, tool schema and response);
- under any other mode an original body's SHA-256, a `source_sha256`, a
  `byte_range` or (for transformed objects) a `source_byte_length` appears;
- a scenario's spool holds fewer exchange records than calls, or under
  `retain_original` the planted body canaries were not found inside the
  retained objects (a vacuous scan proves nothing).

Not scanned yet, added by the units that produce those bytes: the OTLP
requests the sink receives, the Node's queue and the store (055-t13), the
registration files and the ledger under faults (055-t16), the status file and
the exit note (055-t14).

## Scanner self-test

The `retain_original` scenario again, with a test-only fault in the harness's
own Fabric worker (`lib/fabric-worker.ts`, never in the SDK) that adds one
canary to each record's span attributes and another to its spool header. The
scanner must report both; otherwise the gate fails.
