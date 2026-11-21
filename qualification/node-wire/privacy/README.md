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

## Network step

Spec 055 §3.4 and §7.1 (unit 055-t12). `lib/network.mjs` runs Fabric's real
delivery clients (content logs and trace export, `src/wire/delivery.ts`,
`src/wire/node-content.ts`) and its redaction client in a child process
(`lib/network-client.ts`) started with hostile `HTTP_PROXY`, `HTTPS_PROXY`,
`ALL_PROXY` and an empty `NO_PROXY` (upper and lower case), provider base URLs
(`OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, `AZURE_OPENAI_ENDPOINT`) and Node's
startup proxy mode (`NODE_USE_ENV_PROXY=1`, plus `--use-env-proxy` where the
Node has it). The delivery and redaction endpoints answer 301, 302, 303, 307
and 308 with a `Location` on a recording socket; every hostile proxy and the
provider are recording sockets too. `FABRIC_WIRE_PROXY` is a CONNECT proxy in
front of a TLS Node whose certificate comes from a test CA (made with
`openssl`, which the step needs on `PATH`). The child records every TCP
connection it opens (`net.client.socket`).

It fails when any byte or connection reaches a hostile proxy, a redirect
target or the provider; when the configured proxy receives anything but
`CONNECT`, or a canary or the ingress credential in the clear; when the child
connects to an address that was not configured; or when an outcome differs (a
redirect is a `retry` for delivery and a withheld object for redaction, and is
requested exactly once; loopback delivery is direct and accepted even with
`FABRIC_WIRE_PROXY` set; remote delivery goes only through the tunnel and is
accepted).

Its self-test runs the child again with one body sent through the global
`fetch` dispatcher (which honours the proxy environment and follows
redirects); the step must report it, or the gate fails.
Where the Node has the `http`/`https` startup proxy mode (24.5 and later, the
releases with `--use-env-proxy`), a second self-test sends one body on Node's
global `http` agent; it must reach the hostile `HTTP_PROXY`, which proves the
mode was live in the child. The report's `startup_proxy_mode_active` says
whether the run exercised it. Node 24.4.0, the privacy job's main Node, has the
mode for `fetch` only, so CI runs the step again on the newest qualified Node
24:

```sh
node qualification/node-wire/privacy/run.mjs --network-only --require-startup-proxy-mode --out report.json
```

`--network-only` runs the network step and its self-tests alone;
`--require-startup-proxy-mode` fails the run on a Node without the mode.

## Scanner self-test

The `retain_original` scenario again, with a test-only fault in the harness's
own Fabric worker (`lib/fabric-worker.ts`, never in the SDK) that adds one
canary to each record's span attributes and another to its spool header. The
scanner must report both; otherwise the gate fails.
