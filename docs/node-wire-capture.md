# Model-call capture for Node.js agents

> **Status:** qualified, undici only (spec 055 unit 055-t17). The gates `TS-1U`
> (`wire.ts.undici`) and `TS-1D` (protection, spool, sender and readback) passed
> on the builds listed below, so a release may carry the preload with this claim.
> Core HTTP (`node:http`, `TS-1H`) and worker threads are not part of it yet.

Fabric records the model calls a Node.js agent makes, as observed on the wire,
without changing the agent: the request and response bytes, timing,
cancellation and errors the agent sees stay exactly as they were. Each matched
call is protected by your capture policy before it is written anywhere,
spooled to disk (encrypted when you give it a key), and delivered to the
destination you choose. `python -m fabric.reconstruct` reads the record and
verifies it, as for a Python agent.

```text
CAPTURE -> PROTECT -> DELIVER
```

## What is captured

| Sends through | Captured |
|---|---|
| Global `fetch` (ES modules and CommonJS) | yes |
| The official `openai` client | yes (it sends through global `fetch`) |
| The official `@anthropic-ai/sdk` client | yes (it sends through global `fetch`) |
| A custom `fetch` that calls global `fetch` | yes, once |
| A custom `fetch` over `node:http` | no (declared uncaptured, class `node_http`) |
| `node:http` / `node:https` and libraries built on them | not yet (declared uncaptured, class `node_http`) |
| The `undici` npm package (`fetch`, `request`, `Client`, `Pool`, its HTTP/2 agent) | no: each matched call is a named `uninstrumented_client` loss (`FW-035`) |
| Worker threads | not yet (declared, `FW-030`) |
| Gemini, Bedrock, gRPC, WebSocket and realtime APIs | no |
| Bun and Deno | no (`unsupported_runtime`, `FW-026`) |

### Qualified builds

Capture is on only on the exact Node.js builds listed as `active` in the
package's compatibility table, `@singleaxis/fabric/wire-qualification.json`.
For each of them every CI gate of spec 055 §9.2 passed and its report is
committed under `qualification/node-wire/results/` (passivity, privacy,
Python/TypeScript parity, the client matrix, the negative rows, the chaos suite,
and the production profile through a real Fabric Node):

<!-- qualified-tuples:begin -->
| Node.js | Bundled undici | Platform |
|---|---|---|
| `24.4.0` | `7.11.0` | `linux-x64-glibc` |
| `24.22.3` | `7.30.2` | `linux-x64-glibc` |
<!-- qualified-tuples:end -->

This is not a claim for "Node.js 24 or later". On any other build (other Node.js
24 patches, Node.js 22, Node.js 24.0 to 24.3, whose undici publishes no body
chunks, Linux arm64, musl and macOS, which are audited but not yet qualified),
nothing is installed and the status says why (`FW-026`); the agent runs
unchanged. Linux and macOS on x64 and arm64 have the native lock module the
spool needs; other platforms report `FW-027`.

Limits of the claim:

- Only the undici inside Node.js is qualified. Loading the `undici` npm package
  also makes it the process-wide dispatcher, so global `fetch` then sends
  through that copy too: those calls are recorded as `uninstrumented_client`
  losses, and the run cannot verify complete (`FW-035`). Do not load the
  `undici` package in an agent you want recorded.
- A request whose response is cut short (an abort or cancel mid-stream, a
  closed connection) is recorded as far as it went, marked truncated, and its
  run reads back `partial`, as the Python SDK's runs do: the reader cannot
  vouch for a response it never saw whole. A call aborted before any response
  (an SDK timeout) is recorded with its request and response state `error`.
- `process.exit()` and `SIGKILL` cannot wait for delivery: what was spooled is
  delivered by the next process on the spool; a position allocated but never
  written makes that process's record incomplete, never falsely complete.
- The record is a passive copy: nothing here changes, blocks or delays a call.

## Turn it on with `fabric run`

With the operator CLI (`pip install "singleaxis-fabric[cli]"`, or its container
image), install the package in the agent's own project and start the agent
through `fabric run`:

```sh
npm install @singleaxis/fabric
fabric init && fabric up
fabric run -- node agent.mjs      # also npx, tsx, ts-node and `#!` node scripts
fabric verify
```

`fabric run` appends `--import=@singleaxis/fabric/register` to `NODE_OPTIONS`
(it never replaces what is there, and never adds it twice) and sets
`FABRIC_WIRE_AUTOLOAD=1` with the project's settings, only when all three hold:
the command runs Node.js; `@singleaxis/fabric` resolves from the agent's
working directory with its qualification gates passed and its preload file
present; and this Node.js build
and platform are listed `active` in the package's
`@singleaxis/fabric/wire-qualification.json`. Otherwise it starts the agent
unchanged (only the explicit API's tenant, agent and run label are added) and
names the reason and its fix: `FC-098` (package not installed: `npm i
@singleaxis/fabric`), `FC-099` (an installed copy without qualified capture:
`npm i @singleaxis/fabric@latest`), `FC-100` (this Node.js build is not
qualified; the message lists the ones that are) or `FC-101` (no qualified
build for this platform). `fabric verify` then reports model calls `recorded`,
or the same reason. `fabric run --print-env -- node agent.mjs` prints the same
environment for a launcher `fabric run` cannot wrap; its `docker` and `k8s`
formats describe a container, whose Node.js must be one of the listed builds.

## Turn it on by hand: no code change

Install the package next to the agent, then start the agent with the preload
and the gate variable. Append the flag to `NODE_OPTIONS`; never replace it.

```sh
npm install @singleaxis/fabric

export FABRIC_WIRE_AUTOLOAD=1
export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--import=@singleaxis/fabric/register"
export FABRIC_WIRE_SPOOL_DIR=/var/lib/my-agent/fabric-spool
export FABRIC_OTLP_ENDPOINT=http://127.0.0.1:4318   # your Fabric Node
node agent.mjs                                       # or agent.cjs
```

The preload installs capture synchronously, before the agent's first line runs,
in both ES module and CommonJS applications. A launcher that passes only `-r`
can use `--require=@singleaxis/fabric/register` instead, for a CommonJS entry
point. Without `FABRIC_WIRE_AUTOLOAD=1`
it does nothing (`FW-031`). Every other setting uses the same variables as the
Python SDK (`FABRIC_WIRE_ENDPOINTS`, `FABRIC_CAPTURE_POLICY`,
`FABRIC_WIRE_ID_KEY`, `FABRIC_WIRE_SPOOL_KEY`, `FABRIC_WIRE_CONTENT_ENDPOINT`,
`FABRIC_OTLP_*` and the rest; see [deployment](deployment.md)), so the
environment file `fabric init` writes configures a Node.js agent unchanged.

Short-lived scripts: the record is delivered by a bounded drain when the
process is about to exit. Set `FABRIC_WIRE_DRAIN_ON_EXIT_S` to let a batch or
serverless worker wait that many more seconds for delivery; records left
behind stay in the spool for the next process or a drainer (`FW-033`).
`process.exit()` and `SIGKILL` cannot wait for delivery.

## Or install it in code

```ts
import { install, run, endRun, resumeToken } from "@singleaxis/fabric/wire";

const capture = install(); // reads the same environment; never throws for capture
const token = await run({ runId: "order-1234" }, async () => {
  await agent(); // unchanged
  return resumeToken();
});
endRun({ outcome: "completed", stopReason: "goal_reached", resume: [token] });
await capture.close({ timeoutMs: 2000 });
```

`install()` throws only for malformed configuration (fixed text naming the
variable and the fix). A missing prerequisite returns a handle that captures
nothing, with `capture.reason` and `capture.status()` saying why. The preload
and `install()` share one runtime per process: a second `install()` with the
same settings returns the first handle. One with different settings (or its own
`transformations`) throws while the first is capturing; `await capture.close()`
first, then install again. A first handle that captures nothing is replaced.

## Why is nothing recorded? One command

Run it with the agent's environment:

```sh
node -p "require('@singleaxis/fabric/wire').envStatus()"
```

It reads the configuration, the compatibility table and the native module,
installs nothing and sends nothing, and prints the status document with each
warning's text and fix. Set `FABRIC_WIRE_STATUS_FILE` to have every process
write the same document at start and at exit (mode 0600), which
`fabric doctor` reads. Fabric prints nothing on the agent's stdout or stderr
unless `FABRIC_WIRE_DIAGNOSTICS=stderr`.

| Id | Meaning | Fix |
|---|---|---|
| `FW-006` | a model-looking request went to a host no endpoint covers | `status.unmatched_model_hosts` lists each host with the exact `FABRIC_WIRE_ENDPOINTS` value that records it |
| `FW-025` | the configuration is invalid; `reason_id` names the setting | the status names the variable and its fix |
| `FW-026` | this Node.js or undici build is not in the compatibility table (or the runtime is Bun or Deno) | run the agent on a listed Node.js build |
| `FW-027` | no native lock module for this operating system or CPU | Linux or macOS, x64 or arm64 |
| `FW-028` | the native lock module could not be used (`native_missing`, ...) | reinstall the package with its `prebuilds/` directory; keep the spool on a local disk |
| `FW-029` | a capture point is switched off (`FABRIC_WIRE_UNDICI=0`) | set it to `1` |
| `FW-030` | a worker thread records nothing | record from the main thread for now |
| `FW-031` | the preload ran but `FABRIC_WIRE_AUTOLOAD` is not `1` | set `FABRIC_WIRE_AUTOLOAD=1` |
| `FW-032` | the policy masks content and no redaction service is configured | set `FABRIC_REDACTION_ENDPOINT` or change the role's mode |
| `FW-033` | records wait in the spool with no process draining it | start the agent again, or set `FABRIC_WIRE_DRAIN_ON_EXIT_S` |
| `FW-034` | the spool directory is not set or cannot be used | set `FABRIC_WIRE_SPOOL_DIR` to a local directory the agent's user owns |
| `FW-035` | a model call went through an undici copy that is not Node's own; it was not recorded | send model calls through global `fetch` or a client that uses it; do not load the `undici` package |

Every id, with its exact text, is in [diagnostics](diagnostics.md).

## What the package installs

Installing `@singleaxis/fabric` runs no install script and installs no hook:
importing the package root records nothing on the wire. The tarball carries
one prebuilt native lock module per supported platform under `prebuilds/`,
each checked against a SHA-256 the loader embeds before it is loaded; nothing
is compiled on your machine. It never sends a request to a model provider, and
it never contacts SingleAxis.
