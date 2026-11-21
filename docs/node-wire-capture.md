# Model-call capture for Node.js agents

> **Status:** built, not yet released. The package that carries it exports the
> preload, and the release workflow refuses to publish such a package until the
> qualification gates `TS-1U` and `TS-1D` pass (spec 055 unit 055-t17). Until
> then this page describes what the source tree builds and tests.

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
| `node:http` / `node:https` and libraries built on them | not yet (declared uncaptured, class `node_http`) |
| Worker threads | not yet (declared, `FW-030`) |
| WebSocket and realtime APIs | no |

Capture is on only on the exact Node.js builds listed as `active` in the
package's compatibility table, `@singleaxis/fabric/wire-qualification.json`
(today: Node.js 24.4.0 and 24.22.3 on Linux x64 with glibc). On any other build,
Node.js 22 included, nothing is installed and the status says why (`FW-026`);
the agent runs unchanged. Linux and macOS on x64 and arm64 have the native lock
module the spool needs; other platforms report `FW-027`.

## Turn it on: no code change

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
same settings returns the first handle, and one with different settings throws
until you `close()` the first.

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
| `FW-025` | the configuration is invalid; `reason_id` names the setting | the status names the variable and its fix |
| `FW-026` | this Node.js or undici build is not in the compatibility table | run a listed Node.js 24 build |
| `FW-027` | no native lock module for this operating system or CPU | Linux or macOS, x64 or arm64 |
| `FW-028` | the native lock module could not be used (`native_missing`, ...) | reinstall the package with its `prebuilds/` directory; keep the spool on a local disk |
| `FW-029` | a capture point is switched off (`FABRIC_WIRE_UNDICI=0`) | set it to `1` |
| `FW-030` | a worker thread records nothing | record from the main thread for now |
| `FW-031` | the preload ran but `FABRIC_WIRE_AUTOLOAD` is not `1` | set `FABRIC_WIRE_AUTOLOAD=1` |
| `FW-032` | the policy masks content and no redaction service is configured | set `FABRIC_REDACTION_ENDPOINT` or change the role's mode |
| `FW-033` | records wait in the spool with no process draining it | start the agent again, or set `FABRIC_WIRE_DRAIN_ON_EXIT_S` |
| `FW-034` | the spool directory is not set or cannot be used | set `FABRIC_WIRE_SPOOL_DIR` to a local directory the agent's user owns |

Every id, with its exact text, is in [diagnostics](diagnostics.md).

## What the package installs

Installing `@singleaxis/fabric` runs no install script and installs no hook:
importing the package root records nothing on the wire. The tarball carries
one prebuilt native lock module per supported platform under `prebuilds/`,
each checked against a SHA-256 the loader embeds before it is loaded; nothing
is compiled on your machine. It never sends a request to a model provider, and
it never contacts SingleAxis.
