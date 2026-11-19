# Get started: your Node.js agent

Record what your own Node.js agent does on this machine, then look at the
record. You need Node.js 22.18 or later and Docker; no Python. You write no
file, set no variable and make no key: Fabric generates everything it needs.

**What you get today.** Fabric does not yet capture a Node.js agent's model
calls by itself. Your agent reports its model and tool calls through the
SDK's API (the lines below), and Fabric delivers and shows them, labelled
*reported*. It cannot check them against the model's own bytes, so `verify`
says `decisions: unsupported(unsupported_runtime)` and never calls the run
verified. For a verified record of every model call, see
[the Python page](python.md).

## 1. Install

In your agent's project:

<!-- fabric-docs-test: path=laptop-node step=1 kind=install -->
```bash
npm install @singleaxis/fabric @opentelemetry/api@1.10.0 @opentelemetry/sdk-trace@3.1.0 @opentelemetry/context-async-hooks@3.1.0 @opentelemetry/exporter-trace-otlp-http@0.301.0
```

## 2. Report your agent's calls

Add these lines to your agent: one exporter, one `decision` around a task,
and a wrapper around each model call and tool call.

```js
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { BatchSpanProcessor, TracerProvider } from "@opentelemetry/sdk-trace";
import { Fabric, fabricExporterOptions, installDefaultProvider } from "@singleaxis/fabric";

const exporter = new OTLPTraceExporter(fabricExporterOptions());
const provider = new TracerProvider({ spanProcessors: [new BatchSpanProcessor({ exporter })] });
installDefaultProvider({ provider, contextManager: new AsyncLocalStorageContextManager() });
const fabric = Fabric.fromEnv();

await fabric.decision({ sessionId, requestId }, async (decision) => {
  const reply = await decision.llmCall({ provider: "openai", operationName: "chat", model },
    async (call) => { /* your model call */ });
  await decision.toolCall("get_weather", { callId }, async () => { /* your tool */ });
});
await provider.shutdown(); // before the process exits
```

`fabricExporterOptions()` sends these records to Fabric only; an
OpenTelemetry export your agent already has is left as it is.

## 3. Start the recorder

<!-- fabric-docs-test: path=laptop-node step=2 -->
```bash
npx fabric up
# expect: next: fabric run --
```

This runs Fabric's command-line tool from its container image (pulled once),
writes `fabric.yaml`, generates the keys and certificates into a private
directory, and starts the Fabric Node and a local destination,
`./fabric-data`. On macOS, turn on host networking in Docker Desktop
(Settings, Resources, Network) first.

## 4. Run your agent

<!-- fabric-docs-test: path=laptop-node step=3 -->
```bash
npx fabric run -- node agent.mjs
```

Your agent runs exactly as it would without Fabric: same arguments, input,
output and exit code. If anything in the setup is wrong it still runs, and
`npx fabric doctor` says why.

## 5. Check and see the record

<!-- fabric-docs-test: path=laptop-node step=4 -->
```bash
npx fabric verify
# expect: FC-065
# expect: decisions: unsupported(unsupported_runtime)
npx fabric show
# expect: verdict: reported (not verified)
```

`verify` sends a test exchange through the whole path and reads it back
(`FC-065`), then reads your run and lists what it reported (`FC-163`).
`show` lists each reported model and tool call.

## Next

- Stop the recorder with `npx fabric down`. Your records stay in `./fabric-data`.
- Something wrong: `npx fabric doctor`, and the [diagnostics catalogue](../diagnostics.md).
- What Fabric can see for your agent, and what stays invisible: `npx fabric plan -- node agent.mjs`.
