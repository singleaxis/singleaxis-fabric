// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * A Node process killed while PROTECT runs (unit 055-t8, "crash before protect leaves no
 * unprotected byte on disk"). It captures one model call whose roles are `redact`, and
 * its pipeline waits on a redaction service that never answers. Once the service holds
 * the request, it prints `{"protecting": true}`; the test then SIGKILLs it and scans the
 * spool directory.
 *
 *   node crash.cjs '<json: prebuilds, digest, spool, socket, canary>'
 */
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

import { ExchangeTable } from "../../../../src/wire/exchange.js";
import { endpointMatcher } from "../../../../src/wire/match.js";
import { loadNative, nativeTarget } from "../../../../src/wire/native.js";
import { WireRuntime, createRuntimeShared } from "../../../../src/wire/runtime.js";
import { Spool } from "../../../../src/wire/spool.js";
import { installUndiciHook } from "../../../../src/wire/undici.js";
import { CapturePipeline } from "../../../../src/wire/worker.js";

const config = JSON.parse(process.argv[2]!) as Record<string, string>;
const target = nativeTarget()!;
const loaded = loadNative({
  prebuildsDir: config.prebuilds,
  digests: { [target]: config.digest! },
});
if (!loaded.ok) throw new Error(loaded.reason);
const spool = new Spool(config.spool!, { maxBytes: 1 << 20, addon: loaded.addon });

const service = createServer(() => {
  process.stdout.write(JSON.stringify({ protecting: true }) + "\n"); // and never answer
});
const provider = createServer((req, res) => {
  req.resume();
  req.on("end", () =>
    res.writeHead(200, { "content-type": "application/json" }).end(`{"echo":"${config.canary}"}`),
  );
});

void (async () => {
  await new Promise<void>((resolve) => service.listen(config.socket, resolve));
  await new Promise<void>((resolve) => provider.listen(0, "127.0.0.1", resolve));
  const port = (provider.address() as AddressInfo).port;
  const runtime = new WireRuntime(createRuntimeShared(), "installer");
  const table = new ExchangeTable(runtime);
  installUndiciHook({
    table,
    endpoints: [
      endpointMatcher({
        endpointId: "local",
        dialect: "openai",
        hosts: ["127.0.0.1"],
        ports: [port],
        schemes: ["http"],
      }),
    ],
  });
  const roles = ["model.exchange.request", "model.exchange.response"];
  const policy = {
    schema_version: "fabric.deployment-policy/v1",
    policy_id: "crash",
    policy_version: 1,
    tenant_id: "tenant-a",
    workload_id: "w",
    privacy: Object.fromEntries(roles.map((r) => [r, "redact"])),
    storage: { backend: "local", region: "local", key_id: "k" },
    retention: { days: 1 },
    required_integrations: [],
    deployment: {
      profile: "local",
      image_digest: "local",
      tls_required: false,
      encrypted_store_required: false,
    },
  };
  const pipeline = new CapturePipeline(
    {
      sourceId: "s-" + "ef".repeat(16),
      tenantId: "tenant-a",
      serviceName: "svc-crash",
      node: false,
      store: true,
      spool: true,
      policy: policy as never,
      transformations: Object.fromEntries(roles.map((r) => [r, { id: "mask", version: "1" }])),
      redaction: { endpoint: `unix://${config.socket}`, timeoutMs: 300_000 },
      maxBodyBytes: 1 << 20,
      idKey: undefined,
      spoolKey: undefined,
      tokenizationKey: undefined,
      endpoints: [{ endpointId: "local", providerName: "openai" }],
      enrichment: {
        points: {},
        endpointIds: {},
        identity: {},
        requestIdKey: undefined,
        modelAllowlist: [],
      },
    },
    spool,
    { lose: () => undefined },
  );
  const body = JSON.stringify({ messages: [{ role: "user", content: config.canary }] });
  await (
    await fetch(`http://127.0.0.1:${port}/v1/chat/completions`, { method: "POST", body })
  ).arrayBuffer();
  await new Promise((resolve) => setTimeout(resolve, 20));
  const record = runtime.jobs.peek();
  if (record === undefined) {
    throw new Error(
      "no captured job: this Node build publishes no body chunks; run the crash fixture on a listed Node 24 build",
    );
  }
  await pipeline.handle(table.job(record.byteOffset), table.arena, runtime.epoch);
})();
