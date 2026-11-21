// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The child of the network step of `ts-wire-privacy` (spec 055 §9.2, unit 055-t12): runs
 * Fabric's real delivery clients (content logs and trace export) and its redaction
 * client from the SDK source, in a process started with hostile `HTTP_PROXY`,
 * `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, provider base URLs and Node's startup proxy
 * mode. Every TCP connection this process opens is recorded through the
 * `net.client.socket` diagnostics channel. Prints one JSON line: the outcome of each call
 * and the connections (address and port only; never a canary).
 *
 *   node network-client.cjs '<json config>'
 */
import diagnostics_channel from "node:diagnostics_channel";
import http from "node:http";
import type net from "node:net";

import { RedactionClient } from "../../../../sdk/typescript/src/redaction.js";
import { TraceClient } from "../../../../sdk/typescript/src/wire/delivery.js";
import { NodeContentClient } from "../../../../sdk/typescript/src/wire/node-content.js";
import type { OtlpSpan } from "../../../../sdk/typescript/src/wire/otlp.js";

interface Config {
  /** The scripted loopback Node (`http://127.0.0.1:<port>`). */
  readonly node: string;
  /** The TLS Node, reachable only through the configured proxy (`https://<name>:<port>`). */
  readonly remoteNode: string;
  readonly caFile: string;
  /** `FABRIC_WIRE_PROXY` (a CONNECT proxy run by the parent). */
  readonly proxy: string;
  readonly redactionPort: number;
  readonly codes: readonly number[];
  readonly canaries: { readonly body: string; readonly credential: string };
  /**
   * Self-test only (never Fabric code): `fetch` sends one body through the global
   * dispatcher; `global_agent` sends one through `http.request` on Node's global agent,
   * which Node's startup proxy mode routes to `HTTP_PROXY` (Node 24.5 and later).
   */
  readonly fault?: "fetch" | "global_agent";
}

const config = JSON.parse(process.argv[2]!) as Config;
const C = config.canaries;
const connections: string[] = [];
diagnostics_channel.subscribe("net.client.socket", (message) => {
  const socket = (message as { socket: net.Socket }).socket;
  socket.once("connect", () => connections.push(`${socket.remoteAddress}:${socket.remotePort}`));
});

const headers = { authorization: `Bearer ${C.credential}` };
const item = (n: number) => ({
  descriptor: {
    role: "model.exchange.request",
    object_id: `object-${n}`,
    captured_at: "2026-10-07T00:00:01.120000+00:00",
  },
  body: Buffer.from(`{"prompt":"${C.body}-${n}"}`),
});
const span: OtlpSpan = {
  name: "fabric.model_call",
  traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
  spanId: "a3ce929d0e0e4736",
  kind: "client",
  startNs: 1_791_331_201_120_000_000n,
  endNs: 1_791_331_202_050_000_000n,
  attributes: { "fabric.wire.store_status": "stored" },
  status: "unset",
  serviceName: "svc-network",
  scope: { name: "fabric.wire", version: "0" },
};

async function main(): Promise<Record<string, unknown>> {
  const results: Record<string, unknown> = {};
  const target = (url: string, extra: object = {}) => ({ url, headers, timeoutMs: 5000, ...extra });
  // 1. Every redirect status from the delivery endpoints: a retry; Location never followed.
  for (const code of config.codes) {
    const content = new NodeContentClient(target(`${config.node}/redirect/${code}/v1/logs`), {
      serviceName: "svc-network",
      proxy: config.proxy,
    });
    const traces = new TraceClient(target(`${config.node}/redirect/${code}/v1/traces`), { proxy: config.proxy });
    results[`content_${code}`] = await content.sendMany([item(1), item(2)]);
    results[`content_single_${code}`] = await content.send(item(3));
    results[`traces_${code}`] = (await traces.export([span])).outcome;
    content.close();
    traces.close();
  }
  // 2. Every redirect status from the redaction service: the object is withheld (null).
  const redaction = new RedactionClient(
    { endpoint: `http://127.0.0.1:${config.redactionPort}`, timeoutMs: 5000 },
    { maxOutputBytes: 1 << 20 },
  );
  for (const code of config.codes) {
    const out = await redaction.transform(Buffer.from(`${C.body}-redaction`), {
      transformation: { id: "network-step", version: "1" },
      role: `code-${code}`,
      mode: "redact",
    });
    results[`redaction_${code}`] = out === null ? "withheld" : "transformed";
  }
  await redaction.close();
  // 3. Loopback delivery with FABRIC_WIRE_PROXY set: direct, accepted.
  const direct = new NodeContentClient(target(`${config.node}/v1/logs`), { serviceName: "svc-network", proxy: config.proxy });
  const directTraces = new TraceClient(target(`${config.node}/v1/traces`), { proxy: config.proxy });
  results.direct_proxied = direct.proxied || directTraces.proxied;
  results.direct_content = await direct.sendMany([item(4), item(5)]);
  results.direct_traces = (await directTraces.export([span])).outcome;
  direct.close();
  directTraces.close();
  // 4. Remote HTTPS delivery: only through the FABRIC_WIRE_PROXY tunnel, TLS verified.
  const remote = new NodeContentClient(target(`${config.remoteNode}/v1/logs`, { certificate: config.caFile }), {
    serviceName: "svc-network",
    proxy: config.proxy,
  });
  const remoteTraces = new TraceClient(target(`${config.remoteNode}/v1/traces`, { certificate: config.caFile }), {
    proxy: config.proxy,
  });
  results.remote_proxied = remote.proxied && remoteTraces.proxied;
  results.remote_content = await remote.sendMany([item(6), item(7)]);
  results.remote_traces = (await remoteTraces.export([span])).outcome;
  remote.close();
  remoteTraces.close();
  if (config.fault === "fetch") {
    // The self-test's leak: the global dispatcher honours the proxy environment and
    // follows redirects, which the gate must report.
    await fetch(`${config.node}/redirect/301/v1/logs`, {
      method: "POST",
      body: C.body,
      headers,
      signal: AbortSignal.timeout(2000),
    }).catch(() => undefined);
  }
  if (config.fault === "global_agent") {
    // The self-test's leak: Node's global http agent, which the startup proxy mode
    // sends through HTTP_PROXY. Proves the mode Fabric's private agents ignore was live.
    await new Promise<void>((resolve) => {
      const request = http.request(`${config.node}/v1/logs`, { method: "POST", headers, timeout: 2000 }, (res) => {
        res.resume();
        res.on("end", resolve);
      });
      request.on("error", () => resolve());
      request.on("timeout", () => {
        request.destroy();
        resolve();
      });
      request.end(C.body);
    });
  }
  return results;
}

main().then(
  (results) => {
    const line = `${JSON.stringify({ results, connections, node: process.versions.node })}\n`;
    // The self-test's fetch leaves undici's socket to the silent hostile proxy open; the
    // clean run must exit on its own (Fabric's clients leave no handle behind).
    if (config.fault === undefined) process.stdout.write(line);
    else process.stdout.write(line, () => process.exit(0));
  },
  (error: unknown) => {
    process.stdout.write(`${JSON.stringify({ error: error instanceof Error ? error.name : "Error" })}\n`);
    process.exitCode = 1;
  },
);
