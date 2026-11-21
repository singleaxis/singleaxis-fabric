// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Helpers of the undici hook tests (spec 055 §9.5, unit 055-t6): a scripted local
 * provider that records the exact bytes it received, a capture runtime with the hook
 * installed for that provider, and the jobs the Fabric worker would read.
 */
import { type IncomingMessage, type Server, type ServerResponse, createServer } from "node:http";
import type { AddressInfo } from "node:net";

import { endpointMatcher } from "../../../src/wire/match.js";
import { type RuntimeOptions } from "../../../src/wire/runtime.js";
import {
  type UndiciHook,
  type UndiciHookOptions,
  type UndiciMeta,
  installUndiciHook,
  readUndiciMeta,
} from "../../../src/wire/undici.js";
import { type Drained, drain, isolate } from "../runtime/helpers.js";

export type Route = (req: IncomingMessage, res: ServerResponse, body: Buffer) => void;

export interface Provider {
  readonly port: number;
  readonly base: string;
  /** Request bodies exactly as the server received them, in arrival order. */
  readonly received: Buffer[];
  route(path: string, route: Route): void;
  /** A route that answers as soon as the request starts, before its body has arrived. */
  early(path: string, route: (req: IncomingMessage, res: ServerResponse) => void): void;
  close(): Promise<void>;
}

/** A loopback HTTP/1.1 server; each path answers with its scripted route. */
export async function provider(): Promise<Provider> {
  const routes = new Map<string, Route>();
  const early = new Map<string, (req: IncomingMessage, res: ServerResponse) => void>();
  const received: Buffer[] = [];
  const server: Server = createServer((req, res) => {
    const first = early.get((req.url ?? "/").split("?")[0]!);
    if (first !== undefined) {
      req.resume();
      first(req, res);
      return;
    }
    const parts: Buffer[] = [];
    req.on("data", (part: Buffer) => parts.push(part));
    req.on("end", () => {
      const body = Buffer.concat(parts);
      received.push(body);
      const route = routes.get((req.url ?? "/").split("?")[0]!);
      if (route === undefined) {
        res.writeHead(404).end();
        return;
      }
      route(req, res, body);
    });
  });
  server.keepAliveTimeout = 100;
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    port,
    base: `http://127.0.0.1:${port}`,
    received,
    route: (path, route) => void routes.set(path, route),
    early: (path, route) => void early.set(path, route),
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

export const CHAT = "/v1/chat/completions";
export const MESSAGES = "/v1/messages";

export interface Capture {
  readonly hook: UndiciHook;
  readonly runtime: ReturnType<typeof isolate>["runtime"];
  readonly table: ReturnType<typeof isolate>["table"];
  /** Every completed job (bytes and decoded metadata) and loss since the last call. */
  jobs(): Job[];
  drained(): Drained;
  close(): void;
}

export type Job = Drained["jobs"][number] & { readonly undici: UndiciMeta };

/** A runtime with the hook installed for `port` on 127.0.0.1 (openai and anthropic paths). */
export function capture(
  port: number,
  options: Partial<UndiciHookOptions> & { runtime?: RuntimeOptions } = {},
): Capture {
  const { runtime, table } = isolate({ maxInflightBytes: 32 * 1024 * 1024, ...options.runtime });
  const endpoints = [
    endpointMatcher({
      endpointId: "local-openai",
      dialect: "openai",
      hosts: ["127.0.0.1"],
      ports: [port],
      schemes: ["http"],
    }),
    endpointMatcher({
      endpointId: "local-anthropic",
      dialect: "anthropic",
      hosts: ["127.0.0.1"],
      ports: [port],
      schemes: ["http"],
      pathPrefix: "/anthropic",
      providerName: "anthropic",
    }),
  ];
  const hook = installUndiciHook({ table, endpoints, ...options });
  let losses: Drained["losses"] = [];
  const drained = (): Drained => {
    const out = drain(table);
    losses = losses.concat(out.losses);
    return out;
  };
  return {
    hook,
    runtime,
    table,
    drained,
    jobs: () => drained().jobs.map((job) => ({ ...job, undici: readUndiciMeta(job.meta)! })),
    close: () => hook.uninstall(),
  };
}

/** Lets undici publish the events that follow the last await (trailers, error). */
export const settle = (ms = 20): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** The application's view of a response: the bytes of every chunk its reader got. */
export async function readAll(response: Response): Promise<Buffer[]> {
  const chunks: Buffer[] = [];
  const reader = response.body!.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return chunks;
    chunks.push(Buffer.from(value));
  }
}

/** A seeded PRNG (mulberry32): property tests replay the same cases. */
export function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Does this Node build publish the body-chunk channels (spec 055 §3.1)? */
export const PUBLISHES_BODIES = (() => {
  const [major, minor] = process.versions.node.split(".").map(Number) as [number, number];
  return major > 24 || (major === 24 && minor >= 4);
})();
