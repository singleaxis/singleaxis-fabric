// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Helpers of the sender tests (spec 055 §9.5, unit 055-t13): spool records made from the
 * shared vectors, in-memory trace and content paths that script each outcome and record
 * a timeline, and a loopback Fabric Node that records the exact bytes it received.
 */
import { type IncomingMessage, type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";

import type { PostResult } from "../../../src/wire/delivery.js";
import type { ContentResult } from "../../../src/wire/node-content.js";
import type { ContentItem, OtlpSpan } from "../../../src/wire/otlp.js";
import type { ContentSender, TraceExporter } from "../../../src/wire/sender.js";
import { Spool } from "../../../src/wire/spool.js";

import { KEY, entryOf, native, spoolDir } from "../spool/helpers.js";

/** The vector exchange entry at `sequence` (its descriptors and attributes updated). */
export function exchangeAt(sequence: number): { doc: Record<string, unknown>; bodies: Buffer[] } {
  const { doc, bodies } = entryOf("exchange");
  const copy = globalThis.structuredClone(doc) as any;
  copy.span.attributes["fabric.source.sequence"] = sequence;
  copy.span.span_id = sequence.toString(16).padStart(16, "a");
  for (const body of copy.bodies) body.descriptor.source_sequence = sequence;
  return { doc: copy, bodies };
}

export function newSpool(dir = spoolDir(), pid?: number): Spool {
  return new Spool(dir, {
    maxBytes: 1 << 24,
    addon: native().addon,
    key: KEY,
    ...(pid === undefined ? {} : { pid }),
  });
}

export type Event =
  { kind: "content"; sequences: number[]; roles: string[] } | { kind: "traces"; spans: string[] };

/** Scripted in-memory delivery: each call takes the next scripted outcome (default ok). */
export class FakeDelivery {
  readonly timeline: Event[] = [];
  readonly sent: ContentItem[] = [];
  readonly exported: OtlpSpan[][] = [];
  contentScript: (item: ContentItem) => ContentResult = () => "ok";
  traceScript: (spans: readonly OtlpSpan[]) => PostResult = () => ({ outcome: "ok", status: 200 });
  lastResult: PostResult | undefined;

  readonly content: ContentSender = {
    send: async (item) => (await this.content.sendMany!([item]))[0]!,
    sendMany: async (items) => {
      this.timeline.push({
        kind: "content",
        sequences: items.map((i) => Number(i.descriptor.source_sequence)),
        roles: items.map((i) => String(i.descriptor.role)),
      });
      const results = items.map((item) => this.contentScript(item));
      items.forEach((item, i) => results[i] !== "retry" && this.sent.push(item));
      return results;
    },
  };

  readonly traces: TraceExporter = {
    export: async (spans) => {
      this.timeline.push({
        kind: "traces",
        spans: spans.map((s) => `${s.name}:${String(s.attributes["fabric.source.sequence"])}`),
      });
      const result = this.traceScript(spans);
      if (result.outcome === "ok") this.exported.push([...spans]);
      return result;
    },
  };
}

/** A loopback Fabric Node: the raw request bodies per path, in arrival order. */
export interface FakeNode {
  readonly url: string;
  readonly bodies: { path: string; body: Buffer }[];
  /** Status per request path (default 200). */
  status: (path: string) => number;
  close(): Promise<void>;
}

export async function fakeNode(): Promise<FakeNode> {
  const bodies: { path: string; body: Buffer }[] = [];
  const node = {
    bodies,
    status: () => 200,
  } as unknown as FakeNode;
  const server: Server = createServer((req: IncomingMessage, res) => {
    const parts: Buffer[] = [];
    req.on("data", (part: Buffer) => parts.push(part));
    req.on("end", () => {
      const path = req.url ?? "/";
      bodies.push({ path, body: Buffer.concat(parts) });
      res.writeHead(node.status(path), { "content-type": "application/x-protobuf" }).end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return Object.assign(node, {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  });
}

export const target = (url: string) => ({ url, headers: {}, timeoutMs: 5000 });
