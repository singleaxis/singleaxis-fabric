// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Helpers of the run-structure tests (spec 055 §9.5, unit 055-t11): a run table bound to
 * a fresh runtime, with every message it sends to the Fabric worker recorded (and also
 * pushed through the real run ring), and allocation as a transport hook does it.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { bindRunTable, captureScope } from "../../../src/wire/run-api.js";
import type { WireRuntime } from "../../../src/wire/runtime.js";
import { segmentIdOf } from "../../../src/wire/seal.js";
import {
  type BindOptions,
  type MarkerMessage,
  type RunMessage,
  RunMessages,
  type SealMessage,
  SegmentTable,
  encodeRunMessage,
} from "../../../src/wire/segments.js";

import { isolate } from "../runtime/helpers.js";

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO = join(HERE, "..", "..", "..", "..", "..");

export const SOURCE = "s-" + "cd".repeat(16);
/** The id key the resume-token-v2 vectors use. */
export const VECTOR_KEY = Buffer.from("fabric-test-id-key-not-a-secret", "utf8");
export const MANIFEST = Object.freeze({
  manifestId: "0b7a8a52-6a0e-4b5e-9a39-0d6f7d1c2e11",
  digest: "sha256:" + "ab".repeat(32),
});

/** The shared resume-token vectors (spec 050 WP-00). */
export const TOKEN_VECTORS = JSON.parse(
  readFileSync(join(REPO, "contracts/coverage/v1/fixtures/vectors/resume-token-v2.json"), "utf8"),
) as {
  tokens: { name: string; token: string; parsed: Record<string, unknown> | null }[];
  run_identity: {
    name: string;
    rule: number;
    inputs: {
      tokens: string[];
      run_id: string | null;
      identity_mode: "pseudonymous" | "clear";
      key: string | null;
      run_id_emitted: boolean;
      minted: string;
    };
    expected: {
      run_id: string;
      id_basis: string;
      predecessors: string[];
      branch_ids: string[];
      tokens_rejected: number;
    };
  }[];
  end_run: {
    name: string;
    inputs: {
      tokens: string[];
      run_id: string | null;
      identity_mode: "pseudonymous" | "clear";
      key: string | null;
    };
    expected: Record<string, unknown> & { status: string };
  }[];
};

export interface Harness {
  readonly runtime: WireRuntime;
  readonly table: SegmentTable;
  readonly messages: RunMessage[];
  /** The marker field objects of `kind`, in the order sent. */
  markers(kind?: "run_start" | "run_end"): Record<string, any>[];
  seals(): SealMessage[];
  /** One position as a transport hook allocates it in the calling context. */
  alloc(): { sequence: bigint; segment: string | undefined };
}

/** A run table bound to a fresh runtime (and to the run API) for one test. */
export function harness(options: Partial<BindOptions> = {}): Harness {
  const runtime = options.runtime ?? isolate().runtime;
  const messages: RunMessage[] = [];
  const table = new SegmentTable({
    runtime,
    sourceId: SOURCE,
    key: VECTOR_KEY,
    manifest: () => MANIFEST,
    send: (message) => {
      messages.push(message);
      return encodeRunMessage(runtime, message);
    },
    ...options,
  });
  bindRunTable(table);
  return {
    runtime,
    table,
    messages,
    markers: (kind) =>
      messages
        .filter((m): m is MarkerMessage => m.t === "marker")
        .map((m) => m.fields as Record<string, any>)
        .filter((f) => kind === undefined || f.kind === kind),
    seals: () => messages.filter((m): m is SealMessage => m.t === "seal"),
    alloc: () => {
      const allocation = runtime.allocate(captureScope()?.runSlot ?? -1);
      return {
        sequence: allocation.sequence,
        segment: segmentIdOf(allocation.segmentHi, allocation.segmentLo),
      };
    },
  };
}

/** Unbinds the run table (afterEach). */
export function unbind(): void {
  bindRunTable(undefined);
}

/** A token's predecessor entry (the token without `fr3/<correlation>/` and branch). */
export function entryOf(token: string): string {
  const body = token.split("/").slice(token.startsWith("fr2/") ? 1 : 2);
  if (body[body.length - 1]!.startsWith("br-")) body.pop();
  return body.join("/");
}

/** Every message waiting in the runtime's run ring, as the Fabric worker reassembles them. */
export function ringMessages(runtime: WireRuntime): RunMessage[] {
  const ring = runtime.runRing!;
  const reader = new RunMessages();
  const out: RunMessage[] = [];
  for (let record = ring.peek(); record !== undefined; record = ring.peek()) {
    const message = reader.take(record.body);
    if (message !== undefined) out.push(message);
    ring.commit();
  }
  return out;
}
