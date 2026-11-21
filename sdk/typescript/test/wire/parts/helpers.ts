// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Helpers of the split and review-copy tests (spec 055 §5, unit 055-t15): request
 * bodies with inline parts, the capture policy of the three exchange roles, one side
 * through the {@link Protector}, and a reader's reassembly of a split side.
 */
import { createHash } from "node:crypto";

import { DeploymentPolicy } from "../../../src/deployment-policy.js";
import {
  type CapturePolicy,
  type ContentObject,
  Protector,
  type ProtectorOptions,
  type SideResult,
  capturePolicyOf,
} from "../../../src/wire/protect.js";
import { TOKEN_KEY, policyDoc } from "../protect/helpers.js";

export const REQUEST = "model.exchange.request";
export const RESPONSE = "model.exchange.response";
export const PART = "model.exchange.part";
export const SECRET = "canary-ssn-078-05-1120";
export const PNG = Buffer.concat([
  Buffer.from("\x89PNG\r\n\x1a\n", "latin1"),
  Buffer.alloc(768).map((_, i) => i % 256),
]).toString("base64"); // 1036 base64 bytes
export const WAV = Buffer.concat([
  Buffer.from("RIFF\0\0\0\0WAVEfmt ", "latin1"),
  Buffer.alloc(1024),
]).toString("base64"); // 1388 base64 bytes
export const BASE: Readonly<Record<string, unknown>> = {
  schema_version: "fabric.content-object/v2",
  tenant_id: "tenant-a",
  media_type: "application/json",
  content_encoding: "identity",
  provenance: "protocol",
  boundary: "provider_bound",
  source_id: "s-" + "a".repeat(32),
  source_epoch: 1n,
  source_sequence: 0n,
  captured_at: "2026-10-19T09:00:00+00:00",
  run_id: "r-" + "b".repeat(32),
  operation_id: "0f4c2a7e-9b1d-4e3f-8a6c-5d2e1b0a9f8e",
};
export const MASK = { id: "acme-part-mask", version: "2" };

export const sha = (data: Uint8Array): string =>
  "sha256:" + createHash("sha256").update(data).digest("hex");

/** A chat request: the text (with the canary), then each part as an image data URL. */
export function bigRequest(parts: readonly string[], text = "describe " + SECRET): Buffer {
  const content: unknown[] = [{ type: "text", text }];
  for (const part of parts) {
    content.push({ type: "image_url", image_url: { url: "data:image/png;base64," + part } });
  }
  return Buffer.from(JSON.stringify({ model: "gpt-4o", messages: [{ role: "user", content }] }));
}

/** A capture policy naming these roles (`request`, `response`, `part`). */
export function policy(modes: {
  request?: string;
  response?: string;
  part?: string;
}): CapturePolicy {
  const privacy: Record<string, string> = {};
  if (modes.request !== undefined) privacy[REQUEST] = modes.request;
  if (modes.response !== undefined) privacy[RESPONSE] = modes.response;
  if (modes.part !== undefined) privacy[PART] = modes.part;
  return capturePolicyOf(new DeploymentPolicy(policyDoc(privacy)));
}

export function protectorOf(
  capture: CapturePolicy,
  options: Partial<ProtectorOptions> = {},
): Protector {
  return new Protector(capture, {
    maxBodyBytes: 1 << 20,
    partMinBytes: 64,
    tokenizationKey: TOKEN_KEY,
    ...options,
  });
}

/** One whole side through `protector` (a complete, exact side unless told otherwise). */
export function side(
  protector: Protector,
  data: Buffer,
  options: {
    role?: string;
    pieces?: Uint8Array[];
    cut?: string;
    partial?: boolean;
    base?: Record<string, unknown>;
  } = {},
): Promise<SideResult> {
  return protector.side(
    { ...BASE, ...options.base },
    options.role ?? REQUEST,
    options.pieces ?? [data],
    {
      observed: data.byteLength,
      cutReason: options.cut,
      partial: options.partial ?? false,
    },
  );
}

/** The `byte_range` of a part's `part_of` link. */
export function rangeOf(object: ContentObject): [number, number] {
  const links = object.descriptor.links as { byte_range?: [number, number] }[];
  return links[0]!.byte_range!;
}

/** A reader's reassembly: every part inserted at its range, ascending, into the skeleton. */
export function reassemble(skeleton: Uint8Array, parts: readonly ContentObject[]): Buffer {
  const sorted = [...parts].sort((a, b) => rangeOf(a)[0] - rangeOf(b)[0]);
  const pieces: Uint8Array[] = [];
  let pos = 0;
  let consumed = 0;
  for (const part of sorted) {
    const [start, end] = rangeOf(part);
    const take = start - consumed;
    pieces.push(skeleton.subarray(pos, pos + take), part.data);
    pos += take;
    consumed = end;
  }
  pieces.push(skeleton.subarray(pos));
  return Buffer.concat(pieces);
}

/** No original byte, digest, length or range in a protected side's objects. */
export function expectNothingOriginal(
  result: SideResult,
  original: Buffer,
  parts: readonly string[],
  expect: (value: unknown) => any,
): void {
  const digest = sha(original).slice(7);
  const text = JSON.stringify(
    result.objects.map((o) => o.descriptor),
    (_k, v: unknown) => (typeof v === "bigint" ? String(v) : v),
  );
  expect(text.includes(digest)).toBe(false);
  for (const object of result.objects) {
    const bytes = Buffer.from(object.data).toString("latin1");
    expect(bytes.includes(SECRET)).toBe(false);
    for (const part of parts) expect(bytes.includes(part)).toBe(false);
    for (const link of (object.descriptor.links as Record<string, unknown>[] | undefined) ?? []) {
      expect("byte_range" in link).toBe(false);
    }
  }
}
