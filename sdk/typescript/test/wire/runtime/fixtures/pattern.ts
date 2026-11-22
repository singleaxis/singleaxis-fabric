// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/** The deterministic body producer `id` sends for its `n`-th exchange. */
export function patternBody(id: number, n: number): Buffer {
  const body = Buffer.alloc(8 + ((n * 7919) % 150_000));
  body.writeUInt32LE(id, 0);
  body.writeUInt32LE(n, 4);
  for (let at = 8; at < body.length; at++) body[at] = (id * 31 + n + at) & 0xff;
  return body;
}
