// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §13.2 (unit 055-t13): the fixture replayer sends a recorded exchange through
 * the real hook and pipeline, and Python's drainer reads the spool it returns: manifest 0,
 * the exchange with the fixture's exact request and response bytes, and `final`.
 */
import { afterAll, describe, expect, it } from "vitest";

import { type ExchangeFixture, KEY, replayExchange } from "../fixtures/replay.js";
import { cleanupDirs, runPython } from "../spool/helpers.js";
import { PUBLISHES_BODIES } from "../undici/helpers.js";

afterAll(() => cleanupDirs());

const PY_READ = `
import json, sys
from fabric.wire._spool import Spool, unframe_all, valid_header
spool = Spool(sys.argv[1], 1 << 26, key=bytes.fromhex(sys.argv[2]))
out = []
try:
    for name in spool.names():
        for doc, blob in unframe_all(spool.read(name)):
            item = {"kind": (doc.get("marker") or {}).get("kind", doc["record_kind"]),
                    "ok": valid_header(doc, len(blob))}
            if doc["record_kind"] == "exchange":
                item["bodies"] = [bytes(blob[b["offset"]:b["offset"] + b["length"]]).hex()
                                  for b in doc["bodies"]]
                item["api"] = doc["span"]["attributes"]["fabric.wire.api"]
                item["point"] = doc["span"]["attributes"]["fabric.capture.point"]
            out.append(item)
finally:
    spool.release()
print(json.dumps(out))
`;

const SSE = [
  'event: message_start\ndata: {"type":"message_start","message":{"id":"msg_1","model":"claude-x","role":"assistant","content":[]}}\n\n',
  'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}\n\n',
  'event: message_stop\ndata: {"type":"message_stop"}\n\n',
];

const FIXTURES: [string, ExchangeFixture, string][] = [
  [
    "openai JSON",
    {
      request: '{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}',
      response:
        '{"id":"chatcmpl-1","choices":[{"index":0,"message":{"role":"assistant","content":"hi"}}]}',
    },
    "openai.chat_completions",
  ],
  [
    "anthropic SSE in chunks",
    {
      dialect: "anthropic",
      request:
        '{"model":"claude-x","stream":true,"max_tokens":8,"messages":[{"role":"user","content":"hello"}]}',
      responseHeaders: { "content-type": "text/event-stream" },
      response: SSE,
    },
    "anthropic.messages",
  ],
];

describe.skipIf(!PUBLISHES_BODIES)("replayExchange", { timeout: 60_000 }, () => {
  it.each(FIXTURES)(
    "%s: the spool holds the fixture's exact bytes, as Python reads them",
    async (_, fixture, api) => {
      const replayed = await replayExchange(fixture);
      const response = Array.isArray(fixture.response)
        ? fixture.response.join("")
        : fixture.response;
      expect(replayed.read.toString()).toBe(response);
      expect(replayed.received.toString()).toBe(fixture.request);
      expect(replayed.closed).toBe(true);
      const records = runPython(PY_READ, [replayed.dir, KEY.toString("hex")]) as any[];
      expect(records.map((r) => r.kind)).toEqual(["manifest", "exchange", "final"]);
      expect(records.every((r) => r.ok)).toBe(true);
      const exchange = records[1];
      expect(exchange.api).toBe(api);
      expect(exchange.point).toMatch(/^wire\.ts\.undici@/);
      expect(exchange.bodies.map((hex: string) => Buffer.from(hex, "hex").toString())).toEqual([
        fixture.request,
        response,
      ]);
    },
  );
});
