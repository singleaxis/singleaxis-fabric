// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Split and review-copy parity with Python (spec 055 §5, unit 055-t15): the same sides
 * go through Python's `wire/_protect.py` `Protector.side` and TypeScript's. After the
 * §7.3 substitution (minted object ids replaced by position; a part's derived id follows
 * its skeleton's) the descriptors and stored bytes are equal: split skeletons, part
 * ranges and media types, `part_cap`, part policies, `original_plus_masked` review copies
 * and their withholding. Both languages call a redaction service that answers every call
 * with `[redacted]`.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { encodeJson, parseJson } from "../../../src/wire/codec.js";
import { LOCAL_DEFAULT, type CapturePolicy } from "../../../src/wire/protect.js";
import { mask, startService, type TestService } from "../../redaction-service.js";
import { runPython } from "../registration/helpers.js";
import { policyDoc } from "../protect/helpers.js";
import {
  BASE,
  MASK,
  PART,
  PNG,
  REQUEST,
  WAV,
  bigRequest,
  policy,
  protectorOf,
  side,
} from "./helpers.js";

const PY = String.raw`
import json, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from fabric.deployment_policy import DeploymentPolicy
from fabric.redaction import RedactionService, Transformation
from fabric.wire._policy import LOCAL_DEFAULT, CapturePolicy
from fabric.wire._protect import Protector

class Mask(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", "10")
        self.end_headers()
        self.wfile.write(b"[redacted]")
    def log_message(self, *a):
        pass

server = ThreadingHTTPServer(("127.0.0.1", 0), Mask)
threading.Thread(target=server.serve_forever, daemon=True).start()
endpoint = f"http://127.0.0.1:{server.server_address[1]}"

def plain(value):
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    return value

out = {}
for case in json.loads(sys.stdin.read()):
    policy = (LOCAL_DEFAULT if case["policy"] is None
              else CapturePolicy.from_deployment(DeploymentPolicy(case["policy"])))
    transforms = {role: Transformation(t["id"], t["version"])
                  for role, t in case["transformations"].items()}
    protector = Protector(policy, max_body_bytes=case["max_body"], part_min_bytes=64,
                          transformations=transforms,
                          redaction=RedactionService(endpoint) if case["service"] else None,
                          tokenization_key=bytes(32))
    chunks = [bytes.fromhex(c) for c in case["chunks"]]
    data = b"".join(chunks)
    result = protector.side({**case["base"]}, case["role"], chunks, observed=len(data),
                            cut_reason=None, partial=case["partial"])
    out[case["name"]] = {"descriptors": [plain(o.descriptor) for o in result.objects],
                         "bodies": [o.data.hex() for o in result.objects],
                         "primary": None if result.primary is None else result.objects.index(result.primary),
                         "reason": result.reason, "truncated": result.truncated}
    protector.close()
server.shutdown()
print(json.dumps(out))
`;

interface Case {
  readonly name: string;
  readonly modes: { request?: string; part?: string } | undefined;
  readonly body: Buffer;
  readonly chunks?: Buffer[];
  readonly maxBody: number;
  readonly transformations?: Record<string, { id: string; version: string }>;
  readonly base?: Record<string, unknown>;
  readonly partial?: boolean;
}

const HUGE = Buffer.concat([
  Buffer.from("\x89PNG\r\n\x1a\n", "latin1"),
  Buffer.alloc(4096, 1),
]).toString("base64");
const TEXT = Buffer.from('{"messages":[{"content":"short text"}]}');
const CASES: Case[] = [
  {
    name: "retained split, two parts",
    modes: undefined,
    body: bigRequest([PNG, WAV]),
    maxBody: 1500,
  },
  { name: "part_cap", modes: undefined, body: bigRequest([HUGE, PNG]), maxBody: 2048 },
  {
    name: "part omitted",
    modes: { request: "retain_original" },
    body: bigRequest([PNG]),
    maxBody: 1100,
  },
  {
    name: "part metadata_only",
    modes: { request: "retain_original", part: "metadata_only" },
    body: bigRequest([PNG]),
    maxBody: 1100,
  },
  {
    name: "redacted skeleton, binary part withheld",
    modes: { request: "redact", part: "redact" },
    body: bigRequest([PNG]),
    maxBody: 1100,
    transformations: { [REQUEST]: MASK },
  },
  {
    name: "redacted skeleton, masked part",
    modes: { request: "redact", part: "masked_only" },
    body: bigRequest([PNG]),
    maxBody: 1100,
    transformations: { [REQUEST]: MASK, [PART]: MASK },
  },
  {
    name: "tokenized split",
    modes: { request: "tokenize", part: "tokenize" },
    body: bigRequest([PNG]),
    maxBody: 1100,
  },
  {
    name: "original_plus_masked whole side",
    modes: { request: "original_plus_masked" },
    body: TEXT,
    maxBody: 1100,
    transformations: { [REQUEST]: MASK },
  },
  {
    name: "original_plus_masked whole side, failed review",
    modes: { request: "original_plus_masked" },
    body: TEXT,
    maxBody: 1100,
  },
  {
    name: "original_plus_masked split side",
    modes: { request: "original_plus_masked", part: "retain_original" },
    body: bigRequest([PNG, WAV]),
    maxBody: 1500,
    transformations: { [REQUEST]: MASK },
  },
  {
    name: "original_plus_masked parts",
    modes: { request: "retain_original", part: "original_plus_masked" },
    body: bigRequest([PNG, WAV]),
    maxBody: 1500,
    transformations: { [PART]: MASK },
  },
  {
    name: "original_plus_masked parts, failed review",
    modes: { request: "retain_original", part: "original_plus_masked" },
    body: bigRequest([PNG, WAV]),
    maxBody: 1500,
  },
  {
    name: "original_plus_masked part over the cap",
    modes: { request: "retain_original", part: "original_plus_masked" },
    body: bigRequest([HUGE]),
    maxBody: 2048,
    transformations: { [PART]: MASK },
  },
  {
    name: "not split: event stream cut to whole chunks",
    modes: undefined,
    body: bigRequest([PNG]),
    chunks: [bigRequest([PNG]).subarray(0, 700), bigRequest([PNG]).subarray(700)],
    maxBody: 1100,
    base: { media_type: "text/event-stream" },
  },
  {
    name: "original_plus_masked cut side: review withheld with the cut",
    modes: { request: "original_plus_masked" },
    body: bigRequest([PNG]),
    chunks: [bigRequest([PNG]).subarray(0, 700), bigRequest([PNG]).subarray(700)],
    maxBody: 1100,
    base: { media_type: "text/plain" },
    transformations: { [REQUEST]: MASK },
  },
];

function capturePolicy(modes: Case["modes"]): CapturePolicy {
  return modes === undefined ? LOCAL_DEFAULT : policy(modes);
}

function privacy(modes: NonNullable<Case["modes"]>): Record<string, string> {
  const out: Record<string, string> = {};
  if (modes.request !== undefined) out[REQUEST] = modes.request;
  if (modes.part !== undefined) out[PART] = modes.part;
  return out;
}

/** §7.3: object ids by position. */
function substitute(result: { descriptors: unknown[]; bodies: string[] }): unknown {
  const descriptors = parseJson(encodeJson(result.descriptors)) as Record<string, unknown>[];
  const ids = new Map<string, string>();
  descriptors.forEach((d, i) => ids.set(String(d.object_id), `<object ${i}>`));
  const swap = (value: unknown): unknown =>
    typeof value === "string"
      ? (ids.get(value) ?? value)
      : Array.isArray(value)
        ? value.map(swap)
        : value !== null && typeof value === "object"
          ? Object.fromEntries(Object.entries(value).map(([k, v]) => [k, swap(v)]))
          : value;
  return { descriptors: swap(descriptors), bodies: result.bodies };
}

let service: TestService;
let python: Record<string, any>;
beforeAll(async () => {
  service = await startService(mask);
  python = runPython(
    PY,
    [],
    encodeJson(
      CASES.map((c) => ({
        name: c.name,
        policy: c.modes === undefined ? null : policyDoc(privacy(c.modes)),
        transformations: c.transformations ?? {},
        service: c.transformations !== undefined,
        max_body: c.maxBody,
        chunks: (c.chunks ?? [c.body]).map((b) => b.toString("hex")),
        base: { ...BASE, ...c.base },
        role: REQUEST,
        partial: c.partial ?? false,
      })),
    ),
  ) as Record<string, any>;
});
afterAll(async () => {
  await service.close();
});

describe("split and review copies equal Python's Protector", () => {
  for (const c of CASES) {
    it(c.name, async () => {
      const protector = protectorOf(capturePolicy(c.modes), {
        maxBodyBytes: c.maxBody,
        tokenizationKey: Buffer.alloc(32),
        ...(c.transformations === undefined
          ? {}
          : { transformations: c.transformations, redaction: { endpoint: service.endpoint } }),
      });
      const result = await side(protector, c.body, {
        pieces: c.chunks,
        base: c.base,
        partial: c.partial,
      });
      await protector.close();
      const ts = {
        descriptors: result.objects.map((o) => o.descriptor),
        bodies: result.objects.map((o) => Buffer.from(o.data).toString("hex")),
      };
      const py = python[c.name];
      expect(py.descriptors.length).toBeGreaterThan(0);
      expect(substitute(ts)).toEqual(substitute(py));
      expect(result.primary === undefined ? null : result.objects.indexOf(result.primary)).toBe(
        py.primary,
      );
      expect(result.reason ?? null).toBe(py.reason);
      expect(result.truncated).toBe(py.truncated);
    });
  }
});
