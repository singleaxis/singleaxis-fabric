// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Span and descriptor parity with Python (spec 055 §7.1, §7.3; unit 055-t8): the same
 * exchanges go through Python's `Protector`, `CapturePipeline._prepare`, `_span_record`
 * and `exchange_doc`, and through TypeScript's writer. After the §7.3 substitution
 * (minted object and span ids replaced by position) the spool entries are equal, keys,
 * values and body bytes. One documented difference: Python reads `gen_ai.response.*`
 * and `gen_ai.usage.*` from the raw response even when the policy withholds or masks it;
 * spec 055 §7.1 allows metadata only from policy-permitted evidence, so TypeScript omits
 * them unless the response is retained as is. Those keys are compared only there.
 */
import { describe, expect, it } from "vitest";

import { DeploymentPolicy } from "../../../src/deployment-policy.js";
import { encodeJson, parseJson } from "../../../src/wire/codec.js";
import { LOCAL_DEFAULT, ROLES, decideGate } from "../../../src/wire/protect.js";
import { ROLE_ROWS, ROLE_TABLE_VERSION } from "../../../src/wire/roles.generated.js";
import { type CapturedExchange, exchangeEntry, prepareExchange } from "../../../src/wire/writer.js";
import { runPython } from "../registration/helpers.js";
import {
  CHAT_REQUEST,
  CHAT_RESPONSE,
  ENRICHMENT,
  ID_KEY,
  TENANT,
  TOKEN_KEY,
  exchange,
  policyDoc,
  protector,
} from "./helpers.js";

const PY = String.raw`
import json, sys
from opentelemetry import trace
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags
from fabric._roles import ROLE_ROWS, ROLE_TABLE_VERSION
from fabric._sequence import encode_opaque_id
from fabric.deployment_policy import DeploymentPolicy
from fabric.wire._attrs import WireEnrichment, WireJob
from fabric.wire._model import CapturedBody
from fabric.wire._pipeline import CapturePipeline
from fabric.wire._policy import LOCAL_DEFAULT, decide
from fabric.wire._protect import Protector
from fabric.wire._spool import exchange_doc

class Loss:
    def queue_marker(self, *a, **k): pass
    def record(self, *a, **k): pass

def body(side):
    if side is None:
        return None
    return CapturedBody([bytes.fromhex(side["hex"])], len(bytes.fromhex(side["hex"])), False,
                        media_type=side["media"], content_encoding=side["encoding"])

cases = json.loads(sys.stdin.read())
out = {"roles": [[r.role, list(r.boundary), list(r.provenance), list(r.media_types),
                  r.default_policy, r.cap, None if r.allowed_modes is None else list(r.allowed_modes)]
                 for r in ROLE_ROWS],
       "role_table_version": ROLE_TABLE_VERSION, "local_default": LOCAL_DEFAULT.policy_digest,
       "cases": {}}
for name, case in cases.items():
    policy = DeploymentPolicy(case["policy"]) if case["policy"] is not None else None
    id_key = bytes.fromhex(case["id_key"]) if case["id_key"] else None
    gate = decide(node=case["node"], store=not case["node"], policy=policy, id_key=id_key,
                  spool=case["node"], spool_key=True)
    protector = Protector(gate.policy, max_body_bytes=32 * 1024 * 1024,
                          tokenization_key=bytes.fromhex(case["token_key"])) if gate.enabled else None
    pipeline = CapturePipeline(store=None, tracer_provider=None, loss=Loss(), node_tenant_id="tenant-a",
                               sender=object(), gate=gate, protector=protector)
    parent = None
    if case["parent"] is not None:
        sc = SpanContext(int(case["parent"]["trace_id"], 16), int(case["parent"]["span_id"], 16),
                         False, TraceFlags(TraceFlags.SAMPLED))
        parent = trace.set_span_in_context(NonRecordingSpan(sc))
    run_id = (f"trace:{case['parent']['trace_id']}" if parent is not None
              else encode_opaque_id(f"source:{case['source_id']}:{case['epoch']}"))
    enrichment = WireEnrichment(points={"wire.ts.undici": "wire.ts.undici@1.0.0"},
                                endpoint_ids={"openai": "openai.default", "anthropic": "anthropic.default"},
                                identity=case["identity"],
                                request_id_key=bytes.fromhex(case["request_id_key"]) if case["request_id_key"] else None)
    job = WireJob(exchange_id=case["exchange_id"], api=case["api"], provider_name=case["provider"],
                  source_id=case["source_id"], source_epoch=case["epoch"], source_sequence=case["sequence"],
                  run_id=run_id, parent_context=parent, started_ns=case["start"], ended_ns=case["end"],
                  request=body(case["request"]), response=body(case["response"]),
                  response_state=case["state"], http_status_code=case["status"], error_type=case["error"],
                  segment_id=case["segment"], event_id=case["event_id"], capture_point="wire.ts.undici",
                  endpoint_id=case["endpoint"], first_chunk_offset_ns=case["first_chunk"],
                  provider_request_id=case["request_id"], enrichment=enrichment)
    attrs, staged = pipeline._prepare(job)
    span = pipeline._span_record(job, attrs)
    doc = exchange_doc(case["source_id"], case["epoch"], "svc-test", span, staged)
    out["cases"][name] = {"doc": doc, "bodies": [data.hex() for _, data in staged]}
    pipeline.close(0.1)
print(json.dumps(out))
`;

interface Case {
  readonly job: CapturedExchange;
  readonly mode: string | undefined;
  readonly idKey: boolean;
}

const sseResponse = Buffer.from(
  'event: message_start\ndata: {"type":"message_start","message":{"model":"claude-sonnet-4-5"}}\n\n' +
    'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"text":"RESPONSE-CANARY-2"}}\n\n',
);
const errorBody = Buffer.from('{"error":{"message":"rate limited","type":"rate_limit_error"}}');

const CASES: Record<string, Case> = {
  retain_original: { job: exchange(), mode: "retain_original", idKey: true },
  local_default_root: { job: exchange({ parent: undefined }), mode: undefined, idKey: false },
  metadata_only: { job: exchange(), mode: "metadata_only", idKey: true },
  omit: { job: exchange(), mode: "omit", idKey: true },
  tokenize: { job: exchange(), mode: "tokenize", idKey: true },
  content_disabled: { job: exchange(), mode: "retain_original", idKey: false },
  provider_error: {
    job: exchange({
      statusCode: 429,
      response: { ...exchange().response!, pieces: [errorBody], observed: errorBody.length },
    }),
    mode: "retain_original",
    idKey: true,
  },
  transport_error_no_response: {
    job: exchange({
      response: undefined,
      responseState: "error",
      statusCode: undefined,
      errorType: "UND_ERR_SOCKET",
      firstChunkOffsetNs: undefined,
    }),
    mode: "retain_original",
    idKey: true,
  },
  sse_closed_early_enriched: {
    job: exchange({
      api: "anthropic.messages",
      providerName: "anthropic",
      endpointId: "anthropic",
      responseState: "closed_early",
      segmentId: "seg-dc036958c70a72cf420903c9385c1051",
      providerRequestId: "req_01ABC",
      response: {
        ...exchange().response!,
        pieces: [sseResponse],
        observed: sseResponse.length,
        mediaType: "text/event-stream",
      },
    }),
    mode: "retain_original",
    idKey: true,
  },
};
const IDENTITY = { "fabric.agent_id": "lbl-5b8e7ef6883e83cd55809d7f0d081532" };
const REQUEST_ID_KEY = Buffer.alloc(32, 9);

function production(mode: string): Record<string, unknown> {
  return policyDoc(
    { "model.exchange.request": mode, "model.exchange.response": mode },
    "production",
  );
}

function pythonInput(): Record<string, unknown> {
  const input: Record<string, unknown> = {};
  for (const [name, { job, mode, idKey }] of Object.entries(CASES)) {
    const side = (s: CapturedExchange["request"] | undefined) =>
      s === undefined
        ? null
        : {
            hex: Buffer.concat(s.pieces).toString("hex"),
            media: s.mediaType,
            encoding: s.contentEncoding,
          };
    const enriched = name === "sse_closed_early_enriched";
    input[name] = {
      policy: mode === undefined ? null : production(mode),
      node: mode !== undefined,
      id_key: idKey ? ID_KEY.toString("hex") : null,
      token_key: TOKEN_KEY.toString("hex"),
      parent:
        job.parent === undefined
          ? null
          : { trace_id: job.parent.traceId, span_id: job.parent.spanId },
      source_id: job.sourceId,
      epoch: job.sourceEpoch,
      sequence: job.sequence,
      exchange_id: job.exchangeId,
      event_id: job.eventId,
      api: job.api,
      provider: job.providerName,
      endpoint: job.endpointId,
      start: job.startNs,
      end: job.endNs,
      request: side(job.request),
      response: side(job.response),
      state: job.responseState,
      status: job.statusCode ?? null,
      error: job.errorType ?? null,
      segment: job.segmentId ?? null,
      first_chunk: job.firstChunkOffsetNs ?? null,
      request_id: job.providerRequestId ?? null,
      request_id_key: enriched ? REQUEST_ID_KEY.toString("hex") : null,
      identity: enriched ? IDENTITY : {},
    };
  }
  return input;
}

async function typescript(name: string, { job, mode, idKey }: Case) {
  const policy = mode === undefined ? undefined : new DeploymentPolicy(production(mode));
  const gate = decideGate({
    node: mode !== undefined,
    store: mode === undefined,
    policy,
    idKey,
    spool: mode !== undefined,
    spoolKey: true,
  });
  const enriched = name === "sse_closed_early_enriched";
  const prepared = await prepareExchange(
    job,
    {
      gate,
      protector: gate.contentCapture === "enabled" ? protector(gate.policy!) : undefined,
      tenantId: TENANT,
      enrichment: {
        ...ENRICHMENT,
        endpointIds: { openai: "openai.default", anthropic: "anthropic.default" },
        identity: enriched ? IDENTITY : {},
        requestIdKey: enriched ? REQUEST_ID_KEY : undefined,
      },
    },
    "f".repeat(32),
  );
  const entry = exchangeEntry(job.sourceId, job.sourceEpoch, "svc-test", prepared);
  return { doc: entry.doc, bodies: entry.bodies.map((b) => Buffer.from(b).toString("hex")) };
}

const METADATA_KEYS = [
  "gen_ai.response.model",
  "gen_ai.response.finish_reasons",
  "gen_ai.usage.input_tokens",
  "gen_ai.usage.output_tokens",
];

/** §7.3: object ids by position; the span id; a root span's trace id. */
function substitute(record: any): any {
  const doc = parseJson(encodeJson(record.doc)) as any;
  const ids = new Map<string, string>();
  doc.bodies.forEach((b: any, i: number) => ids.set(b.descriptor.object_id, `<object ${i}>`));
  const swap = (value: unknown): unknown =>
    typeof value === "string"
      ? (ids.get(value) ?? value)
      : Array.isArray(value)
        ? value.map(swap)
        : value !== null && typeof value === "object"
          ? Object.fromEntries(Object.entries(value).map(([k, v]) => [k, swap(v)]))
          : value;
  const out = swap(doc) as any;
  out.span.span_id = "<span>";
  if (out.span.parent_span_id === undefined) out.span.trace_id = "<root trace>";
  return { doc: out, bodies: record.bodies };
}

describe("parity with Python's writer", () => {
  const python = runPython(PY, [], encodeJson(pythonInput())) as any;

  it("the role table and fabric.local-default equal Python's", () => {
    expect(ROLE_TABLE_VERSION).toBe(python.role_table_version);
    expect(
      ROLE_ROWS.map((r) => [
        r.role,
        r.boundary,
        r.provenance,
        r.media_types,
        r.default_policy,
        r.cap,
        r.allowed_modes ?? null,
      ]),
    ).toEqual(python.roles);
    expect(ROLES.size).toBe(python.roles.length);
    expect(LOCAL_DEFAULT.policyDigest).toBe(python.local_default);
  });

  for (const [name, testCase] of Object.entries(CASES)) {
    it(`${name}: span attributes, descriptors and bodies equal Python's`, async () => {
      const ts = substitute(await typescript(name, testCase));
      const py = substitute(python.cases[name]);
      const retained =
        testCase.mode === undefined || (testCase.mode === "retain_original" && testCase.idKey);
      if (!retained) {
        for (const key of METADATA_KEYS) {
          expect(ts.doc.span.attributes).not.toHaveProperty(key);
          delete py.doc.span.attributes[key];
        }
      }
      expect(ts).toEqual(py);
    });
  }

  it("a retained response's metadata is read, and the tokens match byte for byte", () => {
    const retained = python.cases.retain_original.doc.span.attributes;
    expect(retained["gen_ai.response.model"]).toBe("gpt-4o-2024-08-06");
    expect(python.cases.tokenize.bodies[0]).not.toContain(CHAT_REQUEST.toString("hex"));
    expect(python.cases.retain_original.bodies).toEqual([
      CHAT_REQUEST.toString("hex"),
      CHAT_RESPONSE.toString("hex"),
    ]);
  });
});
