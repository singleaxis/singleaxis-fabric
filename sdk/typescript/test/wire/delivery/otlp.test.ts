// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §7.1 / §9.5 (unit 055-t12): the OTLP/HTTP protobuf encoder equals the Python
 * exporter's bytes for the shared span and content fixtures, with exact int64.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { INT64_MAX, INT64_MIN, parseJson, PyFloat } from "../../../src/wire/codec.js";
import {
  capturedAtNs,
  encodeLogRecord,
  encodeLogsRequest,
  encodeTraceRequest,
  FABRIC_SDK_NAME_NODE,
  type OtlpSpan,
  partialSuccessRejected,
  pyRepr,
  spanOfRecord,
} from "../../../src/wire/otlp.js";
import { SDK_VERSION } from "../../../src/version.js";
import { REPO } from "../helpers.js";
import { pythonOtlp } from "./helpers.js";

const VALID = join(REPO, "contracts", "capture", "v1", "fixtures", "valid");
const SERVICE = "svc-0123456789abcdef0123456789abcdef";

/** Every shared spool-record fixture that stands for a span (exchange, record, loss, marker). */
const RECORDS = readdirSync(VALID)
  .filter((name) => name.startsWith("spool-record-") && name.endsWith(".json"))
  .sort()
  .map((name) => ({ name, text: readFileSync(join(VALID, name), "utf8") }));

/** Every shared content-log-record fixture, with deterministic bytes of its body length. */
const CONTENT = readdirSync(VALID)
  .filter((name) => name.startsWith("content-log-record-") && name.endsWith(".json"))
  .sort()
  .map((name) => {
    const text = readFileSync(join(VALID, name), "utf8");
    const fixture = parseJson(text) as any;
    const descriptor = { ...fixture.attributes };
    delete descriptor.event_class;
    const body = Buffer.alloc(Number(fixture.body?.byte_length ?? 0), name.length);
    return { name, text, descriptor, body };
  });

// Python reads the same JSON text, so both sides start from identical records.
const python = pythonOtlp({
  version: SDK_VERSION,
  sdk_name: FABRIC_SDK_NAME_NODE,
  service_name: SERVICE,
  records: RECORDS.map((r) => r.text),
  content: CONTENT.map((c) => ({ fixture: c.text, body_hex: c.body.toString("hex") })),
});

const options = { serviceName: SERVICE, version: SDK_VERSION };
const spanOf = (text: string): OtlpSpan =>
  spanOfRecord(parseJson(text) as Record<string, unknown>, options);

describe("trace requests equal the Python exporter's bytes", () => {
  it("covers every kind of spool record", () => {
    const kinds = new Set(RECORDS.map((r) => (parseJson(r.text) as any).record_kind));
    expect([...kinds].sort()).toEqual(["exchange", "loss", "marker", "record"]);
    expect(RECORDS.length).toBeGreaterThanOrEqual(25);
  });

  it.each(RECORDS.map((r, i) => [r.name, i] as const))("%s", (_name, index) => {
    const ours = encodeTraceRequest([spanOf(RECORDS[index]!.text)]).toString("hex");
    expect(ours).toBe(python.spans[index]);
  });

  it("one request of every fixture groups resources and scopes as Python does", () => {
    const ours = encodeTraceRequest(RECORDS.map((r) => spanOf(r.text))).toString("hex");
    expect(ours).toBe(python.spans_all);
  });
});

describe("content requests equal Python's encode_content_records", () => {
  it.each(CONTENT.map((c, i) => [c.name, i] as const))("%s", (_name, index) => {
    const item = CONTENT[index]!;
    const ours = encodeLogsRequest([encodeLogRecord(item)], SERVICE).toString("hex");
    expect(ours).toBe(python.content[index]);
  });

  it("several records in one request", () => {
    const ours = encodeLogsRequest(CONTENT.map(encodeLogRecord), SERVICE).toString("hex");
    expect(ours).toBe(python.content_all);
  });
});

describe("exact int64", () => {
  const span = (value: unknown): OtlpSpan => ({
    name: "s",
    traceId: "0".repeat(31) + "1",
    spanId: "0".repeat(15) + "1",
    kind: "internal",
    startNs: INT64_MAX,
    endNs: INT64_MAX,
    attributes: { v: value },
    status: "unset",
    serviceName: "x",
    scope: { name: "n", version: "1" },
  });
  const oracle = pythonOtlp({
    version: SDK_VERSION,
    sdk_name: FABRIC_SDK_NAME_NODE,
    service_name: SERVICE,
    records: [INT64_MAX, INT64_MIN, -1n, 2n ** 53n + 1n].map(
      (v) =>
        `{"schema_version":"fabric.wire-spool-record/v1","record_kind":"record","source":{"source_id":"s","source_epoch":${INT64_MAX}},"order":1,"written_at_unix_nano":${INT64_MAX},` +
        `"span":{"name":"n","kind":"internal","trace_id":"${"a".repeat(32)}","span_id":"${"b".repeat(16)}","trace_flags":1,` +
        `"start_time_unix_nano":${INT64_MAX},"end_time_unix_nano":${INT64_MAX},"status":"ok","attributes":{"v":${v},"f":1.0,"l":[1,${v}]}}}`,
    ),
    content: [],
  });

  it.each([INT64_MAX, INT64_MIN, -1n, 2n ** 53n + 1n].map((v, i) => [String(v), i] as const))(
    "%s through a span attribute and the times",
    (text, index) => {
      const doc = parseJson(
        `{"schema_version":"fabric.wire-spool-record/v1","record_kind":"record","source":{"source_id":"s","source_epoch":${INT64_MAX}},"order":1,"written_at_unix_nano":${INT64_MAX},` +
          `"span":{"name":"n","kind":"internal","trace_id":"${"a".repeat(32)}","span_id":"${"b".repeat(16)}","trace_flags":1,` +
          `"start_time_unix_nano":${INT64_MAX},"end_time_unix_nano":${INT64_MAX},"status":"ok","attributes":{"v":${text},"f":1.0,"l":[1,${text}]}}}`,
      ) as Record<string, unknown>;
      expect(encodeTraceRequest([spanOfRecord(doc, options)]).toString("hex")).toBe(
        oracle.spans[index],
      );
    },
  );

  it("never converts through a float: 2^53 + 1 survives as an int64", () => {
    const bytes = encodeTraceRequest([span(2n ** 53n + 1n)]);
    // int_value field 3, varint of 9007199254740993
    expect(bytes.toString("hex")).toContain("18" + "8180808080808010");
  });

  it("an integer that is not exact, or out of int64, is left out (as Python drops it)", () => {
    const empty = encodeTraceRequest([span(undefined)]);
    expect(encodeTraceRequest([{ ...span(1), attributes: { v: 2 ** 60 } }]).length).toBeLessThan(
      empty.length + 4,
    );
    expect(
      encodeTraceRequest([{ ...span(1), attributes: { v: INT64_MAX + 1n } }]).length,
    ).toBeLessThan(empty.length + 4);
  });

  it("a PyFloat is a double even when integral", () => {
    const bytes = encodeTraceRequest([span(new PyFloat(2))]).toString("hex");
    expect(bytes).toContain("21" + "0000000000000040");
  });
});

describe("helpers", () => {
  it("captured_at follows Python's fromisoformat at microsecond precision", () => {
    expect(capturedAtNs("1970-01-01T00:00:00+00:00")).toBe(0n);
    expect(capturedAtNs("2026-10-07T00:00:01.120000+00:00")).toBe(1791331201120000000n);
    expect(capturedAtNs("2026-10-07T00:00:01.1234569Z")).toBe(1791331201123456000n);
    expect(capturedAtNs("2026-10-07T02:00:01+02:00")).toBe(1791331201000000000n);
    expect(capturedAtNs("0001-01-01T00:00:00+00:00")).toBe(-62135596800000000000n);
    expect(() => capturedAtNs("2026-10-07T00:00:01")).toThrow(/zone/);
    expect(() => capturedAtNs("2026-02-30T00:00:01Z")).toThrow(/valid/);
    expect(() => capturedAtNs(17)).toThrow();
  });

  it("a record before 1970 cannot be encoded (Python refuses a negative fixed64)", () => {
    expect(() =>
      encodeLogRecord({
        descriptor: { captured_at: "1969-12-31T23:59:59+00:00" },
        body: new Uint8Array(),
      }),
    ).toThrow(/range/);
  });

  it("descriptor booleans and floats are refused, as Python's _value refuses them", () => {
    const at = "2026-10-07T00:00:01+00:00";
    expect(() =>
      encodeLogRecord({ descriptor: { captured_at: at, x: true }, body: new Uint8Array() }),
    ).toThrow();
    expect(() =>
      encodeLogRecord({
        descriptor: { captured_at: at, x: new PyFloat(1.5) },
        body: new Uint8Array(),
      }),
    ).toThrow();
    expect(() =>
      encodeLogRecord({ descriptor: { captured_at: at, x: [true] }, body: new Uint8Array() }),
    ).toThrow();
  });

  it("pyRepr matches Python's repr for the root span seed", () => {
    expect(pyRepr({ source_id: "wire-1", source_epoch: 17n })).toBe(
      "{'source_id': 'wire-1', 'source_epoch': 17}",
    );
    expect(pyRepr("it's")).toBe(`"it's"`);
    expect(pyRepr("a'\"\n\u0001é ")).toBe(`'a\\'"\\n\\x01é\\u2028'`);
    expect(pyRepr([null, true, new PyFloat(1)])).toBe("[None, True, 1.0]");
  });

  it("partial success: rejected counts, malformed and empty bodies", () => {
    expect(partialSuccessRejected(Buffer.from("0a020802", "hex"))).toBe(2n);
    expect(partialSuccessRejected(Buffer.from("0a00", "hex"))).toBe(0n);
    expect(partialSuccessRejected(Buffer.alloc(0))).toBe(0n);
    expect(partialSuccessRejected(Buffer.from("0aff", "hex"))).toBe(0n);
    // a negative count (int64 two's complement) is read exactly, never as a float
    expect(partialSuccessRejected(Buffer.from("0a0b08ffffffffffffffffff01", "hex"))).toBe(-1n);
  });
});
