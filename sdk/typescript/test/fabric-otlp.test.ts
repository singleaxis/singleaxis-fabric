// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Fabric's own OTLP route (spec 058 §6.4), the TypeScript side of the Python
 * SDK's `FABRIC_OTLP_*` variables: when any is set, the span delivery rule
 * applies to `FABRIC_OTLP_ENDPOINT` and nothing is read from
 * `OTEL_EXPORTER_OTLP_*`; `fabricExporterOptions()` gives the exporter the
 * Node's URL, CA, client certificate and headers. Never throws.
 */

import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import {
  captureStatus,
  fabricExporterOptions,
  fabricOtlpSelected,
  otlpTraceTransport,
} from "../src/index.js";

const dir = mkdtempSync(join(tmpdir(), "f058-e3b-otlp-"));
const ca = join(dir, "ca.crt");
const cert = join(dir, "client.crt");
const key = join(dir, "client.key");
const headers = join(dir, "headers");
writeFileSync(ca, "CA PEM");
writeFileSync(cert, "CERT PEM");
writeFileSync(key, "KEY PEM");
writeFileSync(headers, "authorization=Bearer%20tok\nx-tenant=acme\n");
chmodSync(headers, 0o600);
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("FABRIC_OTLP_* route", () => {
  it("is not selected without a FABRIC_OTLP_* variable; the OTEL_* rule applies", () => {
    const env = { OTEL_EXPORTER_OTLP_ENDPOINT: "http://collector.internal:4318" };
    expect(fabricOtlpSelected(env)).toBe(false);
    expect(otlpTraceTransport(env).allowed).toBe(false);
    expect(fabricExporterOptions(env)).toEqual({});
  });

  it("wins over OTEL_* and leaves the agent's own export alone", () => {
    const env = {
      FABRIC_OTLP_ENDPOINT: "https://fabric-node:4318/",
      FABRIC_OTLP_CERTIFICATE: ca,
      // The agent's own plaintext collector: not Fabric's concern on this route.
      OTEL_EXPORTER_OTLP_ENDPOINT: "http://collector.internal:4318",
    };
    expect(captureStatus(env)).toEqual({ capture: "enabled" });
    const options = fabricExporterOptions(env);
    expect(options.url).toBe("https://fabric-node:4318/v1/traces");
    expect(options.httpAgentOptions?.ca).toBe("CA PEM");
    expect(options.httpAgentOptions?.cert).toBeUndefined();
    expect(options.headers).toBeUndefined();
  });

  it("reads the client certificate, key and headers file", () => {
    const options = fabricExporterOptions({
      FABRIC_OTLP_ENDPOINT: "https://fabric-node:4318",
      FABRIC_OTLP_CERTIFICATE: ca,
      FABRIC_OTLP_CLIENT_CERTIFICATE: cert,
      FABRIC_OTLP_CLIENT_KEY: key,
      FABRIC_OTLP_HEADERS_FILE: headers,
    });
    expect(options.httpAgentOptions?.cert).toBe("CERT PEM");
    expect(options.httpAgentOptions?.key).toBe("KEY PEM");
    expect(options.headers).toEqual({ authorization: "Bearer tok", "x-tenant": "acme" });
  });

  it("allows loopback plaintext", () => {
    const env = { FABRIC_OTLP_ENDPOINT: "http://127.0.0.1:4318" };
    expect(captureStatus(env).capture).toBe("enabled");
    expect(fabricExporterOptions(env).url).toBe("http://127.0.0.1:4318/v1/traces");
  });

  const refused: [string, Record<string, string>, string][] = [
    [
      "plaintext to a non-loopback host",
      { FABRIC_OTLP_ENDPOINT: "http://fabric-node:4318" },
      "FABRIC_OTLP_ENDPOINT requires verified HTTPS or loopback HTTP",
    ],
    [
      "a setting without the endpoint",
      { FABRIC_OTLP_CERTIFICATE: ca, OTEL_EXPORTER_OTLP_ENDPOINT: "https://x:4318" },
      "a FABRIC_OTLP_* setting is set without FABRIC_OTLP_ENDPOINT",
    ],
    [
      "credentials in the URL",
      { FABRIC_OTLP_ENDPOINT: "https://user:secret@fabric-node:4318" },
      "FABRIC_OTLP_ENDPOINT must not carry credentials, a query or a fragment",
    ],
    [
      "an unreadable CA file",
      { FABRIC_OTLP_ENDPOINT: "https://fabric-node:4318", FABRIC_OTLP_CERTIFICATE: join(dir, "x") },
      "the file named by FABRIC_OTLP_CERTIFICATE is not readable",
    ],
    [
      "a client certificate without its key",
      { FABRIC_OTLP_ENDPOINT: "https://n:4318", FABRIC_OTLP_CLIENT_CERTIFICATE: cert },
      "FABRIC_OTLP_CLIENT_CERTIFICATE and FABRIC_OTLP_CLIENT_KEY must be set together",
    ],
  ];
  it.each(refused)(
    "refuses %s, naming the variable and the fix, never the value",
    (_, env, why) => {
      const status = captureStatus(env);
      expect(status.capture).toBe("disabled");
      if (status.capture !== "disabled") return;
      expect(status.reason).toBe(why);
      expect(status.fix).toContain("FABRIC_OTLP_CERTIFICATE");
      expect(JSON.stringify(status)).not.toContain("secret");
      expect(fabricExporterOptions(env)).toEqual({});
    },
  );

  it("refuses a malformed headers file without echoing it", () => {
    const bad = join(dir, "bad-headers");
    writeFileSync(bad, "Bearer secret-token\n");
    const status = captureStatus({
      FABRIC_OTLP_ENDPOINT: "https://n:4318",
      FABRIC_OTLP_HEADERS_FILE: bad,
    });
    expect(status.capture).toBe("disabled");
    expect(JSON.stringify(status)).not.toContain("secret-token");
  });
});

describe("FABRIC_WIRE_ID_KEY_FILE", () => {
  it("reads the key from the file fabric run names, as the Python SDK does", async () => {
    const { idKeyBytesFromEnv } = await import("../src/id-key-env.js");
    const keyFile = join(dir, "id.key");
    writeFileSync(keyFile, "0123456789abcdef0123456789abcdef\n");
    const bytes = idKeyBytesFromEnv({ FABRIC_WIRE_ID_KEY_FILE: keyFile });
    expect(Buffer.from(bytes ?? []).toString()).toBe("0123456789abcdef0123456789abcdef");
    expect(idKeyBytesFromEnv({})).toBeUndefined();
    expect(() =>
      idKeyBytesFromEnv({ FABRIC_WIRE_ID_KEY: "x".repeat(32), FABRIC_WIRE_ID_KEY_FILE: keyFile }),
    ).toThrow("set FABRIC_WIRE_ID_KEY or FABRIC_WIRE_ID_KEY_FILE, not both");
    expect(() => idKeyBytesFromEnv({ FABRIC_WIRE_ID_KEY_FILE: join(dir, "missing") })).toThrow(
      "FABRIC_WIRE_ID_KEY_FILE is not readable",
    );
  });
});
