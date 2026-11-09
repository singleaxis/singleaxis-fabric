// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * The span delivery rule shared with the Python SDK
 * (`fabric.tracing.check_content_endpoint_url` / `_grpc_options`): the OTLP
 * traces endpoint the standard environment selects must be verified TLS, or
 * plaintext to a loopback host only. A refused endpoint turns Fabric capture
 * off with a status that names the reason and the fix. It never throws into
 * the application, never changes what the application's callbacks return,
 * and prints nothing to the application's stdout or stderr unless
 * `FABRIC_WIRE_DIAGNOSTICS=stderr` asks for it.
 */

import {
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
} from "@opentelemetry/sdk-trace-node";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Fabric, captureStatus, otlpTraceTransport } from "../src/index.js";
import { resetCaptureDiagnostics } from "../src/otlp-transport.js";

const OTLP_VARS = [
  "OTEL_EXPORTER_OTLP_ENDPOINT",
  "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
  "OTEL_EXPORTER_OTLP_PROTOCOL",
  "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
  "OTEL_EXPORTER_OTLP_INSECURE",
  "OTEL_EXPORTER_OTLP_TRACES_INSECURE",
  "FABRIC_WIRE_DIAGNOSTICS",
];

let saved: Record<string, string | undefined> = {};
beforeEach(() => {
  saved = Object.fromEntries(OTLP_VARS.map((name) => [name, process.env[name]]));
  for (const name of OTLP_VARS) delete process.env[name];
  resetCaptureDiagnostics();
});
afterEach(() => {
  for (const [name, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  vi.restoreAllMocks();
});

function recordingFabric(): { fabric: Fabric; exporter: InMemorySpanExporter } {
  const exporter = new InMemorySpanExporter();
  const provider = new BasicTracerProvider({
    spanProcessors: [new SimpleSpanProcessor(exporter)],
  });
  const fabric = new Fabric({ tenantId: "acme", agentId: "bot", tracerProvider: provider });
  return { fabric, exporter };
}

async function oneDecision(fabric: Fabric): Promise<string> {
  return fabric.decision({ sessionId: "s-1", requestId: "r-1" }, async (decision) => {
    await decision.llmCall(
      { provider: "provider-example", operationName: "chat", model: "m" },
      async (call) => {
        call.setResponse({ model: "m" });
      },
    );
    await decision.toolCall("lookup", { callId: "t-1" }, async (tool) => {
      tool.setArguments("{}");
      tool.setResult("{}");
    });
    return "agent-result";
  });
}

describe("otlpTraceTransport (the rule shared with Python)", () => {
  const allowed: Array<[string, Record<string, string>]> = [
    ["no endpoint configured", {}],
    ["https", { OTEL_EXPORTER_OTLP_ENDPOINT: "https://fabric-node:4318" }],
    ["loopback name", { OTEL_EXPORTER_OTLP_ENDPOINT: "http://localhost:4318" }],
    ["loopback v4", { OTEL_EXPORTER_OTLP_ENDPOINT: "http://127.0.0.1:4318" }],
    ["loopback v6", { OTEL_EXPORTER_OTLP_ENDPOINT: "http://[::1]:4318" }],
    ["upper-case scheme and host", { OTEL_EXPORTER_OTLP_ENDPOINT: "HTTP://LOCALHOST:4318" }],
    [
      "signal variable wins over the general one",
      {
        OTEL_EXPORTER_OTLP_ENDPOINT: "http://fabric-node:4318",
        OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: "https://fabric-node:4318/v1/traces",
      },
    ],
    [
      "grpc TLS host:port (insecure unset)",
      { OTEL_EXPORTER_OTLP_PROTOCOL: "grpc", OTEL_EXPORTER_OTLP_ENDPOINT: "fabric-node:4317" },
    ],
    [
      "grpc plaintext to loopback",
      { OTEL_EXPORTER_OTLP_PROTOCOL: "grpc", OTEL_EXPORTER_OTLP_ENDPOINT: "http://127.0.0.1:4317" },
    ],
  ];
  for (const [label, env] of allowed) {
    it(`allows ${label}`, () => {
      expect(otlpTraceTransport(env)).toEqual({ allowed: true });
    });
  }

  const refused: Array<[string, Record<string, string>, string]> = [
    [
      "plaintext to a service name",
      { OTEL_EXPORTER_OTLP_ENDPOINT: "http://fabric-node:4318" },
      "OTEL_EXPORTER_OTLP_ENDPOINT",
    ],
    [
      "plaintext to a non-loopback address",
      { OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: "http://10.0.0.5:4318/v1/traces" },
      "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    ],
    [
      "a loopback-looking name that is not loopback",
      { OTEL_EXPORTER_OTLP_ENDPOINT: "http://localhost.example.com:4318" },
      "OTEL_EXPORTER_OTLP_ENDPOINT",
    ],
    [
      "a signal-specific plaintext endpoint over a TLS general one",
      {
        OTEL_EXPORTER_OTLP_ENDPOINT: "https://fabric-node:4318",
        OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: "http://fabric-node:4318/v1/traces",
      },
      "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    ],
    [
      "a non-HTTP scheme",
      { OTEL_EXPORTER_OTLP_ENDPOINT: "ftp://fabric-node:4318" },
      "OTEL_EXPORTER_OTLP_ENDPOINT",
    ],
    ["an invalid URL", { OTEL_EXPORTER_OTLP_ENDPOINT: "http://" }, "OTEL_EXPORTER_OTLP_ENDPOINT"],
    [
      "grpc plaintext URL to a service name",
      {
        OTEL_EXPORTER_OTLP_PROTOCOL: "grpc",
        OTEL_EXPORTER_OTLP_ENDPOINT: "http://fabric-node:4317",
      },
      "OTEL_EXPORTER_OTLP_ENDPOINT",
    ],
    [
      "grpc host:port marked insecure",
      {
        OTEL_EXPORTER_OTLP_TRACES_PROTOCOL: "grpc",
        OTEL_EXPORTER_OTLP_ENDPOINT: "fabric-node:4317",
        OTEL_EXPORTER_OTLP_INSECURE: "true",
      },
      "OTEL_EXPORTER_OTLP_ENDPOINT",
    ],
  ];
  for (const [label, env, variable] of refused) {
    it(`refuses ${label}, naming the variable and the fix but never the value`, () => {
      const result = otlpTraceTransport(env);
      expect(result.allowed).toBe(false);
      if (result.allowed) return;
      expect(result.variable).toBe(variable);
      expect(result.reason).toContain(variable);
      expect(result.fix).toMatch(/https:\/\//);
      expect(result.fix).toMatch(/loopback/);
      const value = Object.values(env).join(" ");
      for (const piece of ["fabric-node", "10.0.0.5", "example.com", "ftp"]) {
        if (value.includes(piece)) {
          expect(result.reason).not.toContain(piece);
          expect(result.fix).not.toContain(piece);
        }
      }
    });
  }

  it("never echoes credentials carried in the endpoint", () => {
    const result = otlpTraceTransport({
      OTEL_EXPORTER_OTLP_ENDPOINT: "http://user:s3cret-token@fabric-node:4318",
    });
    expect(result.allowed).toBe(false);
    expect(JSON.stringify(result)).not.toContain("s3cret-token");
  });
});

describe("Fabric under a refused plaintext endpoint", () => {
  it("records with an allowed endpoint (control)", async () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://127.0.0.1:4318";
    const { fabric, exporter } = recordingFabric();
    expect(fabric.captureStatus()).toEqual({ capture: "enabled" });
    expect(await oneDecision(fabric)).toBe("agent-result");
    expect(exporter.getFinishedSpans().length).toBeGreaterThanOrEqual(3);
  });

  it("turns capture off, keeps the agent's result, and emits no span", async () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://fabric-node:4318";
    const warn = vi.spyOn(console, "warn");
    const error = vi.spyOn(console, "error");
    const stderr = vi.spyOn(process.stderr, "write");
    const stdout = vi.spyOn(process.stdout, "write");

    const { fabric, exporter } = recordingFabric();
    expect(await oneDecision(fabric)).toBe("agent-result");
    expect(exporter.getFinishedSpans()).toHaveLength(0);

    const status = fabric.captureStatus();
    expect(status.capture).toBe("disabled");
    if (status.capture !== "disabled") return;
    expect(status.reason).toBe(
      "OTEL_EXPORTER_OTLP_ENDPOINT requires verified HTTPS or loopback HTTP",
    );
    expect(status.fix).toContain("https://");
    expect(JSON.stringify(status)).not.toContain("fabric-node");
    // Nothing reaches the agent's own output channels by default.
    expect(warn).not.toHaveBeenCalled();
    expect(error).not.toHaveBeenCalled();
    expect(stderr).not.toHaveBeenCalled();
    expect(stdout).not.toHaveBeenCalled();
  });

  it("does not throw from Fabric.fromEnv or the constructor", () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://fabric-node:4318";
    expect(() =>
      Fabric.fromEnv({ FABRIC_TENANT_ID: "acme", FABRIC_AGENT_ID: "bot" }),
    ).not.toThrow();
    expect(() => new Fabric({ tenantId: "acme", agentId: "bot" })).not.toThrow();
  });

  it("still propagates the application's own error unchanged", async () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://fabric-node:4318";
    const { fabric } = recordingFabric();
    const appError = new Error("application failure");
    await expect(
      fabric.decision({ sessionId: "s", requestId: "r" }, async () => {
        throw appError;
      }),
    ).rejects.toBe(appError);
  });

  it("prints the reason and the fix once on stderr when FABRIC_WIRE_DIAGNOSTICS=stderr", () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://fabric-node:4318";
    process.env.FABRIC_WIRE_DIAGNOSTICS = "stderr";
    const lines: string[] = [];
    vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => {
      lines.push(String(chunk));
      return true;
    });
    recordingFabric();
    recordingFabric();
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("capture off");
    expect(lines[0]).toContain(
      "OTEL_EXPORTER_OTLP_ENDPOINT requires verified HTTPS or loopback HTTP",
    );
    expect(lines[0]).toContain("https://");
    expect(lines[0]).not.toContain("fabric-node");
  });

  it("a diagnostics sink that throws never reaches the agent", () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://fabric-node:4318";
    process.env.FABRIC_WIRE_DIAGNOSTICS = "stderr";
    vi.spyOn(process.stderr, "write").mockImplementation(() => {
      throw new Error("EPIPE");
    });
    expect(() => recordingFabric()).not.toThrow();
  });
});

describe("captureStatus()", () => {
  it("reports the same verdict without building a client", () => {
    expect(captureStatus({})).toEqual({ capture: "enabled" });
    const status = captureStatus({ OTEL_EXPORTER_OTLP_ENDPOINT: "http://fabric-node:4318" });
    expect(status.capture).toBe("disabled");
  });

  it("defaults to process.env", () => {
    process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT = "http://fabric-node:4318/v1/traces";
    expect(captureStatus().capture).toBe("disabled");
  });
});
