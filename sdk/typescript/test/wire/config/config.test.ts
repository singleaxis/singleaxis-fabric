// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §4.2, §4.7 (unit 055-t2): the Python-to-TypeScript environment mapping. Each
// case of test/wire/fixtures/config-env.json is an environment and what
// `python -m fabric.wire status` decided for it (valid with its resolved settings, or
// invalid with the catalogue id wire/_diagnose.py gives the message); TypeScript must
// decide the same, with FW-025 where Python reports its generic FW-001.
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { CATALOGUE, TYPESCRIPT_IDS } from "../../../src/wire/catalogue.generated.js";
import {
  CONFIG_REASON_IDS,
  ENV_NAMES,
  GENERIC_REASON_ID,
  WireConfigError,
  configStatus,
  resolveConfig,
} from "../../../src/wire/config.js";
import type { WireSettings } from "../../../src/wire/types.js";
import { REPO, cases, contract } from "../helpers.js";

const fixture = contract("sdk/typescript/test/wire/fixtures/config-env.json");
const dir = mkdtempSync(join(tmpdir(), "f055-t2-config-"));
for (const [name, text] of Object.entries(fixture.files))
  writeFileSync(join(dir, name), String(text));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const envOf = (env: Record<string, string>): Record<string, string> =>
  Object.fromEntries(Object.entries(env).map(([k, v]) => [k, v.replaceAll("{dir}", dir)]));
const sha = (key: Uint8Array | undefined): string | null =>
  key === undefined ? null : createHash("sha256").update(key).digest("hex");
const nul = <T>(value: T | undefined): T | null => (value === undefined ? null : value);

/** The settings in the shape the Python generator wrote. */
function resolved(s: WireSettings): Record<string, unknown> {
  return {
    endpoints: s.endpoints.map((m) => m.endpointId),
    extraEndpoints: s.extraEndpoints.map((m) => m.endpointId),
    labels: s.labels,
    sourceId: nul(s.sourceId),
    tenantId: nul(s.tenantId),
    contentEndpoint: nul(s.contentEndpoint),
    spoolDir: nul(s.spoolDir),
    modelAllowlist: [...s.modelAllowlist],
    maxBodyBytes: s.maxBodyBytes,
    maxRetainBytes: s.maxRetainBytes,
    queueMaxItems: s.queueMaxItems,
    shutdownTimeoutMs: s.shutdownTimeoutMs,
    drainOnExitMs: s.drainOnExitMs,
    contentBatchBodies: s.contentBatchBodies,
    contentConcurrency: s.contentConcurrency,
    idKeySha256: sha(s.secrets.idKey),
    spoolKeySha256: sha(s.secrets.spoolKey),
    otlp: {
      route: s.otlp.route,
      endpoint: nul(s.otlp.endpoint),
      endpointName: nul(s.otlp.endpointName),
      headers: { ...s.otlp.headers },
      timeoutMs: s.otlp.timeoutMs,
    },
  };
}

describe("config-env.json: what python -m fabric.wire status decides", () => {
  it.each(cases(fixture.cases))("%s", (_name, c: any) => {
    const status = configStatus(envOf(c.env));
    if (c.outcome === "invalid") {
      expect(status.configuration).toBe("invalid");
      if (status.configuration !== "invalid") return;
      const want = c.reason_id === "FW-001" ? GENERIC_REASON_ID : c.reason_id;
      expect(status.reasonId, status.reason).toBe(want);
      expect(status.fix).toBe(CATALOGUE.find((e) => e.id === want)!.fix);
      // Fixed text: never a value the environment held (only variable names).
      for (const value of Object.values(envOf(c.env))) {
        const word = /^[a-z]{1,6}$/.test(value); // "node", "spool": words of the rule itself
        if (value.length >= 4 && !word) expect(status.reason).not.toContain(value);
      }
      return;
    }
    expect(status.configuration).toBe("valid");
    if (status.configuration !== "valid") return;
    expect(status.capture).toBe(c.outcome);
    if (c.resolved !== undefined) expect(resolved(status.settings)).toEqual(c.resolved);
  });

  it("covers unset versus empty, *_FILE variants, 058 names and FABRIC_OTLP_* precedence", () => {
    const names = fixture.cases.map((c: any) => c.name).join("\n");
    for (const topic of [
      "empty values are unset",
      "from a file (058 name)",
      "_FILE",
      "FABRIC_OTLP_* wins",
    ]) {
      expect(names).toContain(topic);
    }
    const used = new Set(fixture.cases.flatMap((c: any) => Object.keys(c.env)));
    for (const name of [
      "FABRIC_WIRE_ID_KEY_FILE",
      "FABRIC_WIRE_BUILTIN_ENDPOINTS",
      "FABRIC_OTLP_ENDPOINT",
      "FABRIC_OTLP_HEADERS_FILE",
    ]) {
      expect(used.has(name), name).toBe(true);
    }
  });
});

describe("the Python-to-TypeScript mapping", () => {
  const base = resolveConfig({}, {});
  const has = (path: string): boolean => {
    let node: unknown = base;
    for (const part of path.split(".")) {
      if (node === null || typeof node !== "object" || !(part in node)) return false;
      node = (node as Record<string, unknown>)[part];
    }
    return true;
  };

  it.each(cases(fixture.mapping, "env"))("%s", (name, row: any) => {
    if (row.typescript === null) {
      expect(ENV_NAMES).not.toContain(name); // Python-only (tracer mode, aiohttp)
      return;
    }
    expect(ENV_NAMES).toContain(name);
    expect(has(row.typescript), row.typescript).toBe(true);
  });

  it("reads only named variables, never enumerating the environment", () => {
    const read = new Set<string>();
    const env = new Proxy({} as Record<string, string | undefined>, {
      get: (_t, key) => {
        if (typeof key === "string") read.add(key);
        return undefined;
      },
      ownKeys: () => {
        throw new Error("the environment was enumerated");
      },
      has: (_t, key) => {
        if (typeof key === "string") read.add(key);
        return false;
      },
    });
    resolveConfig({}, env);
    for (const key of read) expect(ENV_NAMES, key).toContain(key);
  });

  it("explicit options win over the environment", () => {
    const env = {
      FABRIC_WIRE_MAX_BODY_BYTES: "1048576",
      FABRIC_WIRE_LABELS: "clear",
      FABRIC_WIRE_UNDICI: "0",
    };
    const s = resolveConfig(
      { maxBodyBytes: 2 * 1048576, labels: "pseudonymous", undici: true },
      env,
    );
    expect([s.maxBodyBytes, s.labels, s.undici]).toEqual([2 * 1048576, "pseudonymous", true]);
    expect(resolveConfig({}, env).undici).toBe(false);
  });

  it("an option is validated as its variable is", () => {
    expect(() => resolveConfig({ queueMaxItems: 65537 })).toThrow(WireConfigError);
    expect(() =>
      resolveConfig({ extraEndpoints: [{ endpointId: "Bad", dialect: "openai", hosts: ["h"] }] }),
    ).toThrow(/invalid endpoint matcher/);
    const ok = resolveConfig(
      { extraEndpoints: [{ endpointId: "mine", dialect: "anthropic", hosts: ["m.example"] }] },
      {},
    );
    expect(ok.extraEndpoints.map((m) => [m.endpointId, m.providerName, m.schemes])).toEqual([
      ["mine", "openai", ["https"]],
    ]);
  });

  it("pins Python's defaults and TypeScript's switches", () => {
    expect(base.undici).toBe(true);
    expect(base.nodeHttp).toBe(false);
    expect(base.autoload).toBe(false);
    expect(base.diagnostics).toBe("silent");
    expect(base.partMinBytes).toBe(64 * 1024);
    expect(base.maxInflightBytes).toBe(256n * 1024n * 1024n);
    expect(base.spoolMaxBytes).toBe(1n << 30n);
    expect(base.recordsMaxObjectBytes).toBe(16 * 1024 * 1024);
    expect(base.openDeadlineS).toBe(604800);
    expect(base.clockUncertaintyNs).toBe(1_000_000_000n);
    expect(base.identityMode).toBe("pseudonymous");
    expect(base.endpointTableVersion).toBeGreaterThan(0);
  });
});

describe("TypeScript-only settings", () => {
  const id = (env: Record<string, string>): string | undefined => {
    const s = configStatus(env);
    return s.configuration === "invalid" ? s.reasonId : undefined;
  };

  it("parses the switches, the run and records settings and the status file", () => {
    const s = resolveConfig(
      {},
      {
        FABRIC_WIRE_AUTOLOAD: " 1 ",
        FABRIC_WIRE_DIAGNOSTICS: "STDERR",
        FABRIC_WIRE_NODE_HTTP: "on",
        FABRIC_RUN_ID: " order-1 ",
        FABRIC_RUN_RESUME_TOKEN: " fr3/a , ,fr3/b",
        FABRIC_RECORDS_STRICT: "1",
        FABRIC_RECORDS_MAX_OBJECT_BYTES: "1024",
        FABRIC_WIRE_PROVIDER_REQUEST_ID: "true",
        FABRIC_WIRE_STATUS_FILE: " /var/empty/status.json ",
        FABRIC_IDENTITY_MODE: "clear",
      },
    );
    expect([s.autoload, s.diagnostics, s.nodeHttp, s.runId, s.resumeTokens]).toEqual([
      true,
      "stderr",
      true,
      "order-1",
      ["fr3/a", "fr3/b"],
    ]);
    expect([
      s.recordsStrict,
      s.recordsMaxObjectBytes,
      s.providerRequestId,
      s.statusFile,
      s.identityMode,
    ]).toEqual([true, 1024, true, "/var/empty/status.json", "clear"]);
  });

  it("refuses malformed TypeScript settings with a catalogued id", () => {
    expect(id({ FABRIC_WIRE_UNDICI: "maybe" })).toBe("FW-025");
    expect(id({ FABRIC_WIRE_NODE_HTTP: "2" })).toBe("FW-025");
    expect(id({ FABRIC_IDENTITY_MODE: "hashed" })).toBe("FW-025");
    expect(id({ FABRIC_RECORDS_MAX_OBJECT_BYTES: "16777217" })).toBe("FW-025");
    expect(
      id({
        OTEL_EXPORTER_OTLP_ENDPOINT: "https://otel.example:4317",
        OTEL_EXPORTER_OTLP_PROTOCOL: "grpc",
      }),
    ).toBe("FW-024");
    expect(
      id({
        OTEL_EXPORTER_OTLP_ENDPOINT: "https://o.example",
        FABRIC_WIRE_PROXY: "socks5://p:1080",
      }),
    ).toBe("FW-025");
  });

  it("falls back to the default for a malformed open deadline or clock bound, with a note", () => {
    const s = resolveConfig(
      {},
      { FABRIC_RUN_OPEN_DEADLINE_S: "5", FABRIC_CLOCK_UNCERTAINTY_MS: "x" },
    );
    expect([s.openDeadlineS, s.clockUncertaintyNs]).toEqual([604800, 1_000_000_000n]);
    expect(s.settingWarnings).toHaveLength(2);
    expect(s.settingWarnings.join(" ")).not.toContain(" x");
  });

  it("resolves the OTLP signal URL as the OTel exporters do", () => {
    const general = resolveConfig(
      {},
      { OTEL_EXPORTER_OTLP_ENDPOINT: "https://o.example:4318/", FABRIC_WIRE_SPOOL_DIR: "/s" },
    );
    expect(general.otlp.signalUrl).toBe("https://o.example:4318/v1/traces");
    const node = resolveConfig(
      {},
      {
        FABRIC_OTLP_ENDPOINT: "http://127.0.0.1:4318",
        FABRIC_WIRE_CONTENT_ENDPOINT: "http://127.0.0.1:4318",
        FABRIC_TENANT_ID: "t",
        FABRIC_WIRE_SPOOL_DIR: "/s",
      },
    );
    expect([node.otlp.signalUrl, node.otlpLogs?.signalUrl]).toEqual([
      "http://127.0.0.1:4318/v1/traces",
      "http://127.0.0.1:4318/v1/logs",
    ]);
  });
});

describe("every id the configuration can produce is catalogued", () => {
  const ts = new Set<string>(TYPESCRIPT_IDS);

  it("CONFIG_REASON_IDS are TypeScript catalogue entries", () => {
    for (const reason of CONFIG_REASON_IDS) expect(ts.has(reason), reason).toBe(true);
  });

  it("every FW- literal in src/wire is a TypeScript catalogue entry", () => {
    const root = join(REPO, "sdk", "typescript", "src", "wire");
    for (const file of readdirSync(root).filter(
      (f) => f.endsWith(".ts") && !f.endsWith(".generated.ts"),
    )) {
      for (const [literal] of readFileSync(join(root, file), "utf8").matchAll(/F[WC]-\d{3}/g)) {
        expect(ts.has(literal), `${file}: ${literal}`).toBe(true);
      }
    }
  });

  it("every id the shared fixture expects is one config.ts can produce", () => {
    for (const c of fixture.cases.filter((x: any) => x.outcome === "invalid")) {
      const want = c.reason_id === "FW-001" ? GENERIC_REASON_ID : c.reason_id;
      expect(CONFIG_REASON_IDS, c.name).toContain(want);
    }
  });
});
