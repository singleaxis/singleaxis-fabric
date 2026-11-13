// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §3.4 (unit 055-t2): the endpoint matcher against a table generated from
// Python's wire/_match.py (test/wire/fixtures/match-table.json), the built-in rows against
// Python's for `table` and `legacy`, both generated modules against their contracts, and
// property tests of the matching rules.
import { execFileSync } from "node:child_process";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { CATALOGUE, TYPESCRIPT_IDS } from "../../../src/wire/catalogue.generated.js";
import { parseEndpoints } from "../../../src/wire/config.js";
import { ENDPOINT_TABLE } from "../../../src/wire/endpoint-table.generated.js";
import {
  BUILTIN_ENDPOINTS,
  EndpointIndex,
  MODEL_PATH_SUFFIXES,
  OPERATION_NAMES,
  apiForPath,
  loadBuiltinEndpoints,
} from "../../../src/wire/match.js";
import type { EndpointMatcher } from "../../../src/wire/types.js";
import { REPO, cases, contract } from "../helpers.js";

const table = contract("sdk/typescript/test/wire/fixtures/match-table.json");

/** A matcher in the snake_case shape the Python generator wrote. */
function snake(m: EndpointMatcher): Record<string, unknown> {
  return {
    endpoint_id: m.endpointId,
    dialect: m.dialect,
    hosts: [...m.hosts],
    host_suffixes: [...m.hostSuffixes],
    schemes: [...m.schemes],
    ports: m.ports === undefined ? null : [...m.ports],
    path_prefix: m.pathPrefix,
    provider_name: m.providerName,
  };
}

const sets = { table: BUILTIN_ENDPOINTS.table, legacy: BUILTIN_ENDPOINTS.legacy } as const;

describe("EndpointIndex equals Python's wire/_match.py", () => {
  for (const [name, builtin] of Object.entries(sets)) {
    it(`built-in ${name} rows equal Python's`, () => {
      expect(builtin.map(snake)).toEqual(table.sets[name].builtin);
    });
    const index = new EndpointIndex([...builtin, ...parseEndpoints(table.extra_endpoints)]);
    const rows = table.sets[name].cases.map((c: any) => ({
      ...c,
      label: `${c.method} ${c.scheme}://${c.host}${c.port === null ? "" : `:${c.port}`}${c.path}`,
    }));
    it.each(cases(rows, "label"))(`${name}: %s`, (_label, c: any) => {
      const found = index.match(c.method, c.scheme, c.host, c.port, c.path);
      expect(found?.endpoint.endpointId ?? null).toBe(c.endpoint_id);
      expect(found?.api ?? null).toBe(c.api);
    });
  }

  it("reports the table version", () => {
    expect(BUILTIN_ENDPOINTS.version).toBe(ENDPOINT_TABLE.table_version);
    expect(BUILTIN_ENDPOINTS.version).toBeGreaterThan(0);
  });

  it("falls back to the legacy rows when the table does not load (as Python)", () => {
    for (const bad of [
      {},
      { ...ENDPOINT_TABLE, schema: "x" },
      { ...ENDPOINT_TABLE, table_version: 0 },
    ]) {
      const loaded = loadBuiltinEndpoints(bad);
      expect(loaded.version).toBe(0);
      expect(loaded.table.map(snake)).toEqual(table.sets.legacy.builtin);
    }
  });
});

describe("generated modules equal their contracts", () => {
  it("endpoint-table.generated.ts is contracts/providers/v1/builtin-endpoints.json", () => {
    expect(ENDPOINT_TABLE).toEqual(contract("contracts/providers/v1/builtin-endpoints.json"));
  });

  it("catalogue.generated.ts holds the catalogue's FW- entries", () => {
    const doc = contract("contracts/diagnostics/v1/messages-v1.json");
    const fw = doc.messages.filter((m: any) => m.id.startsWith("FW-"));
    expect(CATALOGUE).toEqual(fw);
    expect([...TYPESCRIPT_IDS]).toEqual(
      fw
        .filter((m: any) => (m.sdk ?? ["python"]).includes("typescript") && m.retired !== true)
        .map((m: any) => m.id),
    );
  });

  it("scripts/typescript/sync-contract-data.mjs --check finds nothing stale", () => {
    const script = join(REPO, "scripts", "typescript", "sync-contract-data.mjs");
    expect(() =>
      execFileSync(process.execPath, [script, "--check"], { stdio: "pipe" }),
    ).not.toThrow();
  });
});

// ----------------------------------------------------------------- properties

/** A small deterministic PRNG (mulberry32), so a failure reproduces. */
function prng(seed: number): () => number {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe("matching properties", () => {
  const extra = parseEndpoints(table.extra_endpoints);
  const index = new EndpointIndex([...BUILTIN_ENDPOINTS.table, ...extra]);
  const random = prng(0x055);
  const pick = <T>(list: readonly T[]): T => list[Math.floor(random() * list.length)]!;
  const hosts = [
    "api.openai.com",
    "api.anthropic.com",
    "x.openai.azure.com",
    "models.example.com",
    "a.corp.example",
    "corp.example",
    "evil.example",
  ];
  const prefixes = ["", "/v1", "/llm/v1", "/openai/deployments/d", "/other"];
  const tails = [...MODEL_PATH_SUFFIXES, "/models", "/v1", ""];
  const requests = Array.from({ length: 2000 }, () => ({
    method: pick(["POST", "POST", "POST", "GET", "PUT", "post"]),
    scheme: pick(["https", "https", "http"]),
    host: pick(hosts),
    port: pick([undefined, undefined, 443, 80, 8080, 8443]),
    path: pick(prefixes) + pick(tails),
  }));

  it("only POST matches, and a match has an allowed scheme, prefix and API suffix", () => {
    for (const r of requests) {
      const found = index.match(r.method, r.scheme, r.host, r.port, r.path);
      if (found === undefined) continue;
      expect(r.method).toBe("POST");
      expect(found.endpoint.schemes).toContain(r.scheme);
      expect(r.path.startsWith(found.endpoint.pathPrefix)).toBe(true);
      expect(apiForPath(found.endpoint.dialect, r.path)).toBe(found.api);
      expect(OPERATION_NAMES[found.api]).toBeDefined();
    }
  });

  it("host case never changes the result; the scheme's default port equals no port", () => {
    for (const r of requests) {
      const once = index.match(r.method, r.scheme, r.host, r.port, r.path);
      const upper = index.match(r.method, r.scheme, r.host.toUpperCase(), r.port, r.path);
      expect(upper?.endpoint.endpointId).toBe(once?.endpoint.endpointId);
      if (r.port === undefined) {
        const port = r.scheme === "https" ? 443 : 80;
        expect(index.match(r.method, r.scheme, r.host, port, r.path)?.api).toBe(once?.api);
      }
    }
  });

  it("an exact host never matches its parent domain, a suffix never its bare domain", () => {
    expect(
      index.match("POST", "https", "openai.com", undefined, "/v1/chat/completions"),
    ).toBeUndefined();
    expect(
      index.match("POST", "https", "openai.azure.com", undefined, "/chat/completions"),
    ).toBeUndefined();
    expect(
      index.match("POST", "https", "api.openai.com.evil", undefined, "/v1/chat/completions"),
    ).toBeUndefined();
  });

  it("only an explicitly configured matcher allows plain HTTP", () => {
    for (const m of BUILTIN_ENDPOINTS.table) expect(m.schemes).toEqual(["https"]);
  });
});

describe("apiForPath", () => {
  it("knows only the two dialects; a prototype key is no dialect", () => {
    expect(apiForPath("openai", "/v1/chat/completions")).toBe("openai.chat_completions");
    expect(apiForPath("anthropic", "/v1/messages")).toBe("anthropic.messages");
    for (const dialect of ["toString", "__proto__", "constructor", "hasOwnProperty", "gemini"])
      expect(apiForPath(dialect, "/v1/messages"), dialect).toBeUndefined();
  });
});
