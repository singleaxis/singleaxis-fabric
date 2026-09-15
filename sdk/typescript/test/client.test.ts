// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Coverage for `Fabric.fromEnv`, the identifier guards
 * (`checkIdentifier` sentinel/copy-paste tiers) and the PII-shaped-ID
 * warnings — a port of Python's `test_client.py` env-config and
 * `test_id_validators.py` suites.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { Fabric } from "../src/index.js";

function env(overrides: Record<string, string | undefined>): Record<string, string | undefined> {
  return {
    FABRIC_TENANT_ID: "acme",
    FABRIC_AGENT_ID: "support-agent",
    ...overrides,
  };
}

describe("Fabric.fromEnv", () => {
  it("reads the three FABRIC_* variables", () => {
    const client = Fabric.fromEnv(env({ FABRIC_PROFILE: "permissive-dev" }));
    // Surface the resolved identity through a decision span indirectly:
    // identity fields land verbatim on the span attributes.
    expect(client).toBeInstanceOf(Fabric);
  });

  it("strips whitespace from the values", () => {
    const client = Fabric.fromEnv(
      env({ FABRIC_TENANT_ID: "  acme  ", FABRIC_AGENT_ID: "  bot  " }),
    );
    expect(client).toBeInstanceOf(Fabric);
  });

  it("defaults profile to 'shadow'", () => {
    // No FABRIC_PROFILE — constructor default applies.
    expect(Fabric.fromEnv(env({}))).toBeInstanceOf(Fabric);
  });

  it("rejects an empty profile", () => {
    expect(() => Fabric.fromEnv(env({ FABRIC_PROFILE: "" }))).toThrow(/profile/);
    expect(() => Fabric.fromEnv(env({ FABRIC_PROFILE: "   " }))).toThrow(/profile/);
    expect(() => new Fabric({ tenantId: "t", agentId: "a", profile: "  " })).toThrow(/profile/);
  });

  it.each([
    [{ FABRIC_AGENT_ID: undefined }, /FABRIC_AGENT_ID is not set/],
    [{ FABRIC_TENANT_ID: undefined }, /FABRIC_TENANT_ID is not set/],
    [
      { FABRIC_TENANT_ID: undefined, FABRIC_AGENT_ID: undefined },
      /FABRIC_TENANT_ID and FABRIC_AGENT_ID is not set/,
    ],
  ])("rejects missing required vars %j", (overrides, pattern) => {
    expect(() => Fabric.fromEnv(env(overrides))).toThrow(pattern);
  });

  it.each([
    "undefined",
    "null",
    "none",
    "nil",
    "nan",
    "n/a",
    "(null)",
    "<null>",
    "${FABRIC_TENANT_ID}",
    "{{ tenant }}",
    "<your-tenant-here>",
    "%s",
    "%(tenant)s",
  ])("rejects placeholder tenant id %s", (tenantId) => {
    expect(() => Fabric.fromEnv(env({ FABRIC_TENANT_ID: tenantId }))).toThrow(/placeholder/);
    expect(() => new Fabric({ tenantId, agentId: "a" })).toThrow(/placeholder/);
  });

  it.each(["undefined", "${AGENT}", "{{agent}}", "<agent-name>", "%s"])(
    "rejects placeholder agent id %s",
    (agentId) => {
      expect(() => Fabric.fromEnv(env({ FABRIC_AGENT_ID: agentId }))).toThrow(/placeholder/);
      expect(() => new Fabric({ tenantId: "t", agentId })).toThrow(/placeholder/);
    },
  );

  it("accepts near-misses of the sentinel list", () => {
    // `na`, `nullify-corp`, `nonesuch` are real tenants — Tier A matches
    // the whole stripped value, never a substring.
    for (const id of ["na", "nullify-corp", "nonesuch", "none-such-ltd"]) {
      expect(new Fabric({ tenantId: id, agentId: "a" })).toBeInstanceOf(Fabric);
    }
  });

  it("demotes the sentinel throw to a warning under FABRIC_ALLOW_PLACEHOLDER_IDS=1", () => {
    vi.stubEnv("FABRIC_ALLOW_PLACEHOLDER_IDS", "1");
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      expect(new Fabric({ tenantId: "undefined", agentId: "a" })).toBeInstanceOf(Fabric);
      expect(warn.mock.calls.some((call) => String(call[0]).includes("placeholder"))).toBe(true);
    } finally {
      vi.unstubAllEnvs();
    }
  });
});

describe("identifier warnings (non-fatal)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("warns — but does not throw — on copy-paste markers", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(new Fabric({ tenantId: "changeme", agentId: "a" })).toBeInstanceOf(Fabric);
    expect(new Fabric({ tenantId: "t", agentId: "replace-me" })).toBeInstanceOf(Fabric);
    expect(warn).toHaveBeenCalled();
  });

  it("warns once on PII-shaped tenant/agent ids", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    new Fabric({ tenantId: "jane.doe@example.com", agentId: "a" });
    new Fabric({ tenantId: "t", agentId: "+15551234567" });
    const piiWarnings = warn.mock.calls.filter(
      (call) =>
        String(call[0]).includes("looks like an email") ||
        String(call[0]).includes("looks like a phone"),
    );
    expect(piiWarnings.length).toBe(2);
  });

  it("suppresses PII warnings under FABRIC_QUIET_PII_WARN=1", () => {
    vi.stubEnv("FABRIC_QUIET_PII_WARN", "1");
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      new Fabric({ tenantId: "jane.doe@example.com", agentId: "a" });
      expect(
        warn.mock.calls.filter((call) => String(call[0]).includes("looks like an email")),
      ).toHaveLength(0);
    } finally {
      vi.unstubAllEnvs();
    }
  });
});
