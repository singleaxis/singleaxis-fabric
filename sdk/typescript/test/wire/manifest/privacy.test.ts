// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * No path, secret, host or dependency inventory in any manifest field (spec 055 §7.2,
 * §9.5 055-t9). Canaries are planted in every setting a manifest is built from (the
 * spool directory, the policy file path, the id and spool keys, the endpoint hosts, the
 * tenant, the clear source id and run id); the template (which crosses to the Fabric
 * worker), every manifest document, its spool marker and the final heartbeat are scanned
 * for each canary, each key in hex and base64, the working directory, the home directory,
 * the Node binary path and every package the SDK depends on.
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { DeploymentPolicy } from "../../../src/deployment-policy.js";
import { labelPseudonym } from "../../../src/identity.js";
import { resolveConfig } from "../../../src/wire/config.js";
import {
  Heartbeats,
  ManifestChain,
  UNDICI_POINT,
  initialStates,
  manifestTemplate,
} from "../../../src/wire/manifest.js";
import { decideGate } from "../../../src/wire/protect.js";
import { spoolKeyId } from "../../../src/wire/spool-codec.js";

import { REPO } from "../helpers.js";
import { policyDoc } from "../protect/helpers.js";

const CANARY = "qx7canary";
const dir = mkdtempSync(join(tmpdir(), `f055-t9-${CANARY}-`));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const ID_KEY = `${CANARY}-id-key-0123456789abcdef`;
const SPOOL_KEY = Buffer.alloc(32, 0x71);

describe("manifest privacy", () => {
  it("carries no path, secret, host, clear id or dependency inventory", () => {
    const policyPath = join(dir, `${CANARY}-policy.json`);
    writeFileSync(
      policyPath,
      JSON.stringify({
        ...policyDoc({ "model.exchange.request": "retain_original" }),
        tenant_id: `${CANARY}-tenant`,
      }),
      { mode: 0o600 },
    );
    const env = {
      FABRIC_WIRE_SPOOL_DIR: join(dir, `${CANARY}-spool`),
      FABRIC_CAPTURE_POLICY: policyPath,
      FABRIC_WIRE_ID_KEY: ID_KEY,
      FABRIC_TENANT_ID: `${CANARY}-tenant`,
      FABRIC_RUN_ID: `${CANARY}-run`,
      FABRIC_SOURCE_ID: `${CANARY}-source`,
      FABRIC_OTLP_ENDPOINT: "http://127.0.0.1:4318",
      FABRIC_OTLP_HEADERS: `authorization=Bearer ${CANARY}-token`,
      FABRIC_WIRE_ENDPOINTS: JSON.stringify([
        {
          endpoint_id: `${CANARY}-gateway`,
          dialect: "openai",
          hosts: [`${CANARY}-host.internal`],
          host_suffixes: [`.${CANARY}-models.internal`],
          path_prefix: `/${CANARY}`,
        },
      ]),
    };
    const settings = resolveConfig({ spoolKey: SPOOL_KEY }, env);
    const gate = decideGate({
      node: false,
      store: true,
      policy: new DeploymentPolicy(JSON.parse(readFileSync(policyPath, "utf8"))),
      idKey: true,
      spool: true,
      spoolKey: true,
    });
    const runtime = { node: "24.4.0", undici: "7.11.0", platform: "linux-x64-glibc" };
    const table = JSON.parse(
      readFileSync(join(REPO, "sdk/typescript/wire-qualification.json"), "utf8"),
    );
    const states = initialStates({
      runtime,
      table,
      nativeOk: true,
      enabled: { [UNDICI_POINT]: true },
      installed: { [UNDICI_POINT]: true },
      endpoints: settings.endpoints.length + settings.extraEndpoints.length,
    });
    const template = manifestTemplate(settings, {
      sourceId: labelPseudonym("s", env.FABRIC_SOURCE_ID, settings.secrets.idKey),
      gate,
      spoolKeyId: spoolKeyId(SPOOL_KEY),
      states,
      runtime,
    });
    const chain = new ManifestChain(template);
    const beats = new Heartbeats(chain);
    const out = [
      template,
      chain.initial(5n, { epochs: [3n], count: 1 }),
      chain.pointChanged(5n, UNDICI_POINT, "failed", "internal_error", 9n),
      chain.classUncaptured(5n, "node_worker_unattached", 10n),
      beats.final(5n, 10n),
      beats.tick(5n, 10n, true),
      chain.document,
    ];
    const text = JSON.stringify(out, (_key, value: unknown) =>
      typeof value === "bigint" ? value.toString() : value,
    ).toLowerCase();

    // The manifest says what it should, in its closed vocabulary.
    expect(chain.document!.spool_encrypted).toBe(true);
    expect(chain.document!.spool_key_id).toBe(spoolKeyId(SPOOL_KEY));
    expect(chain.document!.key_id).toMatch(/^kid-[0-9a-f]{8}$/);
    expect(chain.document!.source_id).toMatch(/^s-[0-9a-f]{32}$/);

    const pkg = JSON.parse(readFileSync(join(REPO, "sdk/typescript/package.json"), "utf8"));
    const dependencies = Object.keys({
      ...pkg.dependencies,
      ...pkg.devDependencies,
      ...pkg.peerDependencies,
      ...pkg.optionalDependencies,
    });
    expect(dependencies.length).toBeGreaterThan(0);
    const forbidden = [
      CANARY,
      Buffer.from(ID_KEY).toString("hex"),
      Buffer.from(ID_KEY).toString("base64").toLowerCase(),
      SPOOL_KEY.toString("hex"),
      SPOOL_KEY.toString("base64").toLowerCase(),
      process.cwd().toLowerCase(),
      homedir().toLowerCase(),
      process.execPath.toLowerCase(),
      tmpdir().toLowerCase(),
      "node_modules",
      // `typescript` is also the schema's `sdk.language` value, not an inventory entry.
      ...dependencies.filter((name) => name !== "typescript").map((n) => n.toLowerCase()),
    ];
    for (const value of forbidden) expect(text.includes(value), value).toBe(false);
    // No string anywhere looks like a path or a URL.
    for (const value of strings(out)) {
      expect(value.startsWith("/") || value.includes("://") || value.includes("\\"), value).toBe(
        false,
      );
    }
  });
});

function* strings(value: unknown): Generator<string> {
  if (typeof value === "string") yield value;
  else if (Array.isArray(value)) for (const item of value) yield* strings(item);
  else if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      yield key;
      yield* strings(item);
    }
  }
}
