// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Sol P0-A #4 (TypeScript, parity with Python 00093e6): the production content gate on
 * the explicit input (spec 049 §7.3, §7.7 "both inputs"). Production content capture
 * needs the capture policy and the id key; otherwise every capture is `not_captured`
 * with the reason, and nothing is stored or digested.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ByteEvidenceRecorder,
  DeploymentPolicy,
  LocalFilesystemContentStore,
  type DeploymentPolicyData,
} from "../src/index.js";

const ROOT = path.resolve(import.meta.dirname, "../../..");
const SECRET = Buffer.from("sensitive-value");
const ID_KEY = Buffer.from("fabric-test-id-key-not-a-secret");
const roots: string[] = [];
afterEach(() => {
  vi.unstubAllEnvs();
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function policy(profile: "local" | "production"): DeploymentPolicy {
  const data = JSON.parse(
    fs.readFileSync(path.join(ROOT, "examples/enterprise/policy.local.json"), "utf8"),
  ) as DeploymentPolicyData;
  data.privacy = { "terminal.stdout": "retain_original" };
  data.deployment = {
    profile,
    image_digest: "sha256:" + "0".repeat(64),
    tls_required: true,
    encrypted_store_required: true,
  };
  return DeploymentPolicy.fromDict(data);
}
function store(tenant: string, marked?: DeploymentPolicy): LocalFilesystemContentStore {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "fabric-byte-gate-"));
  roots.push(root);
  const created = new LocalFilesystemContentStore(root, tenant);
  if (marked !== undefined) Object.defineProperty(created, "policy", { value: marked });
  return created;
}
const options = {
  role: "terminal.stdout",
  boundary: "terminal",
  sourceId: "sdk",
  sourceEpoch: 0,
  sourceSequence: 1,
};

describe("the explicit input's production gate", () => {
  it.each([
    ["production policy, no id key", "production", false, undefined, "missing_id_key"],
    ["production store, no policy", undefined, true, undefined, "missing_capture_policy"],
    ["production store, no policy, id key", undefined, true, ID_KEY, "missing_capture_policy"],
    ["production policy and id key", "production", false, ID_KEY, null],
    ["local policy", "local", false, undefined, null],
  ] as const)("%s", async (_name, profile, storeMarked, idKey, reason) => {
    vi.stubEnv("FABRIC_WIRE_ID_KEY", "");
    const deploymentPolicy = profile === undefined ? undefined : policy(profile);
    const tenant = policy("local").tenant_id;
    const target = store(tenant, storeMarked ? policy("production") : undefined);
    const recorder = new ByteEvidenceRecorder({
      store: target,
      roles: new Set(["terminal.stdout"]),
      deploymentPolicy,
      idKey,
    });
    const initial = recorder.capture(SECRET, options);
    await recorder.flush();
    const settled = recorder.get(initial.object_id)!;
    const status = recorder.status();
    expect(status.profile).toBe(profile === "production" || storeMarked ? "production" : "local");
    if (reason === null) {
      expect(status.content_capture).toBe("enabled");
      expect(settled.status).toBe("stored");
      expect(Buffer.from(target.read(settled.ref!))).toEqual(SECRET);
    } else {
      expect(status).toMatchObject({ content_capture: "disabled", content_capture_reason: reason });
      for (const descriptor of [initial, settled]) {
        expect(descriptor.status).toBe("not_captured");
        expect(descriptor.status_reason).toBe(reason);
        expect(descriptor.ref).toBeUndefined();
        expect(descriptor.source_sha256).toBeUndefined();
        expect(descriptor.source_byte_length).toBeUndefined();
      }
      const hex = Buffer.from(createHash("sha256").update(SECRET).digest("hex"));
      for (const root of roots)
        for (const name of fs.readdirSync(root, { recursive: true })) {
          const file = path.join(root, String(name));
          if (fs.lstatSync(file).isFile()) {
            expect(fs.readFileSync(file).includes(SECRET)).toBe(false);
            expect(fs.readFileSync(file).includes(hex)).toBe(false);
          }
        }
    }
    await recorder.close();
  });

  it("reads the id key from FABRIC_WIRE_ID_KEY; a short key is a configuration error", async () => {
    const tenant = policy("local").tenant_id;
    vi.stubEnv("FABRIC_WIRE_ID_KEY", ID_KEY.toString());
    const recorder = new ByteEvidenceRecorder({
      store: store(tenant),
      roles: new Set(["terminal.stdout"]),
      deploymentPolicy: policy("production"),
    });
    expect(recorder.status().content_capture).toBe("enabled");
    await recorder.close();
    vi.stubEnv("FABRIC_WIRE_ID_KEY", "short");
    expect(
      () =>
        new ByteEvidenceRecorder({
          store: store(tenant),
          roles: new Set(["terminal.stdout"]),
          deploymentPolicy: policy("production"),
        }),
    ).toThrow("FABRIC_WIRE_ID_KEY");
    expect(
      () =>
        new ByteEvidenceRecorder({
          store: store(tenant),
          roles: new Set(["terminal.stdout"]),
          idKey: Buffer.from("short"),
        }),
    ).toThrow("FABRIC_WIRE_ID_KEY");
  });
});

describe("the explicit input's identity without the id key", () => {
  // Sol P0-A round 2 #3 (spec 049 §2.9 rule 5): production without FABRIC_WIRE_ID_KEY
  // exports no caller-derived id: a random per-process source id, the generated run
  // fallback, and generated ids for every other caller id (stable, so records join).
  const canaries = [
    "customer-alice",
    "private-case-123",
    "op-private-7",
    "att-private-9",
    "stream-private-1",
  ];
  const identity = {
    ...options,
    sourceId: "customer-alice",
    runId: "private-case-123",
    operationId: "op-private-7",
    attemptId: "att-private-9",
    streamId: "stream-private-1",
    chunkIndex: 0,
  };
  it("replaces every caller id in production", async () => {
    vi.stubEnv("FABRIC_WIRE_ID_KEY", "");
    const recorder = new ByteEvidenceRecorder({
      store: store(policy("production").tenant_id),
      roles: new Set(["terminal.stdout"]),
      deploymentPolicy: policy("production"),
    });
    const first = recorder.capture(SECRET, identity);
    const second = recorder.capture(SECRET, { ...identity, sourceSequence: 2 });
    await recorder.flush();
    const text = JSON.stringify([first, second, recorder.drainSettled()]);
    for (const canary of canaries) expect(text).not.toContain(canary);
    expect(first.source_id).toMatch(/^s-[0-9a-f]{32}$/);
    expect(first.run_id).toBe(`source:${first.source_id}:0`);
    for (const key of ["source_id", "run_id", "operation_id", "attempt_id", "stream_id"] as const)
      expect(second[key]).toBe(first[key]);
    // the sequence check still applies to the caller's source
    expect(() => recorder.capture(SECRET, identity)).toThrow("sourceSequence");
    await recorder.close();
  });
  it.each([
    ["local", undefined],
    ["production", ID_KEY],
  ] as const)("keeps the caller ids with a %s policy", async (profile, idKey) => {
    vi.stubEnv("FABRIC_WIRE_ID_KEY", "");
    const recorder = new ByteEvidenceRecorder({
      store: store(policy(profile).tenant_id),
      roles: new Set(["terminal.stdout"]),
      deploymentPolicy: policy(profile),
      idKey,
    });
    const descriptor = recorder.capture(SECRET, identity);
    expect([descriptor.source_id, descriptor.run_id]).toEqual([
      "customer-alice",
      "private-case-123",
    ]);
    await recorder.close();
  });
});
