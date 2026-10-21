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
    ["local", undefined, undefined],
    ["production", ID_KEY, "clear"],
  ] as const)("keeps the caller ids with a %s policy", async (profile, idKey, identityMode) => {
    vi.stubEnv("FABRIC_WIRE_ID_KEY", "");
    const recorder = new ByteEvidenceRecorder({
      store: store(policy(profile).tenant_id),
      roles: new Set(["terminal.stdout"]),
      deploymentPolicy: policy(profile),
      idKey,
      identityMode,
    });
    const descriptor = recorder.capture(SECRET, identity);
    expect([descriptor.source_id, descriptor.run_id, descriptor.operation_id]).toEqual([
      "customer-alice",
      "private-case-123",
      "op-private-7",
    ]);
    await recorder.close();
  });
});

describe("the explicit input's identity with the id key", () => {
  // Spec 049 §2.9: with FABRIC_WIRE_ID_KEY, in the default pseudonymous identity mode,
  // every caller id leaves as its keyed pseudonym (run r-, source s-, any other caller id
  // lbl-), byte-identical to Python `fabric._sequence.KeyedIds` and the wire line.
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
  // Computed by the Python SDK (KeyedIds with the test key): cross-SDK parity.
  const expected = {
    source_id: "s-d196c616097bb8984f6ada4557109619",
    run_id: "r-7d4a93f9ecdfc6e4615a0f16d3a44b72",
    operation_id: "lbl-7972e6c680673bc371ed0645267ddcce",
    attempt_id: "lbl-cb8290324423bf78a132033a1ebd41d5",
    stream_id: "lbl-b8bf64540989ab7375f7654158f38e73",
  };

  it.each([
    ["production", "the environment"],
    ["local", "the environment"],
    ["production", "the config"],
  ] as const)(
    "emits keyed pseudonyms with a %s policy and the key from %s",
    async (profile, from) => {
      vi.stubEnv("FABRIC_IDENTITY_MODE", "");
      vi.stubEnv("FABRIC_WIRE_ID_KEY", from === "the environment" ? ID_KEY.toString() : "");
      const recorders = [0, 1].map(
        () =>
          new ByteEvidenceRecorder({
            store: store(policy(profile).tenant_id),
            roles: new Set(["terminal.stdout"]),
            deploymentPolicy: policy(profile),
            ...(from === "the config" ? { idKey: ID_KEY } : {}),
          }),
      );
      const [first, second] = recorders.map((recorder) => recorder.capture(SECRET, identity));
      for (const recorder of recorders) await recorder.flush();
      const settled = recorders.flatMap((recorder) => recorder.drainSettled());
      expect(settled.map((descriptor) => descriptor.status)).toEqual(["stored", "stored"]);
      const text = JSON.stringify([first, second, settled]);
      for (const canary of canaries) expect(text).not.toContain(canary);
      expect(first).toMatchObject(expected);
      expect(second).toMatchObject(expected); // deterministic: recorders and processes join
      expect(recorders[0]!.emittedRunId("private-case-123")).toBe(expected.run_id);
      // nothing written outside content carries a clear caller id
      for (const root of roots)
        for (const name of fs.readdirSync(root, { recursive: true })) {
          const file = path.join(root, String(name));
          if (fs.lstatSync(file).isFile())
            for (const canary of canaries)
              expect(fs.readFileSync(file).includes(Buffer.from(canary))).toBe(false);
        }
      for (const recorder of recorders) await recorder.close();
    },
  );

  it("maps a hex-shaped or unregistered lbl- caller id; only its own emitted ids pass", async () => {
    // Sol P0-A round 4 #1: shape never proves provenance. Values computed by the Python SDK.
    vi.stubEnv("FABRIC_IDENTITY_MODE", "");
    vi.stubEnv("FABRIC_WIRE_ID_KEY", ID_KEY.toString());
    const hex = "0123456789abcdef0123456789abcdef";
    const label = "lbl-024cdec5bc0d58b8a636a3e3084582fc";
    const recorder = new ByteEvidenceRecorder({
      store: store(policy("production").tenant_id),
      roles: new Set(["terminal.stdout"]),
      deploymentPolicy: policy("production"),
    });
    const first = recorder.capture(SECRET, {
      ...identity,
      operationId: hex,
      attemptId: hex,
      streamId: hex,
    });
    expect(first).toMatchObject({ operation_id: label, attempt_id: label, stream_id: label });
    const forged = recorder.capture(SECRET, {
      ...options,
      sourceSequence: 2,
      operationId: "lbl-" + "f".repeat(32),
      attemptId: label, // emitted by this recorder: it maps to itself
    });
    expect(forged).toMatchObject({
      operation_id: "lbl-39de82a31fdc6362cccd1d7479f54e0c",
      attempt_id: label,
    });
    await recorder.flush();
    expect(JSON.stringify([first, forged, recorder.drainSettled()])).not.toContain(hex);
    for (const root of roots)
      for (const name of fs.readdirSync(root, { recursive: true })) {
        const file = path.join(root, String(name));
        if (fs.lstatSync(file).isFile())
          expect(fs.readFileSync(file).includes(Buffer.from(hex))).toBe(false);
      }
    await recorder.close();
  });

  it("maps r-/s--shaped caller run and source ids; only its own emitted ids pass", async () => {
    // Sol P0-A round 5 #1: a caller run/source id is always mapped through the keyed
    // function, whatever its shape. Values computed by the Python SDK (cross-SDK parity).
    vi.stubEnv("FABRIC_IDENTITY_MODE", "");
    vi.stubEnv("FABRIC_WIRE_ID_KEY", "");
    const hex = "0123456789abcdef0123456789abcdef";
    const prefixed = { ...options, runId: "r-" + hex, sourceId: "s-" + hex };
    const recorder = (idKey: Buffer) =>
      new ByteEvidenceRecorder({
        store: store(policy("production").tenant_id),
        roles: new Set(["terminal.stdout"]),
        deploymentPolicy: policy("production"),
        idKey,
      });
    const first = recorder(ID_KEY);
    const rotated = recorder(Buffer.from("another-test-id-key-not-secret"));
    const mapped = {
      run_id: "r-115b7affde7a19e0990d1c3dfab4e0d4",
      source_id: "s-5db24377fab0ff85a785a1cd798c29c4",
    };
    expect(first.emittedRunId("r-" + hex)).toBe(mapped.run_id);
    expect(first.capture(SECRET, prefixed)).toMatchObject(mapped);
    expect(rotated.capture(SECRET, prefixed)).toMatchObject({
      run_id: "r-e9a42cbfd07ef0f60230aa4eaef84ffb",
      source_id: "s-75a3249c2f47ca70ec484d11a4337a25",
    });
    const emitted = {
      ...options,
      sourceSequence: 2,
      runId: mapped.run_id,
      sourceId: mapped.source_id,
    };
    expect(first.capture(SECRET, emitted)).toMatchObject(mapped); // emitted here: unchanged
    expect(rotated.capture(SECRET, emitted).run_id).not.toBe(mapped.run_id); // never emitted there
    for (const target of [first, rotated]) {
      await target.flush();
      expect(JSON.stringify(target.drainSettled())).not.toContain(hex);
      await target.close();
    }
  });

  it("FABRIC_IDENTITY_MODE=clear keeps the caller ids; an invalid mode throws", async () => {
    vi.stubEnv("FABRIC_WIRE_ID_KEY", ID_KEY.toString());
    vi.stubEnv("FABRIC_IDENTITY_MODE", "clear");
    const recorder = new ByteEvidenceRecorder({
      store: store(policy("production").tenant_id),
      roles: new Set(["terminal.stdout"]),
      deploymentPolicy: policy("production"),
    });
    expect(recorder.capture(SECRET, identity)).toMatchObject({
      source_id: "customer-alice",
      run_id: "private-case-123",
      operation_id: "op-private-7",
    });
    expect(recorder.emittedRunId("private-case-123")).toBe("private-case-123");
    await recorder.close();
    expect(
      () =>
        new ByteEvidenceRecorder({
          store: store(policy("production").tenant_id),
          roles: new Set(["terminal.stdout"]),
          identityMode: "canary" as never,
        }),
    ).toThrow("identityMode must be");
  });
});
