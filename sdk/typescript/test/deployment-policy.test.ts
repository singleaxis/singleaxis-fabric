// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import {
  ByteEvidenceRecorder,
  ContentProtector,
  DeploymentPolicy,
  LocalFilesystemContentStore,
  type DeploymentPolicyData,
  type PrivacyMode,
} from "../src/index.js";

const ROOT = path.resolve(import.meta.dirname, "../../..");
const SECRET = Buffer.from("sensitive-value");
const DIGEST = "sha256:777dda0c14d100c2c6728b2e3858f53c55cd62fdf3c1c3ced5decee0a5f36ea6";
const TOKEN = "fabric.token.v1:a603512146debdb7ec03d124e146fbd4ae088f64c32642b950877829a632a31d";
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});
function policyData(): DeploymentPolicyData {
  return JSON.parse(
    fs.readFileSync(path.join(ROOT, "examples/enterprise/policy.local.json"), "utf8"),
  ) as DeploymentPolicyData;
}
function policyFor(mode: PrivacyMode): DeploymentPolicy {
  const data = policyData();
  data.privacy = { "terminal.stdout": mode };
  return DeploymentPolicy.fromDict(data);
}
function store(tenant: string): LocalFilesystemContentStore {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "fabric-deployment-policy-"));
  roots.push(root);
  return new LocalFilesystemContentStore(root, tenant);
}

describe("DeploymentPolicy", () => {
  it("matches Python canonical digest and snapshots configuration", () => {
    const data = policyData();
    const policy = DeploymentPolicy.from_dict(data);
    expect(policy.digest).toBe(DIGEST);
    expect(policy.to_dict()).toEqual(data);
    expect(policy.schema_version).toBe("fabric.deployment-policy/v1");
    expect(policy.policy_id).toBe("local-example");
    expect(policy.policy_version).toBe(1);
    expect(policy.tenant_id).toBe("example-tenant");
    expect(policy.workload_id).toBe("example-agent");
    expect(policy.storage.key_id).toBe("local-example-key");
    expect(policy.retention.days).toBe(7);
    expect(policy.deployment.profile).toBe("local");
    expect(policy.required_integrations).toEqual(["fabric.call_recorder"]);
    data.privacy["tool.call.arguments"] = "retain_original";
    const clone = policy.toDict();
    clone.storage.key_id = "other";
    expect(policy.digest).toBe(DIGEST);
    expect(policy.privacy["tool.call.arguments"]).toBe("omit");
    expect(Object.isFrozen(policy.privacy)).toBe(true);
  });
  it.each([
    ["schema_version", "future"],
    ["policy_id", "secret/path"],
    ["policy_version", true],
    ["policy_version", 0],
    ["policy_version", 2 ** 31],
    ["privacy", {}],
    ["privacy", { "terminal.stdout": "original" }],
    ["privacy", { "invalid role": "omit" }],
    ["required_integrations", ["http", "http"]],
    ["required_integrations", "http"],
    ["storage", { backend: "cloud", region: "local", key_id: "key" }],
    ["storage", { backend: "local", region: "local", key_id: "key", secret: "secret" }],
    ["storage", { backend: "local", region: "local", key_id: "key", root: "\n" }],
    ["retention", { days: 0 }],
    ["retention", { days: 36501 }],
  ])("rejects invalid %s", (field, value) => {
    expect(() => new DeploymentPolicy({ ...policyData(), [field as string]: value })).toThrow();
  });
  it("rejects unknown fields and unsafe production declarations", () => {
    expect(() => new DeploymentPolicy({ ...policyData(), secret: "never-print-me" })).toThrow(
      "fields",
    );
    const data = policyData();
    data.deployment.profile = "production";
    expect(() => new DeploymentPolicy(data)).toThrow("production");
    Object.assign(data.deployment, {
      image_digest: "sha256:" + "a".repeat(64),
      tls_required: true,
      encrypted_store_required: true,
    });
    expect(new DeploymentPolicy(data).deployment.profile).toBe("production");
    expect(
      () => new DeploymentPolicy({ ...data, deployment: { ...data.deployment, tls_required: 1 } }),
    ).toThrow("booleans");
  });
  it("canonicalizes set-like integration ordering", () => {
    const data = policyData();
    data.required_integrations = ["z", "a"];
    const policy = new DeploymentPolicy(data);
    data.required_integrations.reverse();
    expect(new DeploymentPolicy(data).digest).toBe(policy.digest);
    expect(policy.required_integrations).toEqual(["a", "z"]);
  });
});

describe("ContentProtector", () => {
  it.each(["omit", "metadata_only"] as const)("withholds %s without original digests", (mode) => {
    const protector = new ContentProtector(policyFor(mode));
    const result = protector.protect("terminal.stdout", SECRET);
    expect(result.status).toBe("withheld");
    expect(result.originalDigest).toBeNull();
    expect(result.protectedBytes).toBeNull();
    expect(Object.hasOwn(result.metadata, "source_byte_length")).toBe(mode === "metadata_only");
    expect(JSON.stringify(result)).not.toContain("sensitive-value");
    expect(JSON.stringify(result)).not.toContain(createHash("sha256").update(SECRET).digest("hex"));
    const unknown = protector.protect("tool.call.result", SECRET);
    expect(unknown.mode).toBe("omit");
    expect(unknown.metadata.source_byte_length).toBeUndefined();
  });
  it("separates original and derivative bytes and never serializes payloads", () => {
    const original = new ContentProtector(policyFor("retain_original")).protect(
      "terminal.stdout",
      SECRET,
    );
    expect(original.status).toBe("retained");
    expect(Buffer.from(original.protectedBytes!)).toEqual(SECRET);
    expect(original.originalDigest).toBe(
      "sha256:" + createHash("sha256").update(SECRET).digest("hex"),
    );
    expect(JSON.stringify(original)).not.toContain("sensitive-value");
    const redacted = new ContentProtector(policyFor("redact"), {
      redactors: { "terminal.stdout": () => Buffer.from("[redacted]") },
    }).protect("terminal.stdout", SECRET);
    expect(redacted.status).toBe("redacted");
    expect(redacted.originalDigest).toBeNull();
    expect(redacted.metadata.source_byte_length).toBeUndefined();
    expect(Buffer.from(redacted.protectedBytes!).toString()).toBe("[redacted]");
    const copy = original.protectedBytes!;
    copy[0] = 0;
    expect(Buffer.from(original.protectedBytes!)).toEqual(SECRET);
  });
  it("rejects absent transforms and keys before capture", () => {
    expect(() => new ContentProtector(policyFor("redact"))).toThrow("redactor");
    expect(() => new ContentProtector(policyFor("tokenize"))).toThrow("caller-supplied key");
    expect(
      () => new ContentProtector(policyFor("tokenize"), { tokenizationKey: Buffer.from("weak") }),
    ).toThrow("32 bytes");
    expect(
      () =>
        new ContentProtector(policyFor("omit"), {
          redactors: { "terminal.stdout": (data) => data },
        }),
    ).toThrow("explicitly");
  });
  it("matches Python HMAC vector and scopes to tenant, workload, policy and key", () => {
    const policy = policyFor("tokenize");
    const key = Buffer.alloc(32, "k");
    const result = new ContentProtector(policy, { tokenizationKey: key }).protect(
      "terminal.stdout",
      SECRET,
    );
    expect(Buffer.from(result.protectedBytes!).toString()).toBe(TOKEN);
    expect(result.originalDigest).toBeNull();
    expect(result.metadata.source_byte_length).toBeUndefined();
    for (const [field, value] of [
      ["tenant_id", "other-tenant"],
      ["workload_id", "other-workload"],
      ["policy_version", 2],
    ]) {
      const data = { ...policy.toDict(), [field!]: value };
      const other = new ContentProtector(new DeploymentPolicy(data), { tokenizationKey: key });
      expect(
        Buffer.from(other.protect("terminal.stdout", SECRET).protectedBytes!).toString(),
      ).not.toBe(TOKEN);
    }
    expect(
      Buffer.from(
        new ContentProtector(policy, { tokenizationKey: Buffer.alloc(32, "j") }).protect(
          "terminal.stdout",
          SECRET,
        ).protectedBytes!,
      ).toString(),
    ).not.toBe(TOKEN);
  });
  it("makes failed, unsupported and oversized transformations explicit without error text", () => {
    const protector = new ContentProtector(policyFor("redact"), {
      redactors: {
        "terminal.stdout": () => {
          throw new Error("sensitive-value");
        },
      },
    });
    const result = protector.protect("terminal.stdout", SECRET);
    expect(result.status).toBe("lost");
    expect(result.metadata.reason).toBe("protection_failed");
    expect(JSON.stringify(result)).not.toContain("sensitive-value");
    expect(result.protectedBytes).toBeNull();
    const bad = new ContentProtector(policyFor("redact"), {
      redactors: { "terminal.stdout": () => "bad" as unknown as Uint8Array },
    });
    expect(bad.protect("terminal.stdout", SECRET).status).toBe("unsupported");
    const oversized = new ContentProtector(policyFor("redact"), {
      redactors: { "terminal.stdout": () => Buffer.from("abc") },
      payloadMaxBytes: 2,
    });
    expect(oversized.protect("terminal.stdout", Buffer.from("x")).metadata.reason).toBe(
      "protected_payload_too_large",
    );
    expect(oversized.protect("terminal.stdout", SECRET).metadata.reason).toBe("payload_too_large");
    expect(oversized.protect("terminal.stdout", "bad" as unknown as Uint8Array).status).toBe(
      "unsupported",
    );
  });
});

describe("Deployment-protected byte recorder", () => {
  it("keeps retained-source metadata paired when the protected queue is full", async () => {
    const policy = policyFor("retain_original");
    const recorder = new ByteEvidenceRecorder({
      store: store(policy.tenant_id),
      deploymentPolicy: policy,
      roles: new Set(["terminal.stdout"]),
      queueMaxItems: 1,
    });
    const options = {
      role: "terminal.stdout",
      boundary: "terminal",
      sourceId: "sdk",
      sourceEpoch: 0,
      sourceSequence: 0,
    };
    recorder.capture(SECRET, options);
    const dropped = recorder.capture(SECRET, { ...options, sourceSequence: 1 });
    expect(dropped).toMatchObject({
      status: "dropped",
      representation: "unavailable",
      status_reason: "queue_full",
      source_byte_length: SECRET.length,
      source_sha256: "sha256:" + createHash("sha256").update(SECRET).digest("hex"),
      protection_status: "retained",
    });
    expect(dropped.ref).toBeUndefined();
    await recorder.close();
  });

  it.each(["retain_original", "omit", "metadata_only", "redact", "tokenize"] as const)(
    "applies %s before queue/store",
    async (mode) => {
      const policy = policyFor(mode);
      const original = store(policy.tenant_id);
      const derivative = store(policy.tenant_id);
      const contentProtector = new ContentProtector(policy, {
        redactors:
          mode === "redact" ? { "terminal.stdout": () => Buffer.from("[redacted]") } : undefined,
        tokenizationKey: Buffer.alloc(32, "k"),
      });
      const recorder = new ByteEvidenceRecorder({
        store: original,
        reviewStore: derivative,
        roles: new Set(["terminal.stdout"]),
        deploymentPolicy: policy,
        contentProtector,
      });
      const initial = recorder.capture(SECRET, {
        role: "terminal.stdout",
        boundary: "terminal",
        sourceId: "sdk",
        sourceEpoch: 0,
        sourceSequence: 1,
      });
      await recorder.flush();
      const settled = recorder.get(initial.object_id)!;
      expect(settled.policy_digest).toBe(policy.digest);
      if (mode === "retain_original") {
        expect(settled.status).toBe("stored");
        expect(Buffer.from(original.read(settled.ref!))).toEqual(SECRET);
      } else if (mode === "redact" || mode === "tokenize") {
        expect(settled.status).toBe("redacted");
        expect(settled.representation).toBe(mode === "redact" ? "redacted" : "tokenized");
        expect(settled.source_sha256).toBeUndefined();
        expect(settled.source_byte_length).toBeUndefined();
        expect(Buffer.from(derivative.read(settled.ref!)).toString()).toBe(
          mode === "redact" ? "[redacted]" : TOKEN,
        );
        const bytes = derivative.read(settled.ref!);
        const descriptor = derivative.readDescriptor(settled.ref!);
        for (const change of [
          { source_byte_length: SECRET.length },
          { policy_id: undefined },
          { policy_version: 0 },
          { protection_status: "retained" },
        ]) {
          expect(() => derivative.putBytesObject({ ...descriptor, ...change }, bytes)).toThrow(
            "invalid content-v2",
          );
        }
      } else {
        expect(settled.status).toBe("not_captured");
        expect(settled.ref).toBeUndefined();
      }
      if (mode !== "retain_original") {
        for (const root of roots)
          for (const filename of fs.readdirSync(root, { recursive: true })) {
            const target = path.join(root, String(filename));
            const fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
            try {
              if (fs.fstatSync(fd).isFile()) {
                const bytes = fs.readFileSync(fd);
                expect(bytes.includes(SECRET)).toBe(false);
                expect(
                  bytes.includes(Buffer.from(createHash("sha256").update(SECRET).digest("hex"))),
                ).toBe(false);
              }
            } finally {
              fs.closeSync(fd);
            }
          }
      }
      await recorder.close();
    },
  );
  it("rejects wrong tenant and overlapping derivative destinations", () => {
    const policy = policyFor("redact");
    const original = store(policy.tenant_id);
    const contentProtector = new ContentProtector(policy, {
      redactors: { "terminal.stdout": () => Buffer.from("safe") },
    });
    expect(
      () =>
        new ByteEvidenceRecorder({
          store: original,
          roles: new Set(["terminal.stdout"]),
          contentProtector,
        }),
    ).toThrow("same-tenant");
    expect(
      () =>
        new ByteEvidenceRecorder({
          store: original,
          reviewStore: original,
          roles: new Set(["terminal.stdout"]),
          contentProtector,
        }),
    ).toThrow("namespaces");
    expect(
      () =>
        new ByteEvidenceRecorder({
          store: store("wrong"),
          roles: new Set(["terminal.stdout"]),
          deploymentPolicy: policy,
        }),
    ).toThrow("tenant");
  });

  it.each([false, true])("rejects nested resolver namespaces (reverse=%s)", (reverse) => {
    const policy = policyFor("redact");
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "fabric-nested-policy-"));
    roots.push(root);
    const outer = new LocalFilesystemContentStore(root, policy.tenant_id);
    const inner = new LocalFilesystemContentStore(
      path.join(root, policy.tenant_id, "nested"),
      policy.tenant_id,
    );
    const contentProtector = new ContentProtector(policy, {
      redactors: { "terminal.stdout": () => Buffer.from("safe") },
    });
    expect(
      () =>
        new ByteEvidenceRecorder({
          store: reverse ? inner : outer,
          reviewStore: reverse ? outer : inner,
          roles: new Set(["terminal.stdout"]),
          contentProtector,
        }),
    ).toThrow("namespaces");
  });
});

it("bounds token output and keeps failing redactors from ever storing input", async () => {
  const token = new ContentProtector(policyFor("tokenize"), {
    tokenizationKey: Buffer.alloc(32, "k"),
    payloadMaxBytes: 2,
  }).protect("terminal.stdout", Buffer.from("x"));
  expect(token.status).toBe("lost");
  expect(token.metadata.reason).toBe("protected_payload_too_large");
  expect(token.protectedBytes).toBeNull();
  const policy = policyFor("redact");
  const original = store(policy.tenant_id);
  const derivative = store(policy.tenant_id);
  const contentProtector = new ContentProtector(policy, {
    redactors: {
      "terminal.stdout": () => {
        throw new Error("sensitive-value");
      },
    },
  });
  const recorder = new ByteEvidenceRecorder({
    store: original,
    reviewStore: derivative,
    roles: new Set(["terminal.stdout"]),
    contentProtector,
  });
  const item = recorder.capture(SECRET, {
    role: "terminal.stdout",
    boundary: "terminal",
    sourceId: "sdk",
    sourceEpoch: 0,
    sourceSequence: 1,
  });
  expect(item.status).toBe("failed");
  expect(item.protection_status).toBe("lost");
  expect(item.status_reason).toBe("protection_failed");
  expect(item.source_sha256).toBeUndefined();
  expect(item.source_byte_length).toBeUndefined();
  expect(JSON.stringify(item)).not.toContain("sensitive-value");
  expect(original.listObjectUris()).toEqual([]);
  expect(derivative.listObjectUris()).toEqual([]);
  await recorder.close();
});
