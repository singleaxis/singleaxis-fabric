// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Sol P0-A #5 (TypeScript): customer redaction never runs on the caller's thread. A
 * redactor is a customer module loaded in a worker_threads Worker, bounded by a hard
 * timeout (`worker.terminate()`); an error or timeout withholds the object
 * (`protection_failed`), and a saturated bound withholds at once.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { monitorEventLoopDelay } from "node:perf_hooks";
import { pathToFileURL } from "node:url";
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
const FIXTURES = path.join(import.meta.dirname, "fixtures/redactors");
const SECRET = Buffer.from("sensitive-value");
const roots: string[] = [];
const protectors: ContentProtector[] = [];
afterEach(async () => {
  for (const protector of protectors.splice(0)) await protector.close();
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function policyFor(mode: PrivacyMode): DeploymentPolicy {
  const data = JSON.parse(
    fs.readFileSync(path.join(ROOT, "examples/enterprise/policy.local.json"), "utf8"),
  ) as DeploymentPolicyData;
  data.privacy = { "terminal.stdout": mode };
  return DeploymentPolicy.fromDict(data);
}
function store(tenant: string): LocalFilesystemContentStore {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "fabric-redactor-worker-"));
  roots.push(root);
  return new LocalFilesystemContentStore(root, tenant);
}
function protectorFor(
  mode: PrivacyMode,
  fixture: string,
  transformTimeoutMs = 2_000,
): ContentProtector {
  const protector = new ContentProtector(policyFor(mode), {
    redactors: { "terminal.stdout": { module: path.join(FIXTURES, fixture) } },
    transformTimeoutMs,
  });
  protectors.push(protector);
  return protector;
}
function recorderFor(protector: ContentProtector): {
  recorder: ByteEvidenceRecorder;
  review: LocalFilesystemContentStore;
} {
  const review = store(protector.policy.tenant_id);
  const recorder = new ByteEvidenceRecorder({
    store: store(protector.policy.tenant_id),
    reviewStore: review,
    roles: new Set(["terminal.stdout"]),
    contentProtector: protector,
  });
  return { recorder, review };
}
const options = (sourceSequence: number) => ({
  role: "terminal.stdout",
  boundary: "terminal",
  sourceId: "sdk",
  sourceEpoch: 0,
  sourceSequence,
});

/** Run `body` while measuring the main event loop's worst delay, in ms. */
async function worstLoopDelay(body: () => Promise<void>): Promise<number> {
  const histogram = monitorEventLoopDelay({ resolution: 10 });
  histogram.enable();
  try {
    await body();
  } finally {
    histogram.disable();
  }
  return histogram.max / 1e6;
}

function assertNoSecretOnDisk(): void {
  for (const root of roots)
    for (const filename of fs.readdirSync(root, { recursive: true })) {
      const target = path.join(root, String(filename));
      if (fs.lstatSync(target).isFile())
        expect(fs.readFileSync(target).includes(SECRET)).toBe(false);
    }
}

describe("customer redaction in a worker thread", () => {
  it.each(["redact", "masked_only"] as const)(
    "rejects in-process closure redactors for %s at construction",
    (mode) => {
      expect(
        () =>
          new ContentProtector(policyFor(mode), {
            redactors: {
              "terminal.stdout": (() => Buffer.from("x")) as unknown as { module: string },
            },
          }),
      ).toThrow("in-process redactor functions are not supported");
      expect(
        () =>
          new ContentProtector(policyFor(mode), {
            redactors: { "terminal.stdout": { module: "relative/redactor.mjs" } },
          }),
      ).toThrow("absolute path or file: URL");
      expect(
        () =>
          new ContentProtector(policyFor(mode), {
            redactors: { "terminal.stdout": { module: path.join(FIXTURES, "mask.mjs") } },
            transformTimeoutMs: 0,
          }),
      ).toThrow("transformTimeoutMs");
    },
  );

  it.each(["redact", "masked_only"] as const)(
    "a slow transformer module never blocks the caller (%s)",
    async (mode) => {
      const protector = protectorFor(mode, "slow.mjs");
      const { recorder, review } = recorderFor(protector);
      let settledId = "";
      const delay = await worstLoopDelay(async () => {
        const started = performance.now();
        const initial = recorder.capture(SECRET, options(1));
        expect(performance.now() - started).toBeLessThan(50);
        expect(initial.status).toBe("pending");
        expect(initial.source_sha256).toBeUndefined();
        expect(initial.source_byte_length).toBeUndefined();
        settledId = initial.object_id;
        await recorder.flush();
      });
      expect(delay).toBeLessThan(150); // the 200 ms busy loop ran on another thread
      const settled = recorder.get(settledId)!;
      expect(settled.status).toBe("redacted");
      expect(Buffer.from(review.read(settled.ref!)).toString()).toBe("[slow-redacted]");
      assertNoSecretOnDisk();
      await recorder.close();
    },
  );

  it("a hung transformer module is terminated at its timeout and withholds", async () => {
    const protector = protectorFor("redact", "hung.mjs", 300);
    const { recorder } = recorderFor(protector);
    const ids: string[] = [];
    const delay = await worstLoopDelay(async () => {
      for (let sequence = 1; sequence <= 3; sequence += 1) {
        const started = performance.now();
        ids.push(recorder.capture(SECRET, options(sequence)).object_id);
        expect(performance.now() - started).toBeLessThan(50);
      }
      await recorder.flush(20_000);
    });
    expect(delay).toBeLessThan(150);
    for (const id of ids) {
      const settled = recorder.get(id)!;
      expect(settled).toMatchObject({
        status: "not_captured",
        status_reason: "protection_failed",
        protection_status: "withheld",
        representation: "unavailable",
      });
      expect(settled.ref).toBeUndefined();
      expect(settled.transformations).toBeUndefined();
    }
    expect(protector.stats().transform_timeouts).toBe(3); // every capture still processed
    assertNoSecretOnDisk();
    await recorder.close();
  });

  it("a throwing transformer module withholds without its error text", async () => {
    const protector = protectorFor("masked_only", "throws.mjs");
    const { recorder } = recorderFor(protector);
    const initial = recorder.capture(SECRET, options(1));
    await recorder.flush();
    const settled = recorder.get(initial.object_id)!;
    expect(settled.status).toBe("not_captured");
    expect(settled.status_reason).toBe("protection_failed");
    expect(JSON.stringify(settled)).not.toContain("sensitive-value");
    assertNoSecretOnDisk();
    await recorder.close();
  });

  it("bounds concurrent and abandoned calls: beyond the bound it withholds at once", async () => {
    const protector = protectorFor("redact", "hung.mjs", 1_000);
    const started = performance.now();
    const calls = [1, 2, 3].map(() => protector.protectAsync("terminal.stdout", SECRET));
    const third = await calls[2]!;
    expect(performance.now() - started).toBeLessThan(500); // refused without waiting
    expect(third.status).toBe("lost");
    expect(third.metadata.reason).toBe("protection_failed");
    for (const result of await Promise.all(calls.slice(0, 2)))
      expect(result.metadata.reason).toBe("protection_failed");
    expect(protector.stats()).toMatchObject({ transform_timeouts: 2, transform_saturated: 1 });
    const masked = protectorFor("redact", "mask.mjs");
    const ok = await masked.protectAsync("terminal.stdout", SECRET);
    expect(Buffer.from(ok.protectedBytes!).toString()).toBe("[redacted]");
    const viaUrl = new ContentProtector(policyFor("redact"), {
      redactors: {
        "terminal.stdout": {
          module: pathToFileURL(path.join(FIXTURES, "mask.mjs")),
          exportName: "default",
        },
      },
    });
    protectors.push(viaUrl);
    expect((await viaUrl.protectAsync("terminal.stdout", SECRET)).status).toBe("redacted");
  });
});

describe("the redactor Worker source", () => {
  it.each(["--input-type=module", "--input-type=commonjs"])(
    "runs under an inherited %s",
    async (flag) => {
      const { Worker } = await import("node:worker_threads");
      const { WORKER_SOURCE } = await import("../src/redactor-worker.js");
      const worker = new Worker(WORKER_SOURCE, {
        eval: true,
        execArgv: [flag],
        workerData: {
          href: pathToFileURL(path.join(FIXTURES, "mask.mjs")).href,
          exportName: "redact",
        },
      });
      try {
        const reply = await new Promise<{ kind: string; data: Uint8Array }>((resolve, reject) => {
          worker.once("message", resolve);
          worker.once("error", reject);
          worker.postMessage({ id: 1, data: new Uint8Array([1]) });
        });
        expect(reply.kind).toBe("ok");
        expect(Buffer.from(reply.data).toString()).toBe("[redacted]");
      } finally {
        await worker.terminate();
      }
    },
  );
});
