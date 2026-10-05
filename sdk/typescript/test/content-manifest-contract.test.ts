// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
import { expect, it } from "vitest";
import { readFileSync } from "node:fs";
import {
  TranscriptManifest,
  CONTENT_ROLES,
  ContentStatus,
  buildContentDescriptor,
} from "../src/index.js";

it("projects coverage under the published manifest contract and observes only descriptor-bearing statuses", () => {
  const schema = JSON.parse(
    readFileSync(
      new URL(
        "../../../contracts/content/v1/schema/transcript-manifest-v1.schema.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  const manifest = new TranscriptManifest({
    manifestId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    tenantId: "acme",
    agentId: "agent",
    decisionId: "decision",
    producer: { name: "test", version: "1", language: "typescript" },
    rolesEnabled: CONTENT_ROLES,
  });
  const roles = [...CONTENT_ROLES];
  const observed: string[] = [];
  for (const [index, status] of Object.values(ContentStatus).entries()) {
    const role = roles[index]!;
    if (["pending", "stored", "truncated"].includes(status)) {
      const { descriptor } = buildContentDescriptor({
        tenantId: "acme",
        role,
        content: "payload",
        mediaType: "text/plain",
        source: "caller",
        status,
        bindings: {},
        payloadMaxBytes: status === "truncated" ? 3 : 100,
      });
      manifest.add({
        sequence: 0,
        role,
        status,
        descriptor,
        ref: `file:///store/acme/${descriptor.digest.slice(7)}`,
      });
      observed.push(role);
    } else {
      manifest.add({ sequence: 0, role, status });
    }
  }
  const doc = manifest.toJSON();
  for (const key of schema.required) expect(doc).toHaveProperty(key);
  expect(schema.additionalProperties).toBe(false);
  for (const key of Object.keys(doc)) expect(schema.properties).toHaveProperty(key);
  expect(doc.coverage).toEqual({
    roles_enabled: [...CONTENT_ROLES].sort(),
    roles_observed: observed.sort(),
  });
  expect(doc).not.toHaveProperty("roles_enabled");
  expect(doc).not.toHaveProperty("roles_observed");
  expect(doc.completeness).toEqual(
    Object.fromEntries(Object.values(ContentStatus).map((status) => [status, 1])),
  );
  expect(manifest.rolesObserved()).toEqual(observed);
});

it("does not serialize an empty observation window as a transcript", () => {
  const manifest = new TranscriptManifest({
    manifestId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    tenantId: "acme",
    agentId: "agent",
    decisionId: "decision",
    producer: { name: "test", version: "1", language: "typescript" },
    rolesEnabled: CONTENT_ROLES,
  });
  expect(manifest.items).toEqual([]);
  expect(() => manifest.toJSON()).toThrow(/no observations/);
});

import { mkdtempSync, existsSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
} from "@opentelemetry/sdk-trace-node";
import {
  Fabric,
  LocalFilesystemContentStore,
  ContentResolver,
  ResolveStatus,
  type Decision,
} from "../src/index.js";

for (const durability of ["inline", "process", "spooled"] as const) {
  for (const fails of [false, true]) {
    it(`leaves no empty manifest or reference for ${durability} ${fails ? "failure" : "success"}`, async () => {
      const root = mkdtempSync(join(tmpdir(), "fabric-empty-manifest-"));
      const exporter = new InMemorySpanExporter();
      const provider = new BasicTracerProvider({
        spanProcessors: [new SimpleSpanProcessor(exporter)],
      });
      const store = new LocalFilesystemContentStore(root, "acme");
      const fabric = new Fabric({
        tenantId: "acme",
        agentId: "agent",
        tracerProvider: provider,
        contentCapture: { store, roles: "all", durability, spoolDir: join(root, "spool") },
      });
      let decision: Decision | undefined;
      const error = new Error("application failure");
      try {
        let result: unknown;
        let caught: unknown;
        try {
          result = fabric.decision({ sessionId: "s", requestId: "r" }, (d) => {
            decision = d;
            expect(d.contentManifestUri).toBeUndefined();
            if (fails) throw error;
            return 42;
          });
        } catch (value) {
          caught = value;
        }
        expect(caught).toBe(fails ? error : undefined);
        if (!fails) expect(result).toBe(42);
        expect(decision?.contentManifest?.items).toEqual([]);
        expect(decision?.contentManifestUri).toBeUndefined();
        const counts = await fabric.flushContent();
        expect(counts?.stored).toBe(0);
        expect(counts?.pending).toBe(0);
        const expectedUri = store.manifestUriFor(decision!.contentManifest!.manifest_id);
        expect((await new ContentResolver([store]).resolve(expectedUri)).status).toBe(
          ResolveStatus.MISSING,
        );
        expect(existsSync(join(root, "acme"))).toBe(false);
        if (existsSync(join(root, "spool"))) expect(readdirSync(join(root, "spool"))).toEqual([]);
        expect(exporter.getFinishedSpans()).toHaveLength(1);
        expect(exporter.getFinishedSpans()[0]!.attributes).not.toHaveProperty(
          "fabric.content.manifest_ref",
        );
      } finally {
        await fabric.close();
        await provider.shutdown();
        rmSync(root, { recursive: true, force: true });
      }
    });
  }
}
