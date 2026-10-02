// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/* global Buffer, process */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { URL } from "node:url";

import {
    EXPECTED_PACKAGE_FILES,
    FORBIDDEN_RECORDER_TOKENS,
    PACKAGE_NAME,
    validatePackRecord,
    validateRecorderPayloads,
} from "../scripts/package-qualified.mjs";

function metadata(bytes, overrides = {}) {
    return {
        name: PACKAGE_NAME,
        version: "1.2.3-beta.1",
        size: bytes.length,
        shasum: createHash("sha1").update(bytes).digest("hex"),
        integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
        files: EXPECTED_PACKAGE_FILES.map((path) => ({ path, size: 1, mode: 0o644 })),
        ...overrides,
    };
}

test("accepts one exact, integrity-bound package allowlist", () => {
    const bytes = Buffer.from("qualified-artifact");
    const result = validatePackRecord(metadata(bytes), bytes, "1.2.3-beta.1");
    assert.equal(result.sha256, createHash("sha256").update(bytes).digest("hex"));
    assert.deepEqual(result.files, [...EXPECTED_PACKAGE_FILES].sort());
});

test("rejects an undeclared file even when npm metadata includes it", () => {
    const bytes = Buffer.from("qualified-artifact");
    const record = metadata(bytes);
    record.files.push({ path: "src/private.ts", size: 1, mode: 0o644 });
    assert.throws(
        () => validatePackRecord(record, bytes, "1.2.3-beta.1"),
        /unexpected=\[src\/private\.ts\]/,
    );
});

test("rejects altered bytes and version drift", () => {
    const original = Buffer.from("qualified-artifact");
    const record = metadata(original);
    assert.throws(
        () => validatePackRecord(record, Buffer.from("tampered-artifact"), "1.2.3-beta.1"),
        /SHA-1 does not match/,
    );
    assert.throws(() => validatePackRecord(record, original, "1.2.4"), /expected 1\.2\.4/);
});

test("rejects hidden control or evaluation code in packed JS and declarations", () => {
    for (const token of FORBIDDEN_RECORDER_TOKENS) {
        assert.throws(
            () => validateRecorderPayloads({ "dist/index.js": `class Decision { ${token}() {} }` }),
            /contains forbidden token/,
        );
    }
});

test("accepts recorder-only packed payloads", () => {
    assert.doesNotThrow(() =>
        validateRecorderPayloads({
            "dist/index.js": "class Decision { recordRetrieval() {} recordSideEffect() {} }",
            "dist/index.d.ts": "declare class Decision { recordRetrieval(): void }",
        }),
    );
});

test(
    "built local store rejects FIFO reads without blocking",
    { skip: process.platform === "win32" },
    () => {
        const root = mkdtempSync(join(tmpdir(), "fabric-fifo-"));
        try {
            const tenant = join(root, "acme");
            mkdirSync(tenant);
            const fifo = join(tenant, "fifo");
            const made = spawnSync("mkfifo", [fifo], { timeout: 2000, encoding: "utf8" });
            assert.equal(made.status, 0, made.stderr);
            const code = `
            import { LocalFilesystemContentStore } from ${JSON.stringify(new URL("../dist/index.js", import.meta.url).href)};
            const store = new LocalFilesystemContentStore(process.argv[1], "acme");
            try { store.read(process.argv[2]); process.exitCode = 2; }
            catch (error) { if (!/regular file/.test(error.message)) throw error; }
        `;
            const result = spawnSync(
                process.execPath,
                ["--input-type=module", "-e", code, root, `file://${fifo}`],
                { timeout: 2000, encoding: "utf8" },
            );
            assert.equal(result.error, undefined, result.error?.message);
            assert.equal(result.status, 0, result.stderr);
        } finally {
            rmSync(root, { recursive: true, force: true });
        }
    },
);
