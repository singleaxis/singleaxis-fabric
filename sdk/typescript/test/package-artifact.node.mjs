// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/* global Buffer */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

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
