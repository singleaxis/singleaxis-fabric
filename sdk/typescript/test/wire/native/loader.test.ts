// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The loader (spec 055 §4.4 "Unsupported fallback"): it loads the module after the
 * SHA-256 check, or returns one named reason with its fix. It never throws.
 */
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { CATALOGUE } from "../../../src/wire/catalogue.generated.js";
import { NATIVE_DIGESTS } from "../../../src/wire/native-digests.generated.js";
import {
  NATIVE_FILE,
  NATIVE_TARGETS,
  loadNative,
  nativeTarget,
  type NativeDisabled,
  type NativeDisabledReason,
  type NativeLoad,
} from "../../../src/wire/native.js";
import { REPO } from "../helpers.js";
import { nativeBuild, privateDir, sha256, type NativeBuild } from "./build.js";

let build: NativeBuild;
let scratch: string;
let copies = 0;

beforeAll(() => {
  build = nativeBuild();
  scratch = privateDir("loader");
}, 120_000);

afterAll(() => {
  if (scratch !== undefined) rmSync(scratch, { recursive: true, force: true });
  build?.cleanup();
});

afterEach(() => {
  delete process.env.FABRIC_WIRE_TEST_FAULT;
});

/**
 * A prebuilds directory holding a private copy of `source`. A copy is a new file to the
 * dynamic loader, so each one starts with fresh process-global state (and, for the
 * fault-injection build, reads `FABRIC_WIRE_TEST_FAULT` afresh).
 */
function prebuildsWith(source: string | Uint8Array): { dir: string; file: string } {
  const dir = join(scratch, `prebuilds-${copies++}`);
  mkdirSync(join(dir, build.target), { recursive: true });
  const file = join(dir, build.target, NATIVE_FILE);
  if (typeof source === "string") copyFileSync(source, file);
  else writeFileSync(file, source);
  return { dir, file };
}

function expectDisabled(result: NativeLoad, reason: NativeDisabledReason): NativeDisabled {
  expect(result.ok).toBe(false);
  const off = result as NativeDisabled;
  expect(off.reason).toBe(reason);
  expect(off.reasonId).toBe(reason === "platform_unsupported" ? "FW-027" : "FW-028");
  const entry = CATALOGUE.find((row) => row.id === off.reasonId);
  expect(entry).toBeDefined();
  // The message names the cause, the fix says what to do; neither leaks a path or digest.
  expect(off.message).toContain(entry?.text as string);
  expect(off.message).toContain(reason);
  expect(off.fix.length).toBeGreaterThan(20);
  for (const text of [off.message, off.fix]) {
    expect(text).not.toContain(scratch);
    expect(text).not.toMatch(/[0-9a-f]{64}/);
  }
  expect(Object.isFrozen(off)).toBe(true);
  if (reason !== "native_selftest_failed") expect(off.failedStep).toBeUndefined();
  else expect(off.failedStep).toMatch(/^[A-Za-z-]+=[A-Z_]+$/);
  return off;
}

describe("loading", () => {
  it("loads the module whose digest matches, once per file", () => {
    const { dir, file } = prebuildsWith(build.release);
    const digests = { [build.target]: sha256(file) };
    const spool = privateDir("selftest");
    const first = loadNative({ prebuildsDir: dir, digests, selfTestDir: spool });
    rmSync(spool, { recursive: true, force: true });
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(first.target).toBe(build.target);
    expect(first.addon.abiVersion()).toBe(1);
    const second = loadNative({
      prebuildsDir: dir,
      digests: { [build.target]: sha256(file).toUpperCase() },
    });
    expect(second.ok && second.addon === first.addon).toBe(true);
  });

  it("the self-test leaves no file and no handle behind", () => {
    const { dir, file } = prebuildsWith(build.release);
    const spool = privateDir("selftest");
    try {
      const result = loadNative({
        prebuildsDir: dir,
        digests: { [build.target]: sha256(file) },
        selfTestDir: spool,
      });
      expect(result.ok).toBe(true);
      expect(readdirSync(spool)).toEqual([]);
      if (!result.ok) return;
      // All 64 descriptor handles are free again: the self-test closed its three.
      const d = result.addon.openDir(spool);
      const handles: number[] = [];
      for (let i = 0; i < 63; i++) handles.push(result.addon.openFile(d, "probe", true));
      expect(handles.every((h) => h > 0)).toBe(true);
      for (const h of [...handles, d]) expect(result.addon.close(h)).toBe(0);
    } finally {
      rmSync(spool, { recursive: true, force: true });
    }
  });

  it("selects one of the six targets, or none", () => {
    expect(nativeTarget("linux", "x64", "glibc")).toBe("linux-x64-glibc");
    expect(nativeTarget("linux", "arm64", "glibc")).toBe("linux-arm64-glibc");
    expect(nativeTarget("linux", "x64", "musl")).toBe("linux-x64-musl");
    expect(nativeTarget("linux", "arm64", "musl")).toBe("linux-arm64-musl");
    expect(nativeTarget("darwin", "x64")).toBe("darwin-x64");
    expect(nativeTarget("darwin", "arm64")).toBe("darwin-arm64");
    for (const [platform, arch] of [
      ["win32", "x64"],
      ["freebsd", "x64"],
      ["linux", "ia32"],
      ["linux", "riscv64"],
      ["darwin", "ppc64"],
    ] as const) {
      expect(nativeTarget(platform, arch)).toBeNull();
    }
    expect(NATIVE_TARGETS).toContain(nativeTarget());
    if (build.prebuilt) expect(nativeTarget()).toBe(build.target);
  });
});

describe("each disabled reason", () => {
  it("platform_unsupported: no prebuild for the operating system or CPU", () => {
    for (const [platform, arch] of [
      ["win32", "x64"],
      ["linux", "ia32"],
      ["sunos", "arm64"],
    ] as const) {
      const off = expectDisabled(
        loadNative({ prebuildsDir: build.dir, platform, arch }),
        "platform_unsupported",
      );
      expect(off.fix).toMatch(/Linux|macOS/);
    }
  });

  it("native_missing: the prebuild file is not there", () => {
    const empty = join(scratch, "no-prebuilds");
    mkdirSync(empty);
    expectDisabled(loadNative({ prebuildsDir: empty }), "native_missing");
    expectDisabled(loadNative({ prebuildsDir: join(scratch, "absent") }), "native_missing");
    // A directory where the file should be is not a module either.
    mkdirSync(join(empty, build.target, NATIVE_FILE), { recursive: true });
    expectDisabled(loadNative({ prebuildsDir: empty }), "native_missing");
    // This checkout ships no prebuilds: the default location reports the same reason.
    if (!existsSync(join(REPO, "sdk/typescript/prebuilds"))) {
      expectDisabled(loadNative(), "native_missing");
    }
  });

  it("native_digest_mismatch: a corrupt or unlisted file is never loaded", () => {
    const { dir, file } = prebuildsWith(build.release);
    const good = sha256(file);
    // One flipped byte. The file would crash or misbehave if it were loaded; it is not.
    const bytes = readFileSync(file);
    bytes[bytes.length >> 1] = (bytes[bytes.length >> 1] as number) ^ 0xff;
    writeFileSync(file, bytes);
    expectDisabled(
      loadNative({ prebuildsDir: dir, digests: { [build.target]: good } }),
      "native_digest_mismatch",
    );
    // No digest for this target, an empty table, and a malformed entry.
    const intact = prebuildsWith(build.release);
    for (const digests of [{}, { [build.target]: "" }, { [build.target]: good.slice(1) }]) {
      expectDisabled(loadNative({ prebuildsDir: intact.dir, digests }), "native_digest_mismatch");
    }
    // The committed table is what the loader uses when none is passed.
    // CI-built files are listed there and load; a local compile is not and does not.
    if (NATIVE_DIGESTS[build.target] !== sha256(intact.file)) {
      expectDisabled(loadNative({ prebuildsDir: intact.dir }), "native_digest_mismatch");
    } else {
      expect(loadNative({ prebuildsDir: intact.dir }).ok).toBe(true);
    }
  });

  it("native_load_failed: the operating system refuses the file", () => {
    const garbage = new TextEncoder().encode("this is not a shared object\n");
    const { dir, file } = prebuildsWith(garbage);
    expectDisabled(
      loadNative({ prebuildsDir: dir, digests: { [build.target]: sha256(file) } }),
      "native_load_failed",
    );
  });

  it("native_abi_mismatch: the module reports another ABI version", () => {
    const { dir, file } = prebuildsWith(build.faults);
    process.env.FABRIC_WIRE_TEST_FAULT = "abi=2";
    expectDisabled(
      loadNative({ prebuildsDir: dir, digests: { [build.target]: sha256(file) } }),
      "native_abi_mismatch",
    );
  });

  it("native_selftest_failed: an exclusive flock does not exclude a second handle", () => {
    const { dir, file } = prebuildsWith(build.faults);
    const spool = privateDir("selftest");
    try {
      process.env.FABRIC_WIRE_TEST_FAULT = "flock=ignore";
      const options = { prebuildsDir: dir, digests: { [build.target]: sha256(file) } };
      const off = expectDisabled(
        loadNative({ ...options, selfTestDir: spool }),
        "native_selftest_failed",
      );
      // The second handle got the lock too: the step and what it returned are named.
      expect(off.failedStep).toBe("flock-second-handle=UNEXPECTED_RESULT");
      expect(off.message).toContain("file locks or shared mappings do not work");
      expect(off.message).toContain("self-test step flock-second-handle=UNEXPECTED_RESULT");
      expect(off.fix).toContain("local disk");
      expect(readdirSync(spool)).toEqual([]);
      // Without a self-test directory the same module loads: only install runs the test.
      expect(loadNative(options).ok).toBe(true);
      // A failed self-test is not remembered as passed.
      expectDisabled(loadNative({ ...options, selfTestDir: spool }), "native_selftest_failed");
    } finally {
      rmSync(spool, { recursive: true, force: true });
    }
  });

  // Each failure names its own cause and fix: a full disk is not a filesystem without locks.
  it.each([
    ["recordLock=EOPNOTSUPP", "recordLock=UNSUPPORTED", "do not work in the spool", "local disk"],
    ["mapShared=EOPNOTSUPP", "mapShared=UNSUPPORTED", "do not work in the spool", "local disk"],
    ["allocate=ENOSPC", "allocate=NO_SPACE", "no free space or quota", "free space"],
    ["allocate=EDQUOT", "allocate=QUOTA", "no free space or quota", "free space"],
    ["openFile=EMFILE", "openFile=LIMIT", "handles are all in use", "restart the process"],
    ["openDir=EACCES", "openDir=PERMISSION", "not owned by this user", "mode 0700"],
  ])("native_selftest_failed: %s is reported as %s", (fault, failedStep, cause, fix) => {
    const { dir, file } = prebuildsWith(build.faults);
    const spool = privateDir("selftest");
    try {
      process.env.FABRIC_WIRE_TEST_FAULT = fault;
      const off = expectDisabled(
        loadNative({
          prebuildsDir: dir,
          digests: { [build.target]: sha256(file) },
          selfTestDir: spool,
        }),
        "native_selftest_failed",
      );
      expect(off.failedStep).toBe(failedStep);
      expect(off.message).toContain(cause);
      expect(off.message).toContain(`self-test step ${failedStep}`);
      expect(off.fix).toContain(fix);
      expect(readdirSync(spool)).toEqual([]);
    } finally {
      rmSync(spool, { recursive: true, force: true });
    }
  });

  it("native_selftest_failed: the spool directory is not private or not there", () => {
    const { dir, file } = prebuildsWith(build.release);
    const options = { prebuildsDir: dir, digests: { [build.target]: sha256(file) } };
    const shared = privateDir("selftest");
    try {
      chmodSync(shared, 0o755);
      const open = expectDisabled(
        loadNative({ ...options, selfTestDir: shared }),
        "native_selftest_failed",
      );
      expect(open.failedStep).toBe("openDir=UNSAFE_PATH");
      const absent = expectDisabled(
        loadNative({ ...options, selfTestDir: join(shared, "absent") }),
        "native_selftest_failed",
      );
      expect(absent.failedStep).toBe("openDir=NOT_FOUND");
      for (const off of [open, absent]) {
        expect(off.message).toContain("missing, is not owned by this user or is open to other");
        expect(off.fix).toContain("mode 0700");
        expect(off.fix).not.toContain("NFS"); // moving the spool would not help
      }
    } finally {
      rmSync(shared, { recursive: true, force: true });
    }
  });

  it("never throws, whatever it is given", () => {
    // A file no table lists: with `digests: null` the loader falls back to the committed
    // table, which on a CI-built target lists the real module, so a real copy would load.
    const unlisted = prebuildsWith(new TextEncoder().encode("not listed\n")).dir;
    const bad = [
      { prebuildsDir: 7 },
      { prebuildsDir: unlisted, digests: null },
      { prebuildsDir: build.dir, digests: { [build.target]: 7 } },
      { platform: {}, arch: [] },
      { prebuildsDir: "\0" },
    ] as unknown as Parameters<typeof loadNative>[0][];
    for (const options of bad) {
      const result = loadNative(options);
      expect(result.ok).toBe(false);
    }
  });
});

describe("nothing compiles or downloads at install or startup", () => {
  const ts = join(REPO, "sdk/typescript");

  it("package.json has no install script and the package root has no binding.gyp", () => {
    const manifest = JSON.parse(readFileSync(join(ts, "package.json"), "utf8")) as {
      scripts: Record<string, string>;
      dependencies?: Record<string, string>;
      gypfile?: boolean;
    };
    for (const name of ["preinstall", "install", "postinstall", "prepare"]) {
      expect(manifest.scripts[name], name).toBeUndefined();
    }
    // npm runs "node-gyp rebuild" for any package with a binding.gyp at its root and no
    // install script. The maintainer's binding.gyp therefore lives in native/.
    expect(existsSync(join(ts, "binding.gyp"))).toBe(false);
    expect(existsSync(join(ts, "native", "binding.gyp"))).toBe(true);
    expect(manifest.gypfile).not.toBe(true);
    expect(Object.keys(manifest.dependencies ?? {})).toEqual([]);
  });

  it("the loader source spawns nothing and opens no network connection", () => {
    const source = readFileSync(join(ts, "src/wire/native.ts"), "utf8");
    const imports = [...source.matchAll(/from "([^"]+)"/g)].map((m) => m[1]);
    expect(imports.sort()).toEqual([
      "./catalogue.generated.js",
      "./native-digests.generated.js",
      "node:crypto",
      "node:fs",
      "node:path",
      "node:url",
    ]);
  });

  it("the committed digest table lists only known targets with SHA-256 values", () => {
    for (const [target, digest] of Object.entries(NATIVE_DIGESTS)) {
      expect(NATIVE_TARGETS).toContain(target);
      expect(digest).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});
