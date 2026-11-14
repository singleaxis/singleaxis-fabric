// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The loader of Fabric's Node-API lock module (spec 055 §4.4, R12).
 *
 * The module gives the JavaScript runtime the kernel primitives Node lacks: `flock`,
 * POSIX record locks, positional I/O on descriptors it owns, a shared mapping and one
 * isolate-teardown notification. This file finds the prebuild for the running platform,
 * checks its SHA-256 against the table embedded here before `process.dlopen`, checks the
 * ABI version and export list, and (at install) runs a self-test on the spool
 * filesystem. It runs no compiler and downloads nothing.
 *
 * It never throws. When the module cannot be used, the result names one reason
 * (`platform_unsupported`, `native_missing`, `native_digest_mismatch`,
 * `native_load_failed`, `native_abi_mismatch`, `native_selftest_failed`), its
 * diagnostics-catalogue id and the fix. The caller then installs no transport hook:
 * there are never hooks without locks, and there is no JavaScript lockfile fallback.
 *
 * Nothing here runs in a transport hook. Call {@link loadNative} from the installing
 * thread, the Fabric worker and each attaching isolate.
 */
import { createHash, randomBytes } from "node:crypto";
import { readFileSync, unlinkSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { CATALOGUE } from "./catalogue.generated.js";
import { NATIVE_DIGESTS } from "./native-digests.generated.js";

/** `abiVersion()` of the module this loader accepts (`FABRIC_WIRE_ABI_VERSION`). */
export const NATIVE_ABI_VERSION = 1;

/** The file name of the module inside `prebuilds/<target>/`. */
export const NATIVE_FILE = "fabric_wire.node";

/** The six prebuild targets of spec 055 §4.4. */
export const NATIVE_TARGETS = [
  "linux-x64-glibc",
  "linux-arm64-glibc",
  "linux-x64-musl",
  "linux-arm64-musl",
  "darwin-x64",
  "darwin-arm64",
] as const;
export type NativeTarget = (typeof NATIVE_TARGETS)[number];

/** The fixed result codes of `native/fabric_wire_abi.h`. */
export const NativeCode = Object.freeze({
  OK: 0,
  WOULD_BLOCK: -1,
  NOT_FOUND: -2,
  EXISTS: -3,
  PERMISSION: -4,
  NO_SPACE: -5,
  QUOTA: -6,
  IO: -7,
  UNSAFE_PATH: -8,
  BAD_HANDLE: -9,
  BAD_ARGUMENT: -10,
  LIMIT: -11,
  FORKED: -12,
  RETIRED: -13,
  OVERFLOW: -14,
  UNSUPPORTED: -15,
  OTHER: -16,
} as const);
export type NativeCodeName = keyof typeof NativeCode;

/** `flock(h, op)` operations. */
export const FLOCK_SHARED = 0;
export const FLOCK_EXCLUSIVE = 1;
export const FLOCK_UNLOCK = 2;
/** `recordLock(h, offset, length, op)` operations. */
export const RECORD_READ = 0;
export const RECORD_WRITE = 1;
export const RECORD_UNLOCK = 2;

/** The name of a result code, or `OTHER` for a value outside the table. */
export function nativeCodeName(code: number | bigint): NativeCodeName {
  const value = Number(code);
  for (const name of Object.keys(NativeCode) as NativeCodeName[]) {
    if (NativeCode[name] === value) return name;
  }
  return "OTHER";
}

/**
 * The module's exports, exactly the functions of spec 055 §4.4. Each is synchronous,
 * returns a value >= 0 or a negative {@link NativeCode}, and never throws.
 */
export interface NativeAddon {
  abiVersion(): number;
  openDir(path: string): number;
  openFile(dir: number, name: string, create: boolean): number;
  flock(h: number, op: 0 | 1 | 2): number;
  recordLock(h: number, offset: bigint, length: bigint, op: 0 | 1 | 2): number;
  pread(h: number, dst: Uint8Array, offset: bigint): number;
  pwrite(h: number, src: Uint8Array, offset: bigint): number;
  fsync(h: number): number;
  allocate(h: number, length: bigint): number;
  mapShared(h: number, length: number): number;
  store64(m: number, offset: number, value: bigint): number;
  load64(m: number, offset: number): bigint;
  retire(m: number): number;
  close(h: number): number;
  envAttach(): number;
  takeDetachedEnvs(dst: Uint32Array): number;
}

/** The export names, in the order of `FABRIC_WIRE_FUNCTIONS`. */
export const NATIVE_FUNCTIONS: readonly (keyof NativeAddon)[] = [
  "abiVersion",
  "openDir",
  "openFile",
  "flock",
  "recordLock",
  "pread",
  "pwrite",
  "fsync",
  "allocate",
  "mapShared",
  "store64",
  "load64",
  "retire",
  "close",
  "envAttach",
  "takeDetachedEnvs",
];

/** Why the module cannot be used (spec 055 §4.4 "Unsupported fallback"). */
export type NativeDisabledReason =
  | "platform_unsupported"
  | "native_missing"
  | "native_digest_mismatch"
  | "native_load_failed"
  | "native_abi_mismatch"
  | "native_selftest_failed";

export interface NativeLoaded {
  readonly ok: true;
  readonly addon: NativeAddon;
  readonly target: NativeTarget;
}

export interface NativeDisabled {
  readonly ok: false;
  /** The status reason; the capture points report `unsupported(unsupported_runtime)`. */
  readonly reason: NativeDisabledReason;
  /** The diagnostics-catalogue id: `FW-027` (platform) or `FW-028` (module unusable). */
  readonly reasonId: "FW-027" | "FW-028";
  /** What is wrong, in one line. Fixed text: never a path, a digest or an OS message. */
  readonly message: string;
  /** What to do about it. */
  readonly fix: string;
}

export type NativeLoad = NativeLoaded | NativeDisabled;

export interface NativeLoadOptions {
  /** The directory holding `<target>/fabric_wire.node`. Default: the package's `prebuilds`. */
  readonly prebuildsDir?: string;
  /** Lower-case SHA-256 hex per target. Default: the table embedded at build time. */
  readonly digests?: Readonly<Partial<Record<NativeTarget, string>>>;
  /**
   * Run the install self-test in this directory (the spool directory: owned by this
   * user, mode 0700, on the filesystem the locks will live on). Install passes it;
   * an isolate attaching to a runtime that already passed omits it. The self-test
   * uses one of the process's eight map handles, once per directory and isolate.
   */
  readonly selfTestDir?: string;
  /** Overrides for tests: the platform, CPU and C library to select a prebuild for. */
  readonly platform?: string;
  readonly arch?: string;
  readonly libc?: "glibc" | "musl";
}

const REASON_DETAIL: Readonly<Record<NativeDisabledReason, readonly [string, string]>> = {
  platform_unsupported: [
    "there is no prebuilt module for this operating system, CPU or C library",
    "",
  ],
  native_missing: [
    "the prebuilt module file for this platform is not in the package's prebuilds directory",
    "reinstall @singleaxis/fabric; if a bundler or image build prunes package files, keep its prebuilds/ directory",
  ],
  native_digest_mismatch: [
    "the prebuilt module file does not match the SHA-256 recorded in this release, so it was not loaded",
    "reinstall @singleaxis/fabric from the registry; do not rebuild, strip or patch prebuilds/",
  ],
  native_load_failed: [
    "the operating system refused to load the prebuilt module",
    "check that the prebuilds directory is not on a noexec mount and that the C library is glibc 2.28 or newer, or musl",
  ],
  native_abi_mismatch: [
    "the prebuilt module reports a different ABI version or export list than this release expects",
    "reinstall @singleaxis/fabric so its JavaScript and prebuilds come from the same release",
  ],
  native_selftest_failed: [
    "file locks or shared mappings do not work in the spool directory",
    "put FABRIC_WIRE_SPOOL_DIR on a local disk (not NFS, SMB or a FUSE mount), owned by the agent's user with mode 0700",
  ],
};

function disabled(reason: NativeDisabledReason): NativeDisabled {
  const reasonId = reason === "platform_unsupported" ? "FW-027" : "FW-028";
  const entry = CATALOGUE.find((row) => row.id === reasonId);
  const [detail, fix] = REASON_DETAIL[reason];
  return Object.freeze({
    ok: false as const,
    reason,
    reasonId,
    message: `${entry?.text ?? "model-call capture is off"} (${reason}: ${detail})`,
    fix: fix === "" ? (entry?.fix ?? "") : `${fix}; or: ${entry?.fix ?? ""}`,
  });
}

/** Defined in the CommonJS build only. */
declare const __dirname: string | undefined;

/** The part of `process.report` this file uses. */
interface ProcessReportLike {
  excludeNetwork?: boolean;
  getReport(): unknown;
}

let detectedLibc: "glibc" | "musl" | undefined;

/** The C library Node was built against, on Linux (worked out once per isolate). */
function detectLibc(): "glibc" | "musl" {
  detectedLibc ??= readLibc();
  return detectedLibc;
}

function readLibc(): "glibc" | "musl" {
  const report = process.report as ProcessReportLike | undefined;
  if (report === undefined || typeof report.getReport !== "function") return "glibc";
  // The header alone is needed; skip the report's network interface enumeration.
  const previous = report.excludeNetwork;
  try {
    if (previous !== undefined) report.excludeNetwork = true;
    const header = (report.getReport() as { header?: Record<string, unknown> }).header;
    return typeof header?.glibcVersionRuntime === "string" ? "glibc" : "musl";
  } finally {
    if (previous !== undefined) report.excludeNetwork = previous;
  }
}

/** The prebuild target for a platform, or `null` when there is none. */
export function nativeTarget(
  platform: string = process.platform,
  arch: string = process.arch,
  libc?: "glibc" | "musl",
): NativeTarget | null {
  if (arch !== "x64" && arch !== "arm64") return null;
  if (platform === "darwin") return `darwin-${arch}`;
  if (platform !== "linux") return null;
  try {
    return `linux-${arch}-${libc ?? detectLibc()}`;
  } catch {
    return null;
  }
}

function defaultPrebuildsDir(): string {
  // dist/index.{js,cjs} sit one level below the package root, beside prebuilds/.
  const here = typeof __dirname === "string" ? __dirname : dirname(fileURLToPath(import.meta.url));
  return join(here, "..", "prebuilds");
}

function hasExactExports(value: unknown): value is NativeAddon {
  if (value === null || typeof value !== "object") return false;
  const names = Object.keys(value);
  if (names.length !== NATIVE_FUNCTIONS.length) return false;
  return NATIVE_FUNCTIONS.every(
    (name) => typeof (value as Record<string, unknown>)[name] === "function",
  );
}

/**
 * The install self-test (spec 055 §4.4): two handles on one file, where an exclusive
 * `flock` on the first must make the second `WOULD_BLOCK`; then a `recordLock` and a
 * `mapShared` store/load round trip must succeed. Removes its file and closes its
 * descriptors whatever happens.
 */
function selfTest(addon: NativeAddon, dir: string): boolean {
  const name = `.fabric-selftest-${process.pid}-${randomBytes(6).toString("hex")}`;
  const probe = 0x0fab01c0ffee0001n;
  let dirHandle = -1;
  let first = -1;
  let second = -1;
  try {
    dirHandle = addon.openDir(dir);
    if (dirHandle <= 0) return false;
    first = addon.openFile(dirHandle, name, true);
    second = first > 0 ? addon.openFile(dirHandle, name, false) : -1;
    if (first <= 0 || second <= 0) return false;
    if (addon.flock(first, FLOCK_EXCLUSIVE) !== NativeCode.OK) return false;
    if (addon.flock(second, FLOCK_EXCLUSIVE) !== NativeCode.WOULD_BLOCK) return false;
    if (addon.flock(first, FLOCK_UNLOCK) !== NativeCode.OK) return false;
    if (addon.recordLock(first, 0n, 1n, RECORD_WRITE) !== NativeCode.OK) return false;
    if (addon.recordLock(first, 0n, 1n, RECORD_UNLOCK) !== NativeCode.OK) return false;
    if (addon.allocate(first, 4096n) !== NativeCode.OK) return false;
    const map = addon.mapShared(first, 4096);
    if (map <= 0) return false;
    const stored = addon.store64(map, 8, probe);
    const loaded = addon.load64(map, 8);
    const onDisk = new Uint8Array(8);
    const read = addon.pread(first, onDisk, 8n);
    addon.retire(map);
    if (stored !== NativeCode.OK || loaded !== probe || read !== 8) return false;
    return new DataView(onDisk.buffer).getBigUint64(0, endianness()) === probe;
  } catch {
    return false;
  } finally {
    try {
      if (first > 0) unlinkSync(join(dir, name));
    } catch {
      // Best effort: a leftover .fabric-selftest-* file is empty and never read.
    }
    for (const handle of [second, first, dirHandle]) {
      try {
        if (handle > 0) addon.close(handle);
      } catch {
        // close never throws; this guards a broken module only.
      }
    }
  }
}

function endianness(): boolean {
  return new Uint8Array(new Uint16Array([1]).buffer)[0] === 1;
}

// Per isolate: the loaded module by file path and digest, and the directories that passed.
const loaded = new Map<string, NativeAddon>();
const selfTested = new Set<string>();

/**
 * Loads the lock module for this platform, or says why it cannot be used. Never throws.
 */
export function loadNative(options: NativeLoadOptions = {}): NativeLoad {
  try {
    const target = nativeTarget(options.platform, options.arch, options.libc);
    if (target === null) return disabled("platform_unsupported");
    const file = join(options.prebuildsDir ?? defaultPrebuildsDir(), target, NATIVE_FILE);
    let bytes: Buffer;
    try {
      bytes = readFileSync(file);
    } catch {
      return disabled("native_missing");
    }
    const expected = (options.digests ?? NATIVE_DIGESTS)[target];
    const actual = createHash("sha256").update(bytes).digest("hex");
    if (typeof expected !== "string" || expected.toLowerCase() !== actual) {
      return disabled("native_digest_mismatch");
    }
    const key = `${file}\0${actual}`;
    let addon = loaded.get(key);
    if (addon === undefined) {
      const holder: { exports: unknown } = { exports: {} };
      try {
        process.dlopen(holder, file);
      } catch {
        return disabled("native_load_failed");
      }
      const candidate = holder.exports as Partial<NativeAddon> | null;
      let version: unknown;
      try {
        version = typeof candidate?.abiVersion === "function" ? candidate.abiVersion() : undefined;
      } catch {
        version = undefined;
      }
      if (version !== NATIVE_ABI_VERSION || !hasExactExports(candidate)) {
        return disabled("native_abi_mismatch");
      }
      addon = candidate;
      loaded.set(key, addon);
    }
    if (options.selfTestDir !== undefined) {
      const tested = `${key}\0${options.selfTestDir}`;
      if (!selfTested.has(tested)) {
        if (!selfTest(addon, options.selfTestDir)) return disabled("native_selftest_failed");
        selfTested.add(tested);
      }
    }
    return Object.freeze({ ok: true as const, addon, target });
  } catch {
    return disabled("native_load_failed");
  }
}
