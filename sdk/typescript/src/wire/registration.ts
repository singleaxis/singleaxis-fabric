// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Epoch registration (spec 050 §3.2, spec 055 §6.1): the TypeScript port of Python's
 * `fabric/wire/_registration.py`, byte for byte. One `.epochs/<epoch:020d>.reg` file per
 * writer epoch, `flock`-held for the writer's lifetime, with a shared-mapped mirror of
 * `next_sequence` so a drainer (TypeScript or Python) can declare a killed writer's
 * allocated positions.
 *
 * - {@link register} runs at install only, synchronously, under the spool's admission
 *   lock (`flock(.admit)`, shared with Python). It creates the 4,096-byte file 0600,
 *   writes and fsyncs it, holds `flock(LOCK_EX)` on it and maps it shared. A taken epoch
 *   (a held file, an unheld one without `final`, a declared orphan) is redrawn, at most 8
 *   times; the runtime then adopts the drawn epoch and every allocation stores the next
 *   sequence in the mirror (`store64`: a memory store, no system call). Every outcome is
 *   an explicit {@link Registration} status; no failure stops capture.
 * - {@link scanOrphans} (the drainer) finds registrations whose writer is gone without
 *   `final`, renames them `.orphan` and returns each once, so the drainer queues its
 *   `periodic` heartbeat at `next_sequence - 1` ({@link orphanBeat}).
 *
 * Every lock, admission and registration file is opened through the native module
 * (spec 055 §4.4), never with `node:fs`, which only lists, `lstat`s, renames and removes
 * names. The file holds the emitted (pseudonymous) source id, the pid and the
 * registration time: no content.
 *
 * Nothing here runs in a transport hook: the allocation path only calls the mirror's
 * `store64` (see `WireRuntime.next`).
 */
import { createHash } from "node:crypto";
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  renameSync,
  unlinkSync,
  utimesSync,
} from "node:fs";
import { join } from "node:path";

import { utf8SurrogatePass } from "../identity.js";
import { FLOCK_EXCLUSIVE, FLOCK_UNLOCK, NativeCode, type NativeAddon } from "./native.js";
import type { RegistrationStatus } from "./p1-types.js";
import { type WireRuntime, newEpoch } from "./runtime.js";

export { newEpoch };

export const EPOCHS_DIR = ".epochs";
/** The spool's admission lock file, shared with Python's `Spool._admission()`. */
export const ADMIT_LOCK = ".admit";
/** Python's `ADMIT_TIMEOUT_S`: a busy admission lock past this fails the registration. */
export const ADMIT_TIMEOUT_MS = 5000;
export const REG_SUFFIX = ".reg";
export const ORPHAN_SUFFIX = ".orphan";
export const CORRUPT_SUFFIX = ".corrupt";
export const REG_SIZE = 4096;
export const REG_MAGIC = Buffer.from("FWEPOCH1", "latin1");
export const REG_VERSION = 1;
/** Byte offsets of the 4,096-byte file (050 §3.2 rule 2); integers are little-endian. */
export const OFF_MAGIC = 0;
export const OFF_VERSION = 8;
export const OFF_EPOCH = 12;
export const OFF_PID = 20;
export const OFF_REGISTERED_AT = 24;
export const OFF_SOURCE_ID = 32;
export const OFF_NEXT_SEQUENCE = 256;
export const OFF_FINAL = 264;
export const OFF_HEADER_SHA256 = 4064;
/** Bytes 0..255 are the immutable header the trailing SHA-256 covers. */
export const HEADER_BYTES = 256;
export const MAX_SOURCE_ID_BYTES = 160;
export const MAX_REDRAWS = 8;
export const MAX_REGISTRATIONS = 4096;
/** Manifest `unsealed_prior_epochs` lists at most 64; the count is exact. */
export const MAX_DECLARED = 64;

const EPOCH_DIGITS = 20;
const EPOCH_LIMIT = 1n << 63n;
const U64_LIMIT = 1n << 64n;
// Strict, and keeping a leading U+FEFF as Python's `bytes.decode("utf-8")` does.
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Why a registration did not happen (fixed classes: never a path or a value). */
export type RegistrationReason =
  "admission_timeout" | "io_error" | "redraws_exhausted" | "epoch_in_use" | "registration_full";

/** The decoded fields of a registration file. */
export interface RegistrationFields {
  readonly epoch: bigint;
  readonly pid: number;
  readonly registeredAtUnixNano: bigint;
  readonly sourceId: string;
  readonly nextSequence: bigint;
  readonly final: boolean;
}

/** A registration whose writer is gone without `final` (050 §3.2 rule 5). */
export interface Orphan {
  readonly sourceId: string;
  readonly epoch: bigint;
  readonly nextSequence: bigint;
}

/** The `periodic` heartbeat a drainer queues for an orphan (Python's `LegacyBeat`). */
export interface OrphanBeat {
  readonly sourceId: string;
  readonly epoch: bigint;
  /** The last allocated sequence: the killed writer's unwritten positions become a gap. */
  readonly sequence: bigint;
  readonly kind: "periodic";
}

/** The heartbeat for `orphan`, or `undefined` when it allocated nothing. */
export function orphanBeat(orphan: Orphan): OrphanBeat | undefined {
  if (orphan.nextSequence <= 0n) return undefined;
  return {
    sourceId: orphan.sourceId,
    epoch: orphan.epoch,
    sequence: orphan.nextSequence - 1n,
    kind: "periodic",
  };
}

// ------------------------------------------------------------------------------ the file

/** The 4,096 bytes of a fresh registration (`next_sequence` 0, `final` 0). */
export function encode(
  epoch: bigint,
  sourceId: string,
  pid: number,
  registeredAtUnixNano: bigint,
): Buffer {
  const source = utf8SurrogatePass(sourceId);
  if (!(epoch > 0n && epoch < EPOCH_LIMIT) || source.length > MAX_SOURCE_ID_BYTES) {
    throw new RangeError("registration epoch or source id out of range");
  }
  if (!(registeredAtUnixNano >= 0n && registeredAtUnixNano < U64_LIMIT)) {
    throw new RangeError("registration time out of range");
  }
  const data = Buffer.alloc(REG_SIZE);
  REG_MAGIC.copy(data, OFF_MAGIC);
  data.writeUInt32LE(REG_VERSION, OFF_VERSION);
  data.writeBigUInt64LE(epoch, OFF_EPOCH);
  data.writeUInt32LE(pid >>> 0, OFF_PID);
  data.writeBigUInt64LE(registeredAtUnixNano, OFF_REGISTERED_AT);
  data.writeUInt16LE(source.length, OFF_SOURCE_ID);
  source.copy(data, OFF_SOURCE_ID + 2);
  createHash("sha256")
    .update(data.subarray(0, HEADER_BYTES))
    .digest()
    .copy(data, OFF_HEADER_SHA256);
  return data;
}

/**
 * A registration's fields, or `null` when it is short, foreign, of another version or
 * its header digest does not match (a corrupt file).
 */
export function decode(bytes: Uint8Array): RegistrationFields | null {
  const data = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (data.length !== REG_SIZE || !data.subarray(0, REG_MAGIC.length).equals(REG_MAGIC)) {
    return null;
  }
  const digest = createHash("sha256").update(data.subarray(0, HEADER_BYTES)).digest();
  if (!digest.equals(data.subarray(OFF_HEADER_SHA256))) return null;
  const length = data.readUInt16LE(OFF_SOURCE_ID);
  if (data.readUInt32LE(OFF_VERSION) !== REG_VERSION || length > MAX_SOURCE_ID_BYTES) {
    return null;
  }
  let sourceId: string;
  try {
    sourceId = UTF8.decode(data.subarray(OFF_SOURCE_ID + 2, OFF_SOURCE_ID + 2 + length));
  } catch {
    return null;
  }
  return {
    epoch: data.readBigUInt64LE(OFF_EPOCH),
    pid: data.readUInt32LE(OFF_PID),
    registeredAtUnixNano: data.readBigUInt64LE(OFF_REGISTERED_AT),
    sourceId,
    nextSequence: data.readBigUInt64LE(OFF_NEXT_SEQUENCE),
    final: data[OFF_FINAL] !== 0,
  };
}

/** The directory entry of `epoch` with `suffix`: 20 zero-padded digits. */
export function epochName(epoch: bigint, suffix: string = REG_SUFFIX): string {
  return `${epoch.toString().padStart(EPOCH_DIGITS, "0")}${suffix}`;
}

/** The epoch a registration-directory name carries; `undefined` for any other name. */
export function epochOf(name: string): bigint | undefined {
  const dot = name.indexOf(".");
  if (dot < 0) return undefined;
  const suffix = name.slice(dot);
  if (suffix !== REG_SUFFIX && suffix !== ORPHAN_SUFFIX && suffix !== CORRUPT_SUFFIX) {
    return undefined;
  }
  const stem = name.slice(0, dot);
  if (!/^[0-9]{20}$/.test(stem)) return undefined;
  const epoch = BigInt(stem);
  return epoch > 0n && epoch < EPOCH_LIMIT ? epoch : undefined;
}

// ------------------------------------------------------------------------ file access

/** A native call that failed: the fixed code, never a path or an OS message. */
class NativeFailure extends Error {
  constructor(readonly code: number) {
    super("native call failed");
  }
}

function check(result: number): number {
  if (result < 0) throw new NativeFailure(result);
  return result;
}

function forked(error: unknown): boolean {
  return error instanceof NativeFailure && error.code === NativeCode.FORKED;
}

function errno(error: unknown): string | undefined {
  return (error as { code?: string } | null)?.code;
}

function closeQuietly(addon: NativeAddon, handle: number): void {
  try {
    if (handle > 0) addon.close(handle);
  } catch {
    // close never throws; this guards a broken module only.
  }
}

function fsyncDir(addon: NativeAddon, path: string): void {
  const handle = check(addon.openDir(path));
  try {
    check(addon.fsync(handle));
  } finally {
    closeQuietly(addon, handle);
  }
}

/**
 * `<spool>/.epochs`: a real 0700 directory of this user (made, and its entry fsync'd,
 * when `create`); `undefined` when absent and not created. Throws when it is not usable.
 */
function epochsDir(addon: NativeAddon, spoolDir: string, create: boolean): string | undefined {
  const path = join(spoolDir, EPOCHS_DIR);
  let exists = true;
  try {
    lstatSync(path);
  } catch (error) {
    if (errno(error) !== "ENOENT") throw error;
    exists = false;
  }
  if (!exists) {
    if (!create) return undefined;
    try {
      mkdirSync(path, 0o700);
      fsyncDir(addon, spoolDir);
    } catch (error) {
      if (errno(error) !== "EEXIST") throw error;
    }
  }
  const info = lstatSync(path);
  if (!info.isDirectory() || info.uid !== process.getuid?.()) {
    throw new Error("the registration directory must be a real directory of this user");
  }
  if ((info.mode & 0o777) !== 0o700) chmodSync(path, 0o700);
  return path;
}

/** `flock(LOCK_EX | LOCK_NB)`: `false` when another open description holds it. */
function tryLock(addon: NativeAddon, handle: number): boolean {
  return addon.flock(handle, FLOCK_EXCLUSIVE) === NativeCode.OK;
}

/** Opens `name` (no symlink, owner-only, one link) and reads it: `[handle, bytes]`. */
function readFile(addon: NativeAddon, dir: number, name: string): [number, Buffer] {
  const handle = check(addon.openFile(dir, name, false));
  try {
    const buffer = Buffer.alloc(REG_SIZE + 1);
    const read = check(addon.pread(handle, buffer, 0n));
    return [handle, buffer.subarray(0, read)];
  } catch (error) {
    closeQuietly(addon, handle);
    throw error;
  }
}

function busyFor(ms: number): void {
  // Install only, never a hook: the installing isolate never calls Atomics.wait (055-t4).
  const until = performance.now() + ms;
  while (performance.now() < until) {
    // spin
  }
}

/**
 * Runs `body` holding the spool's admission lock: `flock(.admit)` on a handle of its
 * own, which excludes every other holder in this process and in other processes,
 * Python's included. Retries with backoff for `timeoutMs`, then throws `"timeout"`.
 */
function withAdmission<T>(
  addon: NativeAddon,
  spoolDir: string,
  timeoutMs: number,
  body: () => T,
): T {
  const dir = check(addon.openDir(spoolDir));
  let admit = -1;
  try {
    admit = check(addon.openFile(dir, ADMIT_LOCK, true));
    const deadline = performance.now() + timeoutMs;
    let pause = 0.5;
    for (;;) {
      const result = addon.flock(admit, FLOCK_EXCLUSIVE);
      if (result === NativeCode.OK) break;
      if (result !== NativeCode.WOULD_BLOCK) throw new NativeFailure(result);
      if (performance.now() >= deadline) throw new AdmissionTimeout();
      busyFor(pause);
      pause = Math.min(pause * 2, 10);
    }
    try {
      return body();
    } finally {
      addon.flock(admit, FLOCK_UNLOCK);
    }
  } finally {
    closeQuietly(addon, admit);
    closeQuietly(addon, dir);
  }
}

class AdmissionTimeout extends Error {
  constructor() {
    super("spool admission lock busy");
  }
}

// --------------------------------------------------------------------------- registering

// Per isolate: the registrations this isolate holds (never orphans, whatever the
// filesystem's locks say) and the spool directories already warned about.
const HELD = new Set<Registration>();
const WARNED_UNENFORCED = new Set<string>();

/** The warning {@link register} gives once per spool directory on a lock-less filesystem. */
export const UNENFORCED_LOCKS_WARNING =
  "fabric.wire: the spool directory's filesystem does not enforce file locks " +
  "(a Docker Desktop bind mount?); put the spool (FABRIC_WIRE_SPOOL_DIR) on a local " +
  "disk or a named volume so several processes can share it safely";

/** One epoch's registration as the writer holds it. */
export class Registration {
  /** Set by a registered one: whether the filesystem enforced the file lock. */
  locksEnforced: boolean | undefined;
  #addon: NativeAddon | undefined;
  #dir: string | undefined;
  #file = -1;
  #map = -1;
  #final = false;
  #runtime: WireRuntime | undefined;

  constructor(
    /** What the status document reports as `registration`. */
    public status: RegistrationStatus,
    readonly epoch: bigint,
    readonly sourceId: string,
    /** A fixed failure class; never a path or a value. */
    readonly reason?: RegistrationReason,
  ) {}

  /** @internal Holds the file: its directory, descriptor handle and map handle. */
  hold(addon: NativeAddon, dir: string, file: number, map: number): void {
    this.#addon = addon;
    this.#dir = dir;
    this.#file = file;
    this.#map = map;
    HELD.add(this);
  }

  /**
   * @internal Binds the runtime that drew `drawnFrom`: it adopts this (possibly redrawn)
   * epoch and mirrors its next sequence here.
   */
  bind(runtime: WireRuntime, drawnFrom: bigint): boolean {
    const addon = this.#addon;
    if (addon === undefined || this.#map < 0) return false;
    if (!runtime.adoptRegistration(drawnFrom, this.epoch, this.#map)) {
      return false;
    }
    this.#runtime = runtime;
    attachMirror(runtime, addon);
    this.mirror(runtime.nextSequence);
    return true;
  }

  /** Whether this registration holds its file (and so its lock) now. */
  get held(): boolean {
    return this.#file > 0;
  }

  /**
   * @internal The file's descriptor handle, or -1. Never published to application
   * isolates (spec 055 §4.4): the installing thread hands it to the Fabric worker in its
   * `workerData`, so that worker, or a replacement, can close the file at shutdown.
   */
  get fileHandle(): number {
    return this.#file;
  }

  /** The file's name inside `.epochs`, for a registered one. */
  get name(): string | undefined {
    return this.#dir === undefined ? undefined : epochName(this.epoch);
  }

  /**
   * Stores `next` in the mirror (a memory store, no system call). The bound runtime
   * stores the same bytes itself on every allocation.
   */
  mirror(next: bigint): void {
    if (this.#addon !== undefined && this.#map > 0) {
      this.#addon.store64(this.#map, OFF_NEXT_SEQUENCE, next);
    }
  }

  /**
   * Sets the `final` flag: from now on no scan takes the epoch for an orphan. Called only
   * once the epoch's `final` marker is durably in the spool, never before: a writer that
   * dies or fails to spool it first stays declarable. {@link close} then removes the file.
   */
  final(): void {
    if (this.#addon === undefined || this.#map < 0) return;
    // Bytes 264..271: the flag byte, then seven bytes that are already zero.
    if (this.#addon.store64(this.#map, OFF_FINAL, 1n) === NativeCode.OK) this.#final = true;
  }

  /**
   * Releases the lock and the mirror and, once `final` is set, removes the file. Without
   * `final` the file stays and the next scan declares the epoch an orphan. Idempotent.
   */
  close(): void {
    const addon = this.#addon;
    if (addon === undefined || this.#file < 0) return;
    if (this.#runtime !== undefined && this.#runtime.mirrorHandle === this.#map) {
      this.#runtime.releaseRegistration();
    }
    this.#runtime = undefined;
    const dir = this.#dir!;
    if (this.#final) {
      try {
        unlinkSync(join(dir, epochName(this.epoch)));
      } catch (error) {
        // Declared while alive by a scan on a filesystem that does not enforce flock:
        // the renamed file is this one, with `final` set, so it is no orphan.
        if (errno(error) === "ENOENT") this.#unlinkDeclared(addon, dir);
      }
    }
    // Later stores into the mapping become no-ops; the kernel unmaps it at exit (§4.4).
    addon.retire(this.#map);
    const result = addon.close(this.#file);
    this.#map = this.#file = -1;
    HELD.delete(this);
    if (result === NativeCode.FORKED) this.status = "unregistered_fork";
  }

  /**
   * Removes this epoch's `.orphan` file when it is this registration's own (its header
   * equals ours and its `final` flag is set), never another writer's.
   */
  #unlinkDeclared(addon: NativeAddon, dir: string): void {
    const declared = epochName(this.epoch, ORPHAN_SUFFIX);
    let directory = -1;
    let handle = -1;
    try {
      directory = check(addon.openDir(dir));
      const [opened, data] = readFile(addon, directory, declared);
      handle = opened;
      const mine = Buffer.alloc(HEADER_BYTES);
      const read = addon.pread(this.#file, mine, 0n);
      const found = decode(data);
      if (
        read === HEADER_BYTES &&
        found?.final === true &&
        mine.equals(data.subarray(0, HEADER_BYTES))
      ) {
        unlinkSync(join(dir, declared));
      }
    } catch {
      // Best effort: a leftover .orphan with `final` set is retired like any other.
    } finally {
      closeQuietly(addon, handle);
      closeQuietly(addon, directory);
    }
  }
}

export interface RegisterOptions {
  /** The native module (spec 055 §4.4); every file access goes through it. */
  readonly addon: NativeAddon;
  /** The spool directory; `undefined` registers nothing (`unregistered_direct`). */
  readonly spoolDir: string | undefined;
  /** The emitted (pseudonymous) source id; at most 160 UTF-8 bytes. */
  readonly sourceId: string;
  /**
   * The runtime that adopts the registered epoch and mirrors its next sequence. Its
   * current epoch is the one registered (or redrawn from).
   */
  readonly runtime?: WireRuntime;
  /** The epoch to register without a runtime. */
  readonly epoch?: bigint;
  /** Where the warning about a filesystem without locks goes. Default: `console.warn`. */
  readonly warn?: (message: string) => void;
  /** Tests only: the epoch drawer, the clock (Unix ns), the admission deadline, the cap. */
  readonly newEpoch?: () => bigint;
  readonly now?: () => bigint;
  readonly admitTimeoutMs?: number;
  readonly maxRegistrations?: number;
}

function nowUnixNano(): bigint {
  return BigInt(Date.now()) * 1_000_000n;
}

/**
 * Registers the runtime's epoch on the spool and binds its mirror (install only,
 * synchronous, before any hook exists). Never throws: `unregistered_direct` without a
 * spool; `registration_full` at 4,096 files; `failed` on an I/O error, a busy admission
 * lock, after 8 redraws, or when the runtime already allocated in its epoch and a redraw
 * was needed. Capture continues unregistered in each.
 */
export function register(options: RegisterOptions): Registration {
  const { addon, spoolDir, sourceId, runtime } = options;
  const epoch = runtime?.epoch ?? options.epoch ?? 0n;
  if (spoolDir === undefined) return new Registration("unregistered_direct", epoch, sourceId);
  let registration: Registration;
  try {
    registration = withAdmission(addon, spoolDir, options.admitTimeoutMs ?? ADMIT_TIMEOUT_MS, () =>
      create(options, spoolDir, epoch),
    );
  } catch (error) {
    if (forked(error)) return new Registration("unregistered_fork", epoch, sourceId);
    const reason = error instanceof AdmissionTimeout ? "admission_timeout" : "io_error";
    return new Registration("failed", epoch, sourceId, reason);
  }
  if (registration.status !== "registered" || runtime === undefined) return registration;
  let bound: boolean;
  try {
    bound = registration.bind(runtime, epoch);
  } catch {
    bound = false;
  }
  if (!bound) {
    // The runtime moved on: the registered epoch is never used.
    registration.final();
    registration.close();
    return new Registration("failed", epoch, sourceId, "epoch_in_use");
  }
  return registration;
}

/** Under the admission lock: the registration of `epoch`, or of a redrawn one. */
function create(options: RegisterOptions, spoolDir: string, drawn: bigint): Registration {
  const { addon, sourceId } = options;
  const dir = epochsDir(addon, spoolDir, true)!;
  const taken = new Set<bigint>();
  for (const name of readdirSync(dir)) {
    const found = epochOf(name);
    if (found !== undefined) taken.add(found);
  }
  if (taken.size >= (options.maxRegistrations ?? MAX_REGISTRATIONS)) {
    return new Registration("registration_full", drawn, sourceId, "registration_full");
  }
  const handle = check(addon.openDir(dir));
  try {
    let epoch = drawn;
    for (let attempt = 0; attempt <= MAX_REDRAWS; attempt++) {
      if (attempt > 0) epoch = (options.newEpoch ?? newEpoch)();
      if (taken.has(epoch)) {
        // Held, unheld without final, declared or corrupt: redraw.
        clearStale(addon, handle, dir, epochName(epoch));
        continue;
      }
      const pid = process.pid;
      const data = encode(epoch, sourceId, pid, (options.now ?? nowUnixNano)());
      const made = newFile(addon, handle, dir, epoch, sourceId, data);
      if (made === undefined) continue; // the name exists: redraw
      checkLockEnforced(addon, handle, made, spoolDir, options.warn);
      return made;
    }
    return new Registration("failed", epoch, sourceId, "redraws_exhausted");
  } finally {
    closeQuietly(addon, handle);
  }
}

/**
 * Creates, locks, writes, fsyncs and maps the registration file; `undefined` when the
 * name is taken. On any later error the file is removed and closed, and it throws.
 */
function newFile(
  addon: NativeAddon,
  dirHandle: number,
  dir: string,
  epoch: bigint,
  sourceId: string,
  data: Buffer,
): Registration | undefined {
  const name = epochName(epoch);
  // The module has no O_EXCL; names are only created under the admission lock, so "not
  // there, then created empty" is exclusive among writers that follow the protocol.
  const existing = addon.openFile(dirHandle, name, false);
  if (existing > 0) {
    closeQuietly(addon, existing);
    return undefined;
  }
  if (existing !== NativeCode.NOT_FOUND) throw new NativeFailure(existing);
  const file = check(addon.openFile(dirHandle, name, true));
  const probe = Buffer.alloc(1);
  const size = addon.pread(file, probe, 0n);
  if (size !== 0) {
    // Not the empty file this call created: someone else's, never removed here.
    closeQuietly(addon, file);
    if (size < 0) throw new NativeFailure(size);
    return undefined;
  }
  let map = -1;
  try {
    if (!tryLock(addon, file)) throw new Error("a fresh registration is locked");
    for (let offset = 0; offset < data.length;) {
      const wrote = check(addon.pwrite(file, data.subarray(offset), BigInt(offset)));
      if (wrote === 0) throw new NativeFailure(NativeCode.IO); // it would never finish
      offset += wrote;
    }
    check(addon.fsync(file));
    check(addon.fsync(dirHandle));
    map = check(addon.mapShared(file, REG_SIZE));
  } catch (error) {
    if (map > 0) addon.retire(map);
    try {
      unlinkSync(join(dir, name));
    } catch {
      // Best effort: the scan treats a leftover like any unheld registration.
    }
    closeQuietly(addon, file);
    throw error;
  }
  const registration = new Registration("registered", epoch, sourceId);
  registration.hold(addon, dir, file, map);
  return registration;
}

/**
 * Warns once per spool directory when its filesystem lets a second open description
 * take the held registration's flock (a Docker Desktop bind mount): another process's
 * scan could then declare a live epoch an orphan. One extra open, at install only.
 */
function checkLockEnforced(
  addon: NativeAddon,
  dirHandle: number,
  registration: Registration,
  spoolDir: string,
  warn: ((message: string) => void) | undefined,
): void {
  const handle = addon.openFile(dirHandle, epochName(registration.epoch), false);
  if (handle < 0) return;
  let taken: boolean;
  try {
    taken = tryLock(addon, handle);
  } finally {
    closeQuietly(addon, handle);
  }
  registration.locksEnforced = !taken;
  if (!taken || WARNED_UNENFORCED.has(spoolDir)) return;
  WARNED_UNENFORCED.add(spoolDir);
  try {
    (warn ?? console.warn)(UNENFORCED_LOCKS_WARNING);
  } catch {
    // A warning sink that throws never fails the registration.
  }
}

/**
 * A `.reg` whose writer finished (unheld, `final` set) but died before removing it:
 * removed, under the admission lock. Anything else stays for the scan.
 */
function clearStale(addon: NativeAddon, dirHandle: number, dir: string, name: string): void {
  let handle = -1;
  try {
    const [opened, data] = readFile(addon, dirHandle, name);
    handle = opened;
    if (tryLock(addon, handle) && decode(data)?.final === true) unlinkSync(join(dir, name));
  } catch {
    // Missing, unreadable or held: left for the scan.
  } finally {
    closeQuietly(addon, handle);
  }
}

// --------------------------------------------------------------------- the mirror

/**
 * Points this isolate's allocator at the registration mirror published in the control
 * block, if any: every allocation then stores the next sequence with `store64` (a
 * memory store, no lock, no system call). An attaching application isolate calls this
 * after loading the native module; the installing isolate gets it from {@link register}.
 */
export function attachMirror(runtime: WireRuntime, addon: NativeAddon): void {
  const map = runtime.mirrorHandle;
  if (map <= 0) {
    runtime.mirror = undefined;
    return;
  }
  const store64 = addon.store64.bind(addon);
  runtime.mirror = (next: bigint) => {
    store64(map, OFF_NEXT_SEQUENCE, next);
  };
}

// ------------------------------------------------------------------- the drainer's side

export interface ScanOptions {
  readonly addon: NativeAddon;
  readonly spoolDir: string;
  /** The caller already holds the admission lock. */
  readonly admitted?: boolean;
  /** This process's runtime: its registered epoch is never declared, whatever the locks say. */
  readonly runtime?: WireRuntime;
  readonly admitTimeoutMs?: number;
}

/** The epochs whose registration this process holds now. */
function heldHere(runtime: WireRuntime | undefined): Set<bigint> {
  const held = new Set<bigint>();
  for (const registration of HELD) if (registration.held) held.add(registration.epoch);
  if (runtime !== undefined && runtime.mirrorHandle > 0) held.add(runtime.epoch);
  return held;
}

/**
 * The orphaned registrations of the spool (050 §3.2 rule 5), each renamed `.orphan` and
 * returned once: the drainer queues {@link orphanBeat} for each. A registration whose
 * flock can be taken (its writer is gone) with `final` set is a finished writer's
 * leftover and is removed; one that does not decode is renamed `.corrupt` (its epoch is
 * still declared). Never throws: `[]` when the lock is busy or the directory unusable.
 */
export function scanOrphans(options: ScanOptions): Orphan[] {
  const { addon, spoolDir } = options;
  try {
    const dir = epochsDir(addon, spoolDir, false);
    if (dir === undefined) return [];
    const run = (): Orphan[] => scan(addon, dir, heldHere(options.runtime));
    if (options.admitted === true) return run();
    return withAdmission(addon, spoolDir, options.admitTimeoutMs ?? ADMIT_TIMEOUT_MS, run);
  } catch {
    return [];
  }
}

function scan(addon: NativeAddon, dir: string, held: Set<bigint>): Orphan[] {
  const found: Orphan[] = [];
  let renamed = false;
  const dirHandle = check(addon.openDir(dir));
  try {
    for (const name of readdirSync(dir).sort()) {
      const epoch = epochOf(name);
      if (!name.endsWith(REG_SUFFIX) || epoch === undefined) continue;
      if (held.has(epoch)) continue; // this process's own live writer
      let handle: number;
      let data: Buffer;
      try {
        [handle, data] = readFile(addon, dirHandle, name);
      } catch {
        continue;
      }
      try {
        // Its writer is alive (or a child that inherited the description still is).
        if (!tryLock(addon, handle)) continue;
        const fields = decode(data);
        const same = fields !== null && fields.epoch === epoch;
        if (same && fields.final) {
          unlinkSync(join(dir, name));
          continue;
        }
        const target = join(dir, epochName(epoch, same ? ORPHAN_SUFFIX : CORRUPT_SUFFIX));
        renameSync(join(dir, name), target);
        renamed = true;
        const now = new Date();
        utimesSync(target, now, now); // the retention deadline counts from the declaration
        if (same)
          found.push({ sourceId: fields.sourceId, epoch, nextSequence: fields.nextSequence });
      } catch {
        continue;
      } finally {
        closeQuietly(addon, handle);
      }
    }
    if (renamed) {
      try {
        check(addon.fsync(dirHandle));
      } catch {
        // The renames stand; a crash may undo one, and the next scan redoes it.
      }
    }
  } finally {
    closeQuietly(addon, dirHandle);
  }
  return found;
}

/**
 * The declared (`.orphan`) registrations of the spool, decoded, in epoch order: what a
 * restarted drainer re-queues heartbeats for. Never throws.
 */
export function declaredOrphans(addon: NativeAddon, spoolDir: string): Orphan[] {
  const out: Orphan[] = [];
  try {
    const dir = epochsDir(addon, spoolDir, false);
    if (dir === undefined) return out;
    const dirHandle = check(addon.openDir(dir));
    try {
      for (const name of readdirSync(dir).sort()) {
        const epoch = epochOf(name);
        if (!name.endsWith(ORPHAN_SUFFIX) || epoch === undefined) continue;
        try {
          const [handle, data] = readFile(addon, dirHandle, name);
          closeQuietly(addon, handle);
          const fields = decode(data);
          if (fields !== null) {
            out.push({ sourceId: fields.sourceId, epoch, nextSequence: fields.nextSequence });
          }
        } catch {
          // Unreadable: skipped, as Python skips an OSError.
        }
      }
    } finally {
      closeQuietly(addon, dirHandle);
    }
  } catch {
    // An unusable directory declares nothing.
  }
  return out;
}

/**
 * Manifest 0's `unsealed_prior_epochs` (at most 64, ascending) and the exact count
 * (049 X45): every declared orphan, corrupt files included (the name carries the
 * epoch). Never throws.
 */
export function unsealedPriorEpochs(
  addon: NativeAddon,
  spoolDir: string | undefined,
): { readonly epochs: bigint[]; readonly count: number } {
  const epochs: bigint[] = [];
  try {
    const dir = spoolDir === undefined ? undefined : epochsDir(addon, spoolDir, false);
    for (const name of dir === undefined ? [] : readdirSync(dir)) {
      const epoch = epochOf(name);
      if (epoch !== undefined && (name.endsWith(ORPHAN_SUFFIX) || name.endsWith(CORRUPT_SUFFIX))) {
        epochs.push(epoch);
      }
    }
  } catch {
    // An unusable directory declares nothing.
  }
  epochs.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return { epochs: epochs.slice(0, MAX_DECLARED), count: epochs.length };
}

/**
 * Removes the declared orphan (or corrupt file) of `epoch` once the caller knows its
 * manifest-0 declaration is spooled and its heartbeat delivered, and `deadlineS`
 * (`open_run_deadline_s`) has passed since the scan declared it (§3.2 rule 5.4).
 * `true` when something was removed; never throws.
 */
export function retireOrphan(
  addon: NativeAddon,
  spoolDir: string,
  epoch: bigint,
  deadlineS: number,
  nowS: number = Date.now() / 1000,
): boolean {
  let removed = false;
  try {
    const dir = epochsDir(addon, spoolDir, false);
    if (dir === undefined) return false;
    for (const suffix of [ORPHAN_SUFFIX, CORRUPT_SUFFIX]) {
      const path = join(dir, epochName(epoch, suffix));
      try {
        if (nowS - lstatSync(path).mtimeMs / 1000 >= deadlineS) {
          unlinkSync(path);
          removed = true;
        }
      } catch (error) {
        if (errno(error) !== "ENOENT") throw error;
      }
    }
  } catch {
    // Never throws.
  }
  return removed;
}
