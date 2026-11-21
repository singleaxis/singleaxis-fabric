// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The spool's loss ledger (spec 055 §6.3; a port of Python's `fabric/wire/_ledger.py`):
 * evidence of loss that survives a full disk and the death of the process that lost the
 * data. Byte for byte the file Python writes, so a Python drainer recovers a Node
 * process's slots and the reverse.
 *
 * `.ledger` in the spool directory is created once, fully allocated (`allocate`, then
 * every byte written) and fsync'd while the volume has room, so writing it later
 * allocates nothing: slots are overwritten in place (`pwrite` + `fsync`).
 *
 * Layout: a 4 KiB header (`FWLEDGR1`, u32be slot count, u32be slot size), then 64 slots
 * of 4 KiB. A slot is zeros (empty) or `FWLSLOT1 | u32be len | payload | sha256(magic,
 * len, payload)`, zero padded; the payload is the ASCII canonical JSON `{"owner", "records"}`
 * of complete spool headers (`loss` and `marker` kinds only, each loss with its
 * `segment_id`). Never content.
 *
 * Ownership: a process writes only slots it holds a POSIX record lock on (`recordLock`
 * on the slot's byte range); the kernel releases them when the process dies, however it
 * dies. A drainer takes over the non-empty slots whose lock it can take (their owner is
 * gone), exports them and clears them. POSIX record locks belong to the process: within
 * one process a second descriptor on the file would share them and closing it would drop
 * them, so this module keeps one descriptor per ledger file per isolate (refcounted) and
 * one claim table, and every `LossLedger` of the isolate goes through them.
 *
 * Every call does synchronous I/O: it runs on the Fabric worker (or at install), never
 * in a transport hook. File access goes through the native module (§4.4), except the
 * one directory step it lacks: the fully written new ledger is linked into place with
 * `fs.linkSync` (never replacing one another process made first).
 */
import { createHash, randomBytes } from "node:crypto";
import { linkSync, lstatSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { isMainThread } from "node:worker_threads";

import { encodeJson, parseJson } from "./codec.js";
import {
  type NativeAddon,
  NativeCode,
  RECORD_UNLOCK,
  RECORD_WRITE,
  nativeCodeName,
} from "./native.js";

export const LEDGER = ".ledger";
/** A ledger being created (a dead creator's leftover is swept by the drainer). */
export const NEW_PREFIX = ".ledger-new-";
export const LEDGER_MAGIC = Buffer.from("FWLEDGR1", "latin1");
export const SLOT_MAGIC = Buffer.from("FWLSLOT1", "latin1");
export const HEADER_BYTES = 4096;
export const SLOT_BYTES = 4096;
export const SLOTS = 64;
/** 260 KiB, taken from the spool's 1 MiB reserve. */
export const LEDGER_SIZE = HEADER_BYTES + SLOTS * SLOT_BYTES;
/** One process never holds more, so others always find room. */
export const MAX_OWN_SLOTS = 16;
const PAYLOAD_MAX = SLOT_BYTES - SLOT_MAGIC.length - 4 - 32;
/** How long a claim waits for the header lock (Python blocks in `lockf`). */
const HEADER_LOCK_MS = 1000;
/** The native module's largest single `pwrite`. */
const IO_CHUNK = 1024 * 1024;

/** A ledger header or a spool `loss`/`marker` header, as stored in a slot. */
export type LedgerRecord = Record<string, unknown>;

/** The 4 KiB header: `>8sII` (magic, slot count, slot size), zero padded. */
export function ledgerHeader(): Buffer {
  const head = Buffer.alloc(HEADER_BYTES);
  LEDGER_MAGIC.copy(head, 0);
  head.writeUInt32BE(SLOTS, 8);
  head.writeUInt32BE(SLOT_BYTES, 12);
  return head;
}

const BLANK = Buffer.alloc(SLOT_BYTES);

/**
 * A slot holding `records` for `owner` (Python `_encode`): `undefined` when the payload
 * does not fit. The JSON is Python's `json.dumps(sort_keys=True, separators=(",", ":"))`,
 * ASCII-escaped.
 */
export function encodeSlot(owner: string, records: readonly LedgerRecord[]): Buffer | undefined {
  const payload = Buffer.from(encodeJson({ owner, records }, { asciiOnly: true }), "ascii");
  if (payload.length > PAYLOAD_MAX) return undefined;
  const length = Buffer.alloc(4);
  length.writeUInt32BE(payload.length, 0);
  const body = Buffer.concat([SLOT_MAGIC, length, payload]);
  const slot = Buffer.alloc(SLOT_BYTES);
  body.copy(slot, 0);
  createHash("sha256").update(body).digest().copy(slot, body.length);
  return slot;
}

/** A slot's records (Python `decode_slot`): `[]` when empty, `undefined` when torn. */
export function decodeSlot(data: Uint8Array): LedgerRecord[] | undefined {
  const slot = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  if (!slot.subarray(0, SLOT_MAGIC.length).equals(SLOT_MAGIC)) {
    return slot.every((byte) => byte === 0) ? [] : undefined;
  }
  if (slot.length < 12) return undefined;
  const size = slot.readUInt32BE(8);
  const end = 12 + size;
  if (size > PAYLOAD_MAX || end + 32 > slot.length) return undefined;
  const digest = createHash("sha256").update(slot.subarray(0, end)).digest();
  if (!digest.equals(slot.subarray(end, end + 32))) return undefined;
  try {
    const doc = parseJson(slot.subarray(12, end).toString("utf8")) as { records?: unknown };
    return Array.isArray(doc.records) ? (doc.records as LedgerRecord[]) : undefined;
  } catch {
    return undefined;
  }
}

function isManifest(record: LedgerRecord): boolean {
  const marker = record.marker as { kind?: unknown } | undefined;
  return record.record_kind === "marker" && marker?.kind === "manifest";
}

/** A native call that failed: the step and its fixed code, never a path. */
export class LedgerError extends Error {
  readonly code: string | undefined;
  constructor(
    readonly step: string,
    readonly result: number,
  ) {
    super(
      `wire spool loss ledger ${step} failed (${nativeCodeName(result)}); fix: check the ` +
        "local volume holding FABRIC_WIRE_SPOOL_DIR (free space, permissions, disk errors)",
    );
    this.name = "LedgerError";
    if (result === NativeCode.NO_SPACE) this.code = "ENOSPC";
    else if (result === NativeCode.QUOTA) this.code = "EDQUOT";
    else this.code = undefined;
  }
}

function check(step: string, result: number): number {
  if (result < 0) throw new LedgerError(step, result);
  return result;
}

let sleeper: Int32Array | undefined;
function pause(ms: number): void {
  if (!isMainThread) {
    sleeper ??= new Int32Array(new SharedArrayBuffer(4));
    Atomics.wait(sleeper, 0, 0, ms);
    return;
  }
  const until = performance.now() + ms;
  while (performance.now() < until) {
    // a bounded spin: the main thread never calls Atomics.wait
  }
}

/** One open ledger file of this isolate: its descriptor and every slot an instance holds. */
interface SharedFile {
  readonly handle: number;
  readonly claimed: Set<number>;
  users: number;
}

const FILES = new Map<string, SharedFile>();

function fileKey(path: string): string {
  const info = lstatSync(path, { bigint: true });
  return `${info.dev}:${info.ino}`;
}

/** Statistics a drainer and the status document report (content-free counts). */
export interface LedgerStats {
  readonly slots: number;
  readonly overflows: number;
  readonly failures: number;
  readonly corrupt: number;
  readonly manifestsUnledgered: number;
}

/**
 * One process's handle on a spool's ledger. Every method runs on the Fabric worker (or
 * a test), never in a transport hook.
 */
export class LossLedger {
  readonly path: string;
  /** Records that did not fit (the newest stay in memory only). */
  overflows = 0;
  /** Writes or fsyncs that failed (and claims whose header lock stayed busy). */
  failures = 0;
  /** Torn orphan slots cleared without being read. */
  corrupt = 0;
  readonly #addon: NativeAddon;
  readonly #key: string;
  readonly #file: SharedFile;
  readonly #owner: string;
  /** Slots this instance holds (locked), in use order, and what each holds now. */
  #own: number[] = [];
  #stored: Buffer[] = [];
  /** Orphan slots this instance locked as the drainer. */
  readonly #held = new Set<number>();
  /** Written since the last successful fsync (an `IO` failure keeps it set). */
  #dirty = false;
  readonly #unledgered = new Set<string>();
  #closed = false;

  /**
   * Opens (creating it, fully allocated, when missing) the ledger of `directory`.
   * Throws a {@link LedgerError} or a validation error when it cannot be used; the spool
   * then runs without one (losses stay in memory, as before).
   */
  constructor(directory: string, addon: NativeAddon, options: { readonly pid?: number } = {}) {
    this.#addon = addon;
    this.path = join(directory, LEDGER);
    this.#owner = `${options.pid ?? process.pid}-${randomBytes(4).toString("hex")}`;
    createLedger(directory, addon, options.pid ?? process.pid);
    this.#key = fileKey(this.path);
    const shared = FILES.get(this.#key);
    if (shared !== undefined) {
      shared.users += 1;
      this.#file = shared;
      return;
    }
    const handle = openLedger(directory, addon);
    try {
      validate(this.path, addon, handle);
    } catch (error) {
      addon.close(handle);
      throw error;
    }
    this.#file = { handle, claimed: new Set(), users: 1 };
    FILES.set(this.#key, this.#file);
  }

  get #handle(): number {
    return this.#file.handle;
  }

  /** Manifest markers too large for a slot (050 §3.5; their loss is in `manifest_seq`). */
  get manifestsUnledgered(): number {
    return this.#unledgered.size;
  }

  /** Slots this process holds now. */
  used(): number {
    return this.#own.length;
  }

  stats(): LedgerStats {
    return {
      slots: this.#own.length,
      overflows: this.overflows,
      failures: this.failures,
      corrupt: this.corrupt,
      manifestsUnledgered: this.manifestsUnledgered,
    };
  }

  #lock(index: number | undefined, op: 1 | 2): number {
    const [start, length] =
      index === undefined
        ? [0, HEADER_BYTES]
        : [HEADER_BYTES + index * SLOT_BYTES, SLOT_BYTES];
    return this.#addon.recordLock(this.#handle, BigInt(start), BigInt(length), op);
  }

  #tryLock(index: number): boolean {
    return this.#lock(index, RECORD_WRITE) === NativeCode.OK;
  }

  #unlock(index: number): void {
    this.#lock(index, RECORD_UNLOCK);
  }

  #read(index: number): Buffer {
    const out = Buffer.alloc(SLOT_BYTES);
    let filled = 0;
    while (filled < SLOT_BYTES) {
      const got = check(
        "pread",
        this.#addon.pread(
          this.#handle,
          out.subarray(filled),
          BigInt(HEADER_BYTES + index * SLOT_BYTES + filled),
        ),
      );
      if (got === 0) throw new LedgerError("pread", NativeCode.IO); // shorter than its layout
      filled += got;
    }
    return out;
  }

  #write(index: number, data: Buffer): void {
    let offset = 0;
    while (offset < data.length) {
      const wrote = check(
        "pwrite",
        this.#addon.pwrite(
          this.#handle,
          data.subarray(offset),
          BigInt(HEADER_BYTES + index * SLOT_BYTES + offset),
        ),
      );
      if (wrote === 0) throw new LedgerError("pwrite", NativeCode.IO);
      offset += wrote;
    }
  }

  #sync(): void {
    check("fsync", this.#addon.fsync(this.#handle));
  }

  /** Takes the header lock, retrying (the native call never blocks) for a bounded time. */
  #headerLock(): boolean {
    const deadline = performance.now() + HEADER_LOCK_MS;
    let wait = 0.5;
    for (;;) {
      const result = this.#lock(undefined, RECORD_WRITE);
      if (result === NativeCode.OK) return true;
      if (result !== NativeCode.WOULD_BLOCK || performance.now() >= deadline) return false;
      pause(wait);
      wait = Math.min(wait * 2, 10);
    }
  }

  /** Locks an empty slot no live process holds (under the header lock). */
  #claim(): number | undefined {
    if (!this.#headerLock()) {
      this.failures += 1;
      return undefined;
    }
    try {
      for (let index = 0; index < SLOTS; index++) {
        if (this.#file.claimed.has(index) || !this.#tryLock(index)) continue;
        if (this.#read(index).equals(BLANK)) {
          this.#file.claimed.add(index);
          return index;
        }
        this.#unlock(index); // a dead owner's records: the drainer's to take
      }
      return undefined;
    } finally {
      this.#lock(undefined, RECORD_UNLOCK);
    }
  }

  #release(index: number): void {
    this.#unlock(index);
    this.#file.claimed.delete(index);
  }

  /**
   * Makes this process's slots hold exactly `records` (loss records first, then markers,
   * as given), fsync'd; `[]` clears and releases them. `false` when not all fit (the
   * rest, the newest, stay in memory only; counted) or the write failed. Encoding stops
   * once {@link MAX_OWN_SLOTS} are full. Never throws.
   */
  store(records: readonly LedgerRecord[]): boolean {
    if (this.#closed) return false;
    const chunks: Buffer[] = [];
    let batch: LedgerRecord[] = [];
    let fits = true;
    for (const record of records) {
      if (batch.length > 0 && encodeSlot(this.#owner, [...batch, record]) === undefined) {
        chunks.push(encodeSlot(this.#owner, batch) ?? BLANK);
        batch = [];
        if (chunks.length >= MAX_OWN_SLOTS) {
          fits = false; // the rest cannot be mirrored
          break;
        }
      }
      if (encodeSlot(this.#owner, [record]) === undefined) {
        // larger than a slot: a manifest is not mirrored (050 §3.5, counted apart)
        if (isManifest(record)) {
          const marker = record.marker as { event_id?: unknown };
          this.#unledgered.add(String(marker.event_id));
        } else {
          fits = false;
        }
        continue;
      }
      batch.push(record);
    }
    if (batch.length > 0 && chunks.length < MAX_OWN_SLOTS) {
      chunks.push(encodeSlot(this.#owner, batch) ?? BLANK);
    }
    try {
      while (this.#own.length < chunks.length) {
        const index = this.#claim();
        if (index === undefined) {
          chunks.length = this.#own.length;
          fits = false;
          break;
        }
        this.#own.push(index);
        this.#stored.push(BLANK);
      }
      while (chunks.length < this.#own.length) chunks.push(BLANK);
      chunks.forEach((data, position) => {
        if (!this.#stored[position]!.equals(data)) {
          this.#dirty = true;
          this.#write(this.#own[position]!, data);
          this.#stored[position] = data;
        }
      });
      if (this.#dirty) {
        // also a retry after a failed fsync: synced before success
        this.#sync();
        this.#dirty = false;
      }
      while (this.#own.length > 0 && this.#stored[this.#stored.length - 1]!.equals(BLANK)) {
        this.#release(this.#own.pop()!);
        this.#stored.pop();
      }
    } catch {
      this.failures += 1;
      return false;
    }
    if (!fits) this.overflows += 1;
    return fits;
  }

  /**
   * Drainer: locks and reads every non-empty slot whose owner is gone. The caller exports
   * each and calls {@link clear} (or {@link releaseSlot} to retry later). A slot that does
   * not verify is cleared here and counted. Never throws.
   */
  orphans(): { readonly index: number; readonly records: LedgerRecord[] }[] {
    const found: { index: number; records: LedgerRecord[] }[] = [];
    if (this.#closed) return found;
    for (let index = 0; index < SLOTS; index++) {
      if (this.#file.claimed.has(index)) continue;
      let records: LedgerRecord[] | undefined;
      try {
        if (this.#read(index).equals(BLANK) || !this.#tryLock(index)) continue;
        this.#file.claimed.add(index);
        records = decodeSlot(this.#read(index));
      } catch {
        if (this.#file.claimed.has(index) && !this.#held.has(index)) this.#release(index);
        continue;
      }
      if (records === undefined) {
        this.corrupt += 1;
        this.#clear(index);
      } else if (records.length > 0) {
        found.push({ index, records });
        this.#held.add(index);
        continue;
      }
      this.#release(index);
    }
    return found;
  }

  #clear(index: number): boolean {
    try {
      this.#dirty = true;
      this.#write(index, BLANK);
      this.#sync();
      this.#dirty = false;
      return true;
    } catch {
      this.failures += 1;
      return false;
    }
  }

  /** Drainer: an orphan slot's records were delivered; empties and releases it. */
  clear(index: number): boolean {
    if (!this.#held.has(index)) return false;
    try {
      return this.#clear(index);
    } finally {
      this.#held.delete(index);
      this.#release(index);
    }
  }

  /** Drainer: an orphan slot was not delivered; leaves it for a later attempt. */
  releaseSlot(index: number): void {
    if (!this.#held.delete(index)) return;
    this.#release(index);
  }

  /**
   * Releases this instance's slots without clearing them (their records then belong to
   * a drainer, as a dead process's do) and, with the last instance of the isolate, the
   * descriptor. Idempotent.
   */
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    for (const index of [...this.#own, ...this.#held]) this.#release(index);
    this.#own = [];
    this.#stored = [];
    this.#held.clear();
    this.#file.users -= 1;
    if (this.#file.users === 0) {
      FILES.delete(this.#key);
      this.#addon.close(this.#handle);
    }
  }
}

function openDir(directory: string, addon: NativeAddon): number {
  return check("openDir", addon.openDir(directory));
}

/** The ledger's descriptor; retries while another creator's link is not yet unlinked. */
function openLedger(directory: string, addon: NativeAddon): number {
  const dir = openDir(directory, addon);
  try {
    for (let attempt = 0; ; attempt++) {
      const handle = addon.openFile(dir, LEDGER, false);
      if (handle >= 0) return handle;
      // UNSAFE_PATH: two links for a moment (a creator between its link and unlink)
      if (handle !== NativeCode.UNSAFE_PATH || attempt >= 20) throw new LedgerError("open", handle);
      pause(5);
    }
  } finally {
    addon.close(dir);
  }
}

/** Checks the file is the ledger this version writes: its size and its header. */
function validate(path: string, addon: NativeAddon, handle: number): void {
  const info = lstatSync(path);
  const head = Buffer.alloc(16);
  const got = addon.pread(handle, head, 0n);
  if (
    !info.isFile() ||
    (process.getuid !== undefined && info.uid !== process.getuid()) ||
    info.size !== LEDGER_SIZE ||
    got !== head.length ||
    !head.equals(ledgerHeader().subarray(0, 16))
  ) {
    throw new Error(
      "the spool loss ledger is not one this version wrote; fix: remove FABRIC_WIRE_SPOOL_DIR/.ledger " +
        "while no process uses the spool (it is recreated)",
    );
  }
}

function exists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if ((error as { code?: unknown }).code === "ENOENT") return false;
    throw error;
  }
}

/**
 * Creates the ledger once, atomically and fully allocated (Python `_create`): written in
 * full under a private name, fsync'd, then linked into place (never replacing one) and
 * the directory fsync'd. Another process may win the race; its ledger is used.
 */
function createLedger(directory: string, addon: NativeAddon, pid: number): void {
  const path = join(directory, LEDGER);
  if (exists(path)) return;
  const tmpName = `${NEW_PREFIX}${pid}-${randomBytes(4).toString("hex")}`;
  const tmp = join(directory, tmpName);
  const dir = openDir(directory, addon);
  try {
    const handle = check("create", addon.openFile(dir, tmpName, true));
    try {
      // a fresh name: anything already there is not ours to write
      if (check("pread", addon.pread(handle, Buffer.alloc(1), 0n)) !== 0) {
        throw new LedgerError("create", NativeCode.EXISTS);
      }
      check("allocate", addon.allocate(handle, BigInt(LEDGER_SIZE)));
      const data = Buffer.concat([ledgerHeader(), Buffer.alloc(LEDGER_SIZE - HEADER_BYTES)]);
      for (let offset = 0; offset < data.length; ) {
        const piece = data.subarray(offset, Math.min(data.length, offset + IO_CHUNK));
        const wrote = check("pwrite", addon.pwrite(handle, piece, BigInt(offset)));
        if (wrote === 0) throw new LedgerError("pwrite", NativeCode.IO);
        offset += wrote;
      }
      check("fsync", addon.fsync(handle));
    } finally {
      addon.close(handle);
    }
    try {
      linkSync(tmp, path);
    } catch (error) {
      if ((error as { code?: unknown }).code !== "EEXIST") {
        throw new Error("the spool loss ledger could not be linked into place");
      }
    }
    removeQuietly(tmp);
    check("fsync", addon.fsync(dir));
  } finally {
    removeQuietly(tmp);
    addon.close(dir);
  }
}

function removeQuietly(path: string): void {
  try {
    unlinkSync(path);
  } catch {
    // gone already, or swept by the drainer once stale
  }
}
