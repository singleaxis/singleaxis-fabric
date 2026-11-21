// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The durable wire spool (spec 055 §6.2, §6.3; part 1): a port of Python's
 * `fabric/wire/_spool.py` `Spool` that writes and reads the same directory, so a Python
 * drainer delivers a Node agent's records and a Node drainer delivers Python's.
 *
 * One fsync'd `<source_epoch:020d>-<pid:010d>-<order:012d>.rec` per record (name order
 * is drain order), sealed in the `FWSPENC1` envelope when a key is configured. Commit:
 * reserve the full encoded size under `flock(.admit)` against every process's bytes on
 * disk (pending, temp and quarantined records, receipts) -> create the exclusive temp at
 * its full size -> write the frame -> fsync -> rename under the admission lock -> fsync
 * the directory. One `flock(.lock)` holder drains, in stable name order; a corrupt record
 * is quarantined (`.corrupt`, still charged) and a record sealed under an unknown key
 * stays pending and charged for a drainer holding that key.
 *
 * Every call here does synchronous I/O, so a `Spool` lives on the Fabric worker (or is
 * opened at install); no transport hook ever reaches this module. One thread owns a
 * `Spool`: Python's in-flight bookkeeping for concurrent threads is not needed, since no
 * other call can interleave with a write or a rescan.
 *
 * Record files use Node `fs` (libuv opens them with `O_CLOEXEC`); the `.admit` and
 * `.lock` files and directory fsyncs use the native module (§4.4). Left to `055-t16`:
 * the loss ledger, `.ack` receipts for other writers, the ancestor directory barrier,
 * batch-file writing and the plaintext migration (a Python batch file is read here).
 */
import {
  closeSync,
  constants,
  fsyncSync,
  lstatSync,
  mkdirSync,
  chmodSync,
  openSync,
  readSync,
  ftruncateSync,
  readdirSync,
  renameSync,
  unlinkSync,
  writeSync,
  writevSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { isMainThread } from "node:worker_threads";

import {
  FLOCK_EXCLUSIVE,
  FLOCK_UNLOCK,
  type NativeAddon,
  NativeCode,
  nativeCodeName,
} from "./native.js";
import {
  CorruptRecordError,
  OverBoundError,
  SCHEMA,
  SPOOL_KEY_BYTES,
  type SpoolDoc,
  UndecryptableRecordError,
  frame,
  overBound,
  recordName,
  seal,
  spoolKeyId,
  unframeAll,
  unseal,
} from "./spool-codec.js";

/** Loss and marker records may exceed the bound by this much (the ledger's share included). */
export const RESERVE_BYTES = 1024 * 1024;
/** The shared loss ledger (Python `_ledger.LEDGER`), preallocated inside the reserve. */
export const LEDGER = ".ledger";
/** The ledger's size: a 4 KiB header and 64 slots of 4 KiB (Python `_ledger`). */
export const LEDGER_BYTES = 4096 + 64 * 4096;
/** The shared admission lock every writer of the directory takes (never `.lock`). */
export const ADMIT_LOCK = ".admit";
export const DRAIN_LOCK = ".lock";
/** A busy admission lock past this refuses the record (Python `ADMIT_TIMEOUT_S`). */
export const ADMIT_TIMEOUT_MS = 5000;
export const TMP_PREFIX = ".tmp-";
export const QUARANTINE_SUFFIX = ".corrupt";
export const ACK_SUFFIX = ".ack";
/** A receipt counts at least this much (an inode and a directory entry). */
export const RECEIPT_OVERHEAD = 128;
/** Temp files older than this were left by a writer that exited (Python `RECEIPT_TTL_S`). */
export const STALE_MS = 3600 * 1000;
/** Names Python's spool owns beside records (`_own_name`), and the native self-test probe. */
/** The content-free note of records left at exit with no drainer (Python `EXIT_NOTE`). */
export const EXIT_NOTE = ".exit-backlog";
export const EXIT_NOTE_SCHEMA = "fabric.wire-exit-backlog/v1";
const OWN_NAMES = new Set([DRAIN_LOCK, ADMIT_LOCK, ".barrier", LEDGER, ".epochs", EXIT_NOTE]);
const OWN_PREFIXES = [TMP_PREFIX, ".ledger-new-", ".fabric-selftest-"];
const OWN_SUFFIXES = [".rec", ACK_SUFFIX, QUARANTINE_SUFFIX];

/** A spool directory or key that cannot be used: what is wrong and how to fix it. */
export class SpoolConfigError extends Error {
  constructor(
    message: string,
    readonly fix: string,
  ) {
    super(`${message}; fix: ${fix}`);
    this.name = "SpoolConfigError";
  }
}

/** Whether a spool write failed because the volume or the user's quota is full. */
export function diskFull(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  return code === "ENOSPC" || code === "EDQUOT";
}

/** How to fix a failed file-system call of the spool, by its `errno` code. */
function ioFix(code: string | undefined): string {
  switch (code) {
    case "ENOSPC":
    case "EDQUOT":
      return "free space on the volume (or the quota) holding FABRIC_WIRE_SPOOL_DIR, or lower FABRIC_WIRE_SPOOL_MAX_BYTES to what it can hold";
    case "EACCES":
    case "EPERM":
      return "give FABRIC_WIRE_SPOOL_DIR to the agent's user (a directory it owns, mode 0700)";
    case "EROFS":
      return "point FABRIC_WIRE_SPOOL_DIR at a writable local volume";
    case "ELOOP":
      return "remove the symlink from FABRIC_WIRE_SPOOL_DIR; the spool never follows one";
    case "EMFILE":
    case "ENFILE":
      return "raise the open-file limit of the agent's process (ulimit -n)";
    case "ENOTDIR":
    case "ENOENT":
      return "point FABRIC_WIRE_SPOOL_DIR at a directory that stays in place while the agent runs";
    default:
      return "check the local volume holding FABRIC_WIRE_SPOOL_DIR (disk errors, a lost mount)";
  }
}

/**
 * A file-system call of the spool that failed: the call and its `errno` code (`code`, so
 * {@link diskFull} and the callers' checks work as for an `fs` error) with how to fix it.
 * Never the path, which Node puts in its own error message.
 */
export class SpoolIoError extends Error {
  readonly code: string | undefined;
  readonly errno: number | undefined;
  constructor(
    readonly syscall: string,
    error: unknown,
  ) {
    const { code, errno } = (error ?? {}) as { code?: unknown; errno?: unknown };
    const known = typeof code === "string" ? code : undefined;
    super(`wire spool ${syscall} failed (${known ?? "unknown error"}); fix: ${ioFix(known)}`);
    this.name = "SpoolIoError";
    this.code = known;
    this.errno = typeof errno === "number" ? errno : undefined;
  }
}

/** Runs one `fs` call, rethrowing its failure as a {@link SpoolIoError}. */
function scrub<T>(syscall: string, call: () => T): T {
  try {
    return call();
  } catch (error) {
    throw new SpoolIoError(syscall, error);
  }
}

/** How to fix a failed native call of the spool, by its fixed code. */
function nativeFix(result: number): string {
  switch (result) {
    case NativeCode.NO_SPACE:
    case NativeCode.QUOTA:
      return ioFix("ENOSPC");
    case NativeCode.PERMISSION:
      return ioFix("EACCES");
    case NativeCode.UNSAFE_PATH:
      return "point FABRIC_WIRE_SPOOL_DIR at a real directory owned by the agent's user, with no symlink in the spool";
    case NativeCode.LIMIT:
      return "the native module's handles are all in use in this process; close spools that are no longer used";
    case NativeCode.NOT_FOUND:
      return ioFix("ENOENT");
    default:
      return ioFix(undefined);
  }
}

/** A native call that failed: its fixed result code and how to fix it, never a path. */
export class NativeSpoolError extends Error {
  constructor(
    readonly step: string,
    readonly result: number,
  ) {
    super(`wire spool ${step} failed (${nativeCodeName(result)}); fix: ${nativeFix(result)}`);
    this.name = "NativeSpoolError";
    // The callers tell a full disk apart by `code`, as for an `fs` error.
    if (result === NativeCode.NO_SPACE) (this as { code?: string }).code = "ENOSPC";
    if (result === NativeCode.QUOTA) (this as { code?: string }).code = "EDQUOT";
  }
}

/**
 * A record file larger than this spool's bound plus the reserve: a writer configured with
 * a larger `FABRIC_WIRE_SPOOL_MAX_BYTES` shares the directory. Left pending, never read.
 */
export class RecordTooLargeError extends Error {
  constructor() {
    super(
      "a spool record is larger than this process's spool bound; give every writer of " +
        "FABRIC_WIRE_SPOOL_DIR the same FABRIC_WIRE_SPOOL_MAX_BYTES",
    );
    this.name = "RecordTooLargeError";
  }
}

/** Python's `TimeoutError("spool admission lock busy")`: the record is refused. */
export class AdmissionTimeout extends Error {
  constructor() {
    super("spool admission lock busy");
    this.name = "AdmissionTimeout";
  }
}

/** What a file looks like to the spool. */
export interface SpoolStat {
  readonly size: number;
  readonly mtimeMs: number;
  readonly isFile: boolean;
  readonly isSymbolicLink: boolean;
}

/**
 * The file-system operations of the spool. The default uses Node `fs` for record files
 * and the native module for directory fsyncs; tests wrap it to inject a fault at any step.
 */
export interface SpoolIo {
  /** `O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW`, mode 0600. */
  openExclusive(path: string): number;
  /** `O_RDONLY | O_NOFOLLOW`. */
  openRead(path: string): number;
  write(fd: number, data: Uint8Array, position: number): number;
  /** Gathered write at `position`; may be short. */
  writev(fd: number, data: readonly Uint8Array[], position: number): number;
  read(fd: number, into: Uint8Array, position: number): number;
  fsync(fd: number): void;
  close(fd: number): void;
  rename(from: string, to: string): void;
  unlink(path: string): void;
  lstat(path: string): SpoolStat;
  readdir(path: string): string[];
  /** fsync a directory, opened without following a symlink. */
  syncDir(path: string): void;
  /**
   * Truncates `path` to zero bytes and fsyncs it (a delivery receipt); nothing when it
   * does not exist. Opened without following a symlink.
   */
  truncate(path: string): void;
  /** Writes `data` to `path` with mode 0600 (truncating; never through a symlink). */
  writeFile(path: string, data: Uint8Array): void;
}

/**
 * The default {@link SpoolIo}. Every `fs` failure is a {@link SpoolIoError}: its code and
 * fix, never the path Node's own message carries.
 */
export function nodeSpoolIo(addon: NativeAddon): SpoolIo {
  const nofollow = constants.O_NOFOLLOW ?? 0;
  // A FIFO swapped in after the reader's lstat must not block the open.
  const nonblock = constants.O_NONBLOCK ?? 0;
  return {
    openExclusive: (path) =>
      scrub("open", () =>
        openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | nofollow, 0o600),
      ),
    openRead: (path) =>
      scrub("open", () => openSync(path, constants.O_RDONLY | nofollow | nonblock)),
    write: (fd, data, position) =>
      scrub("write", () => writeSync(fd, data, 0, data.length, position)),
    writev: (fd, data, position) =>
      scrub("writev", () => writevSync(fd, data as Uint8Array[], position)),
    read: (fd, into, position) => scrub("read", () => readSync(fd, into, 0, into.length, position)),
    fsync: (fd) => scrub("fsync", () => fsyncSync(fd)),
    close: (fd) => scrub("close", () => closeSync(fd)),
    rename: (from, to) => scrub("rename", () => renameSync(from, to)),
    unlink: (path) => scrub("unlink", () => unlinkSync(path)),
    lstat: (path) => {
      const info = scrub("lstat", () => lstatSync(path));
      return {
        size: info.size,
        mtimeMs: info.mtimeMs,
        isFile: info.isFile(),
        isSymbolicLink: info.isSymbolicLink(),
      };
    },
    readdir: (path) => scrub("readdir", () => readdirSync(path)),
    truncate: (path) => {
      let fd: number;
      try {
        fd = openSync(path, constants.O_WRONLY | nofollow);
      } catch (error) {
        if (errnoOf(error) === "ENOENT") return;
        throw new SpoolIoError("open", error);
      }
      try {
        scrub("ftruncate", () => ftruncateSync(fd, 0));
        scrub("fsync", () => fsyncSync(fd));
      } finally {
        closeSync(fd);
      }
    },
    writeFile: (path, data) => {
      const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | nofollow;
      const fd = scrub("open", () => openSync(path, flags, 0o600));
      try {
        scrub("write", () => writeSync(fd, data, 0, data.length, 0));
      } finally {
        closeSync(fd);
      }
    },
    syncDir: (path) => {
      const handle = addon.openDir(path);
      if (handle < 0) throw new NativeSpoolError("openDir", handle);
      try {
        const result = addon.fsync(handle);
        if (result < 0) throw new NativeSpoolError("fsync", result);
      } finally {
        addon.close(handle);
      }
    },
  };
}

function errnoOf(error: unknown): unknown {
  return (error as { code?: unknown } | null)?.code;
}

/** Whether `name` is one the wire spool (Python's or this one) creates. */
export function ownName(name: string): boolean {
  return (
    OWN_NAMES.has(name) ||
    OWN_PREFIXES.some((prefix) => name.startsWith(prefix)) ||
    OWN_SUFFIXES.some((suffix) => name.endsWith(suffix))
  );
}

/** The bytes a spool entry counts against the bound; `undefined`: not a spool entry. */
export function accounted(name: string, size: number): number | undefined {
  if (name.endsWith(ACK_SUFFIX)) return Math.max(size, RECEIPT_OVERHEAD);
  if (name.startsWith(TMP_PREFIX) || name.endsWith(".rec") || name.endsWith(QUARANTINE_SUFFIX)) {
    return size;
  }
  return undefined;
}

/**
 * Creates `path` (and missing parents) 0700; refuses a symlink, a file or a directory of
 * another user. Python `_secure_dir`. Exported for `install()`, which prepares the spool
 * directory before the native module's self-test runs in it.
 */
export function secureDir(path: string): void {
  const missing: string[] = [];
  let current = path;
  for (;;) {
    try {
      scrub("lstat", () => lstatSync(current));
      break;
    } catch (error) {
      if (errnoOf(error) !== "ENOENT") throw error;
      missing.push(current);
      const parent = dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  for (const directory of missing.reverse()) {
    try {
      scrub("mkdir", () => mkdirSync(directory, 0o700));
    } catch (error) {
      if (errnoOf(error) !== "EEXIST") throw error;
    }
  }
  const info = scrub("lstat", () => lstatSync(path));
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new SpoolConfigError(
      "FABRIC_WIRE_SPOOL_DIR must be a real directory, not a symlink or a file",
      "point FABRIC_WIRE_SPOOL_DIR at a directory (or a path that does not exist yet) owned by the agent's user",
    );
  }
  if (process.getuid !== undefined && info.uid !== process.getuid()) {
    throw new SpoolConfigError(
      "FABRIC_WIRE_SPOOL_DIR must be owned by the user the agent runs as",
      "create the spool directory as the agent's user, or point FABRIC_WIRE_SPOOL_DIR at one it owns",
    );
  }
  scrub("chmod", () => chmodSync(path, 0o700));
}

/** A record of {@link Spool.recover}: one pending file and its records, in drain order. */
export interface RecoveredFile {
  readonly name: string;
  readonly records: readonly { readonly doc: SpoolDoc; readonly blob: Buffer }[];
}

/** What a drainer's stable-order scan found. */
export interface RecoveryScan {
  /** Readable pending files, in drain (name) order. */
  readonly files: readonly RecoveredFile[];
  /** Files quarantined now, with every header that parsed (their sequences are losses). */
  readonly quarantined: readonly { readonly name: string; readonly docs: readonly SpoolDoc[] }[];
  /** Files sealed under another key: kept pending and charged, never read or removed. */
  readonly undecryptable: readonly string[];
  /**
   * Files that could not be read or quarantined now (an I/O error), or that are larger
   * than this spool's bound plus the reserve: left pending and charged, retried next scan.
   */
  readonly deferred: readonly string[];
}

export interface SpoolOptions {
  /** The configured bound in bytes (`FABRIC_WIRE_SPOOL_MAX_BYTES`). */
  readonly maxBytes: number;
  /** The 32-byte spool key; records are sealed in the `FWSPENC1` envelope when set. */
  readonly key?: Uint8Array;
  /** The native lock module (§4.4). */
  readonly addon: NativeAddon;
  /** File-system operations; default {@link nodeSpoolIo}. */
  readonly io?: SpoolIo;
  /** The process id written into record names; default `process.pid`. */
  readonly pid?: number;
  /** Nanoseconds since the epoch for `written_at_unix_nano`. */
  readonly clock?: () => bigint;
  /** The admission lock's retry deadline (default {@link ADMIT_TIMEOUT_MS}). */
  readonly admitTimeoutMs?: number;
}

/** A record to write: its header fields (kind, source and body) and its body bytes. */
export interface SpoolEntry {
  readonly doc: Record<string, unknown>;
  readonly bodies?: readonly Uint8Array[];
}

/** Per record: its file name, `null` (refused: over the bound or the lock busy) or the error. */
export type WriteOutcome = string | null | Error;

const ANCHOR_NS = BigInt(Date.now()) * 1_000_000n - process.hrtime.bigint();
const wallClockNs = (): bigint => ANCHOR_NS + process.hrtime.bigint();

let sleeper: Int32Array | undefined;

/**
 * Waits `ms` between admission retries: `Atomics.wait` on a Fabric worker, a bounded
 * spin on the main thread (which never calls `Atomics.wait`).
 */
function pause(ms: number): void {
  if (!isMainThread) {
    sleeper ??= new Int32Array(new SharedArrayBuffer(4));
    Atomics.wait(sleeper, 0, 0, ms);
    return;
  }
  const until = performance.now() + ms;
  while (performance.now() < until) {
    // spin
  }
}

/**
 * A bounded record directory shared by every writer (Node or Python) of the same
 * `FABRIC_WIRE_SPOOL_DIR`. `bytes` is this process's per-file ledger of what is on disk
 * (every file it knows, at its accounted size); every admission is also checked, under
 * the shared admission lock, against the bytes on disk of all writers.
 */
export class Spool {
  readonly dir: string;
  readonly maxBytes: number;
  /** The spool key's public id (`kid-` + 8 hex), when a key is configured. */
  readonly keyId: string | undefined;
  /** This process's ledger total. */
  bytes = 0;
  /** Receipts in the ledger. */
  receipts = 0;
  /** The shared on-disk total at this process's last admission. */
  sharedBytes = 0;
  /** Admissions refused because the lock stayed busy. */
  admissionTimeouts = 0;
  /** Own records that will never be delivered (quarantined). */
  failed = 0;
  /** Whether this process holds the drain lock. */
  holder = false;
  /** Names this process wrote, until their outcome is known. */
  readonly mine = new Set<string>();
  /**
   * Whether the shared loss ledger exists in the directory (a Python writer creates it):
   * its 260 KiB then lives inside the reserve, so reserve records get 1 MiB minus that,
   * as Python's do, and the directory stays within bound + 1 MiB. Once seen, kept.
   */
  ledgerSeen = false;

  readonly #key: Uint8Array | undefined;
  readonly #addon: NativeAddon;
  readonly #io: SpoolIo;
  readonly #pid: number;
  readonly #clock: () => bigint;
  readonly #admitTimeoutMs: number;
  readonly #files = new Map<string, number>();
  /** Own records being retired: a retry after a failure must still unlink, not rename. */
  readonly #ownRetiring = new Set<string>();
  /** Accounted size by name, as last observed under the admission lock. */
  #disk = new Map<string, number>();
  #order = 0;
  #lockHandle = -1;
  #admitHandle = -1;

  constructor(directory: string, options: SpoolOptions) {
    if (!Number.isSafeInteger(options.maxBytes) || options.maxBytes <= 0) {
      throw new SpoolConfigError(
        "the spool bound must be a positive whole number of bytes",
        "set FABRIC_WIRE_SPOOL_MAX_BYTES to a positive integer",
      );
    }
    if (options.key !== undefined && options.key.length !== SPOOL_KEY_BYTES) {
      throw new SpoolConfigError(
        "the spool key must be exactly 32 bytes (AES-256-GCM)",
        "supply a 32-byte key through the configured spool key source",
      );
    }
    this.#key = options.key === undefined ? undefined : Buffer.from(options.key);
    this.keyId = options.key === undefined ? undefined : spoolKeyId(options.key);
    this.#addon = options.addon;
    this.#io = options.io ?? nodeSpoolIo(options.addon);
    this.#pid = options.pid ?? process.pid;
    this.#clock = options.clock ?? wallClockNs;
    this.#admitTimeoutMs = options.admitTimeoutMs ?? ADMIT_TIMEOUT_MS;
    this.maxBytes = options.maxBytes;
    secureDir(directory);
    this.dir = directory.length > 1 ? directory.replace(/\/+$/, "") : directory;
    if (this.#io.readdir(this.dir).some((name) => !ownName(name))) {
      throw new SpoolConfigError(
        "FABRIC_WIRE_SPOOL_DIR holds files the wire spool does not own",
        "give the wire spool its own empty directory; never share it with another spool or application files",
      );
    }
    const dirHandle = this.#native("openDir", this.#addon.openDir(this.dir));
    try {
      this.#lockHandle = this.#native(
        "openFile",
        this.#addon.openFile(dirHandle, DRAIN_LOCK, true),
      );
      this.#admitHandle = this.#native(
        "openFile",
        this.#addon.openFile(dirHandle, ADMIT_LOCK, true),
      );
    } catch (error) {
      this.close();
      throw error;
    } finally {
      this.#addon.close(dirHandle);
    }
    this.rescan();
  }

  #native(step: string, result: number): number {
    if (result < 0) throw new NativeSpoolError(step, result);
    return result;
  }

  #path(name: string): string {
    return join(this.dir, name);
  }

  /** Whether records are sealed under a key. */
  get encrypted(): boolean {
    return this.#key !== undefined;
  }

  /** Releases the drain lock and the admission handle. Idempotent. */
  close(): void {
    this.release();
    if (this.#admitHandle > 0) this.#addon.close(this.#admitHandle);
    this.#admitHandle = -1;
  }

  // --------------------------------------------------------------------- the ledger

  #account(name: string, size: number | undefined): void {
    const old = this.#files.get(name);
    this.#files.delete(name);
    if (size !== undefined) this.#files.set(name, size);
    this.bytes += (size ?? 0) - (old ?? 0);
    if (name.endsWith(ACK_SUFFIX)) {
      this.receipts += (size !== undefined ? 1 : 0) - (old !== undefined ? 1 : 0);
    }
  }

  /** Sets `name`'s entry from disk; an observation error keeps the entry. */
  #observe(name: string): void {
    let size: number | undefined;
    try {
      size = accounted(name, this.#io.lstat(this.#path(name)).size);
    } catch (error) {
      if (errnoOf(error) !== "ENOENT") return;
      size = undefined;
    }
    this.#account(name, size);
  }

  /** The ledger side of a rename `src` -> `dst`: `dst` takes over the charge, then disk. */
  #move(src: string, dst: string): void {
    const charge = this.#files.get(src);
    if (charge !== undefined) {
      this.#account(src, undefined);
      this.#account(dst, Math.max(charge, this.#files.get(dst) ?? 0));
    }
    let size: number | undefined;
    try {
      size = accounted(dst, this.#io.lstat(this.#path(dst)).size);
    } catch {
      return;
    }
    this.#account(dst, size);
  }

  /** The ledger's charge for one name (tests and status). */
  charge(name: string): number | undefined {
    return this.#files.get(name);
  }

  /**
   * Rebuilds the ledger from disk (pending, temp and quarantined records and receipts of
   * all writers). The drainer removes temp files older than an hour (a writer that
   * exited). When a file cannot be observed, no charge is released.
   */
  rescan(): void {
    const scanned = new Map<string, number>();
    let unknown = false;
    const stale = Date.now() - STALE_MS;
    for (const name of this.#io.readdir(this.dir)) {
      if (name === LEDGER) this.ledgerSeen = true;
      const path = this.#path(name);
      const tmp = name.startsWith(TMP_PREFIX) || name.startsWith(".ledger-new-");
      let info: SpoolStat;
      try {
        info = this.#io.lstat(path);
        if (tmp && this.holder && info.mtimeMs < stale) {
          try {
            this.#io.unlink(path);
            continue;
          } catch {
            // still counted
          }
        }
      } catch (error) {
        if (errnoOf(error) !== "ENOENT") unknown ||= accounted(name, 0) !== undefined;
        continue;
      }
      const size = accounted(name, info.size);
      if (size !== undefined) scanned.set(name, size);
    }
    if (unknown) {
      for (const [name, size] of this.#files) if (!scanned.has(name)) scanned.set(name, size);
    }
    this.#files.clear();
    this.bytes = 0;
    this.receipts = 0;
    for (const [name, size] of scanned) this.#account(name, size);
  }

  /** What loss and marker records may use above the bound (Python `_reserve_bytes`). */
  get reserveBytes(): number {
    return RESERVE_BYTES - (this.ledgerSeen ? LEDGER_BYTES : 0);
  }

  #limit(reserve: boolean): number {
    return this.maxBytes + (reserve ? this.reserveBytes : 0);
  }

  // ------------------------------------------------------------------ admission

  /**
   * Runs `body` holding `flock(.admit)`: across processes, Python's included, and across
   * other `Spool` objects of this process (each has its own open file description).
   * Retries with backoff until the deadline, then throws {@link AdmissionTimeout}.
   */
  #admission<T>(body: () => T): T {
    const deadline = performance.now() + this.#admitTimeoutMs;
    let wait = 0.5;
    for (;;) {
      const result = this.#addon.flock(this.#admitHandle, FLOCK_EXCLUSIVE);
      if (result === NativeCode.OK) break;
      if (result !== NativeCode.WOULD_BLOCK) throw new NativeSpoolError("flock", result);
      if (performance.now() >= deadline) throw new AdmissionTimeout();
      pause(wait);
      wait = Math.min(wait * 2, 10);
    }
    try {
      return body();
    } finally {
      this.#addon.flock(this.#admitHandle, FLOCK_UNLOCK);
    }
  }

  /**
   * Under the admission lock: what every process's spool files count against the bound,
   * from disk. A file is re-stat'd only when its name is new, it is a temp file, or it is
   * a receipt not yet seen truncated; a record never changes size and a rename makes a
   * new name. An observation error on a new name throws (the caller fails closed).
   */
  #sharedTotal(): number {
    const disk = new Map<string, number>();
    let total = 0;
    for (const name of this.#io.readdir(this.dir)) {
      if (name === LEDGER) this.ledgerSeen = true;
      if (accounted(name, 0) === undefined) continue;
      let size = this.#disk.get(name);
      if (
        size === undefined ||
        name.startsWith(TMP_PREFIX) ||
        (name.endsWith(ACK_SUFFIX) && size > RECEIPT_OVERHEAD)
      ) {
        try {
          size = accounted(name, this.#io.lstat(this.#path(name)).size);
        } catch (error) {
          if (errnoOf(error) === "ENOENT") continue;
          if (size === undefined) throw error;
        }
      }
      if (size !== undefined) {
        disk.set(name, size);
        total += size;
      }
    }
    this.#disk = disk;
    return total;
  }

  /**
   * Shared admission: under one admission lock, admits each `(temp path, size)` only
   * while the on-disk total plus its size stays within `limit`, and reserves it on disk
   * before the lock is released (the temp file is created at its full size, its last
   * byte written). The limit is taken after the scan, which may have found the ledger.
   * Per entry: the descriptor, `null` (refused) or the creation error.
   */
  #reserveMany(wanted: readonly [string, number][], reserve: boolean): (number | null | Error)[] {
    const results: (number | null | Error)[] = wanted.map(() => null);
    if (wanted.length === 0) return results;
    try {
      this.#admission(() => {
        let total: number;
        try {
          total = this.#sharedTotal();
        } catch (error) {
          results.fill(asError(error));
          return;
        }
        this.sharedBytes = total;
        const limit = this.#limit(reserve);
        wanted.forEach(([tmp, size], index) => {
          if (total + size > limit) return;
          let fd: number;
          try {
            fd = this.#io.openExclusive(tmp);
          } catch (error) {
            results[index] = asError(error);
            return;
          }
          try {
            if (this.#io.write(fd, ZERO, size - 1) !== 1)
              throw new Error("short reservation write");
          } catch (error) {
            results[index] = asError(error);
            closeQuietly(this.#io, fd);
            try {
              this.#io.unlink(tmp);
            } catch {
              // a leftover temp file is counted by every scan until a drainer sweeps it
            }
            return;
          }
          results[index] = fd;
          total += size;
        });
        this.sharedBytes = total;
      });
    } catch (error) {
      if (!(error instanceof AdmissionTimeout)) {
        return results.map((result) => (typeof result === "number" ? result : asError(error)));
      }
      this.admissionTimeouts += 1; // raised before the lock was taken: nothing reserved
    }
    return results;
  }

  #exists(name: string): boolean {
    try {
      this.#io.lstat(this.#path(name));
      return true;
    } catch (error) {
      if (errnoOf(error) === "ENOENT") return false;
      throw error;
    }
  }

  #renameMany(names: readonly string[]): (Error | null)[] {
    if (names.length === 0) return [];
    try {
      return this.#admission(() =>
        names.map((name) => {
          try {
            // Never over another record: every writer renames under this lock, so the
            // check holds until the rename (two writers sharing a pid and an epoch).
            if (this.#exists(name)) {
              throw Object.assign(new Error("a spool record of that name already exists"), {
                code: "EEXIST",
              });
            }
            this.#io.rename(this.#path(TMP_PREFIX + name), this.#path(name));
            return null;
          } catch (error) {
            return asError(error);
          }
        }),
      );
    } catch (error) {
      return names.map(() => asError(error));
    }
  }

  // ------------------------------------------------------------------------ writing

  /**
   * Appends one record (temp, fsync, rename, directory fsync): its name, or `null` when
   * over the bound or the admission lock stayed busy. A failure throws ({@link diskFull}
   * tells a full volume apart). `reserve`: a loss or marker record, which may use the
   * 1 MiB reserve above the bound.
   */
  write(
    doc: Record<string, unknown>,
    bodies: readonly Uint8Array[] = [],
    reserve = false,
  ): string | null {
    const [result] = this.writeBatch([{ doc, bodies }], reserve);
    if (result instanceof Error) throw result;
    return result ?? null;
  }

  /**
   * Appends records, each to its own file, sharing the steps across the batch: one
   * admission reserves every temp file, each is written and fsync'd, one admission
   * renames them all and one directory fsync makes them durable. A record counts as
   * written (its name returned) only after its file and the directory were fsync'd.
   * A record over its body bound is refused before anything is written
   * ({@link OverBoundError}).
   */
  writeBatch(records: readonly SpoolEntry[], reserve = false): WriteOutcome[] {
    const results: WriteOutcome[] = records.map((record) =>
      overBound(record.doc) ? new OverBoundError() : null,
    );
    const kept = records.flatMap((record, index) => (results[index] === null ? [index] : []));
    const prepared = kept.map((index) => this.#prepare(records[index]!));
    const limit = this.#limit(reserve);
    const live: number[] = [];
    prepared.forEach(({ name, size }, at) => {
      if (this.bytes + size <= limit) {
        this.#account(name, size);
        live.push(at);
      }
    });
    const outcome = new Map<number, WriteOutcome>();
    const fail = (at: number, error: Error): void => {
      const { name } = prepared[at]!;
      outcome.set(at, error);
      try {
        this.#io.unlink(this.#path(TMP_PREFIX + name));
      } catch {
        // charged where its bytes are (below)
      }
      this.#failedWrite(name);
    };
    const fds = new Map<number, number>();
    let current = [...live];
    try {
      const reserved = this.#reserveMany(
        current.map((at) => [this.#path(TMP_PREFIX + prepared[at]!.name), prepared[at]!.size]),
        reserve,
      );
      const admitted: number[] = [];
      current.forEach((at, index) => {
        const got = reserved[index];
        if (typeof got === "number") {
          fds.set(at, got);
          admitted.push(at);
        } else if (got === null || got === undefined) {
          this.#account(prepared[at]!.name, undefined); // refused: over the bound or busy
        } else {
          fail(at, got);
        }
      });
      current = admitted;
      const written: number[] = [];
      for (const at of current) {
        const fd = fds.get(at)!;
        fds.delete(at);
        try {
          writeAll(this.#io, fd, prepared[at]!.pieces);
          this.#io.fsync(fd);
          written.push(at);
        } catch (error) {
          fail(at, asError(error));
        } finally {
          closeQuietly(this.#io, fd);
        }
      }
      current = written;
      const renamed = this.#renameMany(current.map((at) => prepared[at]!.name));
      current = current.filter((at, index) => {
        const error = renamed[index];
        if (error === null || error === undefined) return true;
        fail(at, error);
        return false;
      });
      if (current.length > 0) {
        try {
          this.#io.syncDir(this.dir);
        } catch (error) {
          for (const at of current) fail(at, asError(error));
          current = [];
        }
      }
    } catch (error) {
      for (const fd of fds.values()) closeQuietly(this.#io, fd);
      for (const at of current)
        if (!outcome.has(at)) fail(at, new Error("spool write interrupted"));
      throw error;
    }
    for (const at of current) {
      const { name, size } = prepared[at]!;
      this.#account(name, size);
      this.mine.add(name);
      outcome.set(at, name);
    }
    kept.forEach((index, at) => {
      results[index] = outcome.get(at) ?? null;
    });
    return results;
  }

  /** The record framed and (with a key) sealed: its name, pieces and size. */
  #prepare(record: SpoolEntry): { name: string; pieces: Buffer[]; size: number } {
    const order = this.#order;
    this.#order += 1;
    const doc = {
      ...record.doc,
      schema_version: SCHEMA,
      order,
      written_at_unix_nano: this.#clock(),
    };
    const source = (record.doc.source ?? {}) as { source_epoch?: unknown };
    const epoch = source.source_epoch;
    if (typeof epoch !== "bigint" && typeof epoch !== "number") {
      throw new TypeError("a spool record needs source.source_epoch");
    }
    const name = recordName(epoch, this.#pid, order);
    const framed = frame(doc, record.bodies ?? []);
    const pieces = this.#key === undefined ? framed : seal(name, framed, this.#key, this.keyId!);
    return { name, pieces, size: pieces.reduce((sum, piece) => sum + piece.length, 0) };
  }

  /**
   * Charges a failed write where its bytes are: still in the temp file (its unlink
   * failed), renamed before the failure, or gone. Unknown (an error): kept as is.
   */
  #failedWrite(name: string): void {
    try {
      this.#io.lstat(this.#path(TMP_PREFIX + name));
    } catch (error) {
      if (errnoOf(error) === "ENOENT") this.#observe(name);
      return;
    }
    this.#move(name, TMP_PREFIX + name);
  }

  // ----------------------------------------------------------------------- draining

  /** Takes the drain lock without waiting: `true` when this process holds it. */
  tryLock(): boolean {
    if (!this.holder && this.#lockHandle > 0) {
      this.holder = this.#addon.flock(this.#lockHandle, FLOCK_EXCLUSIVE) === NativeCode.OK;
    }
    return this.holder;
  }

  /** Releases the drain lock (closing its description releases the `flock`). */
  release(): void {
    if (this.#lockHandle > 0) this.#addon.close(this.#lockHandle);
    this.#lockHandle = -1;
    this.holder = false;
  }

  /**
   * Whether another live process holds the drain lock. A probe on a new open file
   * description: it never takes or keeps the lock.
   */
  drainedElsewhere(): boolean {
    if (this.holder) return false;
    const dirHandle = this.#addon.openDir(this.dir);
    if (dirHandle < 0) return false;
    let probe = -1;
    try {
      probe = this.#addon.openFile(dirHandle, DRAIN_LOCK, false);
      if (probe < 0) return false;
      return this.#addon.flock(probe, FLOCK_EXCLUSIVE) === NativeCode.WOULD_BLOCK;
    } finally {
      if (probe > 0) this.#addon.close(probe);
      this.#addon.close(dirHandle);
    }
  }

  /** Pending record files in drain order (stable: by name). */
  names(): string[] {
    return this.#io
      .readdir(this.dir)
      .filter((name) => name.endsWith(".rec") && !name.startsWith("."))
      .sort();
  }

  /**
   * A record file's framed bytes, opened from its envelope when it has one (see
   * {@link unseal}). Never follows a symlink (one is corrupt). Reads are bounded: a file
   * larger than this spool's bound plus the reserve is {@link RecordTooLargeError} (left
   * pending and charged for a drainer configured with a larger bound, never quarantined).
   */
  read(name: string): Buffer {
    const path = this.#path(name);
    const info = this.#io.lstat(path);
    if (info.isSymbolicLink || !info.isFile) throw new CorruptRecordError();
    const limit = this.maxBytes + RESERVE_BYTES;
    if (info.size > limit) throw new RecordTooLargeError();
    let fd: number;
    try {
      fd = this.#io.openRead(path);
    } catch (error) {
      if (errnoOf(error) === "ELOOP") throw new CorruptRecordError();
      throw error;
    }
    try {
      const buffer = Buffer.alloc(Math.min(info.size, limit) + 1);
      let filled = 0;
      while (filled < buffer.length) {
        const got = this.#io.read(fd, buffer.subarray(filled), filled);
        if (got === 0) break;
        filled += got;
      }
      if (filled > limit) throw new RecordTooLargeError();
      return unseal(buffer.subarray(0, filled), name, this.#key, this.keyId);
    } finally {
      closeQuietly(this.#io, fd);
    }
  }

  /**
   * The drainer's stable-order recovery scan: rebuilds the ledger from disk, then reads
   * every pending file in name order. A corrupt file (bad frame, digest, header or body
   * ranges, failed authentication, plaintext under a key, a symlink) is quarantined and
   * reported with the headers that parsed; a file sealed under another key stays pending
   * and charged. Only the drain lock holder may scan.
   */
  recover(): RecoveryScan {
    if (!this.holder)
      throw new Error("only the drain lock holder recovers the spool (call tryLock first)");
    this.rescan();
    const files: RecoveredFile[] = [];
    const quarantined: { name: string; docs: readonly SpoolDoc[] }[] = [];
    const undecryptable: string[] = [];
    const deferred: string[] = [];
    for (const name of this.names()) {
      try {
        files.push({ name, records: unframeAll(this.read(name)) });
      } catch (error) {
        if (error instanceof UndecryptableRecordError) {
          undecryptable.push(name);
        } else if (error instanceof CorruptRecordError) {
          try {
            this.quarantine(name);
            quarantined.push({ name, docs: error.docs });
          } catch {
            deferred.push(name);
          }
        } else if (errnoOf(error) !== "ENOENT") {
          deferred.push(name);
        }
      }
    }
    return { files, quarantined, undecryptable, deferred };
  }

  /**
   * Kept for the operator, never retried; its bytes stay counted against the bound (an
   * operator removes `*.corrupt` files to free the space). An own record is a failure.
   */
  quarantine(name: string): void {
    if (this.mine.delete(name)) this.failed += 1;
    this.#admission(() => this.#io.rename(this.#path(name), this.#path(name + QUARANTINE_SUFFIX)));
    try {
      this.#io.syncDir(this.dir);
    } finally {
      this.#move(name, name + QUARANTINE_SUFFIX);
    }
  }

  /**
   * Retires a delivered record this process wrote: unlink, then fsync the directory. An
   * error leaves the ledger holding what is on disk; a retry is idempotent. Another
   * writer's record is retired through a delivery receipt (`055-t16`).
   */
  retireOwn(name: string): void {
    if (!this.mine.has(name)) {
      throw new Error(
        "retireOwn takes a record this process wrote; another writer's needs a receipt",
      );
    }
    try {
      try {
        this.#io.unlink(this.#path(name));
      } catch (error) {
        if (errnoOf(error) !== "ENOENT") throw error;
      }
      this.#io.syncDir(this.dir);
      this.mine.delete(name);
    } finally {
      this.#observe(name);
    }
  }

  /**
   * Retires delivered records in order, with one directory fsync for all of them (Python
   * `retire_many`): an own record is unlinked; another writer's becomes its delivery
   * receipt in place (renamed to `<name>.ack`, truncated to zero and fsync'd), which its
   * writer consumes ({@link settle}). Returns how many (a prefix of `names`) are retired
   * and the error that stopped the rest (they stay pending and charged; a retry is
   * idempotent). Receipt expiry and the receipt cap are unit 055-t16's.
   */
  retireMany(names: readonly string[]): { retired: number; error: Error | undefined } {
    const done: { name: string; own: boolean; renamed: boolean }[] = [];
    let error: Error | undefined;
    for (const name of names) {
      if (this.mine.delete(name)) this.#ownRetiring.add(name); // a retry must still unlink
      const own = this.#ownRetiring.has(name);
      let renamed = false;
      try {
        if (own) {
          try {
            this.#io.unlink(this.#path(name));
          } catch (failure) {
            if (errnoOf(failure) !== "ENOENT") throw failure;
          }
        } else {
          try {
            this.#io.rename(this.#path(name), this.#path(name + ACK_SUFFIX));
          } catch (failure) {
            if (errnoOf(failure) !== "ENOENT") throw failure; // renamed by an earlier try
          }
          renamed = true;
          this.#io.truncate(this.#path(name + ACK_SUFFIX));
        }
      } catch (failure) {
        error = asError(failure);
        this.#settleRetired(name, own, renamed);
        break;
      }
      done.push({ name, own, renamed });
    }
    let synced = false;
    try {
      if (done.length > 0) this.#io.syncDir(this.dir);
      synced = true;
    } catch (failure) {
      error ??= asError(failure);
    } finally {
      for (const { name, own, renamed } of done) this.#settleRetired(name, own, renamed);
    }
    if (synced) for (const { name } of done) this.#ownRetiring.delete(name);
    return { retired: synced ? done.length : 0, error };
  }

  #settleRetired(name: string, own: boolean, renamed: boolean): void {
    if (own) this.#observe(name);
    else if (renamed) this.#move(name, name + ACK_SUFFIX);
  }

  /**
   * Resolves own records another process drained (Python `settle`): gone with a receipt
   * is delivered (the receipt is consumed), gone without one is `failed` (quarantined
   * or removed by anyone else). Returns how many of `names` (default: all own) are still
   * pending.
   */
  settle(names?: Iterable<string>): number {
    if (this.mine.size > 0) {
      const present = new Set(this.#io.readdir(this.dir));
      for (const name of [...this.mine]) {
        if (present.has(name)) continue;
        let receipt = true;
        try {
          this.#io.unlink(this.#path(name + ACK_SUFFIX));
        } catch {
          receipt = false;
        }
        this.#account(name + ACK_SUFFIX, undefined);
        if (this.mine.delete(name) && !receipt) this.failed += 1;
      }
    }
    if (names === undefined) return this.mine.size;
    let pending = 0;
    for (const name of names) if (this.mine.has(name)) pending += 1;
    return pending;
  }

  /**
   * Records that this process exits leaving `recordsLeft` records with no drainer
   * (Python `write_exit_note`: `{schema, records_left, exited_at, drain_on_exit_s}`,
   * replaced atomically). Counts only: never a path, URL or id.
   */
  writeExitNote(recordsLeft: number, drainOnExitS: number): void {
    const at = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    // Python's json.dumps(sort_keys=True) of these four keys; a float keeps its ".0".
    const drain = Number.isInteger(drainOnExitS) ? `${drainOnExitS}.0` : String(drainOnExitS);
    const text =
      `{"drain_on_exit_s": ${drain}, "exited_at": "${at}", ` +
      `"records_left": ${Math.max(0, Math.trunc(recordsLeft))}, "schema": "${EXIT_NOTE_SCHEMA}"}`;
    const tmp = this.#path(`${TMP_PREFIX}exit-${this.#pid}`);
    try {
      this.#io.writeFile(tmp, Buffer.from(text, "ascii"));
      this.#io.rename(tmp, this.#path(EXIT_NOTE));
    } catch (error) {
      try {
        this.#io.unlink(tmp);
      } catch {
        // gone or never made
      }
      throw error;
    }
  }

  /** Drainer: the spool is empty, so a previous exit's backlog was delivered. */
  clearExitNote(): void {
    try {
      this.#io.unlink(this.#path(EXIT_NOTE));
    } catch (error) {
      if (errnoOf(error) !== "ENOENT") throw error;
    }
  }

  /** Every spool entry on disk at its accounted size, summed (a fresh, uncached scan). */
  diskTotal(): number {
    let total = 0;
    for (const name of this.#io.readdir(this.dir)) {
      try {
        total += accounted(name, this.#io.lstat(this.#path(name)).size) ?? 0;
      } catch {
        // gone meanwhile
      }
    }
    return total;
  }

  /** The documents of the ledger (name -> charge), for tests and status. */
  ledger(): ReadonlyMap<string, number> {
    return new Map(this.#files);
  }
}

const ZERO = new Uint8Array(1);

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error("spool operation failed");
}

function closeQuietly(io: SpoolIo, fd: number): void {
  try {
    io.close(fd);
  } catch {
    // the descriptor is gone either way
  }
}

/** The most vectors one `writev` accepts (Linux and macOS `IOV_MAX`). */
const IOV_MAX = 1024;

/** Writes every piece at its offset in gathered writes, looping over short writes. */
function writeAll(io: SpoolIo, fd: number, pieces: readonly Buffer[]): void {
  let views = pieces.filter((piece) => piece.length > 0);
  let position = 0;
  while (views.length > 0) {
    let wrote = io.writev(fd, views.slice(0, IOV_MAX), position);
    if (wrote <= 0) throw new Error("spool write made no progress");
    position += wrote;
    while (views.length > 0 && wrote >= views[0]!.length) {
      wrote -= views[0]!.length;
      views = views.slice(1);
    }
    if (wrote > 0) views = [views[0]!.subarray(wrote), ...views.slice(1)];
  }
}
