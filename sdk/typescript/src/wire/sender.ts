// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The spool sender (spec 055 §7.1; Python `wire/_sender.py`), on the Fabric worker.
 *
 * Holding the spool's drain lock, it delivers record files in name order: an exchange's
 * or a record's bodies go to the Fabric Node as content logs (several per request, a few
 * requests in flight), and a file's spans are exported to `/v1/traces` only after every
 * body of that file was accepted or permanently rejected. A delivered file is retired
 * (unlinked, or turned into its writer's receipt). Accepted bodies are remembered per
 * file and never sent again; a file whose bodies are not all settled holds back the files
 * after it. Failures retry with capped backoff (0.5 s doubling to 30 s, raised to a
 * bounded `Retry-After`).
 *
 * A body the Node refuses for good (400, 413, 415, 422 or a rejected record) is counted
 * (`content_rejected`), warned about once per epoch by class only, and settled: its span
 * is still exported, unchanged, and the reader reports the object
 * `not_captured(store_failed)`. A file whose trace export is refused for good on its own
 * is quarantined (kept for the operator) and its positions become `internal_error`
 * losses: neither is retried forever, neither blocks the spool.
 *
 * The sender also exports the periodic heartbeats the pipeline queued and declares
 * orphaned epoch registrations with a periodic heartbeat (050 §3.2 rule 5). Nothing here
 * runs on an application thread; nothing here throws into its caller's loop.
 */
import { createHash, randomUUID } from "node:crypto";

import { SDK_VERSION } from "../version.js";
import { BACKOFF_CAP_MS, Backoff, type PostResult } from "./delivery.js";
import { type Heartbeat, heartbeatFields, markerSpan } from "./manifest.js";
import type { ContentResult } from "./node-content.js";
import { type ContentItem, FABRIC_SDK_NAME_NODE, type OtlpSpan, spanOfRecord } from "./otlp.js";
import type { Orphan } from "./registration.js";
import {
  CorruptRecordError,
  type SpoolDoc,
  UndecryptableRecordError,
  unframeAll,
  validHeader,
} from "./spool-codec.js";
import { RecordTooLargeError, type Spool } from "./spool.js";

/** Record files read per drain pass (Python `_BATCH`). */
export const DRAIN_FILES = 64;
/** A pass exports at most about this many spans (Python `_EXPORT_SPANS`). */
export const EXPORT_SPANS = 512;
/** Body bytes per content request, unless one body alone is larger (Python `_REQUEST_BYTES`). */
export const REQUEST_BYTES = 4 * 1024 * 1024;
/** Pending body bytes a pass reads before sending them (Python `_DRAIN_BYTES`). */
export const DRAIN_BYTES = 32 * 1024 * 1024;
/** How often the directory is rescanned and the drain lock retried (Python 5 s). */
export const RESCAN_MS = 5000;
export const LOCK_RETRY_MS = 5000;
/** Orphan heartbeats awaiting export (Python `_MAX_ORPHAN_BEATS`). */
export const MAX_ORPHAN_BEATS = 4096;
const IDLE_WAIT_MS = 1000;
const SETTLE_POLL_MS = 20;

/** The trace path: one `ExportTraceServiceRequest` per call (`delivery.ts` `TraceClient`). */
export interface TraceExporter {
  export(spans: readonly OtlpSpan[]): Promise<PostResult>;
}

/** The content path (`node-content.ts` `NodeContentClient`). */
export interface ContentSender {
  send(item: ContentItem): Promise<ContentResult>;
  sendMany?(items: readonly ContentItem[]): Promise<ContentResult[]>;
  readonly lastResult?: PostResult | undefined;
}

/** Periodic heartbeats the pipeline queued (`manifest.ts` `Heartbeats`). */
export interface BeatSource {
  readonly pending: readonly Heartbeat[];
  delivered(count: number): void;
}

export interface SenderOptions {
  readonly spool: Spool;
  readonly traces: TraceExporter;
  /** `undefined`: no Node is configured, so every body is settled as rejected (Python). */
  readonly content: ContentSender | undefined;
  /** The capture `service.name` of loss, marker and heartbeat spans. */
  readonly serviceName: string;
  readonly version?: string;
  /** `FABRIC_WIRE_CONTENT_BATCH_BODIES` and `FABRIC_WIRE_CONTENT_CONCURRENCY`. */
  readonly batchBodies?: number;
  readonly concurrency?: number;
  readonly beats?: BeatSource;
  /** The drainer's orphan scan (`registration.ts` `scanOrphans`). */
  readonly orphans?: () => readonly Orphan[];
  /** A quarantined file's headers that parsed: their positions are explained losses. */
  readonly quarantined?: (docs: readonly SpoolDoc[]) => void;
  /** Capture events of this process that will never be delivered (Python `_failures`). */
  readonly failures?: () => number;
  /** Class-only warnings (fixed text, never a value). */
  readonly warn?: (text: string) => void;
  /** Tests: the backoff's sleep. */
  readonly sleep?: (ms: number, wake: Promise<void>) => Promise<void>;
}

export type DrainState = "more" | "idle" | "retry";

/** Content-free counters (Python `_STATS`, plus the trace-side rejections). */
export interface SenderStats {
  delivered: number;
  send_retries: number;
  content_rejected: number;
  traces_rejected: number;
  quarantined: number;
  spool_undecryptable: number;
  spool_oversized: number;
  orphan_heartbeats: number;
  markers_dropped: number;
  beats_exported: number;
  /** Plaintext records sealed by the explicit local-profile migration. */
  spool_migrated: number;
  /** Loss and marker records exported from dead writers' ledger slots. */
  ledger_recovered: number;
}

/** The spool's durability and loss-ledger counters (Python `Sender.stats`). */
export interface SpoolHealth {
  /** 1 while the directory barrier is not established (records not durable). */
  readonly spool_undurable: number;
  readonly spool_barrier_failures: number;
  readonly ledger_slots: number;
  readonly ledger_overflows: number;
  readonly ledger_failures: number;
  readonly ledger_corrupt: number;
  readonly manifests_unledgered: number;
}

interface BodyJob {
  readonly name: string;
  readonly index: number;
  readonly item: ContentItem;
}

interface ReadyFile {
  readonly name: string;
  readonly docs: readonly SpoolDoc[];
}

const now = (): number => performance.now();

function defaultSleep(ms: number, wake: Promise<void>): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return Promise.race([
    wake,
    new Promise<void>((resolve) => {
      timer = setTimeout(resolve, ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

const errnoOf = (error: unknown): unknown => (error as { code?: unknown } | null)?.code;

/** A root span (loss, heartbeat) whose ids derive from `seed` (Python `Sender._root`). */
export function rootSpan(
  name: string,
  attributes: Readonly<Record<string, unknown>>,
  at: bigint,
  seed: string,
  serviceName: string,
  version: string,
): OtlpSpan {
  const digest = createHash("sha256").update(seed, "utf8").digest();
  const id = (bytes: Buffer): string =>
    bytes.every((b) => b === 0) ? `${"0".repeat(bytes.length * 2 - 1)}1` : bytes.toString("hex");
  return {
    name,
    traceId: id(digest.subarray(0, 16)),
    spanId: id(digest.subarray(16, 24)),
    kind: "internal",
    startNs: at,
    endNs: at,
    attributes,
    status: "unset",
    serviceName,
    scope: { name: FABRIC_SDK_NAME_NODE, version },
  };
}

const ANCHOR_NS = BigInt(Date.now()) * 1_000_000n - process.hrtime.bigint();
const wallNs = (): bigint => ANCHOR_NS + process.hrtime.bigint();

export class Sender {
  readonly spool: Spool;
  readonly #o: SenderOptions;
  readonly #version: string;
  readonly #batchBodies: number;
  readonly #concurrency: number;
  readonly #stats: SenderStats = {
    delivered: 0,
    send_retries: 0,
    content_rejected: 0,
    traces_rejected: 0,
    quarantined: 0,
    spool_undecryptable: 0,
    spool_oversized: 0,
    orphan_heartbeats: 0,
    markers_dropped: 0,
    beats_exported: 0,
    spool_migrated: 0,
    ledger_recovered: 0,
  };
  /** Body indexes (per record file) the Node accepted or rejected for good. */
  readonly #progress = new Map<string, Set<number>>();
  /** Delivered files whose retirement failed: never exported again, retried first. */
  readonly #retiring = new Set<string>();
  /** Files sealed under another key or larger than this bound: left for another drainer. */
  readonly #skipped = new Set<string>();
  /** Orphan heartbeats, kept (with their event ids) until exported. */
  readonly #orphanBeats: Heartbeat[] = [];
  /** Epochs whose content rejection was already warned about. */
  readonly #warnedEpochs = new Set<string>();
  readonly #backoff = new Backoff();
  #noteCleared = false;
  #retryAfterMs: number | undefined;
  #failedAtStart: number;
  #failedAtFlush: number;
  #loop: Promise<void> | undefined;
  /** The loop returned (it released the drain lock as it stopped). */
  #ended = false;
  #stopped = false;
  #wake: () => void = () => undefined;
  #woken: Promise<void>;
  /** Resolved by {@link close}: the retry backoff waits on it, never on a wake-up. */
  #stopSignal: () => void = () => undefined;
  readonly #stopping: Promise<void>;
  /** Drain passes that found nothing to deliver while holding the lock. */
  idlePasses = 0;

  constructor(options: SenderOptions) {
    this.#o = options;
    this.spool = options.spool;
    this.#version = options.version ?? SDK_VERSION;
    this.#batchBodies = Math.max(1, options.batchBodies ?? 32);
    this.#concurrency = Math.max(1, options.concurrency ?? 4);
    this.#woken = this.#nextWake();
    this.#stopping = new Promise<void>((resolve) => {
      this.#stopSignal = resolve;
    });
    this.#failedAtStart = this.#failedAtFlush = this.#failures();
  }

  #nextWake(): Promise<void> {
    return new Promise<void>((resolve) => {
      this.#wake = resolve;
    });
  }

  #failures(): number {
    try {
      return (this.#o.failures?.() ?? this.spool.failed) + this.#stats.markers_dropped;
    } catch {
      return Number.MAX_SAFE_INTEGER;
    }
  }

  #warn(text: string): void {
    try {
      this.#o.warn?.(text);
    } catch {
      // a warning sink's failure is never the sender's
    }
  }

  stats(): Readonly<SenderStats> &
    SpoolHealth & { readonly retiring: number; readonly backlog: number } {
    let backlog: number;
    try {
      backlog = this.backlog().deliverable;
    } catch {
      backlog = -1;
    }
    return { ...this.#stats, ...this.health(), retiring: this.#retiring.size, backlog };
  }

  /** The spool's durability and ledger counters (content-free). */
  health(): SpoolHealth {
    const ledger = this.spool.ledger?.stats();
    return {
      spool_undurable: this.spool.durable ? 0 : 1,
      spool_barrier_failures: this.spool.barrierFailures,
      ledger_slots: ledger?.slots ?? 0,
      ledger_overflows: ledger?.overflows ?? 0,
      ledger_failures: ledger?.failures ?? 0,
      ledger_corrupt: ledger?.corrupt ?? 0,
      manifests_unledgered: ledger?.manifestsUnledgered ?? 0,
    };
  }

  /**
   * Establishes the spool's directory barrier (Python `ensure_durable`); a failure is
   * warned about once until it succeeds, by class only. Delivery goes on either way, with
   * `spool_undurable` reported; no flush or close succeeds until it holds.
   */
  ensureDurable(): boolean {
    if (this.spool.durable) return true;
    const failures = this.spool.barrierFailures;
    if (this.spool.establishBarrier()) {
      if (failures > 0) this.#warn("fabric.wire: spool directory barrier established");
      return true;
    }
    if (failures === 0) {
      this.#warn(
        "fabric.wire: spool directory barrier not established; spooled records are not durable " +
          "against power loss (retrying). Fix: put FABRIC_WIRE_SPOOL_DIR on a local volume whose " +
          "directories the agent's user can open, or set FABRIC_WIRE_SPOOL_DURABLE_BOUNDARY to the " +
          "highest ancestor it may fsync",
      );
    }
    return false;
  }

  /**
   * Drainer: exports the ledger slots of processes that died with unspooled loss or marker
   * records (D1), directly (a full disk needs no room for this), then clears them; a
   * failed export leaves the slot for the next attempt. Returns the spans exported.
   */
  async recoverOrphans(): Promise<number> {
    const ledger = this.spool.ledger;
    if (ledger === undefined || !this.spool.holder) return 0;
    let recovered = 0;
    for (const { index, records } of ledger.orphans()) {
      let delivered: boolean;
      let spans: OtlpSpan[] = [];
      try {
        spans = records
          .filter(
            (doc) =>
              (doc.record_kind === "loss" || doc.record_kind === "marker") && validHeader(doc, 0),
          )
          .map((doc) => this.#span(doc as SpoolDoc));
        delivered = spans.length === 0 || (await this.#o.traces.export(spans)).outcome === "ok";
      } catch {
        delivered = false;
      }
      if (delivered && ledger.clear(index)) {
        this.#stats.ledger_recovered += spans.length;
        recovered += spans.length;
      } else if (!delivered) {
        ledger.releaseSlot(index);
      }
    }
    return recovered;
  }

  /** Starts the delivery loop (idempotent). */
  start(): void {
    if (this.#loop !== undefined || this.#stopped) return;
    this.#loop = this.#run();
  }

  /**
   * Whether the delivery loop is still running (after {@link close}: a pass past the
   * deadline). It holds the drain lock until it stops; the spool must stay open.
   */
  get running(): boolean {
    return this.#loop !== undefined && !this.#ended;
  }

  /** Resolves `true` once the loop has stopped (or never started), `false` after `ms`. */
  async stopped(ms: number): Promise<boolean> {
    const loop = this.#loop;
    if (loop === undefined || this.#ended) return true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    await Promise.race([
      loop,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, Math.max(0, ms));
      }),
    ]);
    clearTimeout(timer);
    return this.#ended;
  }

  wake(): void {
    const wake = this.#wake;
    this.#woken = this.#nextWake();
    wake();
  }

  async #run(): Promise<void> {
    let scanned = -RESCAN_MS;
    let locked = -LOCK_RETRY_MS;
    let barrier = -RESCAN_MS;
    const sleep = this.#o.sleep ?? defaultSleep;
    while (!this.#stopped) {
      let state: DrainState;
      try {
        if (!this.spool.durable && now() - barrier >= RESCAN_MS) {
          barrier = now();
          this.ensureDurable();
        }
        if (now() - scanned >= RESCAN_MS) {
          scanned = now();
          this.spool.rescan();
          this.spool.settle(); // own records drained elsewhere: consume their receipts
          if (this.spool.holder) {
            await this.recoverOrphans();
            this.scanEpochs();
          }
        }
        await this.exportBeats();
        if (!this.spool.holder && now() - locked >= LOCK_RETRY_MS) {
          locked = now();
          if (this.spool.tryLock()) {
            // a new drainer: dead processes' ledger slots first
            await this.recoverOrphans();
            this.scanEpochs();
          }
        }
        state = this.spool.holder ? await this.drain() : "idle";
        if (state === "idle" && this.spool.holder) this.idlePasses += 1;
      } catch (error) {
        // never let the loop die; never log a message or a path
        this.#warn(`fabric.wire: spool sender error (${className(error)})`);
        state = "retry";
      }
      if (this.#stopped) break;
      if (state === "retry") {
        this.#stats.send_retries += 1;
        const delay = this.#backoff.next(this.#retryAfterMs);
        this.#retryAfterMs = undefined;
        // As Python's sender: a backoff ends early only on stop. A wake-up (a new record,
        // a flush) must not turn a Node that is down into a retry storm.
        await sleep(delay, this.#stopping);
      } else if (state === "idle") {
        this.#backoff.reset();
        await sleep(IDLE_WAIT_MS, this.#woken);
      } else {
        // let the capture loop of this worker run between passes
        await new Promise<void>((resolve) => setImmediate(resolve));
      }
    }
    // Stopped: another process (or a later install) may drain. Released here, by the loop,
    // never while one of its passes is still exporting or retiring (Python's `_run`).
    try {
      this.spool.release();
    } catch {
      // the lock goes with the process
    } finally {
      this.#ended = true;
    }
  }

  /**
   * One drain pass over up to {@link DRAIN_FILES} ready files: `more`, `idle` or `retry`.
   * Only the drain lock holder calls it.
   */
  async drain(): Promise<DrainState> {
    if (!this.#retireDelivered()) return "retry";
    if (this.spool.migrate) {
      // 049 §7.8: the explicit local migration, before any read (an error: retried)
      this.#stats.spool_migrated += this.spool.migratePlaintext();
      this.spool.migrate = false;
    }
    const skip = this.#skipped;
    const names = this.spool
      .names()
      .filter((name) => !skip.has(name))
      .slice(0, DRAIN_FILES);
    if (names.length === 0 && skip.size === 0 && !this.#noteCleared) {
      try {
        this.spool.clearExitNote(); // empty: a previous exit's backlog was delivered
      } catch {
        // retried on the next empty pass
      }
    }
    this.#noteCleared = names.length === 0 && skip.size === 0;
    const { files, jobs } = this.#readReady(names);
    const failed = await this.#sendJobs(jobs);
    const batch: { name: string; spans: OtlpSpan[] }[] = [];
    let state: DrainState = "idle";
    for (const file of files) {
      if (failed.has(file.name)) {
        state = "retry";
        break;
      }
      let spans: OtlpSpan[];
      try {
        spans = file.docs.map((doc) => this.#span(doc));
      } catch {
        // a header the reader accepted but no span can be built from: kept for the operator
        this.#quarantine(file.name, file.docs);
        continue;
      }
      batch.push({ name: file.name, spans });
    }
    if (batch.length > 0) {
      const exported = await this.#export(batch);
      if (!exported) return "retry";
      if (!this.#retireDelivered()) return "retry";
    }
    return state === "retry" || names.length === 0 ? state : "more";
  }

  /**
   * Exports the spans of `batch` in one request. A request refused for good (an encode
   * failure, 400/413/415/422) is sent again one file at a time, and a file refused alone
   * is quarantined: one malformed record never blocks the spool. `false`: retry later.
   */
  async #export(batch: readonly { name: string; spans: OtlpSpan[] }[]): Promise<boolean> {
    const result = await this.#o.traces.export(batch.flatMap((file) => file.spans));
    if (result.outcome === "retry") {
      this.#retryAfterMs = result.retryAfterMs;
      return false;
    }
    if (result.outcome === "ok") {
      for (const file of batch) this.#delivered(file.name, file.spans.length);
      return true;
    }
    for (const file of batch) {
      const alone = batch.length === 1 ? result : await this.#o.traces.export(file.spans);
      if (alone.outcome === "retry") {
        this.#retryAfterMs = alone.retryAfterMs;
        return false;
      }
      if (alone.outcome === "ok") {
        this.#delivered(file.name, file.spans.length);
        continue;
      }
      this.#stats.traces_rejected += 1;
      this.#warn(
        "fabric.wire: the trace endpoint refused a spool record for good; it was quarantined",
      );
      let docs: SpoolDoc[];
      try {
        docs = unframeAll(this.spool.read(file.name)).map(({ doc }) => doc);
      } catch {
        docs = [];
      }
      this.#quarantine(file.name, docs);
    }
    return true;
  }

  #delivered(name: string, spans: number): void {
    this.#retiring.add(name);
    this.#progress.delete(name);
    this.#stats.delivered += spans;
  }

  /** The span a record stands for, identical on every replay (`otlp.ts` `spanOfRecord`). */
  #span(doc: SpoolDoc): OtlpSpan {
    return spanOfRecord(doc, { serviceName: this.#o.serviceName, version: this.#version });
  }

  /**
   * Reads ready files in order, up to about {@link EXPORT_SPANS} records and
   * {@link DRAIN_BYTES} of bodies not yet settled (always at least one file). A corrupt
   * file is quarantined; one sealed under another key, or larger than this spool's
   * bound, is left for a drainer that can read it. Another read error stops the pass.
   */
  #readReady(names: readonly string[]): { files: ReadyFile[]; jobs: BodyJob[] } {
    const files: ReadyFile[] = [];
    const jobs: BodyJob[] = [];
    let spans = 0;
    let pending = 0;
    for (const name of names) {
      if (spans >= EXPORT_SPANS || pending >= DRAIN_BYTES) break;
      let records: { doc: SpoolDoc; blob: Buffer }[];
      try {
        records = unframeAll(this.spool.read(name));
      } catch (error) {
        if (errnoOf(error) === "ENOENT") continue;
        if (error instanceof UndecryptableRecordError || error instanceof RecordTooLargeError) {
          this.#skipped.add(name);
          if (error instanceof UndecryptableRecordError) {
            this.#stats.spool_undecryptable += 1;
            this.#warn(
              "fabric.wire: a spool record sealed under another key was left for its key holder",
            );
          } else {
            this.#stats.spool_oversized += 1;
            this.#warn(
              "fabric.wire: a spool record larger than this process's spool bound was left for " +
                "a drainer with a larger one; set FABRIC_WIRE_SPOOL_MAX_BYTES as the writer did",
            );
          }
          continue;
        }
        if (error instanceof CorruptRecordError) {
          this.#quarantine(name, error.docs);
          continue;
        }
        throw error;
      }
      const done = this.#progress.get(name);
      let index = 0;
      for (const { doc, blob } of records) {
        if (doc.record_kind !== "exchange" && doc.record_kind !== "record") continue;
        for (const body of (doc.bodies ?? []) as readonly Record<string, unknown>[]) {
          if (done?.has(index) !== true) {
            const offset = Number(body.offset);
            const data = blob.subarray(offset, offset + Number(body.length));
            jobs.push({
              name,
              index,
              item: { descriptor: body.descriptor as Record<string, unknown>, body: data },
            });
            pending += data.byteLength;
          }
          index += 1;
        }
      }
      files.push({ name, docs: records.map(({ doc }) => doc) });
      spans += records.length;
    }
    return { files, jobs };
  }

  /** Groups jobs, in order, into requests of `batchBodies` bodies and {@link REQUEST_BYTES}. */
  #requests(jobs: readonly BodyJob[]): BodyJob[][] {
    const groups: BodyJob[][] = [];
    let size = 0;
    for (const job of jobs) {
      const length = job.item.body.byteLength;
      const last = groups.at(-1);
      if (last === undefined || last.length >= this.#batchBodies || size + length > REQUEST_BYTES) {
        groups.push([job]);
        size = length;
      } else {
        last.push(job);
        size += length;
      }
    }
    return groups;
  }

  async #sendGroup(group: readonly BodyJob[]): Promise<ContentResult[]> {
    const content = this.#o.content;
    if (content === undefined) return group.map(() => "rejected");
    const items = group.map((job) => job.item);
    if (content.sendMany !== undefined && items.length > 1) return content.sendMany(items);
    const results: ContentResult[] = [];
    for (const item of items) {
      results.push(await content.send(item));
      if (results.at(-1) === "retry") {
        // the Node is not taking bodies now: stop here
        while (results.length < items.length) results.push("retry");
        break;
      }
    }
    return results;
  }

  /**
   * Sends the bodies with up to `concurrency` requests in flight and records each
   * settled body in the progress map. Returns the files with a body still to retry;
   * once a request must be retried no new one starts.
   */
  async #sendJobs(jobs: readonly BodyJob[]): Promise<Set<string>> {
    const queue = this.#requests(jobs);
    const failed = new Set<string>();
    if (queue.length === 0) return failed;
    let stop = false;
    const work = async (): Promise<void> => {
      while (!stop && queue.length > 0) {
        const group = queue.shift()!;
        let results: ContentResult[];
        try {
          results = await this.#sendGroup(group);
        } catch {
          results = group.map(() => "retry");
        }
        group.forEach((job, i) => {
          const result = results[i] ?? "retry";
          if (result === "retry") {
            failed.add(job.name);
            stop = true;
            const hint = this.#o.content?.lastResult?.retryAfterMs;
            if (hint !== undefined) this.#retryAfterMs = Math.min(BACKOFF_CAP_MS, hint);
            return;
          }
          if (result === "rejected") this.#rejected(job.item);
          let done = this.#progress.get(job.name);
          if (done === undefined) this.#progress.set(job.name, (done = new Set()));
          done.add(job.index);
        });
      }
    };
    await Promise.all(Array.from({ length: Math.min(this.#concurrency, queue.length) }, work));
    for (const group of queue) for (const job of group) failed.add(job.name); // never sent
    return failed;
  }

  /** A body refused for good: counted, warned about once per epoch (class only). */
  #rejected(item: ContentItem): void {
    this.#stats.content_rejected += 1;
    const d = item.descriptor;
    const epoch = `${String(d.source_id)}:${String(d.source_epoch)}`;
    if (this.#warnedEpochs.has(epoch)) return;
    if (this.#warnedEpochs.size < 4096) this.#warnedEpochs.add(epoch);
    this.#warn(
      "fabric.wire: the Fabric Node refused a content record for good; it is not retried and " +
        "the reader reports it not_captured(store_failed). Check the Node's content limits and " +
        "tenant allowlist",
    );
  }

  /**
   * Retires delivered files in order; `false` while one cannot be (it then stays on disk
   * and in the retiring set, so it is never exported again).
   */
  #retireDelivered(): boolean {
    if (this.#retiring.size === 0) return true;
    const names = [...this.#retiring];
    const { retired, error } = this.spool.retireMany(names);
    for (const name of names.slice(0, retired)) this.#retiring.delete(name);
    if (error !== undefined) {
      this.#warn(`fabric.wire: a delivered record was not retired (${className(error)})`);
      return false;
    }
    return true;
  }

  #quarantine(name: string, docs: readonly SpoolDoc[]): void {
    try {
      this.spool.quarantine(name);
    } catch {
      this.#skipped.add(name); // left in place; never read again by this drainer
    }
    this.#progress.delete(name);
    this.#stats.quarantined += 1;
    this.#warn("fabric.wire: a corrupt spool record was quarantined");
    try {
      this.#o.quarantined?.(docs);
    } catch {
      // the positions stay unexplained gaps
    }
  }

  /**
   * Exports the periodic heartbeats the pipeline queued and the orphan heartbeats, in
   * one request; each keeps its event id until delivered. `false` when one was not.
   */
  async exportBeats(): Promise<boolean> {
    const periodic = [...(this.#o.beats?.pending ?? [])];
    const orphans = [...this.#orphanBeats];
    if (periodic.length === 0 && orphans.length === 0) return true;
    const at = wallNs();
    let spans: OtlpSpan[];
    try {
      spans = [...periodic, ...orphans].map((beat) => {
        const [name, attributes] = markerSpan(beat.sourceId, beat.epoch, heartbeatFields(beat));
        return rootSpan(
          name,
          attributes,
          at,
          `marker:${beat.eventId}`,
          this.#o.serviceName,
          this.#version,
        );
      });
    } catch {
      return false;
    }
    const result = await this.#o.traces.export(spans);
    if (result.outcome !== "ok") return false;
    this.#o.beats?.delivered(periodic.length);
    this.#orphanBeats.splice(0, orphans.length);
    this.#stats.beats_exported += spans.length;
    return true;
  }

  /**
   * Drainer (050 §3.2 rule 5): declares each orphaned epoch registration (its writer gone
   * without `final`) with a periodic heartbeat at its last allocated position. Returns
   * how many were queued.
   */
  scanEpochs(): number {
    if (!this.spool.holder || this.#o.orphans === undefined) return 0;
    let orphans: readonly Orphan[];
    try {
      orphans = this.#o.orphans();
    } catch {
      return 0;
    }
    let queued = 0;
    for (const orphan of orphans) {
      if (orphan.nextSequence <= 0n) continue;
      if (this.#orphanBeats.length >= MAX_ORPHAN_BEATS) {
        this.#stats.markers_dropped += 1;
        continue;
      }
      this.#orphanBeats.push({
        kind: "periodic",
        sourceId: orphan.sourceId,
        epoch: orphan.epoch,
        lastSequence: orphan.nextSequence - 1n,
        manifestSeq: undefined,
        eventId: randomUUID(),
      });
      this.#stats.orphan_heartbeats += 1;
      queued += 1;
    }
    if (queued > 0) this.wake();
    return queued;
  }

  /**
   * `(deliverable, undecryptable)`: records this sender can still deliver (on disk, or
   * delivered and not yet retired, and heartbeats not yet exported) and records left for
   * another key holder or a drainer with a larger bound.
   */
  backlog(): { deliverable: number; skipped: number } {
    const names = this.spool.names();
    const skipped = names.filter((name) => this.#skipped.has(name)).length;
    const beats = (this.#o.beats?.pending.length ?? 0) + this.#orphanBeats.length;
    return { deliverable: names.length - skipped + beats, skipped };
  }

  /**
   * At exit, after {@link close}: the records left in the spool (any writer's) that no
   * live process drains; 0 while another process holds the drain lock.
   */
  exitBacklog(): number {
    if (this.spool.drainedElsewhere()) return 0;
    return this.spool.names().length;
  }

  /**
   * Waits until this process's records pending now are settled (delivered, or failed)
   * and, with `everything` in the draining process, until every record pending now
   * (other writers' too) is delivered; `false` at the deadline (ms on `performance.now`).
   */
  async #settle(deadline: number, everything: boolean): Promise<boolean> {
    this.spool.settle();
    const own = new Set(this.spool.mine);
    const others =
      everything && this.spool.holder
        ? new Set(this.spool.names().filter((name) => !own.has(name) && !this.#skipped.has(name)))
        : new Set<string>();
    for (;;) {
      this.wake();
      let open = this.spool.settle(own) > 0;
      if (!open && others.size > 0) {
        const present = new Set(this.spool.names());
        open = [...others].some((name) => present.has(name) && !this.#skipped.has(name));
      }
      if (!open && this.#retiring.size === 0) return true;
      if (now() >= deadline) return false;
      await new Promise((resolve) => setTimeout(resolve, SETTLE_POLL_MS));
    }
  }

  /**
   * Settles this process's records pending now, then exports the queued heartbeats,
   * before `deadline`. `false` also when, since the previous flush, a capture event of
   * this process was lost (the record is incomplete even once all is delivered).
   */
  async flush(deadline: number): Promise<boolean> {
    let delivered: boolean;
    try {
      const durable = this.ensureDurable();
      delivered =
        (await this.#settle(deadline, false)) && (await this.#beatsUntil(deadline)) && durable;
    } catch {
      delivered = false;
    }
    const previous = this.#failedAtFlush;
    this.#failedAtFlush = this.#failures();
    return delivered && this.#failedAtFlush === previous;
  }

  async #beatsUntil(deadline: number): Promise<boolean> {
    for (;;) {
      if (await this.exportBeats()) return true;
      if (now() + SETTLE_POLL_MS >= deadline) return false;
      await new Promise((resolve) => setTimeout(resolve, SETTLE_POLL_MS));
    }
  }

  /**
   * Settles every record pending now (the drainer delivers other writers' too), then
   * stops the loop, which releases the drain lock once its last pass ends (see
   * {@link running}); undelivered records stay on disk. A
   * process that is `exiting` and does not drain the spool only leaves its records
   * durable there, for the drainer. `false` too when any capture event of this process
   * was lost since the sender started.
   */
  async close(deadline: number, options: { exiting?: boolean } = {}): Promise<boolean> {
    let settled: boolean;
    try {
      const durable = this.ensureDurable();
      settled =
        (options.exiting === true && !this.spool.holder
          ? true
          : await this.#settle(deadline, true)) && durable;
    } catch {
      settled = false;
    }
    const delivered = settled && this.#failures() === this.#failedAtStart;
    this.#stopped = true;
    this.#stopSignal();
    this.wake();
    const loop = this.#loop;
    if (loop !== undefined) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      await Promise.race([
        loop,
        new Promise<void>((resolve) => {
          timer = setTimeout(resolve, Math.max(0, deadline - now()));
        }),
      ]);
      clearTimeout(timer);
    }
    if (loop === undefined) {
      try {
        this.spool.release();
      } catch {
        // the lock goes with the process
      }
    }
    // Else the loop releases the lock when its last pass ends: a pass still exporting at
    // the deadline keeps it, so no other drainer exports or retires the same files.
    return delivered;
  }
}

function className(error: unknown): string {
  return error instanceof Error && /^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(error.name)
    ? error.name
    : "Error";
}
