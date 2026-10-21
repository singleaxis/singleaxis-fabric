// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Opt-in, caller-reported content-v2 exact-byte capture. This is a bounded
 * process-memory handoff, not an automatic tool interceptor, durable spool,
 * OTLP delivery receipt, or run-completeness verdict.
 */

import { randomUUID } from "node:crypto";
import { sha256BytesPrefixed as digest } from "./hash.js";

import type { GovernedStore } from "./content-store.js";
import {
  EmittedId,
  checkIdentityMode,
  identityModeFromEnv,
  issuedBy,
  keyId,
  labelPseudonym,
  mintEmittedId,
  type IdentityMode,
} from "./identity.js";
import {
  ContentProtector,
  DeploymentPolicy,
  type PrivacyMode,
  type ProtectionStatus,
} from "./deployment-policy.js";

export const BYTE_EVIDENCE_ROLES = new Set([
  "model.request.instructions",
  "model.request.messages",
  "model.request.tool_definitions",
  "model.request.parameters",
  "model.output.messages",
  "tool.definition",
  "tool.call.arguments",
  "tool.call.result",
  "retrieval.query",
  "retrieval.results",
  "memory.write.content",
  "memory.read.content",
  "side_effect.request",
  "side_effect.result",
  "context.file",
  "interaction.payload",
  "terminal.argv",
  "terminal.stdin",
  "terminal.stdout",
  "terminal.stderr",
  "remote.request",
  "remote.result",
  "remote.stream",
  "database.query",
  "database.parameters",
  "database.rows",
  "database.mutation",
  "network.request",
  "network.response",
  "network.stream",
  "sandbox.config",
  "sandbox.output",
  "artifact.before",
  "artifact.after",
  "service.receipt",
]);

export const BYTE_EVIDENCE_BOUNDARIES = new Set([
  "caller",
  "provider_bound",
  "tool",
  "terminal",
  "sandbox",
  "remote",
  "host",
  "service",
]);

const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MEDIA_TYPE = /^[a-zA-Z0-9!#$&^_.+-]+\/[a-zA-Z0-9!#$&^_.+-]+$/;
const HARD_MAX_BYTES = 64 * 1024 * 1024;
const HARD_MAX_ITEMS = 1 << 20;
const MIN_ID_KEY_BYTES = 16;
export const ID_KEY_ENV = "FABRIC_WIRE_ID_KEY";

function checkIdKey(key: Uint8Array | undefined): Uint8Array | undefined {
  if (key !== undefined && (!(key instanceof Uint8Array) || key.byteLength < MIN_ID_KEY_BYTES))
    throw new Error(`${ID_KEY_ENV} must be at least ${MIN_ID_KEY_BYTES} bytes`);
  return key;
}

/** The id key named by `FABRIC_WIRE_ID_KEY` (unset or empty: undefined); a secret. */
export function idKeyFromEnv(
  env: Record<string, string | undefined> = typeof process !== "undefined" ? process.env : {},
): Uint8Array | undefined {
  const value = env[ID_KEY_ENV] ?? "";
  return value === "" ? undefined : checkIdKey(Buffer.from(value, "utf8"));
}

function productionMarked(policy: unknown): boolean {
  return policy instanceof DeploymentPolicy && policy.deployment.profile === "production";
}

/**
 * Spec 049 §7.3 on the explicit (records) input, as on the wire (§7.7 "both inputs"),
 * in parity with Python `fabric.byte_evidence.content_gate`. The production profile
 * (the deployment policy, or a store's own policy, is marked production) needs the
 * capture policy and the id key; a missing one disables content capture with that
 * reason (metadata continues). The local profile needs nothing.
 */
export function contentGate(
  deploymentPolicy: DeploymentPolicy | undefined,
  idKey: Uint8Array | undefined,
  ...stores: (GovernedStore | undefined)[]
): { profile: "local" | "production"; reason: string | null } {
  const marked =
    productionMarked(deploymentPolicy) ||
    stores.some((store) => productionMarked((store as { policy?: unknown } | undefined)?.policy));
  if (!marked) return { profile: "local", reason: null };
  if (deploymentPolicy === undefined)
    return { profile: "production", reason: "missing_capture_policy" };
  if (idKey === undefined) return { profile: "production", reason: "missing_id_key" };
  return { profile: "production", reason: null };
}

let processSource: string | undefined;
const MAX_GENERATED_IDS = 65536;

/** A caller id, or an id a Fabric recorder emitted (passed through by its issuer). */
export type CallerId = string | EmittedId;

/**
 * Emitted ids when no value derived from a caller-supplied id may leave the process
 * (spec 049 §2.9 rule 5: the production profile without the id key), in parity with
 * Python `fabric._sequence.GeneratedIds`. The source id is random per process (`s-` + 32
 * hex), a run id its generated source fallback (`source:<source>:<epoch>`), and any
 * other caller id a random `g-` id generated on first sight (a bounded cache, so one
 * recorder's records still join; past it a new id is minted). An {@link EmittedId} this
 * instance issued passes through unchanged: provenance is the value's type, never a
 * cache lookup (Sol P0-A round 6 #1).
 */
class GeneratedIds {
  readonly #issuer = "gen-" + randomUUID();
  readonly #ids = new Map<string, string>();

  source(value: CallerId): EmittedId {
    if (issuedBy(value, this.#issuer)) return value;
    processSource ??= "s-" + randomUUID().replaceAll("-", "");
    return mintEmittedId(processSource, this.#issuer);
  }

  run(value: CallerId, epoch: number): EmittedId {
    if (issuedBy(value, this.#issuer)) return value;
    return mintEmittedId(`source:${String(this.source(""))}:${epoch}`, this.#issuer);
  }

  other(value: CallerId): EmittedId {
    if (issuedBy(value, this.#issuer)) return value;
    const text = String(value);
    let found = this.#ids.get(text);
    if (found === undefined) {
      found = "g-" + randomUUID().replaceAll("-", "");
      if (this.#ids.size < MAX_GENERATED_IDS) this.#ids.set(text, found);
    }
    return mintEmittedId(found, this.#issuer);
  }
}

/**
 * Emitted ids in the `pseudonymous` identity mode with the id key (spec 049 §2.9 rules
 * 1-3), in parity with Python `fabric._sequence.KeyedIds` and as the wire line emits
 * them: the run id `r-` and the source id `s-` (function v1, keyed); any other caller id
 * (operation, attempt, stream: step labels, 049 §2.3) the keyed v1 operator label `lbl-`.
 * Deterministic, so records join across recorders and processes holding the key.
 * Provenance, never shape, decides what passes through (Sol P0-A rounds 4-6): only an
 * {@link EmittedId} issued under the same key (its issuer is the key id) maps to itself,
 * for as long as the caller holds it; every plain string, even a 32-hex or
 * `r-`/`s-`/`lbl-`-shaped one, is mapped. No registry: nothing ages out.
 */
class KeyedIds {
  readonly #key: Uint8Array;
  readonly #issuer: string;

  constructor(key: Uint8Array) {
    this.#key = key;
    this.#issuer = keyId(key);
  }

  source(value: CallerId): EmittedId {
    return this.#map("s", value);
  }

  run(value: CallerId): EmittedId {
    return this.#map("r", value);
  }

  other(value: CallerId): EmittedId {
    return this.#map("lbl", value);
  }

  #map(prefix: string, value: CallerId): EmittedId {
    if (issuedBy(value, this.#issuer)) return value;
    return mintEmittedId(labelPseudonym(prefix, String(value), this.#key), this.#issuer);
  }
}

/** Ids as given (the clear mode, or local without the key): typed, never mapped. */
const CLEAR_ISSUER = "clear";

export interface ByteEvidenceDescriptor {
  schema_version: "fabric.content-object/v2";
  object_id: string;
  tenant_id: string;
  run_id?: string;
  operation_id?: string;
  attempt_id?: string;
  stream_id?: string;
  chunk_index?: number;
  role: string;
  media_type: string;
  encoding: "binary";
  representation: "exact" | "unavailable" | "redacted" | "tokenized";
  privacy_mode?: PrivacyMode;
  policy_digest?: string;
  policy_id?: string;
  policy_version?: number;
  workload_id?: string;
  protection_status?: ProtectionStatus;
  transformations?: ("redact" | "tokenize")[];
  transformation_id?: string;
  transformation_version?: string;
  source_byte_length?: number;
  source_sha256?: string;
  stored_byte_length?: number;
  stored_sha256?: string;
  ref?: string;
  provenance: "caller_reported";
  boundary: string;
  source_id: string;
  source_epoch: number;
  source_sequence: number;
  captured_at: string;
  status: "pending" | "stored" | "redacted" | "not_captured" | "unsupported" | "dropped" | "failed";
  status_reason?: string;
}

/**
 * One capture. Id fields take a caller id (a plain string: always mapped as the
 * recorder emits caller ids) or an {@link EmittedId} the recorder returned (passed
 * through unchanged by the recorder, or one holding the same id key, that issued it).
 */
export interface ByteEvidenceCapture {
  role: string;
  boundary: string;
  sourceId: CallerId;
  sourceEpoch: number;
  sourceSequence: number;
  mediaType?: string;
  runId?: CallerId;
  operationId?: CallerId;
  attemptId?: CallerId;
  streamId?: CallerId;
  chunkIndex?: number;
}

type PlainCapture = Omit<
  ByteEvidenceCapture,
  "sourceId" | "runId" | "operationId" | "attemptId" | "streamId"
> & {
  sourceId: string;
  runId?: string;
  operationId?: string;
  attemptId?: string;
  streamId?: string;
};

function plain(value: CallerId | undefined): string | undefined {
  return value instanceof EmittedId ? value.value : (value as string | undefined);
}

export interface ByteEvidenceConfig {
  /** Store must support the v2 byte methods, bound to exactly this tenant. */
  store: GovernedStore;
  reviewStore?: GovernedStore;
  deploymentPolicy?: DeploymentPolicy;
  contentProtector?: ContentProtector;
  /** Closed, explicitly enabled role set. `all` is intentionally absent. */
  roles: ReadonlySet<string>;
  /** In-memory queue length; overflow becomes a visible dropped descriptor. */
  queueMaxItems?: number;
  /** Bounded descriptor index, including terminal outcomes until drained. */
  maxRecords?: number;
  /** Maximum distinct source epochs tracked for monotonicity. */
  maxSources?: number;
  /** Larger inputs are not truncated or mislabeled exact. */
  payloadMaxBytes?: number;
  /** Best-effort delivery attempts; no source spool or durable receipt. */
  retryMaxAttempts?: number;
  /**
   * The id key (spec 049 §7.3; `FABRIC_WIRE_ID_KEY` when unset, at least 16 bytes): the
   * production profile needs it before any content is captured. A secret.
   */
  idKey?: Uint8Array;
  /**
   * Spec 049 §2.9 rule 7 (`FABRIC_IDENTITY_MODE` when unset): caller ids leave as keyed
   * pseudonyms (`pseudonymous`, the default) or as given (`clear`).
   */
  identityMode?: IdentityMode;
}

/** The content state of an explicit-line recorder (spec 049 §7.3). Values only. */
export interface ByteEvidenceStatus {
  profile: "local" | "production";
  content_capture: "enabled" | "disabled";
  content_capture_reason: string | null;
}

interface WorkItem {
  descriptor: ByteEvidenceDescriptor;
  bytes: Uint8Array;
  store: GovernedStore;
  /** A customer redaction deferred from capture(): the redaction service, in drain(). */
  redactRole?: string;
}

export class ByteEvidenceRecorder {
  private readonly store: GovernedStore;
  private readonly reviewStore?: GovernedStore;
  private readonly protector?: ContentProtector;
  private readonly roles: ReadonlySet<string>;
  private readonly queueMaxItems: number;
  private readonly maxRecords: number;
  private readonly maxSources: number;
  private readonly payloadMaxBytes: number;
  private readonly retryMaxAttempts: number;
  private readonly highWater = new Map<string, number>();
  private readonly records = new Map<string, ByteEvidenceDescriptor>();
  private readonly queue: WorkItem[] = [];
  private running = false;
  private closed = false;
  private lostRecordCount = 0;
  private readonly profile: "local" | "production";
  private readonly gateReason: string | null;
  /** How caller ids are emitted (spec 049 §2.9); undefined: as given. */
  private readonly emittedIds?: GeneratedIds | KeyedIds;
  private readonly counts = {
    stored: 0,
    redacted: 0,
    unsupported: 0,
    pending: 0,
    dropped: 0,
    failed: 0,
    not_captured: 0,
  };

  constructor(config: ByteEvidenceConfig) {
    if (
      !config.store ||
      typeof config.store.tenantId !== "string" ||
      typeof config.store.evidenceRefFor !== "function" ||
      typeof config.store.putBytesObject !== "function"
    ) {
      throw new Error("ByteEvidenceRecorder requires a tenant-bound content-v2 byte store");
    }
    if (!OPAQUE_ID.test(config.store.tenantId)) throw new Error("invalid store tenantId");
    if (
      !(config.roles instanceof Set) ||
      config.roles.size === 0 ||
      [...config.roles].some((role) => !BYTE_EVIDENCE_ROLES.has(role))
    ) {
      throw new Error("byte evidence requires a non-empty, closed role set");
    }
    this.queueMaxItems = config.queueMaxItems ?? 64;
    this.maxRecords = config.maxRecords ?? 4096;
    this.maxSources = config.maxSources ?? 4096;
    this.payloadMaxBytes = config.payloadMaxBytes ?? 1024 * 1024;
    this.retryMaxAttempts = config.retryMaxAttempts ?? 3;
    if (
      !Number.isInteger(this.queueMaxItems) ||
      this.queueMaxItems < 1 ||
      this.queueMaxItems > HARD_MAX_ITEMS ||
      !Number.isInteger(this.maxRecords) ||
      this.maxRecords < 1 ||
      this.maxRecords > HARD_MAX_ITEMS ||
      !Number.isInteger(this.maxSources) ||
      this.maxSources < 1 ||
      this.maxSources > HARD_MAX_ITEMS ||
      !Number.isInteger(this.payloadMaxBytes) ||
      this.payloadMaxBytes < 1 ||
      this.payloadMaxBytes > HARD_MAX_BYTES ||
      !Number.isInteger(this.retryMaxAttempts) ||
      this.retryMaxAttempts < 1 ||
      this.retryMaxAttempts > 20
    ) {
      throw new Error("invalid bounded byte-evidence queue, payload, or retry limit");
    }
    const policy = config.deploymentPolicy ?? config.contentProtector?.policy;
    if (policy !== undefined) {
      if (!(policy instanceof DeploymentPolicy) || policy.tenant_id !== config.store.tenantId)
        throw new Error("deployment policy must match byte store tenant");
      this.protector =
        config.contentProtector ??
        new ContentProtector(policy, { payloadMaxBytes: this.payloadMaxBytes });
      if (this.protector.policy.digest !== policy.digest)
        throw new Error("content protector must match deployment policy");
      if (
        [...config.roles].some((role) =>
          ["redact", "masked_only", "tokenize"].includes(policy.privacy[role] ?? "omit"),
        )
      ) {
        const review = config.reviewStore;
        if (
          !review ||
          review.tenantId !== config.store.tenantId ||
          typeof review.evidenceRefFor !== "function" ||
          typeof review.putBytesObject !== "function"
        )
          throw new Error("deployment derivatives require a same-tenant review store");
        const probe = "00000000-0000-4000-8000-000000000000";
        const originalRef = config.store.evidenceRefFor(probe);
        const reviewRef = review.evidenceRefFor(probe);
        if (
          reviewRef === originalRef ||
          config.store.ownsUri(reviewRef) ||
          review.ownsUri(originalRef)
        )
          throw new Error("original and derivative store namespaces must differ");
      }
    }
    this.reviewStore = config.reviewStore;
    this.store = config.store;
    this.roles = new Set(config.roles);
    // Spec 049 §7.3: never blocked, but not silent; a malformed id key still throws.
    const idKey = checkIdKey(config.idKey) ?? idKeyFromEnv();
    const gate = contentGate(policy, idKey, config.store, config.reviewStore);
    this.profile = gate.profile;
    this.gateReason = gate.reason;
    // Spec 049 §2.9: keyed pseudonyms, or generated ids in production without the id key
    // (rule 5, whatever the mode); as given only in the clear mode (or local, no key).
    const mode =
      config.identityMode !== undefined
        ? checkIdentityMode(config.identityMode)
        : identityModeFromEnv(typeof process !== "undefined" ? process.env : {});
    if (gate.profile === "production" && idKey === undefined) this.emittedIds = new GeneratedIds();
    else if (idKey !== undefined && mode === "pseudonymous") this.emittedIds = new KeyedIds(idKey);
    if (gate.reason !== null)
      console.warn(
        `fabric.byteEvidence: content capture disabled (${gate.reason}, ${gate.profile} ` +
          "profile); metadata capture continues",
      );
  }

  /** The content state (spec 049 §7.3): profile, content capture and its reason. */
  /**
   * `runId` as this recorder emits it (epoch 0), in parity with Python
   * `ByteEvidenceRecorder.emitted_run_id`: never the clear value unless ids are emitted
   * as given.
   */
  emittedRunId(runId: CallerId): EmittedId {
    if (this.emittedIds !== undefined) return this.emittedIds.run(runId, 0);
    return runId instanceof EmittedId ? runId : mintEmittedId(runId, CLEAR_ISSUER);
  }

  /**
   * `sourceId` as this recorder emits it: pass the returned value back (as
   * `sourceId`) and it is never mapped again, however many ids the recorder sees.
   */
  emittedSourceId(sourceId: CallerId): EmittedId {
    if (this.emittedIds !== undefined) return this.emittedIds.source(sourceId);
    return sourceId instanceof EmittedId ? sourceId : mintEmittedId(sourceId, CLEAR_ISSUER);
  }

  status(): ByteEvidenceStatus {
    return {
      profile: this.profile,
      content_capture: this.gateReason === null ? "enabled" : "disabled",
      content_capture_reason: this.gateReason,
    };
  }

  /** Snapshot of terminal and pending counts. A pending remainder is a gap. */
  stats(): Record<string, number> {
    return {
      ...this.counts,
      queue_depth: this.queue.length,
      indexed_records: this.records.size,
      unretained_drops: this.lostRecordCount,
    };
  }

  /** Process-local status lookup. `undefined` after a terminal record is drained. */
  get(objectId: string): ByteEvidenceDescriptor | undefined {
    const record = this.records.get(objectId);
    return record === undefined ? undefined : { ...record };
  }

  /** Remove and return all terminal records; pending records stay indexed. */
  drainSettled(): ByteEvidenceDescriptor[] {
    const settled: ByteEvidenceDescriptor[] = [];
    for (const [id, record] of this.records) {
      if (record.status !== "pending") {
        settled.push({ ...record });
        this.records.delete(id);
      }
    }
    return settled;
  }

  /**
   * Capture exactly the caller-supplied bytes. `provenance` is always
   * caller_reported; SDK entry cannot attest a native/protocol boundary.
   * No content bytes are put on OTLP. Caller must retain the returned
   * descriptor (or persist it separately); this slice has no run manifest.
   */
  capture(data: Uint8Array, input: ByteEvidenceCapture): ByteEvidenceDescriptor {
    if (!(data instanceof Uint8Array)) throw new TypeError("byte evidence requires Uint8Array");
    if (input === null || typeof input !== "object") throw new TypeError("invalid capture options");
    let options: PlainCapture = {
      ...input,
      sourceId: plain(input.sourceId)!,
      runId: plain(input.runId),
      operationId: plain(input.operationId),
      attemptId: plain(input.attemptId),
      streamId: plain(input.streamId),
    };
    for (const name of ["runId", "operationId", "attemptId", "streamId"] as const)
      if (options[name] === undefined) delete options[name];
    this.validateOptions(options);
    const key = JSON.stringify([options.sourceId, options.sourceEpoch]);
    const previous = this.highWater.get(key);
    if (previous !== undefined && options.sourceSequence <= previous) {
      throw new Error("sourceSequence must increase within sourceId/sourceEpoch");
    }
    const sourceRegistryFull = previous === undefined && this.highWater.size >= this.maxSources;
    if (!sourceRegistryFull) this.highWater.set(key, options.sourceSequence);
    const ids = this.emittedIds;
    if (ids !== undefined) {
      // Spec 049 §2.9: no clear caller id leaves the process; an EmittedId this recorder
      // issued passes through by its type (never a bounded registry, Sol P0-A round 6 #1).
      options = {
        ...options,
        sourceId: ids.source(input.sourceId).value,
        ...(input.runId !== undefined
          ? { runId: ids.run(input.runId, options.sourceEpoch).value }
          : {}),
        ...(input.operationId !== undefined
          ? { operationId: ids.other(input.operationId).value }
          : {}),
        ...(input.attemptId !== undefined ? { attemptId: ids.other(input.attemptId).value } : {}),
        ...(input.streamId !== undefined ? { streamId: ids.other(input.streamId).value } : {}),
      };
    }
    const descriptor: ByteEvidenceDescriptor = {
      schema_version: "fabric.content-object/v2",
      object_id: randomUUID(),
      tenant_id: this.store.tenantId,
      role: options.role,
      media_type: options.mediaType ?? "application/octet-stream",
      encoding: "binary",
      representation: "unavailable",
      provenance: "caller_reported",
      boundary: options.boundary,
      source_id: options.sourceId,
      source_epoch: options.sourceEpoch,
      source_sequence: options.sourceSequence,
      captured_at: new Date().toISOString(),
      status: "not_captured",
    };
    for (const [keyName, value] of [
      ["run_id", options.runId],
      ["operation_id", options.operationId],
      ["attempt_id", options.attemptId],
      ["stream_id", options.streamId],
    ] as const) {
      if (value !== undefined) descriptor[keyName] = value;
    }
    if (options.chunkIndex !== undefined) descriptor.chunk_index = options.chunkIndex;
    if (sourceRegistryFull) {
      descriptor.status = "dropped";
      descriptor.status_reason = "source_registry_full";
      this.counts.dropped += 1;
      this.lostRecordCount += 1;
      return descriptor;
    }
    if (this.records.size >= this.maxRecords) {
      descriptor.status = "dropped";
      descriptor.status_reason = "record_index_full";
      this.counts.dropped += 1;
      this.lostRecordCount += 1;
      return descriptor;
    }
    this.records.set(descriptor.object_id, descriptor);
    if (this.gateReason !== null) {
      // Spec 049 §7.3: content disabled; nothing stored, digested or queued.
      descriptor.status_reason = this.gateReason;
      this.counts.not_captured += 1;
      return { ...descriptor };
    }
    if (!this.roles.has(options.role)) {
      descriptor.status_reason = "outside_capture_policy";
      this.counts.not_captured += 1;
      return descriptor;
    }
    // The redaction service is never called on the caller's path (spec 049 §7.1, §7.7):
    // it is deferred behind the handoff, before persistence; failure withholds.
    const deferred = this.protector?.needsRedactionService(options.role) === true;
    const protectedContent = deferred ? undefined : this.protector?.protect(options.role, data);
    if (deferred) {
      const policy = this.protector!.policy;
      const transformation = this.protector!.transformationFor(options.role)!;
      Object.assign(descriptor, {
        privacy_mode: policy.privacy[options.role],
        protection_status: "redacted",
        policy_digest: policy.digest,
        policy_id: policy.policy_id,
        policy_version: policy.policy_version,
        workload_id: policy.workload_id,
        transformation_id: transformation.id,
        transformation_version: transformation.version,
      });
    }
    if (protectedContent !== undefined) {
      const policy = this.protector!.policy;
      Object.assign(descriptor, {
        privacy_mode: protectedContent.mode,
        protection_status: protectedContent.status,
        policy_digest: policy.digest,
        policy_id: policy.policy_id,
        policy_version: policy.policy_version,
        workload_id: policy.workload_id,
      });
      if (typeof protectedContent.metadata.source_byte_length === "number")
        descriptor.source_byte_length = protectedContent.metadata.source_byte_length;
      if (protectedContent.original_digest !== null)
        descriptor.source_sha256 = protectedContent.original_digest;
      if (protectedContent.protected_bytes === null) {
        descriptor.status =
          protectedContent.status === "lost"
            ? "failed"
            : protectedContent.status === "unsupported"
              ? "unsupported"
              : "not_captured";
        descriptor.status_reason = String(protectedContent.metadata.reason);
        this.counts[descriptor.status] += 1;
        return { ...descriptor };
      }
      data = protectedContent.protected_bytes;
    }
    if (
      this.closed ||
      data.byteLength > this.payloadMaxBytes ||
      this.counts.pending >= this.queueMaxItems
    ) {
      descriptor.status = "dropped";
      descriptor.status_reason = this.closed
        ? "recorder_closed"
        : data.byteLength > this.payloadMaxBytes
          ? "payload_too_large"
          : "queue_full";
      this.counts.dropped += 1;
      return descriptor;
    }
    const bytes = new Uint8Array(data); // immutable capture snapshot
    let targetStore = this.store;
    if (deferred) {
      descriptor.representation = "redacted"; // pending the redaction service
      descriptor.transformations = ["redact"];
      targetStore = this.reviewStore!;
    } else if (
      protectedContent?.status === "redacted" ||
      protectedContent?.status === "tokenized"
    ) {
      descriptor.representation = protectedContent.status;
      descriptor.transformations = [protectedContent.status === "redacted" ? "redact" : "tokenize"];
      targetStore = this.reviewStore!;
    } else {
      descriptor.representation = "exact";
      descriptor.source_byte_length = bytes.byteLength;
      descriptor.source_sha256 = protectedContent?.original_digest ?? digest(bytes);
    }
    descriptor.status = "pending";
    this.queue.push({
      descriptor,
      bytes,
      store: targetStore,
      ...(deferred ? { redactRole: options.role } : {}),
    });
    this.counts.pending += 1;
    this.schedule();
    return descriptor;
  }

  private validateOptions(options: PlainCapture): void {
    if (typeof options.sourceId !== "string" || !OPAQUE_ID.test(options.sourceId)) {
      throw new Error("sourceId must be an opaque identifier");
    }
    for (const [name, value] of [
      ["role", options.role],
      ["boundary", options.boundary],
      ["sourceId", options.sourceId],
      ["runId", options.runId],
      ["operationId", options.operationId],
      ["attemptId", options.attemptId],
      ["streamId", options.streamId],
    ] as const) {
      if (value !== undefined && (typeof value !== "string" || !OPAQUE_ID.test(value))) {
        throw new Error(`${name} must be an opaque identifier`);
      }
    }
    if (!BYTE_EVIDENCE_ROLES.has(options.role) || !BYTE_EVIDENCE_BOUNDARIES.has(options.boundary)) {
      throw new Error("unknown byte evidence role or boundary");
    }
    if (
      !Number.isSafeInteger(options.sourceEpoch) ||
      options.sourceEpoch < 0 ||
      !Number.isSafeInteger(options.sourceSequence) ||
      options.sourceSequence < 0
    ) {
      throw new Error("source epoch and sequence must be non-negative safe integers");
    }
    if (
      options.chunkIndex !== undefined &&
      (!Number.isSafeInteger(options.chunkIndex) ||
        options.chunkIndex < 0 ||
        options.streamId === undefined)
    ) {
      throw new Error("chunkIndex requires streamId and must be non-negative");
    }
    const media = options.mediaType ?? "application/octet-stream";
    if (media.length > 128 || !MEDIA_TYPE.test(media)) throw new Error("invalid media type");
  }

  private schedule(): void {
    if (this.running) return;
    this.running = true;
    setTimeout(() => {
      void this.drain();
    }, 0);
  }

  private async drain(): Promise<void> {
    try {
      while (this.queue.length > 0) {
        const item = this.queue.shift() as WorkItem;
        const d = item.descriptor;
        if (item.redactRole !== undefined) {
          const redacted = await this.protector!.protectAsync(item.redactRole, item.bytes);
          const bytes = redacted.status === "redacted" ? redacted.protected_bytes : null;
          if (bytes === null) {
            // Spec 049 §7.7 rule 4: withheld, never raw bytes, no error text.
            d.status = "not_captured";
            d.status_reason = "protection_failed";
            d.protection_status = "withheld";
            d.representation = "unavailable";
            delete d.transformations;
            this.counts.pending -= 1;
            this.counts.not_captured += 1;
            continue;
          }
          if (bytes.byteLength > this.payloadMaxBytes) {
            // The recorder's own cap, as before deferral (a supplied protector may allow
            // more): dropped, nothing stored (Sol P0-A round 2 #4).
            d.status = "dropped";
            d.status_reason = "payload_too_large";
            d.representation = "unavailable";
            this.counts.pending -= 1;
            this.counts.dropped += 1;
            continue;
          }
          item.bytes = bytes;
        }
        let succeeded = false;
        let stored: ByteEvidenceDescriptor | undefined;
        for (let attempt = 0; attempt < this.retryMaxAttempts; attempt += 1) {
          try {
            stored = {
              ...d,
              status:
                d.representation === "redacted" || d.representation === "tokenized"
                  ? "redacted"
                  : "stored",
              stored_byte_length: item.bytes.byteLength,
              stored_sha256: digest(item.bytes),
              ref: item.store.evidenceRefFor!(d.object_id),
            };
            const result = await item.store.putBytesObject!(
              stored as unknown as Record<string, unknown>,
              item.bytes,
            );
            if (
              result.uri !== stored.ref ||
              result.contentHash !== stored.stored_sha256?.slice(7)
            ) {
              throw new Error("store returned mismatched evidence reference or digest");
            }
            succeeded = true;
            break;
          } catch {
            // Retry is bounded and entirely off the monitored caller path.
          }
        }
        this.counts.pending -= 1;
        if (succeeded && stored !== undefined) {
          Object.assign(d, stored);
          if (stored.status === "redacted") this.counts.redacted += 1;
          else this.counts.stored += 1;
        } else {
          d.status = "failed";
          d.status_reason = "store_delivery_failed";
          d.representation = "unavailable";
          this.counts.failed += 1;
        }
      }
    } finally {
      this.running = false;
      if (this.queue.length > 0) this.schedule();
    }
  }

  /** Wait for process-memory delivery; return honest per-status counts. */
  async flush(timeoutMs = 10_000): Promise<Record<string, number>> {
    if (!Number.isFinite(timeoutMs) || timeoutMs < 0) throw new Error("invalid flush timeout");
    const end = Date.now() + timeoutMs;
    while (this.running || this.queue.length > 0) {
      if (Date.now() >= end) break;
      await new Promise<void>((resolve) => setTimeout(resolve, 5));
    }
    return this.stats();
  }

  /** Settle accepted writes, then close the redaction service connection pool. */
  async close(timeoutMs = 10_000): Promise<Record<string, number>> {
    this.closed = true;
    const stats = await this.flush(timeoutMs);
    await this.protector?.close();
    return stats;
  }
}
