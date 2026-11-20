// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The PROTECT stage of wire capture (spec 055 §5; Python `wire/_protect.py` and
 * `wire/_policy.py`), run by the Fabric worker before anything is spooled. Nothing
 * reaches the spool, a store or the network before it ran, and a failure withholds the
 * content: there is never a fallback to raw bytes.
 *
 * This unit (`055-t8`) builds the whole-object modes: `omit`, `metadata_only`,
 * `retain_original`, `redact`, `masked_only` and `tokenize`. A digest of the original
 * body exists only under `retain_original`. `redact` and `masked_only` are made by the
 * customer-run redaction service through the existing {@link RedactionClient}, built in
 * the Fabric worker; `tokenize` is the existing whole-object HMAC ({@link tokenBytes}).
 * Split parts and `original_plus_masked` are unit `055-t15`: until then a side over
 * `max_body_bytes` is cut (`body_cap`), and an `original_plus_masked` role is withheld,
 * both objects `not_captured(protection_failed)`, as Python withholds a pair whose review
 * copy failed.
 *
 * Transformations run over the plaintext: a side whose `Content-Encoding` is not
 * `identity` is decoded first, bounded by `max_body_bytes`; a body that cannot be decoded
 * is withheld (`protection_failed`). A retained original stays the wire bytes.
 */
import { createHash, randomUUID } from "node:crypto";
import * as zlib from "node:zlib";

import { DeploymentPolicy, TOKEN_TRANSFORMATION, tokenBytes } from "../deployment-policy.js";
import {
  RedactionClient,
  checkTransformation,
  type RedactionServiceOptions,
  type RedactionStats,
  type Transformation,
} from "../redaction.js";
import { encodeJson } from "./codec.js";
import { ROLE_ROWS, ROLE_TABLE_VERSION } from "./roles.generated.js";
import type { RoleRow } from "./types.js";

export const ROLE_REQUEST = "model.exchange.request";
export const ROLE_RESPONSE = "model.exchange.response";
export const PART_ROLE = "model.exchange.part";
export const LOCAL_DEFAULT_ID = "fabric.local-default";
const MIN_TOKEN_KEY_BYTES = 32;

// ------------------------------------------------------------------ content coding

/** The body cannot be decoded: an unknown or unsupported coding, corrupt or truncated. */
export class UndecodableError extends Error {
  constructor() {
    super("the body's Content-Encoding could not be decoded");
  }
}

/** The decoded body would be larger than the bound. */
export class TooLargeError extends UndecodableError {}

function codings(encoding: string | undefined): string[] {
  return (encoding ?? "")
    .split(",")
    .map((part) => part.trim().toLowerCase())
    .filter((part) => part !== "");
}

/** Whether `encoding` names no transformation of the bytes. */
export function isIdentity(encoding: string | undefined): boolean {
  return codings(encoding).every((coding) => coding === "identity");
}

function bounded(decode: () => Buffer): Buffer {
  try {
    return decode();
  } catch (error) {
    if ((error as { code?: unknown }).code === "ERR_BUFFER_TOO_LARGE") throw new TooLargeError();
    throw error;
  }
}

/**
 * `data` with every coding of `encoding` undone, last applied first, each stage bounded by
 * `limit` (Python `_content_coding.decode_content`): `gzip`/`x-gzip`, `deflate` (zlib,
 * else raw), `br` and `zstd`. Throws {@link UndecodableError} or {@link TooLargeError}.
 */
export function decodeContent(
  data: Uint8Array,
  encoding: string | undefined,
  limit: number,
): Buffer {
  let out = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  const options = { maxOutputLength: Math.max(1, limit) };
  for (const coding of codings(encoding).reverse()) {
    if (coding === "identity") continue;
    try {
      const input = out;
      if (coding === "gzip" || coding === "x-gzip") {
        out = bounded(() => zlib.gunzipSync(input, options));
      } else if (coding === "deflate") {
        try {
          out = bounded(() => zlib.inflateSync(input, options));
        } catch (error) {
          if (error instanceof TooLargeError) throw error;
          out = bounded(() => zlib.inflateRawSync(input, options));
        }
      } else if (coding === "br") {
        out = bounded(() => zlib.brotliDecompressSync(input, options));
      } else if (coding === "zstd" && typeof zlib.zstdDecompressSync === "function") {
        out = bounded(() => zlib.zstdDecompressSync(input, options));
      } else {
        throw new UndecodableError();
      }
    } catch (error) {
      if (error instanceof UndecodableError) throw error;
      throw new UndecodableError();
    }
  }
  return out;
}

// ---------------------------------------------------------------------- role table

const CAPS: Readonly<Record<string, number>> = {
  "64 KiB": 64 << 10,
  "256 KiB": 256 << 10,
  "1 MiB": 1 << 20,
  "4 MiB": 4 << 20,
};
const MEDIA_RE = /^(?=.{3,128}$)[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;

/** The content role table (spec 049 §4.3), generated from the registry. */
export const ROLES: ReadonlyMap<string, RoleRow> = new Map(ROLE_ROWS.map((row) => [row.role, row]));

/** A role's object cap for a deployment whose `max_body_bytes` is `maxBodyBytes`. */
export function capBytes(row: RoleRow, maxBodyBytes: number): number {
  return row.cap === "max_body_bytes" ? maxBodyBytes : CAPS[row.cap]!;
}

/** Exact `type/subtype`, `type/*` or `*`, for a value passing the 047 §7 media rule. */
export function admitsMedia(row: RoleRow, mediaType: string): boolean {
  if (!MEDIA_RE.test(mediaType)) return false;
  const major = mediaType.split("/", 1)[0] + "/*";
  return row.media_types.some((m) => m === "*" || m === mediaType || m === major);
}

/** Whether the Node's role rules (049 §4.3 rules 1-4) admit an object with these values. */
export function admits(
  role: string,
  fields: {
    boundary: string;
    provenance: string;
    mediaType: string;
    storedByteLength: number;
    maxBodyBytes: number;
  },
): boolean {
  const row = ROLES.get(role);
  return (
    row !== undefined &&
    row.boundary.includes(fields.boundary) &&
    row.provenance.includes(fields.provenance) &&
    admitsMedia(row, fields.mediaType) &&
    fields.storedByteLength <= capBytes(row, fields.maxBodyBytes)
  );
}

// ------------------------------------------------------------------ capture policy

/** The policy in force: a deployment policy, or the implicit `fabric.local-default`. */
export interface CapturePolicy {
  readonly policyId: string;
  readonly policyVersion: number;
  readonly policyDigest: string;
  readonly modes: Readonly<Record<string, string>>;
  readonly implicit: boolean;
  readonly profile: "local" | "production";
  readonly encryptedStoreRequired: boolean;
  readonly workloadId: string | undefined;
  readonly tenantId: string | undefined;
}

/** The capture policy of a validated deployment policy (Python `from_deployment`). */
export function capturePolicyOf(policy: DeploymentPolicy): CapturePolicy {
  const deployment = policy.deployment;
  return Object.freeze({
    policyId: policy.policy_id,
    policyVersion: policy.policy_version,
    policyDigest: policy.digest,
    modes: Object.freeze({ ...policy.privacy }),
    implicit: false,
    profile: deployment.profile,
    encryptedStoreRequired: deployment.encrypted_store_required,
    workloadId: policy.workload_id,
    tenantId: policy.tenant_id,
  });
}

/**
 * `fabric.local-default` (version 1): its digest binds the role -> mode table it implies
 * and the role table version, so a role-table change is a new digest (Python `_policy`).
 */
export const LOCAL_DEFAULT: CapturePolicy = (() => {
  const privacy: Record<string, string> = {};
  for (const row of ROLE_ROWS) {
    privacy[row.role] = row.default_policy === "content" ? "retain_original" : "omit";
  }
  const doc = {
    policy_id: LOCAL_DEFAULT_ID,
    policy_version: 1,
    privacy,
    role_table_version: ROLE_TABLE_VERSION,
  };
  const digest = createHash("sha256")
    .update(encodeJson(doc, { asciiOnly: true }))
    .digest("hex");
  return Object.freeze({
    policyId: LOCAL_DEFAULT_ID,
    policyVersion: 1,
    policyDigest: "sha256:" + digest,
    modes: Object.freeze({}),
    implicit: true,
    profile: "local" as const,
    encryptedStoreRequired: false,
    workloadId: undefined,
    tenantId: undefined,
  });
})();

/**
 * A role's privacy mode by 049 §2.7 (rules 2-5): named -> that mode; the implicit local
 * default -> `retain_original` for `content` roles, `omit` for the others; a configured
 * policy that does not name the role -> `omit`.
 */
export function modeOf(policy: CapturePolicy, role: string): string {
  if (Object.hasOwn(policy.modes, role)) return policy.modes[role]!;
  const row = ROLES.get(role);
  return policy.implicit && row?.default_policy === "content" ? "retain_original" : "omit";
}

// ------------------------------------------------------------- the production gate

export type Profile = "local" | "production";
export type ContentCapture = "enabled" | "disabled" | "metadata_only";

/**
 * The install-time content decision (049 §7.3, §7.8). `reason` is the
 * `fabric.wire.store_reason` every exchange span carries while content is not enabled.
 */
export interface ContentGate {
  readonly profile: Profile;
  readonly contentCapture: ContentCapture;
  readonly reason: string | undefined;
  readonly policy: CapturePolicy | undefined;
  readonly spoolEncrypted: boolean;
  readonly keyed: boolean;
}

export interface GateInputs {
  /** Content goes to the Fabric Node (`FABRIC_WIRE_CONTENT_ENDPOINT`). */
  readonly node: boolean;
  /** A direct (`file://`) store is configured. */
  readonly store: boolean;
  readonly policy: DeploymentPolicy | undefined;
  readonly idKey: boolean;
  /** A spool is used (`FABRIC_WIRE_SPOOL_DIR`). */
  readonly spool: boolean;
  readonly spoolKey: boolean;
}

/**
 * The gate, with Python's precedence (`wire/_policy.py` `decide`): no destination ->
 * `metadata_only(no_store)`; production (node mode, or a production policy) without a
 * policy -> `missing_capture_policy`, then without `FABRIC_WIRE_ID_KEY` ->
 * `missing_id_key`, then with a spool but no spool key -> `missing_spool_key`. A missing
 * prerequisite disables content and never fails the agent; safe metadata continues.
 */
export function decideGate(inputs: GateInputs): ContentGate {
  const capture = inputs.policy === undefined ? undefined : capturePolicyOf(inputs.policy);
  const production = inputs.node || capture?.profile === "production";
  const gate = (state: ContentCapture, reason: string | undefined, policy?: CapturePolicy) =>
    Object.freeze({
      profile: production ? ("production" as const) : ("local" as const),
      contentCapture: state,
      reason,
      policy,
      spoolEncrypted: inputs.spool && inputs.spoolKey,
      keyed: inputs.idKey,
    });
  if (!inputs.node && !inputs.store) return gate("metadata_only", "no_store", capture);
  let reason: string | undefined;
  if (production && capture === undefined) reason = "missing_capture_policy";
  else if (production && !inputs.idKey) reason = "missing_id_key";
  else if (production && inputs.spool && !inputs.spoolKey) reason = "missing_spool_key";
  if (reason !== undefined) return gate("disabled", reason, capture);
  return gate("enabled", undefined, capture ?? LOCAL_DEFAULT);
}

// ----------------------------------------------------------------------- protector

/** One object for the content path: a descriptor and its bytes (empty when withheld). */
export interface ContentObject {
  readonly descriptor: Record<string, unknown>;
  readonly data: Uint8Array;
}

/** Whether `object` holds stored bytes (it has a stored digest). */
export function isStored(object: ContentObject): boolean {
  return "stored_sha256" in object.descriptor;
}

/** What one side became: its objects, the primary stored object and why it is partial. */
export interface SideResult {
  readonly objects: ContentObject[];
  primary: ContentObject | undefined;
  reason: string | undefined;
  readonly truncated: boolean;
}

export interface SideInput {
  /** Every byte forwarded on this side, when known (an exact side: its length). */
  readonly observed: number | undefined;
  /** Why retention stopped early: `body_cap`, `inflight_budget`, `transport_incomplete`. */
  readonly cutReason: string | undefined;
  /** The response ended other than `complete`. */
  readonly partial: boolean;
}

export interface ProtectorOptions {
  readonly maxBodyBytes: number;
  /** The customer transformation of each `redact` / `masked_only` role. */
  readonly transformations?: Readonly<Record<string, Transformation>>;
  /** The redaction service; a client is built here, in the Fabric worker. */
  readonly redaction?: RedactionServiceOptions;
  readonly tokenizationKey?: Uint8Array;
}

export interface ProtectorStats extends RedactionStats {
  readonly protection_undecodable: number;
}

const sha = (data: Uint8Array): string =>
  "sha256:" + createHash("sha256").update(data).digest("hex");

/**
 * The longest prefix of whole pieces of at most `limit` bytes (047: no slicing). The
 * arena keeps slab pieces, not the caller's chunk boundaries (§7.2), so the pieces here
 * are the retained slab pieces.
 */
export function wholePiecePrefix(pieces: readonly Uint8Array[], limit: number): Buffer {
  const kept: Uint8Array[] = [];
  let size = 0;
  for (const piece of pieces) {
    if (size + piece.byteLength > limit) break;
    kept.push(piece);
    size += piece.byteLength;
  }
  return Buffer.concat(kept, size);
}

/** Applies the capture policy to one exchange side (049 §7.5; Python `Protector`). */
export class Protector {
  readonly policy: CapturePolicy;
  readonly maxBodyBytes: number;
  readonly #transforms: Readonly<Record<string, Transformation>>;
  readonly #client: RedactionClient | undefined;
  readonly #tokenKey: Uint8Array | undefined;
  #undecodable = 0;

  constructor(policy: CapturePolicy, options: ProtectorOptions) {
    this.policy = policy;
    this.maxBodyBytes = options.maxBodyBytes;
    const transforms: Record<string, Transformation> = {};
    for (const [role, value] of Object.entries(options.transformations ?? {})) {
      if (!ROLES.has(role)) {
        throw new Error("transformations map content roles to { id, version } transformations");
      }
      transforms[role] = checkTransformation(value);
    }
    if (Object.keys(transforms).length > 0 && options.redaction === undefined) {
      throw new Error(
        "transformations require a redaction service endpoint: set FABRIC_REDACTION_ENDPOINT",
      );
    }
    this.#transforms = Object.freeze(transforms);
    this.#client =
      options.redaction === undefined
        ? undefined
        : new RedactionClient(options.redaction, { maxOutputBytes: options.maxBodyBytes });
    this.#tokenKey =
      options.tokenizationKey === undefined ? undefined : Buffer.from(options.tokenizationKey);
  }

  /** The redaction service counters and undecodable sides (never a value). */
  stats(): ProtectorStats {
    const redaction = this.#client?.stats() ?? {
      redaction_timeouts: 0,
      redaction_saturated: 0,
      redaction_failures: 0,
    };
    return { ...redaction, protection_undecodable: this.#undecodable };
  }

  /** Closes the redaction service connections; later masked content is withheld. */
  async close(): Promise<void> {
    await this.#client?.close();
  }

  /**
   * Protects one side. `base` holds the descriptor's identity fields (tenant, source,
   * run, operation, boundary, provenance, captured_at, media type, content encoding);
   * `pieces` are the retained bytes in order. Never throws for content reasons.
   */
  async side(
    base: Readonly<Record<string, unknown>>,
    role: string,
    pieces: readonly Uint8Array[],
    input: SideInput,
  ): Promise<SideResult> {
    const mode = modeOf(this.policy, role);
    let cut = input.cutReason;
    if (mode === "omit") {
      return {
        objects: [],
        primary: undefined,
        reason: "privacy_policy",
        truncated: cut !== undefined,
      };
    }
    if (mode === "metadata_only") {
      const sizes = input.observed === undefined ? {} : { source_byte_length: input.observed };
      // As Python: the descriptor is kept as is (it holds no bytes to refuse).
      return {
        objects: [this.#withheld(base, role, mode, "privacy_policy", sizes)],
        primary: undefined,
        reason: "privacy_policy",
        truncated: cut !== undefined,
      };
    }
    const total = pieces.reduce((sum, piece) => sum + piece.byteLength, 0);
    // Split parts are unit 055-t15: a side over the object bound is cut, as before 049.
    if (cut === undefined && total > this.maxBodyBytes) cut = "body_cap";
    const data =
      cut !== undefined && total > this.maxBodyBytes
        ? wholePiecePrefix(pieces, this.maxBodyBytes)
        : Buffer.concat(pieces, total);
    const result: SideResult = {
      objects: [],
      primary: undefined,
      reason: undefined,
      truncated: cut !== undefined,
    };
    if (mode === "retain_original") {
      this.#original(result, base, role, mode, data, input, cut);
    } else if (mode === "original_plus_masked") {
      this.#withholdPair(result, base, role, mode);
    } else {
      await this.#transformed(result, base, role, mode, data, cut);
    }
    if (result.reason === undefined && cut !== undefined) result.reason = cut;
    return result;
  }

  // ---------------------------------------------------------------------- modes

  #original(
    result: SideResult,
    base: Readonly<Record<string, unknown>>,
    role: string,
    mode: string,
    data: Buffer,
    input: SideInput,
    cut: string | undefined,
  ): void {
    if (cut !== undefined && data.byteLength === 0) {
      result.reason = cut; // no whole piece fit: nothing useful to store
      return;
    }
    let object: ContentObject;
    if (cut !== undefined) {
      // The bytes forwarded past the cut are not counted by the hook: the source length
      // is given only when it is known (Python: max(observed, stored + 1)).
      const source =
        input.observed === undefined
          ? {}
          : { source_byte_length: Math.max(input.observed, data.byteLength + 1) };
      object = this.#stored(
        base,
        role,
        mode,
        data,
        "truncated",
        ["truncate"],
        "truncated",
        "retained",
        source,
      );
    } else {
      const source = { source_byte_length: data.byteLength, source_sha256: sha(data) };
      const representation = input.partial ? "partial" : "exact";
      object = this.#stored(
        base,
        role,
        mode,
        data,
        representation,
        [],
        "stored",
        "retained",
        source,
      );
    }
    this.#admit(result, object, true);
  }

  async #transformed(
    result: SideResult,
    base: Readonly<Record<string, unknown>>,
    role: string,
    mode: string,
    data: Buffer,
    cut: string | undefined,
  ): Promise<void> {
    if (cut !== undefined) {
      // A cut prefix is never transformed (049 §7.5: no claim about the whole).
      this.#admit(result, this.#withheld(base, role, mode, cut), true, cut);
      return;
    }
    const plain = this.#plaintext(base, data);
    if (plain.data === undefined) {
      this.#admit(result, this.#withheld(base, role, mode, plain.failed), true, plain.failed);
      return;
    }
    const object =
      mode === "tokenize"
        ? this.#tokenized(plain.base, role, mode, plain.data)
        : await this.#redacted(plain.base, role, mode, plain.data);
    this.#admit(result, object, true);
  }

  /**
   * `original_plus_masked` before unit 055-t15 builds the review copy: both objects are
   * descriptor-only `not_captured(protection_failed)`, with no digest or length of the
   * original, as Python withholds a pair whose masked copy failed.
   */
  #withholdPair(
    result: SideResult,
    base: Readonly<Record<string, unknown>>,
    role: string,
    mode: string,
  ): void {
    const original = this.#withheld(base, role, mode, "protection_failed");
    const review = this.#withheld(base, role, mode, "protection_failed");
    review.descriptor.links = [
      { relation: "derived_from", object_id: original.descriptor.object_id },
    ];
    this.#admit(result, original, true);
    this.#admit(result, review, false);
  }

  /**
   * The side's plaintext and the base describing it: the bytes as they are for
   * `identity`, else every coding undone (bounded by `max_body_bytes`) and
   * `content_encoding: identity`. A failure names `body_cap` or `protection_failed`.
   */
  #plaintext(
    base: Readonly<Record<string, unknown>>,
    data: Buffer,
  ): { base: Readonly<Record<string, unknown>>; data?: Buffer; failed: string } {
    const encoding = base.content_encoding;
    if (isIdentity(typeof encoding === "string" ? encoding : undefined)) {
      return { base, data, failed: "" };
    }
    try {
      const plain = decodeContent(
        data,
        typeof encoding === "string" ? encoding : "unknown",
        this.maxBodyBytes,
      );
      return { base: { ...base, content_encoding: "identity" }, data: plain, failed: "" };
    } catch (error) {
      if (error instanceof TooLargeError) return { base, failed: "body_cap" };
      this.#undecodable += 1;
      return { base, failed: "protection_failed" };
    }
  }

  #tokenized(
    base: Readonly<Record<string, unknown>>,
    role: string,
    mode: string,
    data: Buffer,
  ): ContentObject {
    const key = this.#tokenKey;
    if (key === undefined || key.byteLength < MIN_TOKEN_KEY_BYTES) {
      return this.#withheld(base, role, mode, "protection_failed");
    }
    let token: Buffer;
    try {
      token = tokenBytes(
        key,
        {
          schema_version: "fabric.token/v1",
          policy_digest: this.policy.policyDigest,
          tenant_id: typeof base.tenant_id === "string" ? base.tenant_id : null,
          workload_id: this.policy.workloadId ?? null,
          role,
        },
        data,
      );
    } catch {
      return this.#withheld(base, role, mode, "protection_failed");
    }
    return this.#stored(
      base,
      role,
      mode,
      token,
      "tokenized",
      ["tokenize"],
      "redacted",
      "tokenized",
      {},
      [TOKEN_TRANSFORMATION, "1"],
    );
  }

  async #redacted(
    base: Readonly<Record<string, unknown>>,
    role: string,
    mode: string,
    data: Buffer,
  ): Promise<ContentObject> {
    const transform = Object.hasOwn(this.#transforms, role) ? this.#transforms[role] : undefined;
    const client = this.#client;
    // No configured transformation or service: withheld, never raw bytes (§5).
    if (transform === undefined || client === undefined) {
      return this.#withheld(base, role, mode, "protection_failed");
    }
    // Timeout, redirect, non-200, connection error, oversized or malformed output and
    // saturation all resolve to null: withheld.
    const out = await client.transform(data, {
      transformation: transform,
      role,
      mode: mode === "redact" ? "redact" : "masked_only",
    });
    const row = ROLES.get(role);
    const cap =
      row === undefined ? 0 : Math.min(capBytes(row, this.maxBodyBytes), this.maxBodyBytes);
    if (out === null || out.byteLength > cap) {
      return this.#withheld(base, role, mode, "protection_failed");
    }
    return this.#stored(base, role, mode, out, "redacted", ["redact"], "redacted", "redacted", {}, [
      transform.id,
      transform.version,
    ]);
  }

  // ---------------------------------------------------------------- descriptors

  #core(
    base: Readonly<Record<string, unknown>>,
    role: string,
    mode: string,
    status: string,
    protection: string,
  ): Record<string, unknown> {
    const policy = this.policy;
    const descriptor: Record<string, unknown> = {
      ...base,
      object_id: randomUUID(),
      role,
      status,
      policy_id: policy.policyId,
      policy_version: policy.policyVersion,
      policy_digest: policy.policyDigest,
      privacy_mode: mode,
      protection_status: protection,
    };
    if (policy.workloadId !== undefined) descriptor.workload_id = policy.workloadId;
    return descriptor;
  }

  #stored(
    base: Readonly<Record<string, unknown>>,
    role: string,
    mode: string,
    data: Uint8Array,
    representation: string,
    transformations: string[],
    status: string,
    protection: string,
    source: Readonly<Record<string, unknown>>,
    transformation?: readonly [string, string],
  ): ContentObject {
    const descriptor = this.#core(base, role, mode, status, protection);
    Object.assign(descriptor, {
      representation,
      transformations,
      stored_byte_length: data.byteLength,
      stored_sha256: sha(data),
      ...source,
    });
    if (transformation !== undefined) {
      descriptor.transformation_id = transformation[0];
      descriptor.transformation_version = transformation[1];
    }
    return { descriptor, data };
  }

  /**
   * A descriptor-only object (`not_captured`): no bytes, no stored digest; a length only
   * where the mode allows one (never under redact, masked_only, tokenize or omit).
   */
  #withheld(
    base: Readonly<Record<string, unknown>>,
    role: string,
    mode: string,
    reason: string,
    sizes: { source_byte_length?: number } = {},
  ): ContentObject {
    const descriptor = this.#core(base, role, mode, "not_captured", "withheld");
    Object.assign(descriptor, {
      representation: "unavailable",
      transformations: [],
      status_reason: reason,
    });
    if (
      ["retain_original", "original_plus_masked", "metadata_only"].includes(mode) &&
      sizes.source_byte_length !== undefined
    ) {
      descriptor.source_byte_length = sizes.source_byte_length;
    }
    return { descriptor, data: new Uint8Array(0) };
  }

  /** Keeps `object` when the role table admits it; a refused object is never sent. */
  #admit(result: SideResult, object: ContentObject, primary: boolean, reason?: string): void {
    const d = object.descriptor;
    const admitted = admits(String(d.role), {
      boundary: String(d.boundary),
      provenance: String(d.provenance),
      mediaType: String(d.media_type),
      storedByteLength: object.data.byteLength,
      maxBodyBytes: this.maxBodyBytes,
    });
    if (!admitted) {
      result.reason ??= "store_failed";
      return;
    }
    result.objects.push(object);
    if (primary && isStored(object)) result.primary = object;
    if (!isStored(object)) result.reason ??= reason ?? String(d.status_reason);
  }
}
