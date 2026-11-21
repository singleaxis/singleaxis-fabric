// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The PROTECT stage of wire capture (spec 055 §5; Python `wire/_protect.py` and
 * `wire/_policy.py`), run by the Fabric worker before anything is spooled. Nothing
 * reaches the spool, a store or the network before it ran, and a failure withholds the
 * content: there is never a fallback to raw bytes.
 *
 * Order: captured bytes -> typed extraction (split, `parts.ts`) -> protect each object ->
 * digest per mode -> link. The modes are `omit`, `metadata_only`, `retain_original`,
 * `redact`, `masked_only`, `tokenize` (units `055-t8`) and `original_plus_masked` (unit
 * `055-t15`). A digest of the original body, and the parts' `byte_range`, exist only
 * under `retain_original` and `original_plus_masked`. `redact`, `masked_only` and the
 * review copies of `original_plus_masked` are made by the customer-run redaction service
 * through the existing {@link RedactionClient}, built in the Fabric worker; `tokenize` is
 * the existing whole-object HMAC ({@link tokenBytes}). An `original_plus_masked` object
 * and its review copy are both produced before either is admitted: a failed copy
 * withholds both.
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
import {
  DEFAULT_PART_MIN_BYTES,
  PART_ROLE,
  type Part,
  findParts,
  partBytes,
  partObjectId,
  skeletonOf,
} from "./parts.js";
import { ROLES, admits, capBytes } from "./roles.js";
import { ROLE_ROWS, ROLE_TABLE_VERSION } from "./roles.generated.js";

export const ROLE_REQUEST = "model.exchange.request";
export const ROLE_RESPONSE = "model.exchange.response";
export { PART_ROLE } from "./parts.js";
export const LOCAL_DEFAULT_ID = "fabric.local-default";
const MIN_TOKEN_KEY_BYTES = 32;
/** Python `DEFAULT_MAX_RETAIN_BYTES`: the largest side the Fabric worker splits. */
export const DEFAULT_MAX_RETAIN_BYTES = 64 * 1024 * 1024;

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

export { ROLES, admits, admitsMedia, capBytes } from "./roles.js";

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

const MASKING_MODES: ReadonlySet<string> = new Set([
  "redact",
  "masked_only",
  "original_plus_masked",
]);

/**
 * Whether the policy gives a model-exchange role a mode that needs the customer's
 * transformation (`redact`, `masked_only`, `original_plus_masked`; for the part role
 * `original_plus_masked`, since a binary part under `redact` is withheld by policy anyway)
 * while the service or that role's transformation is missing, so its content is withheld
 * (`FW-032`).
 */
export function maskingWithheld(
  policy: CapturePolicy,
  service: boolean,
  transformations: Readonly<Record<string, unknown>>,
): boolean {
  const roles: [string, ReadonlySet<string>][] = [
    [ROLE_REQUEST, MASKING_MODES],
    [ROLE_RESPONSE, MASKING_MODES],
    [PART_ROLE, new Set(["original_plus_masked"])],
  ];
  return roles.some(
    ([role, modes]) =>
      modes.has(modeOf(policy, role)) && (!service || !Object.hasOwn(transformations, role)),
  );
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
  /** The largest side that may be split (`max_retain_bytes`; default 64 MiB). */
  readonly maxRetainBytes?: number;
  /** The smallest inline part extracted (`part_min_bytes`; default 64 KiB). */
  readonly partMinBytes?: number;
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

type Base = Readonly<Record<string, unknown>>;

/** The descriptor sizes a withheld object may carry, where its mode allows them. */
interface Sizes {
  readonly source_byte_length?: number;
  readonly source_sha256?: string;
}

/** Applies the capture policy to one exchange side (049 §7.5; Python `Protector`). */
export class Protector {
  readonly policy: CapturePolicy;
  readonly maxBodyBytes: number;
  readonly maxRetainBytes: number;
  readonly partMinBytes: number;
  readonly #transforms: Readonly<Record<string, Transformation>>;
  readonly #client: RedactionClient | undefined;
  readonly #tokenKey: Uint8Array | undefined;
  #undecodable = 0;

  constructor(policy: CapturePolicy, options: ProtectorOptions) {
    this.policy = policy;
    this.maxBodyBytes = options.maxBodyBytes;
    this.maxRetainBytes = options.maxRetainBytes ?? DEFAULT_MAX_RETAIN_BYTES;
    this.partMinBytes = options.partMinBytes ?? DEFAULT_PART_MIN_BYTES;
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
   *
   * A complete, plain JSON side over `max_body_bytes` (and at most `max_retain_bytes`)
   * whose inline parts take it under `max_body_bytes` is split: a skeleton (the original
   * bytes without the parts' ranges) plus one `model.exchange.part` object per part, each
   * under the part role's own mode. Any other side over `max_body_bytes` is cut to its
   * longest whole-piece prefix (`body_cap`).
   */
  async side(
    base: Base,
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
    let whole: Buffer | undefined;
    let parts: Part[] | undefined;
    if (cut === undefined && total > this.maxBodyBytes) {
      const splittable =
        total <= this.maxRetainBytes &&
        base.content_encoding === "identity" &&
        base.media_type === "application/json" &&
        !input.partial;
      if (splittable) {
        whole = Buffer.concat(pieces, total);
        const found = findParts(whole, this.partMinBytes);
        if (found !== null && found.length > 0 && total - partBytes(found) <= this.maxBodyBytes) {
          parts = found;
        }
      }
      if (parts === undefined) cut = "body_cap"; // not split: stored truncated, as before 049
    }
    const data =
      cut !== undefined && total > this.maxBodyBytes
        ? wholePiecePrefix(pieces, this.maxBodyBytes)
        : (whole ?? Buffer.concat(pieces, total));
    const result: SideResult = {
      objects: [],
      primary: undefined,
      reason: undefined,
      truncated: cut !== undefined,
    };
    if (mode === "original_plus_masked") {
      await this.#withReviewCopy(result, base, role, data, parts, input, cut);
    } else if (mode === "retain_original") {
      await this.#original(result, base, role, mode, data, parts, input, cut);
    } else {
      await this.#transformed(result, base, role, mode, data, parts, cut);
    }
    if (result.reason === undefined && cut !== undefined) result.reason = cut;
    return result;
  }

  // ---------------------------------------------------------------------- modes

  async #original(
    result: SideResult,
    base: Base,
    role: string,
    mode: string,
    data: Buffer,
    parts: readonly Part[] | undefined,
    input: SideInput,
    cut: string | undefined,
  ): Promise<void> {
    if (cut !== undefined && data.byteLength === 0) {
      result.reason = cut; // no whole piece fit: nothing useful to store
      return;
    }
    let primary: ContentObject;
    if (cut !== undefined) {
      // The bytes forwarded past the cut are not counted by the hook: the source length
      // is given only when it is known (Python: max(observed, stored + 1)).
      const source =
        input.observed === undefined
          ? {}
          : { source_byte_length: Math.max(input.observed, data.byteLength + 1) };
      primary = this.#stored(
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
      // The original's digest: of the whole body, also when the side is split, so the
      // skeleton and the parts reassemble to `source_sha256`.
      const source = { source_byte_length: data.byteLength, source_sha256: sha(data) };
      if (parts === undefined) {
        const representation = input.partial ? "partial" : "exact";
        primary = this.#stored(
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
      } else {
        const skeleton = skeletonOf(data, parts);
        primary = this.#stored(
          base,
          role,
          mode,
          skeleton,
          "split",
          ["extract_parts"],
          "stored",
          "retained",
          source,
        );
      }
    }
    this.#admit(result, primary, true);
    const skeletonId = String(primary.descriptor.object_id);
    for (const [index, part] of (parts ?? []).entries()) {
      await this.#part(result, base, data, part, skeletonId, index, true);
    }
  }

  async #transformed(
    result: SideResult,
    base: Base,
    role: string,
    mode: string,
    data: Buffer,
    parts: readonly Part[] | undefined,
    cut: string | undefined,
  ): Promise<void> {
    if (cut !== undefined) {
      // A cut prefix is never transformed (049 §7.5: no claim about the whole).
      this.#admit(result, this.#withheld(base, role, mode, cut), true, cut);
      return;
    }
    let object: ContentObject;
    if (parts === undefined) {
      const plain = this.#plaintext(base, data);
      if (plain.data === undefined) {
        this.#admit(result, this.#withheld(base, role, mode, plain.failed), true, plain.failed);
        return;
      }
      object = await this.#protect(plain.base, role, mode, plain.data, false);
    } else {
      // Parts exist only for an identity body: the skeleton is the plaintext.
      object = await this.#protect(base, role, mode, skeletonOf(data, parts), true);
    }
    this.#admit(result, object, true);
    const skeletonId = String(object.descriptor.object_id);
    for (const [index, part] of (parts ?? []).entries()) {
      await this.#part(result, base, data, part, skeletonId, index, false);
    }
  }

  /**
   * One extracted part, under the part role's own mode (049 §7.5; a policy that does not
   * name the part role omits it). Its object id is derived from the skeleton's and its
   * position ({@link partObjectId}); its `byte_range` exists only when both the part and
   * the skeleton are retained originals.
   */
  async #part(
    result: SideResult,
    base: Base,
    data: Buffer,
    part: Part,
    skeletonId: string,
    index: number,
    retainSkeleton: boolean,
  ): Promise<void> {
    const mode = modeOf(this.policy, PART_ROLE);
    if (mode === "omit") return;
    const partBase = { ...base, media_type: part.mediaType, content_encoding: "base64" };
    const length = part.end - part.start;
    const bytes = data.subarray(part.start, part.end);
    const link: Record<string, unknown> = { relation: "part_of", object_id: skeletonId };
    const retained = mode === "retain_original" || mode === "original_plus_masked";
    if (retained && retainSkeleton) link.byte_range = [part.start, part.end];
    if (mode === "original_plus_masked" && length <= this.maxBodyBytes) {
      await this.#partWithReviewCopy(result, partBase, bytes, skeletonId, index, link);
      return;
    }
    let object: ContentObject;
    if (mode === "metadata_only") {
      object = this.#withheld(partBase, PART_ROLE, mode, "privacy_policy", {
        source_byte_length: length,
      });
    } else if (length > this.maxBodyBytes) {
      // Beyond the object cap: descriptor-only; a retaining mode keeps its digest.
      const sizes: Sizes = retained
        ? { source_byte_length: length, source_sha256: sha(bytes) }
        : { source_byte_length: length };
      object = this.#withheld(partBase, PART_ROLE, mode, "part_cap", sizes);
    } else if (retained) {
      const source = { source_byte_length: length, source_sha256: sha(bytes) };
      object = this.#stored(
        partBase,
        PART_ROLE,
        mode,
        bytes,
        "exact",
        [],
        "stored",
        "retained",
        source,
      );
    } else if (
      (mode === "redact" || mode === "masked_only") &&
      !Object.hasOwn(this.#transforms, PART_ROLE)
    ) {
      // Binary a text transformation cannot handle: withheld (049 §7.5).
      object = this.#withheld(partBase, PART_ROLE, mode, "privacy_policy");
    } else {
      object = await this.#protect(partBase, PART_ROLE, mode, bytes, false);
    }
    object.descriptor.links = [link];
    object.descriptor.object_id = partObjectId(skeletonId, index);
    this.#admit(result, object, false);
  }

  /**
   * An `original_plus_masked` part: the whole-side rule per part. The original part and
   * its masked review copy (`part_of` the skeleton, `derived_from` the part) are both
   * produced before either is admitted; a failed copy withholds both,
   * `not_captured(protection_failed)` with no digest, length or range of the original.
   */
  async #partWithReviewCopy(
    result: SideResult,
    partBase: Base,
    bytes: Buffer,
    skeletonId: string,
    index: number,
    link: Record<string, unknown>,
  ): Promise<void> {
    const mode = "original_plus_masked";
    let review = await this.#redacted(partBase, PART_ROLE, mode, bytes, false);
    let original: ContentObject;
    if (isStored(review) && this.#admissible(review)) {
      const source = { source_byte_length: bytes.byteLength, source_sha256: sha(bytes) };
      original = this.#stored(
        partBase,
        PART_ROLE,
        mode,
        bytes,
        "exact",
        [],
        "stored",
        "retained",
        source,
      );
    } else {
      delete link.byte_range;
      original = this.#withheld(partBase, PART_ROLE, mode, "protection_failed");
      review = this.#withheld(partBase, PART_ROLE, mode, "protection_failed");
    }
    original.descriptor.links = [link];
    original.descriptor.object_id = partObjectId(skeletonId, index);
    review.descriptor.links = [
      { relation: "part_of", object_id: skeletonId },
      { relation: "derived_from", object_id: original.descriptor.object_id },
    ];
    this.#admit(result, original, false);
    this.#admit(result, review, false);
  }

  /**
   * `original_plus_masked`: the masked review copy of the whole side is produced before
   * anything is admitted, so a failed copy withholds the original too (049 §7.7 rule 4:
   * never raw bytes on failure). The copy masks the plaintext; the original stays the wire
   * bytes, split or not. A cut side's copy is withheld with the cut's reason.
   */
  async #withReviewCopy(
    result: SideResult,
    base: Base,
    role: string,
    data: Buffer,
    parts: readonly Part[] | undefined,
    input: SideInput,
    cut: string | undefined,
  ): Promise<void> {
    const mode = "original_plus_masked";
    let review: ContentObject;
    if (cut !== undefined) {
      review = this.#withheld(base, role, mode, cut);
    } else {
      const plain = this.#plaintext(base, data);
      review =
        plain.data === undefined
          ? this.#withheld(base, role, mode, "protection_failed")
          : await this.#redacted(plain.base, role, mode, plain.data, false);
      if (!(isStored(review) && this.#admissible(review))) {
        this.#withholdPair(result, base, role, mode);
        return;
      }
    }
    await this.#original(result, base, role, mode, data, parts, input, cut);
    // One review copy per side, linked `derived_from` the original; it never satisfies a
    // requirement for the original.
    if (result.primary === undefined) return;
    review.descriptor.links = [
      { relation: "derived_from", object_id: result.primary.descriptor.object_id },
    ];
    this.#admit(result, review, false);
  }

  /**
   * `original_plus_masked` whose masked copy could not be produced: both objects are
   * descriptor-only `not_captured(protection_failed)`, with no digest or length of the
   * original.
   */
  #withholdPair(result: SideResult, base: Base, role: string, mode: string): void {
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
  #plaintext(base: Base, data: Buffer): { base: Base; data?: Buffer; failed: string } {
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

  // ------------------------------------------------------------ transformations

  #protect(
    base: Base,
    role: string,
    mode: string,
    data: Buffer,
    split: boolean,
  ): Promise<ContentObject> {
    if (mode === "tokenize") return Promise.resolve(this.#tokenized(base, role, mode, data, split));
    return this.#redacted(base, role, mode, data, split);
  }

  #tokenized(base: Base, role: string, mode: string, data: Buffer, split: boolean): ContentObject {
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
    const steps = split ? ["extract_parts", "tokenize"] : ["tokenize"];
    return this.#stored(base, role, mode, token, "tokenized", steps, "redacted", "tokenized", {}, [
      TOKEN_TRANSFORMATION,
      "1",
    ]);
  }

  async #redacted(
    base: Base,
    role: string,
    mode: string,
    data: Buffer,
    split: boolean,
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
    const steps = split ? ["extract_parts", "redact"] : ["redact"];
    return this.#stored(base, role, mode, out, "redacted", steps, "redacted", "redacted", {}, [
      transform.id,
      transform.version,
    ]);
  }

  // ---------------------------------------------------------------- descriptors

  #core(
    base: Base,
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
    base: Base,
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
   * where the mode allows one (never under redact, masked_only, tokenize or omit) and the
   * original's digest only under a retaining mode.
   */
  #withheld(
    base: Base,
    role: string,
    mode: string,
    reason: string,
    sizes: Sizes = {},
  ): ContentObject {
    const descriptor = this.#core(base, role, mode, "not_captured", "withheld");
    Object.assign(descriptor, {
      representation: "unavailable",
      transformations: [],
      status_reason: reason,
    });
    const retaining = mode === "retain_original" || mode === "original_plus_masked";
    if ((retaining || mode === "metadata_only") && sizes.source_byte_length !== undefined) {
      descriptor.source_byte_length = sizes.source_byte_length;
    }
    if (retaining && sizes.source_sha256 !== undefined)
      descriptor.source_sha256 = sizes.source_sha256;
    return { descriptor, data: new Uint8Array(0) };
  }

  /** Whether the role table admits `object` (049 §4.3 rules 1-4). */
  #admissible(object: ContentObject): boolean {
    const d = object.descriptor;
    return admits(String(d.role), {
      boundary: String(d.boundary),
      provenance: String(d.provenance),
      mediaType: String(d.media_type),
      storedByteLength: object.data.byteLength,
      maxBodyBytes: this.maxBodyBytes,
    });
  }

  /** Keeps `object` when the role table admits it; a refused object is never sent. */
  #admit(result: SideResult, object: ContentObject, primary: boolean, reason?: string): void {
    if (!this.#admissible(object)) {
      result.reason ??= "store_failed";
      return;
    }
    result.objects.push(object);
    if (primary && isStored(object)) result.primary = object;
    if (!isStored(object)) result.reason ??= reason ?? String(object.descriptor.status_reason);
  }
}
