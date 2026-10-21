// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/** Local capture configuration, never regulatory certification or an execution gate. */
import { createHmac } from "node:crypto";
import { sha256BytesPrefixed } from "./hash.js";
import {
  RedactionClient,
  checkTransformation,
  parseRedactionEndpoint,
  redactionServiceFromEnv,
  redactorRemovedError,
  type RedactionServiceOptions,
  type RedactionStats,
  type Transformation,
} from "./redaction.js";

export const POLICY_SCHEMA_VERSION = "fabric.deployment-policy/v1";
// masked_only and original_plus_masked: spec 049 §7.7 rule 2 (minor, P0-A).
export type PrivacyMode =
  | "metadata_only"
  | "omit"
  | "redact"
  | "tokenize"
  | "retain_original"
  | "masked_only"
  | "original_plus_masked";
export type ProtectionStatus =
  | "withheld"
  | "redacted"
  | "tokenized"
  | "retained"
  | "unsupported"
  | "lost";
export const PRIVACY_MODES: ReadonlySet<string> = new Set([
  "metadata_only",
  "omit",
  "redact",
  "tokenize",
  "retain_original",
  "masked_only",
  "original_plus_masked",
]);
/**
 * Modes whose stored object is a customer-masked copy (spec 049 §7.7 rule 3). An
 * `original_plus_masked` role needs two objects, which this single-object protector
 * does not make: it reports `unsupported` and stores nothing (fails closed).
 */
const MASKING: ReadonlySet<string> = new Set(["redact", "masked_only"]);
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

export interface DeploymentPolicyData {
  schema_version: typeof POLICY_SCHEMA_VERSION;
  policy_id: string;
  policy_version: number;
  tenant_id: string;
  workload_id: string;
  privacy: Record<string, PrivacyMode>;
  storage: { backend: "local"; region: string; key_id: string; root?: string };
  retention: { days: number };
  required_integrations: string[];
  deployment: {
    profile: "local" | "production";
    image_digest: string;
    tls_required: boolean;
    encrypted_store_required: boolean;
  };
}

function object(
  value: unknown,
  required: string[],
  optional: string[] = [],
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error("invalid deployment policy object");
  const data = value as Record<string, unknown>;
  if (
    required.some((k) => !Object.hasOwn(data, k)) ||
    Object.keys(data).some((k) => !required.includes(k) && !optional.includes(k))
  )
    throw new Error("invalid deployment policy fields");
  return { ...data };
}
function identifier(value: unknown): string {
  if (typeof value !== "string" || !ID.test(value))
    throw new Error("deployment policy requires opaque ASCII identifiers");
  return value;
}
function positive(value: unknown, max: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > max)
    throw new Error("deployment policy integer is outside its bounds");
  return value;
}
/** Compact sorted ASCII JSON; inputs here contain only ASCII strings and safe integers. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value !== null && typeof value === "object") {
    const data = value as Record<string, unknown>;
    return (
      "{" +
      Object.keys(data)
        .sort()
        .map((k) => JSON.stringify(k) + ":" + canonical(data[k]))
        .join(",") +
      "}"
    );
  }
  return JSON.stringify(value);
}

export class DeploymentPolicy {
  readonly #canonical: string;
  readonly #digest: string;
  constructor(value: unknown) {
    const data = object(value, [
      "schema_version",
      "policy_id",
      "policy_version",
      "tenant_id",
      "workload_id",
      "privacy",
      "storage",
      "retention",
      "required_integrations",
      "deployment",
    ]);
    if (data.schema_version !== POLICY_SCHEMA_VERSION)
      throw new Error("unsupported deployment policy schema version");
    for (const key of ["policy_id", "tenant_id", "workload_id"]) data[key] = identifier(data[key]);
    data.policy_version = positive(data.policy_version, 2147483647);
    const privacy = object(
      data.privacy,
      [],
      typeof data.privacy === "object" && data.privacy !== null ? Object.keys(data.privacy) : [],
    );
    if (Object.keys(privacy).length < 1 || Object.keys(privacy).length > 256)
      throw new Error("deployment privacy requires a bounded role map");
    for (const [role, mode] of Object.entries(privacy)) {
      identifier(role);
      if (typeof mode !== "string" || !PRIVACY_MODES.has(mode))
        throw new Error("unsupported deployment privacy mode");
    }
    data.privacy = privacy;
    const storage = object(data.storage, ["backend", "region", "key_id"], ["root"]);
    if (storage.backend !== "local") throw new Error("unsupported deployment storage backend");
    storage.region = identifier(storage.region);
    storage.key_id = identifier(storage.key_id);
    if (
      storage.root !== undefined &&
      (typeof storage.root !== "string" ||
        storage.root.length < 1 ||
        storage.root.length > 4096 ||
        /[^\x20-\x7e]/.test(storage.root))
    )
      throw new Error("storage root must be a bounded printable ASCII path");
    data.storage = storage;
    const retention = object(data.retention, ["days"]);
    retention.days = positive(retention.days, 36500);
    data.retention = retention;
    if (!Array.isArray(data.required_integrations) || data.required_integrations.length > 256)
      throw new Error("required integrations must be a bounded list");
    const integrations = data.required_integrations.map(identifier);
    if (new Set(integrations).size !== integrations.length)
      throw new Error("required integrations must be unique");
    data.required_integrations = integrations.sort();
    const deployment = object(data.deployment, [
      "profile",
      "image_digest",
      "tls_required",
      "encrypted_store_required",
    ]);
    if (deployment.profile !== "local" && deployment.profile !== "production")
      throw new Error("unsupported deployment profile");
    if (
      typeof deployment.image_digest !== "string" ||
      (deployment.image_digest !== "local" && !DIGEST.test(deployment.image_digest))
    )
      throw new Error("image digest must be local or a pinned SHA-256 digest");
    if (
      typeof deployment.tls_required !== "boolean" ||
      typeof deployment.encrypted_store_required !== "boolean"
    )
      throw new Error("deployment security flags must be booleans");
    if (
      deployment.profile === "production" &&
      (deployment.image_digest === "local" ||
        !deployment.tls_required ||
        !deployment.encrypted_store_required)
    )
      throw new Error("production requires pinned image, TLS and encrypted storage");
    data.deployment = deployment;
    this.#canonical = canonical(data);
    this.#digest = sha256BytesPrefixed(Buffer.from(this.#canonical, "ascii"));
  }
  static fromDict(value: unknown): DeploymentPolicy {
    return new DeploymentPolicy(value);
  }
  static from_dict(value: unknown): DeploymentPolicy {
    return new DeploymentPolicy(value);
  }
  toDict(): DeploymentPolicyData {
    return JSON.parse(this.#canonical) as DeploymentPolicyData;
  }
  to_dict(): DeploymentPolicyData {
    return this.toDict();
  }
  get digest(): string {
    return this.#digest;
  }
  get schema_version(): typeof POLICY_SCHEMA_VERSION {
    return POLICY_SCHEMA_VERSION;
  }
  get policy_id(): string {
    return this.toDict().policy_id;
  }
  get policy_version(): number {
    return this.toDict().policy_version;
  }
  get tenant_id(): string {
    return this.toDict().tenant_id;
  }
  get workload_id(): string {
    return this.toDict().workload_id;
  }
  get privacy(): Readonly<Record<string, PrivacyMode>> {
    return Object.freeze(this.toDict().privacy);
  }
  get storage(): Readonly<DeploymentPolicyData["storage"]> {
    return Object.freeze(this.toDict().storage);
  }
  get retention(): Readonly<DeploymentPolicyData["retention"]> {
    return Object.freeze(this.toDict().retention);
  }
  get deployment(): Readonly<DeploymentPolicyData["deployment"]> {
    return Object.freeze(this.toDict().deployment);
  }
  get required_integrations(): readonly string[] {
    return Object.freeze(this.toDict().required_integrations);
  }
}

export class ProtectedContent {
  readonly #bytes: Uint8Array | null;
  constructor(
    readonly status: ProtectionStatus,
    readonly mode: PrivacyMode,
    readonly original_digest: string | null,
    readonly metadata: Readonly<Record<string, string | number>>,
    bytes: Uint8Array | null = null,
  ) {
    this.#bytes = bytes === null ? null : new Uint8Array(bytes);
  }
  get protected_bytes(): Uint8Array | null {
    return this.#bytes === null ? null : new Uint8Array(this.#bytes);
  }
  get protectedBytes(): Uint8Array | null {
    return this.protected_bytes;
  }
  get originalDigest(): string | null {
    return this.original_digest;
  }
  toDict(): Record<string, unknown> {
    return {
      status: this.status,
      mode: this.mode,
      original_digest: this.original_digest,
      metadata: { ...this.metadata },
    };
  }
  to_dict(): Record<string, unknown> {
    return this.toDict();
  }
  toJSON(): Record<string, unknown> {
    return this.toDict();
  }
}
export interface ContentProtectorOptions {
  /**
   * The customer transformation `{ id, version }` of each `redact` / `masked_only` role,
   * performed by the customer-run redaction service (spec 049 §7.7,
   * `contracts/redaction/v1`), never by code in this process.
   */
  transformations?: Readonly<Record<string, Transformation>>;
  /** The redaction service; `FABRIC_REDACTION_ENDPOINT` when unset. */
  redaction?: RedactionServiceOptions;
  tokenizationKey?: Uint8Array;
  payloadMaxBytes?: number;
}
/**
 * Customer redaction and irreversible whole-object HMAC pseudonyms.
 *
 * A masking role is redacted by the customer-run redaction service, called by
 * {@link ContentProtector.protectAsync} through one bounded connection pool; a failed,
 * slow or saturated call loses the content (`protection_failed`), never raw bytes. The
 * byte recorder runs it behind the handoff, never on the caller's path.
 */
export class ContentProtector {
  readonly #client?: RedactionClient;
  readonly #transformations: Readonly<Record<string, Transformation>>;
  readonly #key?: Uint8Array;
  readonly #modes: Readonly<Record<string, PrivacyMode>>;
  readonly payloadMaxBytes: number;
  constructor(
    readonly policy: DeploymentPolicy,
    options: ContentProtectorOptions = {},
  ) {
    if (!(policy instanceof DeploymentPolicy))
      throw new Error("content protection requires a DeploymentPolicy");
    const legacy = options as Record<string, unknown>;
    if (legacy.redactors !== undefined || legacy.transformTimeoutMs !== undefined)
      throw redactorRemovedError();
    this.payloadMaxBytes = positive(options.payloadMaxBytes ?? 1024 * 1024, 64 * 1024 * 1024);
    this.#modes = policy.privacy;
    const transformations: Record<string, Transformation> = {};
    for (const [role, value] of Object.entries(options.transformations ?? {}))
      transformations[role] = checkTransformation(value);
    if (Object.keys(transformations).some((role) => !MASKING.has(this.#modes[role] ?? "")))
      throw new Error("transformations must match explicitly redacted roles");
    const masking = Object.entries(this.#modes).filter(([, mode]) => MASKING.has(mode));
    if (masking.some(([role]) => !Object.hasOwn(transformations, role)))
      throw new Error("redact mode requires an explicit customer transformation for each role");
    this.#transformations = Object.freeze(transformations);
    // A malformed endpoint is a configuration error even when no role needs it.
    const service =
      options.redaction ??
      redactionServiceFromEnv(typeof process !== "undefined" ? process.env : {});
    if (service !== undefined) parseRedactionEndpoint(service.endpoint);
    if (masking.length > 0) {
      if (service === undefined)
        throw new Error(
          "masking modes require a redaction service endpoint (FABRIC_REDACTION_ENDPOINT)",
        );
      this.#client = new RedactionClient(service, { maxOutputBytes: this.payloadMaxBytes });
    }
    if (
      options.tokenizationKey !== undefined &&
      (!(options.tokenizationKey instanceof Uint8Array) || options.tokenizationKey.byteLength < 32)
    )
      throw new Error("tokenization requires a key of at least 32 bytes");
    if (Object.values(this.#modes).includes("tokenize") && options.tokenizationKey === undefined)
      throw new Error("tokenize mode requires a caller-supplied key");
    this.#key =
      options.tokenizationKey === undefined ? undefined : new Uint8Array(options.tokenizationKey);
  }
  /** Whether protecting `role` calls the redaction service (`redact`, `masked_only`). */
  needsRedactionService(role: string): boolean {
    return typeof role === "string" && MASKING.has(this.#modes[role] ?? "");
  }

  /** The transformation configured for a masking `role`. */
  transformationFor(role: string): Transformation | undefined {
    return Object.hasOwn(this.#transformations, role) ? this.#transformations[role] : undefined;
  }

  /** Counters of the redaction service calls (never a value). */
  stats(): RedactionStats {
    return (
      this.#client?.stats() ?? {
        redaction_timeouts: 0,
        redaction_saturated: 0,
        redaction_failures: 0,
      }
    );
  }

  /** Close the redaction service connection pool; later redactions are lost. */
  async close(): Promise<void> {
    await this.#client?.close();
  }

  /**
   * Protect one object. Masking roles are sent to the redaction service, bounded by its
   * timeout and in-flight bound; every other mode is {@link ContentProtector.protect}.
   */
  async protectAsync(role: string, data: Uint8Array): Promise<ProtectedContent> {
    if (!this.needsRedactionService(role) || !(data instanceof Uint8Array))
      return this.protect(role, data);
    const mode = this.#modes[role]!;
    const metadata: Record<string, string | number> = { policy_digest: this.policy.digest };
    const result = (status: ProtectionStatus, reason: string, bytes: Uint8Array | null = null) =>
      new ProtectedContent(status, mode, null, Object.freeze({ ...metadata, reason }), bytes);
    if (data.byteLength > this.payloadMaxBytes) return result("lost", "payload_too_large");
    const transformation = this.#transformations[role]!;
    const out = await this.#client!.transform(data, {
      transformation,
      role,
      mode: mode as "redact" | "masked_only",
    });
    if (out === null) return result("lost", "protection_failed");
    if (out.byteLength > this.payloadMaxBytes) return result("lost", "protected_payload_too_large");
    metadata.transform = "redaction_service";
    metadata.transformation_id = transformation.id;
    metadata.transformation_version = transformation.version;
    return result("redacted", "redacted_by_customer", out);
  }

  /**
   * Protect one object synchronously: every mode but `redact` and `masked_only`, which
   * call the redaction service ({@link ContentProtector.protectAsync}); for those this
   * fails closed (`unsupported`, `redaction_requires_protect_async`).
   */
  protect(role: string, data: Uint8Array): ProtectedContent {
    const mode = Object.hasOwn(this.#modes, role) ? this.#modes[role]! : "omit";
    const metadata: Record<string, string | number> = { policy_digest: this.policy.digest };
    const result = (
      status: ProtectionStatus,
      reason: string,
      bytes: Uint8Array | null = null,
      original: string | null = null,
    ) =>
      new ProtectedContent(status, mode, original, Object.freeze({ ...metadata, reason }), bytes);
    if (mode === "omit") return result("withheld", "omitted_by_policy");
    if (!(data instanceof Uint8Array)) return result("unsupported", "unsupported_input_type");
    if (mode === "metadata_only") {
      metadata.source_byte_length = data.byteLength;
      return result("withheld", "metadata_only");
    }
    if (data.byteLength > this.payloadMaxBytes) return result("lost", "payload_too_large");
    try {
      if (mode === "retain_original") {
        metadata.source_byte_length = data.byteLength;
        return result("retained", "original_retained", data, sha256BytesPrefixed(data));
      }
      if (MASKING.has(mode)) {
        // The service is never called on the caller's path (spec 049 §7.1): protectAsync.
        return result("unsupported", "redaction_requires_protect_async");
      }
      if (mode === "tokenize" && this.#key !== undefined) {
        const scope = Buffer.from(
          canonical({
            schema_version: "fabric.token/v1",
            policy_digest: this.policy.digest,
            tenant_id: this.policy.tenant_id,
            workload_id: this.policy.workload_id,
            role,
          }),
          "ascii",
        );
        const scopeLength = Buffer.alloc(4);
        scopeLength.writeUInt32BE(scope.length);
        const dataLength = Buffer.alloc(8);
        dataLength.writeBigUInt64BE(BigInt(data.byteLength));
        const token = createHmac("sha256", this.#key)
          .update(scopeLength)
          .update(scope)
          .update(dataLength)
          .update(data)
          .digest("hex");
        const payload = Buffer.from("fabric.token.v1:" + token, "ascii");
        if (payload.byteLength > this.payloadMaxBytes)
          return result("lost", "protected_payload_too_large");
        metadata.transform = "hmac_sha256_whole_object_v1";
        return result("tokenized", "tokenized_by_policy", payload);
      }
    } catch {
      return result("lost", "protection_failed");
    }
    return result("unsupported", "unsupported_protection_mode");
  }
}
