// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/** Local capture configuration, never regulatory certification or an execution gate. */
import { createHmac } from "node:crypto";
import { sha256BytesPrefixed } from "./hash.js";
import { WorkerTransformRunner, redactorHref, type RedactorModule } from "./redactor-worker.js";

export type { RedactorModule } from "./redactor-worker.js";

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
   * The customer redactor of each `redact` / `masked_only` role: a module run in a
   * worker thread (spec 049 §7.1, §7.7), never a function on the application's thread.
   */
  redactors?: Readonly<Record<string, RedactorModule>>;
  tokenizationKey?: Uint8Array;
  payloadMaxBytes?: number;
  /** Hard timeout of one redactor call, in ms (default 5000, at most 300000). */
  transformTimeoutMs?: number;
}
/**
 * Customer redaction and irreversible whole-object HMAC pseudonyms.
 *
 * A redactor runs in a `worker_threads` Worker loaded from a customer module, bounded by
 * `transformTimeoutMs` (the Worker is terminated); an error, a timeout or a saturated
 * bound loses the content (`protection_failed`), never raw bytes. Masking roles are
 * protected with {@link ContentProtector.protectAsync}; the byte recorder runs it behind
 * the handoff, never on the caller's path.
 */
export class ContentProtector {
  readonly #runners: Readonly<Record<string, WorkerTransformRunner>>;
  readonly #key?: Uint8Array;
  readonly #modes: Readonly<Record<string, PrivacyMode>>;
  readonly payloadMaxBytes: number;
  readonly transformTimeoutMs: number;
  constructor(
    readonly policy: DeploymentPolicy,
    options: ContentProtectorOptions = {},
  ) {
    if (!(policy instanceof DeploymentPolicy))
      throw new Error("content protection requires a DeploymentPolicy");
    this.payloadMaxBytes = positive(options.payloadMaxBytes ?? 1024 * 1024, 64 * 1024 * 1024);
    this.#modes = policy.privacy;
    const timeout = options.transformTimeoutMs ?? 5_000;
    if (
      typeof timeout !== "number" ||
      !Number.isFinite(timeout) ||
      timeout <= 0 ||
      timeout > 300_000
    )
      throw new Error("transformTimeoutMs must be in (0, 300000]");
    this.transformTimeoutMs = timeout;
    const redactors = { ...options.redactors };
    if (Object.keys(redactors).some((role) => !MASKING.has(this.#modes[role] ?? "")))
      throw new Error("redactors must match explicitly redacted roles");
    for (const spec of Object.values(redactors)) redactorHref(spec); // fixed-text errors
    if (
      Object.entries(this.#modes).some(
        ([role, mode]) => MASKING.has(mode) && !Object.hasOwn(redactors, role),
      )
    )
      throw new Error("redact mode requires an explicit customer redactor for each role");
    this.#runners = Object.freeze(
      Object.fromEntries(
        Object.entries(redactors).map(([role, spec]) => [role, new WorkerTransformRunner(spec)]),
      ),
    );
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
  /** Whether protecting `role` runs a customer redactor (`redact`, `masked_only`). */
  runsCustomerCode(role: string): boolean {
    return typeof role === "string" && MASKING.has(this.#modes[role] ?? "");
  }

  /** Counters of the redactor Workers, summed over roles (never a value). */
  stats(): {
    transform_timeouts: number;
    transform_saturated: number;
    transform_abandoned: number;
  } {
    const totals = { transform_timeouts: 0, transform_saturated: 0, transform_abandoned: 0 };
    for (const runner of Object.values(this.#runners)) {
      const counts = runner.stats();
      totals.transform_timeouts += counts.transform_timeouts;
      totals.transform_saturated += counts.transform_saturated;
      totals.transform_abandoned += counts.transform_abandoned;
    }
    return totals;
  }

  /** Terminate idle redactor Workers; later redactions are lost (`protection_failed`). */
  async close(): Promise<void> {
    await Promise.all(Object.values(this.#runners).map((runner) => runner.close()));
  }

  /**
   * Protect one object. Masking roles run their redactor module in a Worker, bounded by
   * `transformTimeoutMs`; every other mode is {@link ContentProtector.protect}.
   */
  async protectAsync(role: string, data: Uint8Array): Promise<ProtectedContent> {
    if (!this.runsCustomerCode(role) || !(data instanceof Uint8Array))
      return this.protect(role, data);
    const mode = this.#modes[role]!;
    const metadata: Record<string, string | number> = { policy_digest: this.policy.digest };
    const result = (status: ProtectionStatus, reason: string, bytes: Uint8Array | null = null) =>
      new ProtectedContent(status, mode, null, Object.freeze({ ...metadata, reason }), bytes);
    if (data.byteLength > this.payloadMaxBytes) return result("lost", "payload_too_large");
    const outcome = await this.#runners[role]!.run(data, this.transformTimeoutMs);
    if (outcome.outcome === "invalid_output")
      return result("unsupported", "unsupported_transform_output");
    if (outcome.outcome !== "ok") return result("lost", "protection_failed");
    if (outcome.data.byteLength > this.payloadMaxBytes)
      return result("lost", "protected_payload_too_large");
    metadata.transform = "customer_redactor";
    return result("redacted", "redacted_by_customer", outcome.data);
  }

  /**
   * Protect one object synchronously: every mode but `redact` and `masked_only`, whose
   * customer redactor runs only in a Worker ({@link ContentProtector.protectAsync}); for
   * those this fails closed (`unsupported`, `redaction_requires_protect_async`).
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
        // Customer code never runs on the caller's thread (spec 049 §7.1): protectAsync.
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
