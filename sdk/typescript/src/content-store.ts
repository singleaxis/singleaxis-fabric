// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Governed content stores (spec 033) — mirrors Python `fabric.content_store`.
 *
 * `GovernedStore` is the write/read contract the governed pipeline and the
 * resolver share. The local adapter is fully synchronous (atomic
 * tmp+fsync+rename under a tenant namespace). The S3 adapter is
 * asynchronous: it lazily requires the optional `@aws-sdk/client-s3`
 * peer, exactly like Python's optional `boto3`.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { createRequire } from "node:module";

import { createHash } from "node:crypto";
import { sha256Hex } from "./hash.js";

/** A reference to stored content: tenant-resolvable URI + integrity hash. */
export interface ContentRef {
  uri: string;
  contentHash: string;
}

/** A pre-existing object failed digest verification; never overwritten. */
export class CorruptedObjectError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CorruptedObjectError";
  }
}

type MaybePromise<T> = T | Promise<T>;

/**
 * Governed-content store contract (specs 028/033). Methods may return a
 * value or a Promise — the writer awaits either. `synchronous === true`
 * means `putObject` completes inline (required for `inline` durability).
 */
export interface GovernedStore {
  /** Tenant namespace this store is confined to; must be non-empty. */
  readonly tenantId: string;
  /** True when `putObject` returns an already-settled value. */
  readonly synchronous: boolean;

  /**
   * Deterministic resolution URI for `digest` — returned before the
   * object is confirmed stored so telemetry can carry the final
   * reference while delivery is pending.
   */
  refFor(digest: string): string;

  /**
   * Atomically store `content` plus its descriptor sidecar. Pre-existing
   * objects are verified, never silently trusted.
   */
  putObject(descriptor: Record<string, unknown>, content: string): MaybePromise<ContentRef>;

  /** Content-v2 exact-byte evidence, stored per observation rather than
   * deduplicated by digest so distinct source identities keep distinct
   * descriptor sidecars. Optional for legacy custom v1 stores. */
  evidenceRefFor?(objectId: string): string;
  putBytesObject?(
    descriptor: Record<string, unknown>,
    content: Uint8Array,
  ): MaybePromise<ContentRef>;

  /** Store the manifest and a by-decision alias; return its URI. */
  writeManifest(
    manifest: Record<string, unknown>,
    decisionId: string,
    manifestId: string,
  ): MaybePromise<string>;

  /** Deterministic URI for `manifestId` — computable with no store I/O
   * so `manifest_ref` can be stamped before the bytes are delivered. */
  manifestUriFor(manifestId: string): string;

  /** URI of the by-decision alias document (may not exist yet). */
  manifestUriForDecision(decisionId: string): string;

  /**
   * True when `uri` resolves inside this store's configured namespace.
   * Resolution must never exceed the configured set.
   */
  ownsUri(uri: string): boolean;

  exists(uri: string): MaybePromise<boolean>;

  /** Return stored bytes for `uri`. Throws when absent. */
  read(uri: string): MaybePromise<Uint8Array>;

  /** Return the descriptor sidecar for `uri`. Throws when absent. */
  readDescriptor(uri: string): MaybePromise<Record<string, unknown>>;

  readManifest(uri: string): MaybePromise<Record<string, unknown>>;

  /** All object URIs in the tenant namespace (orphan reporting). */
  listObjectUris(): MaybePromise<string[]>;
}

/** SHA-256 hex of the exact stored bytes — digest scope for objects. */
export function contentHashBytes(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

const DIGEST_RE = /^[0-9a-f]{64}$/;
const EVIDENCE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function checkedEvidenceObject(
  descriptor: Record<string, unknown>,
  data: Uint8Array,
  tenantId: string,
): { objectId: string; digest: string } {
  const objectId = descriptor["object_id"];
  const digest = String(descriptor["stored_sha256"] ?? "").split(":", 2)[1] ?? "";
  const hasPolicy = ["policy_digest", "policy_id", "policy_version", "protection_status"].some(
    (key) => Object.hasOwn(descriptor, key),
  );
  const policyIdentityValid =
    typeof descriptor["policy_digest"] === "string" &&
    /^sha256:[0-9a-f]{64}$/.test(descriptor["policy_digest"]) &&
    typeof descriptor["policy_id"] === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(descriptor["policy_id"]) &&
    typeof descriptor["policy_version"] === "number" &&
    Number.isSafeInteger(descriptor["policy_version"]) &&
    descriptor["policy_version"] >= 1 &&
    descriptor["policy_version"] <= 2147483647;
  const exact =
    descriptor["status"] === "stored" &&
    descriptor["representation"] === "exact" &&
    descriptor["source_byte_length"] === data.length &&
    descriptor["source_sha256"] === descriptor["stored_sha256"] &&
    (!hasPolicy ||
      (policyIdentityValid &&
        descriptor["privacy_mode"] === "retain_original" &&
        descriptor["protection_status"] === "retained"));
  const representation = descriptor["representation"];
  const transform = representation === "redacted" ? "redact" : "tokenize";
  const derivative =
    descriptor["status"] === "redacted" &&
    (representation === "redacted" || representation === "tokenized") &&
    descriptor["privacy_mode"] === transform &&
    descriptor["protection_status"] === representation &&
    policyIdentityValid &&
    !Object.hasOwn(descriptor, "source_sha256") &&
    !Object.hasOwn(descriptor, "source_byte_length") &&
    Array.isArray(descriptor["transformations"]) &&
    descriptor["transformations"].length === 1 &&
    descriptor["transformations"][0] === transform;
  if (
    descriptor["schema_version"] !== "fabric.content-object/v2" ||
    descriptor["tenant_id"] !== tenantId ||
    typeof objectId !== "string" ||
    !EVIDENCE_ID_RE.test(objectId) ||
    !DIGEST_RE.test(digest) ||
    descriptor["stored_byte_length"] !== data.length ||
    contentHashBytes(data) !== digest ||
    (!exact && !derivative)
  ) {
    throw new Error("invalid content-v2 descriptor or byte digest");
  }
  return { objectId, digest };
}

/**
 * Spec 033 §2.1 — the shared safe-identifier rule for values used as
 * namespace path/key components (tenant ids). Separators, traversal,
 * NUL, and percent-encoded variants all fail the pattern; `.`/`..` are
 * rejected explicitly as defense in depth. Mirrors Python
 * `check_safe_identifier`.
 */
export const SAFE_IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/;

export function assertSafeIdentifier(fieldName: string, value: string): string {
  if (
    typeof value !== "string" ||
    !SAFE_IDENTIFIER_RE.test(value) ||
    value === "." ||
    value === ".."
  ) {
    throw new Error(
      `${fieldName}=${JSON.stringify(value)} is not a safe namespace identifier: ` +
        "must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$ and may not be '.' or '..'",
    );
  }
  return value;
}

/** Write `data` to `target` atomically: tmp + fsync + rename + dir fsync. */
function atomicWriteBytes(target: string, data: Uint8Array): void {
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  fs.chmodSync(path.dirname(target), 0o700);
  const tmp = path.join(
    path.dirname(target),
    `.${path.basename(target)}.${process.pid}.${Date.now()}.tmp`,
  );
  const fd = fs.openSync(tmp, "w", 0o600);
  try {
    fs.writeSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    fs.renameSync(tmp, target);
  } catch (err) {
    try {
      fs.unlinkSync(tmp);
    } catch {
      // best-effort cleanup only
    }
    throw err;
  }
  const dirFd = fs.openSync(path.dirname(target), "r");
  try {
    fs.fsyncSync(dirFd);
  } finally {
    fs.closeSync(dirFd);
  }
}

function safeName(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]/g, "_");
}

/**
 * Content-addressed store on the local filesystem.
 *
 * With `tenantId` (governed mode, spec 033), objects live at
 * `<root>/<tenant>/<digest>` with descriptor sidecars under
 * `<root>/<tenant>/meta/` and manifests under
 * `<root>/<tenant>/manifests/`. Reads are confined to the tenant
 * namespace — a URI resolving outside it is rejected.
 */
export class LocalFilesystemContentStore implements GovernedStore {
  readonly synchronous = true;
  private readonly rootPath: string;

  constructor(
    root: string,
    readonly tenantId: string,
  ) {
    assertSafeIdentifier("tenantId", tenantId);
    this.rootPath = path.resolve(root);
    // Filesystem-level containment: the resolved tenant root must be
    // strictly inside the resolved configured root.
    const tenantRoot = path.resolve(this.tenantRoot());
    if (tenantRoot !== this.rootPath && !tenantRoot.startsWith(this.rootPath + path.sep)) {
      throw new Error(`tenant root ${tenantRoot} escapes the configured root ${this.rootPath}`);
    }
  }

  private tenantRoot(): string {
    return path.join(this.rootPath, this.tenantId);
  }

  private objectPath(digest: string): string {
    return path.join(this.tenantRoot(), digest);
  }

  refFor(digest: string): string {
    return `file://${this.objectPath(digest)}`;
  }

  putObject(descriptor: Record<string, unknown>, content: string): ContentRef {
    const digest = String(descriptor["digest"] ?? "").split(":", 2)[1] ?? "";
    if (!DIGEST_RE.test(digest)) {
      throw new Error(`descriptor digest is not sha256 hex: ${digest}`);
    }
    const data = new TextEncoder().encode(content);
    if (contentHashBytes(data) !== digest) {
      throw new Error("content bytes do not match descriptor digest");
    }
    const target = this.objectPath(digest);
    if (fs.existsSync(target)) {
      if (contentHashBytes(new Uint8Array(fs.readFileSync(target))) !== digest) {
        throw new CorruptedObjectError(`pre-existing object ${target} fails digest verification`);
      }
    } else {
      atomicWriteBytes(target, data);
    }
    const meta = path.join(this.tenantRoot(), "meta", `${digest}.json`);
    if (!fs.existsSync(meta)) {
      atomicWriteBytes(meta, new TextEncoder().encode(JSON.stringify(descriptor, null, 2) + "\n"));
    }
    return { uri: `file://${target}`, contentHash: digest };
  }

  evidenceRefFor(objectId: string): string {
    if (!EVIDENCE_ID_RE.test(objectId)) throw new Error("invalid evidence object_id");
    return `file://${path.join(this.tenantRoot(), "evidence", objectId)}`;
  }

  putBytesObject(descriptor: Record<string, unknown>, content: Uint8Array): ContentRef {
    const data = new Uint8Array(content);
    const { objectId, digest } = checkedEvidenceObject(descriptor, data, this.tenantId);
    if (descriptor["ref"] !== this.evidenceRefFor(objectId)) {
      throw new Error("content-v2 reference does not match this tenant-bound store");
    }
    const target = path.join(this.tenantRoot(), "evidence", objectId);
    const meta = path.join(this.tenantRoot(), "evidence", "meta", `${objectId}.json`);
    if (fs.existsSync(target)) {
      if (contentHashBytes(new Uint8Array(fs.readFileSync(target))) !== digest) {
        throw new CorruptedObjectError(
          `pre-existing evidence object ${objectId} fails digest verification`,
        );
      }
    } else {
      atomicWriteBytes(target, data);
    }
    if (fs.existsSync(meta)) {
      const existing = JSON.parse(fs.readFileSync(meta, "utf-8")) as Record<string, unknown>;
      if (JSON.stringify(existing) !== JSON.stringify(descriptor)) {
        throw new CorruptedObjectError(`pre-existing evidence descriptor ${objectId} differs`);
      }
    } else {
      atomicWriteBytes(meta, new TextEncoder().encode(JSON.stringify(descriptor, null, 2) + "\n"));
    }
    return { uri: this.evidenceRefFor(objectId), contentHash: digest };
  }

  writeManifest(manifest: Record<string, unknown>, decisionId: string, manifestId: string): string {
    assertSafeIdentifier("manifestId", manifestId);
    const root = path.join(this.tenantRoot(), "manifests");
    const target = path.join(root, `${manifestId}.json`);
    atomicWriteBytes(target, new TextEncoder().encode(JSON.stringify(manifest, null, 2) + "\n"));
    atomicWriteBytes(
      path.join(root, "by-decision", `${safeName(decisionId)}.json`),
      new TextEncoder().encode(JSON.stringify({ manifest_uri: `file://${target}` }) + "\n"),
    );
    return `file://${target}`;
  }

  manifestUriFor(manifestId: string): string {
    assertSafeIdentifier("manifestId", manifestId);
    return `file://${path.join(this.tenantRoot(), "manifests", `${manifestId}.json`)}`;
  }

  manifestUriForDecision(decisionId: string): string {
    return `file://${path.join(this.tenantRoot(), "manifests", "by-decision", `${safeName(decisionId)}.json`)}`;
  }

  private resolveUri(uri: string): string {
    let parsed: URL;
    try {
      parsed = new URL(uri);
    } catch {
      throw new Error(`unsupported uri ${uri}`);
    }
    if (parsed.protocol !== "file:") {
      throw new Error(`unsupported uri scheme ${parsed.protocol}`);
    }
    const candidate = path.resolve(decodeURIComponent(parsed.pathname));
    const boundary = this.tenantRoot();
    if (candidate !== boundary && !candidate.startsWith(boundary + path.sep)) {
      throw new Error(`uri escapes the configured store root: ${uri}`);
    }
    return candidate;
  }

  ownsUri(uri: string): boolean {
    try {
      this.resolveUri(uri);
      return true;
    } catch {
      return false;
    }
  }

  exists(uri: string): boolean {
    return fs.existsSync(this.resolveUri(uri));
  }

  read(uri: string): Uint8Array {
    const target = this.resolveUri(uri);
    if (!fs.existsSync(target)) {
      throw new Error(`no such object: ${uri}`);
    }
    return new Uint8Array(fs.readFileSync(target));
  }

  readDescriptor(uri: string): Record<string, unknown> {
    const target = this.resolveUri(uri);
    const meta = path.join(path.dirname(target), "meta", `${path.basename(target)}.json`);
    if (!fs.existsSync(meta)) {
      throw new Error(`no descriptor sidecar for ${uri}`);
    }
    const value = JSON.parse(fs.readFileSync(meta, "utf-8")) as unknown;
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new Error(`descriptor sidecar at ${uri} is not an object`);
    }
    return value as Record<string, unknown>;
  }

  readManifest(uri: string): Record<string, unknown> {
    const target = this.resolveUri(uri);
    if (!fs.existsSync(target)) {
      throw new Error(`no such manifest: ${uri}`);
    }
    const value = JSON.parse(fs.readFileSync(target, "utf-8")) as unknown;
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new Error(`manifest is not a JSON object: ${uri}`);
    }
    return value as Record<string, unknown>;
  }

  listObjectUris(): string[] {
    const root = this.tenantRoot();
    if (!fs.existsSync(root)) {
      return [];
    }
    const uris: string[] = [];
    for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
      if (entry.isFile() && DIGEST_RE.test(entry.name)) {
        uris.push(`file://${path.join(root, entry.name)}`);
      }
    }
    return uris.sort();
  }
}

const BUCKET_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;

const S3_IMPORT_HINT = "S3ContentStore requires @aws-sdk/client-s3: npm install @aws-sdk/client-s3";

interface S3ClientLike {
  send(command: unknown): Promise<Record<string, unknown>>;
}

/**
 * S3-compatible governed store (spec 033). Asynchronous — `synchronous`
 * is false, so `inline` durability is rejected at config build.
 * `@aws-sdk/client-s3` is an optional peer loaded lazily, matching
 * Python's optional `boto3`.
 */
export class S3ContentStore implements GovernedStore {
  readonly synchronous = false;
  private client: S3ClientLike | undefined;
  private sdk: Record<string, unknown> | undefined;

  constructor(
    readonly bucket: string,
    readonly tenantId: string,
    readonly prefix = "fabric/content/",
    readonly region?: string,
    readonly endpointUrl?: string,
  ) {
    if (!BUCKET_RE.test(bucket)) {
      throw new Error(`invalid S3 bucket name: ${bucket}`);
    }
    assertSafeIdentifier("tenantId", tenantId);
    if (!prefix || !prefix.endsWith("/") || prefix.startsWith("/")) {
      throw new Error("prefix must be a non-empty relative path ending in '/'");
    }
    if (prefix.split("/").includes("..")) {
      throw new Error("prefix must not contain '..' segments");
    }
  }

  private requireSdk(): Record<string, unknown> {
    if (this.sdk === undefined) {
      try {
        const req = createRequire(import.meta.url);
        this.sdk = req("@aws-sdk/client-s3") as Record<string, unknown>;
      } catch {
        throw new Error(S3_IMPORT_HINT);
      }
    }
    return this.sdk;
  }

  private getClient(): S3ClientLike {
    if (this.client === undefined) {
      const sdk = this.requireSdk();
      const S3Client = sdk["S3Client"] as new (opts: Record<string, unknown>) => S3ClientLike;
      this.client = new S3Client({
        region: this.region,
        endpoint: this.endpointUrl,
        forcePathStyle: this.endpointUrl !== undefined,
      });
    }
    return this.client;
  }

  private command(name: string, input: Record<string, unknown>): unknown {
    const sdk = this.requireSdk();
    const Command = sdk[name] as new (input: Record<string, unknown>) => unknown;
    return new Command(input);
  }

  private objectKey(digest: string): string {
    return `${this.prefix}${this.tenantId}/${digest}`;
  }

  refFor(digest: string): string {
    return `s3://${this.bucket}/${this.objectKey(digest)}`;
  }

  evidenceRefFor(objectId: string): string {
    if (!EVIDENCE_ID_RE.test(objectId)) throw new Error("invalid evidence object_id");
    return `s3://${this.bucket}/${this.prefix}${this.tenantId}/evidence/${objectId}`;
  }

  async putBytesObject(
    descriptor: Record<string, unknown>,
    content: Uint8Array,
  ): Promise<ContentRef> {
    const data = new Uint8Array(content);
    const { objectId, digest } = checkedEvidenceObject(descriptor, data, this.tenantId);
    if (descriptor["ref"] !== this.evidenceRefFor(objectId)) {
      throw new Error("content-v2 reference does not match this tenant-bound store");
    }
    const key = `${this.prefix}${this.tenantId}/evidence/${objectId}`;
    const metaKey = `${this.prefix}${this.tenantId}/evidence/meta/${objectId}.json`;
    const client = this.getClient();
    try {
      await client.send(
        this.command("PutObjectCommand", {
          Bucket: this.bucket,
          Key: key,
          Body: data,
          IfNoneMatch: "*",
        }),
      );
    } catch (err) {
      const status = (err as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
      if (status !== 412) throw err;
      const existing = new Uint8Array(await this.read(this.evidenceRefFor(objectId)));
      if (contentHashBytes(existing) !== digest) {
        throw new CorruptedObjectError(
          `pre-existing evidence object ${objectId} fails digest verification`,
        );
      }
    }
    try {
      await client.send(
        this.command("PutObjectCommand", {
          Bucket: this.bucket,
          Key: metaKey,
          Body: JSON.stringify(descriptor, null, 2) + "\n",
          IfNoneMatch: "*",
        }),
      );
    } catch (err) {
      const status = (err as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
      if (status !== 412) throw err;
      const existing = await this.readDescriptor(this.evidenceRefFor(objectId));
      if (JSON.stringify(existing) !== JSON.stringify(descriptor)) {
        throw new CorruptedObjectError(`pre-existing evidence descriptor ${objectId} differs`);
      }
    }
    return { uri: this.evidenceRefFor(objectId), contentHash: digest };
  }

  async putObject(descriptor: Record<string, unknown>, content: string): Promise<ContentRef> {
    const digest = String(descriptor["digest"] ?? "").split(":", 2)[1] ?? "";
    if (!DIGEST_RE.test(digest)) {
      throw new Error(`descriptor digest is not sha256 hex: ${digest}`);
    }
    const data = new TextEncoder().encode(content);
    if (contentHashBytes(data) !== digest) {
      throw new Error("content bytes do not match descriptor digest");
    }
    const key = this.objectKey(digest);
    const client = this.getClient();
    try {
      // Conditional write: never overwrite an existing object.
      await client.send(
        this.command("PutObjectCommand", {
          Bucket: this.bucket,
          Key: key,
          Body: data,
          IfNoneMatch: "*",
        }),
      );
    } catch (err) {
      const status = (err as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
      if (status !== 412) {
        throw err;
      }
      // Pre-existing object: verify, never trust the name.
      const existing = new Uint8Array(await this.read(this.refFor(digest)));
      if (contentHashBytes(existing) !== digest) {
        throw new CorruptedObjectError(
          `pre-existing object s3://${this.bucket}/${key} fails digest verification`,
        );
      }
    }
    const metaKey = `${this.prefix}${this.tenantId}/meta/${digest}.json`;
    try {
      await client.send(
        this.command("PutObjectCommand", {
          Bucket: this.bucket,
          Key: metaKey,
          Body: JSON.stringify(descriptor, null, 2) + "\n",
          IfNoneMatch: "*",
        }),
      );
    } catch (err) {
      const status = (err as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
      if (status !== 412) {
        throw err;
      }
    }
    return { uri: `s3://${this.bucket}/${key}`, contentHash: digest };
  }

  async writeManifest(
    manifest: Record<string, unknown>,
    decisionId: string,
    manifestId: string,
  ): Promise<string> {
    assertSafeIdentifier("manifestId", manifestId);
    const client = this.getClient();
    const key = `${this.prefix}${this.tenantId}/manifests/${manifestId}.json`;
    await client.send(
      this.command("PutObjectCommand", {
        Bucket: this.bucket,
        Key: key,
        Body: JSON.stringify(manifest, null, 2) + "\n",
      }),
    );
    const aliasKey = `${this.prefix}${this.tenantId}/manifests/by-decision/${safeName(decisionId)}.json`;
    await client.send(
      this.command("PutObjectCommand", {
        Bucket: this.bucket,
        Key: aliasKey,
        Body: JSON.stringify({ manifest_uri: `s3://${this.bucket}/${key}` }) + "\n",
      }),
    );
    return `s3://${this.bucket}/${key}`;
  }

  manifestUriFor(manifestId: string): string {
    assertSafeIdentifier("manifestId", manifestId);
    const key = `${this.prefix}${this.tenantId}/manifests/${manifestId}.json`;
    return `s3://${this.bucket}/${key}`;
  }

  manifestUriForDecision(decisionId: string): string {
    const key = `${this.prefix}${this.tenantId}/manifests/by-decision/${safeName(decisionId)}.json`;
    return `s3://${this.bucket}/${key}`;
  }

  private resolveUri(uri: string): string {
    let parsed: URL;
    try {
      parsed = new URL(uri);
    } catch {
      throw new Error(`unsupported uri ${uri}`);
    }
    if (parsed.protocol !== "s3:" || parsed.host !== this.bucket) {
      throw new Error(`uri outside this store's bucket: ${uri}`);
    }
    const key = decodeURIComponent(parsed.pathname.replace(/^\//, ""));
    const base = `${this.prefix}${this.tenantId}/`;
    if (!key.startsWith(base)) {
      throw new Error(`uri escapes the configured namespace: ${uri}`);
    }
    return key;
  }

  ownsUri(uri: string): boolean {
    try {
      this.resolveUri(uri);
      return true;
    } catch {
      return false;
    }
  }

  async exists(uri: string): Promise<boolean> {
    const key = this.resolveUri(uri);
    try {
      await this.getClient().send(
        this.command("HeadObjectCommand", { Bucket: this.bucket, Key: key }),
      );
      return true;
    } catch {
      return false;
    }
  }

  async read(uri: string): Promise<Uint8Array> {
    const key = this.resolveUri(uri);
    const out = (await this.getClient().send(
      this.command("GetObjectCommand", { Bucket: this.bucket, Key: key }),
    )) as { Body?: { transformToByteArray?: () => Promise<Uint8Array> } };
    if (out.Body?.transformToByteArray === undefined) {
      throw new Error(`empty object body for ${uri}`);
    }
    return out.Body.transformToByteArray();
  }

  async readDescriptor(uri: string): Promise<Record<string, unknown>> {
    const key = this.resolveUri(uri);
    const base = key.slice(0, key.lastIndexOf("/"));
    const name = key.slice(key.lastIndexOf("/") + 1);
    const metaKey = `${base}/meta/${name}.json`;
    const out = (await this.getClient().send(
      this.command("GetObjectCommand", { Bucket: this.bucket, Key: metaKey }),
    )) as { Body?: { transformToString?: () => Promise<string> } };
    if (out.Body?.transformToString === undefined) {
      throw new Error(`empty descriptor sidecar for ${uri}`);
    }
    const value = JSON.parse(await out.Body.transformToString()) as unknown;
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new Error(`descriptor sidecar at ${uri} is not an object`);
    }
    return value as Record<string, unknown>;
  }

  async readManifest(uri: string): Promise<Record<string, unknown>> {
    const key = this.resolveUri(uri);
    const out = (await this.getClient().send(
      this.command("GetObjectCommand", { Bucket: this.bucket, Key: key }),
    )) as { Body?: { transformToString?: () => Promise<string> } };
    if (out.Body?.transformToString === undefined) {
      throw new Error(`empty manifest for ${uri}`);
    }
    const value = JSON.parse(await out.Body.transformToString()) as unknown;
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new Error(`manifest is not a JSON object: ${uri}`);
    }
    return value as Record<string, unknown>;
  }

  async listObjectUris(): Promise<string[]> {
    const base = `${this.prefix}${this.tenantId}/`;
    const uris: string[] = [];
    let token: string | undefined;
    do {
      const out = (await this.getClient().send(
        this.command("ListObjectsV2Command", {
          Bucket: this.bucket,
          Prefix: base,
          ContinuationToken: token,
        }),
      )) as { Contents?: { Key?: string }[]; NextContinuationToken?: string };
      for (const obj of out.Contents ?? []) {
        const name = obj.Key?.slice(base.length) ?? "";
        if (DIGEST_RE.test(name)) {
          uris.push(`s3://${this.bucket}/${obj.Key}`);
        }
      }
      token = out.NextContinuationToken;
    } while (token !== undefined);
    return uris;
  }
}

// Re-exported so `sha256Hex` consumers can also hash stored bytes through
// one import site (mirrors Python `content_hash` usage in the stores).
export { sha256Hex };
