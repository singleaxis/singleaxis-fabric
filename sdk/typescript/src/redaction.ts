// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The client of a customer-run redaction service (spec 049 §7.7, contract
 * `contracts/redaction/v1`), in parity with Python `fabric.redaction`.
 *
 * Fabric never runs customer code: `redact`, `masked_only` and the review copy of
 * `original_plus_masked` are performed by a service the customer runs beside the
 * application, reached over a Unix socket or loopback HTTP only. A call is bounded by
 * a hard timeout and an in-flight bound; any failure (a non-200 status, a redirect, a
 * timeout, an oversized body, a connection error, saturation) resolves to `null`, and
 * the caller withholds the object (`protection_failed`), never raw bytes. Nothing here
 * logs or keeps a value, a token, an error body or error text.
 */
import * as fs from "node:fs";
import * as http from "node:http";

export const REDACTION_ENDPOINT_ENV = "FABRIC_REDACTION_ENDPOINT";
export const REDACTION_TOKEN_FILE_ENV = "FABRIC_REDACTION_TOKEN_FILE";
export const DEFAULT_REDACTION_TIMEOUT_MS = 5_000;
export const DEFAULT_REDACTION_MAX_IN_FLIGHT = 2;
const MAX_TIMEOUT_MS = 300_000;
const MAX_IN_FLIGHT = 64;
const MAX_TOKEN_FILE_BYTES = 4096;
const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const LOOPBACK = /^http:\/\/(127\.0\.0\.1|\[::1\]):([0-9]{1,5})\/?$/;
const DOCS =
  "customer redaction is performed by a customer-run redaction service: configure " +
  "FABRIC_REDACTION_ENDPOINT and give each masked role a transformation { id, version } " +
  "(see docs/wire-capture-deployment.md#redaction-service)";

/** A customer transformation's identity, recorded on every object it produced. */
export interface Transformation {
  id: string;
  version: string;
}

export interface RedactionServiceOptions {
  /** `unix:///absolute/path.sock`, `http://127.0.0.1:<port>` or `http://[::1]:<port>`. */
  endpoint: string;
  /** A `0600` file holding a bearer token, read once at construction; never logged. */
  tokenFile?: string;
  /** Hard timeout of one call in ms, from its start to the last body byte (default 5000). */
  timeoutMs?: number;
  /** Concurrent calls; a call above the bound is withheld at once (default 2). */
  maxInFlight?: number;
}

export type RedactionMode = "redact" | "masked_only";

export interface RedactionStats {
  redaction_timeouts: number;
  redaction_saturated: number;
  redaction_failures: number;
}

export type RedactionEndpoint =
  | { kind: "unix"; socketPath: string }
  | { kind: "http"; host: "127.0.0.1" | "::1"; port: number };

/**
 * `value` as a {@link Transformation}; throws (fixed text) for anything else. A function
 * or a module reference is refused with a pointer to the redaction-service docs.
 */
export function checkTransformation(value: unknown): Transformation {
  if (typeof value === "function") throw new Error(DOCS);
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error("a transformation must be { id, version }");
  const data = value as Record<string, unknown>;
  if (["module", "ref", "exportName"].some((key) => Object.hasOwn(data, key)))
    throw new Error(DOCS);
  if (Object.keys(data).some((key) => key !== "id" && key !== "version"))
    throw new Error("a transformation must be { id, version }");
  if (
    typeof data.id !== "string" ||
    typeof data.version !== "string" ||
    !OPAQUE_ID.test(data.id) ||
    !OPAQUE_ID.test(data.version)
  )
    throw new Error("transformation id and version must be opaque ids");
  return Object.freeze({ id: data.id, version: data.version });
}

/** The error for a removed in-process or module redactor option. */
export function redactorRemovedError(): Error {
  return new Error(DOCS);
}

/** Parse an endpoint; throws fixed text (never the value) for any other form. */
export function parseRedactionEndpoint(text: unknown): RedactionEndpoint {
  const invalid = new Error(
    `${REDACTION_ENDPOINT_ENV} must be unix:///absolute/path or http://127.0.0.1:<port> ` +
      "or http://[::1]:<port>",
  );
  if (typeof text !== "string") throw invalid;
  if (text.startsWith("unix://")) {
    const socketPath = text.slice("unix://".length);
    if (!socketPath.startsWith("/") || socketPath.length < 2 || /[\0?#]/.test(socketPath))
      throw invalid;
    return { kind: "unix", socketPath };
  }
  const match = LOOPBACK.exec(text);
  const port = match === null ? NaN : Number(match[2]);
  if (match === null || !Number.isInteger(port) || port < 1 || port > 65535) throw invalid;
  return { kind: "http", host: match[1] === "127.0.0.1" ? "127.0.0.1" : "::1", port };
}

/**
 * The service configured by `FABRIC_REDACTION_ENDPOINT` (and optionally
 * `FABRIC_REDACTION_TOKEN_FILE`), or `undefined` when no endpoint is set. A malformed
 * endpoint throws (fixed text).
 */
export function redactionServiceFromEnv(
  env: Record<string, string | undefined>,
): RedactionServiceOptions | undefined {
  const endpoint = (env[REDACTION_ENDPOINT_ENV] ?? "").trim();
  const tokenFile = env[REDACTION_TOKEN_FILE_ENV] ?? "";
  if (endpoint === "") {
    if (tokenFile !== "")
      throw new Error(`${REDACTION_TOKEN_FILE_ENV} needs ${REDACTION_ENDPOINT_ENV}`);
    return undefined;
  }
  parseRedactionEndpoint(endpoint);
  return tokenFile === "" ? { endpoint } : { endpoint, tokenFile };
}

/** Read a bearer token file: a regular, owner-only (0600) file of printable ASCII. */
export function readRedactionToken(file: string): string {
  const unsafe = new Error(
    `${REDACTION_TOKEN_FILE_ENV} must be a regular file owned by this user, mode 0600, ` +
      "holding at most 4096 bytes of printable ASCII",
  );
  let fd: number;
  try {
    fd = fs.openSync(
      file,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
    );
  } catch {
    throw new Error(`${REDACTION_TOKEN_FILE_ENV} is not readable`);
  }
  try {
    const info = fs.fstatSync(fd);
    const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
    if (
      !info.isFile() ||
      (uid !== undefined && info.uid !== uid) ||
      (info.mode & 0o077) !== 0 ||
      info.size > MAX_TOKEN_FILE_BYTES
    )
      throw unsafe;
    const raw = fs.readFileSync(fd);
    if (raw.length > MAX_TOKEN_FILE_BYTES) throw unsafe;
    const text = raw.toString("latin1").replace(/\n$/, "");
    if (!/^[\x21-\x7e]+$/.test(text)) throw unsafe;
    return text;
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * One recorder's connection to the redaction service: one keep-alive connection pool,
 * bounded in-flight calls and a hard timeout per call. Use only behind the recorder's
 * handoff, never on the application's call path.
 */
export class RedactionClient {
  readonly endpoint: RedactionEndpoint;
  readonly timeoutMs: number;
  readonly maxInFlight: number;
  readonly maxOutputBytes: number;
  readonly #token: string | undefined;
  readonly #agent: http.Agent;
  #inFlight = 0;
  #closed = false;
  readonly #stats: RedactionStats = {
    redaction_timeouts: 0,
    redaction_saturated: 0,
    redaction_failures: 0,
  };

  constructor(options: RedactionServiceOptions, limits: { maxOutputBytes: number }) {
    if (options === null || typeof options !== "object")
      throw new Error("redaction service options must be an object");
    this.endpoint = parseRedactionEndpoint(options.endpoint);
    const timeout = options.timeoutMs ?? DEFAULT_REDACTION_TIMEOUT_MS;
    if (
      typeof timeout !== "number" ||
      !Number.isFinite(timeout) ||
      timeout <= 0 ||
      timeout > MAX_TIMEOUT_MS
    )
      throw new Error("redaction timeoutMs must be in (0, 300000]");
    const inFlight = options.maxInFlight ?? DEFAULT_REDACTION_MAX_IN_FLIGHT;
    if (!Number.isSafeInteger(inFlight) || inFlight < 1 || inFlight > MAX_IN_FLIGHT)
      throw new Error(`redaction maxInFlight must be an integer in [1, ${MAX_IN_FLIGHT}]`);
    if (!Number.isSafeInteger(limits.maxOutputBytes) || limits.maxOutputBytes < 1)
      throw new Error("redaction maxOutputBytes must be a positive integer");
    this.timeoutMs = timeout;
    this.maxInFlight = inFlight;
    this.maxOutputBytes = limits.maxOutputBytes;
    this.#token =
      options.tokenFile === undefined ? undefined : readRedactionToken(options.tokenFile);
    this.#agent = new http.Agent({ keepAlive: true, maxSockets: inFlight });
  }

  /** Counters only, never a value. */
  stats(): RedactionStats {
    return { ...this.#stats };
  }

  /**
   * The service's transformation of one object, or `null` on any failure. Resolves
   * within the timeout; never rejects.
   */
  transform(
    data: Uint8Array,
    request: { transformation: Transformation; role: string; mode: RedactionMode },
  ): Promise<Uint8Array | null> {
    if (this.#closed || !(data instanceof Uint8Array)) {
      this.#stats.redaction_failures += 1;
      return Promise.resolve(null);
    }
    if (this.#inFlight >= this.maxInFlight) {
      this.#stats.redaction_saturated += 1;
      return Promise.resolve(null);
    }
    this.#inFlight += 1;
    return new Promise<Uint8Array | null>((resolve) => {
      let settled = false;
      let req: http.ClientRequest | undefined;
      const finish = (
        result: Uint8Array | null,
        counter: keyof RedactionStats = "redaction_failures",
      ): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.#inFlight -= 1;
        if (result === null) {
          this.#stats[counter] += 1;
          req?.destroy();
        }
        resolve(result);
      };
      const timer = setTimeout(() => finish(null, "redaction_timeouts"), this.timeoutMs);
      try {
        const headers: http.OutgoingHttpHeaders = {
          "Content-Type": "application/octet-stream",
          "Content-Length": String(data.byteLength),
          "X-Fabric-Transformation": request.transformation.id,
          "X-Fabric-Transformation-Version": request.transformation.version,
          "X-Fabric-Role": request.role,
          "X-Fabric-Mode": request.mode,
        };
        if (this.#token !== undefined) headers.Authorization = `Bearer ${this.#token}`;
        const target =
          this.endpoint.kind === "unix"
            ? { socketPath: this.endpoint.socketPath, headers: { ...headers, Host: "localhost" } }
            : { host: this.endpoint.host, port: this.endpoint.port, headers };
        const send = (retry: boolean): void => {
          const current = http.request({
            ...target,
            agent: this.#agent,
            method: "POST",
            path: "/v1/transform",
          });
          req = current;
          let answered = false;
          current.on("error", () => {
            // A pooled connection the service closed before any byte of an answer: once
            // more on a fresh one, as Python does (never after a response began).
            if (retry && !answered && current.reusedSocket && !settled) send(false);
            else finish(null);
          });
          current.on("response", (res) => {
            answered = true;
            onResponse(res);
          });
          current.end(Buffer.from(data.buffer, data.byteOffset, data.byteLength));
        };
        const onResponse = (res: http.IncomingMessage): void => {
          res.on("error", () => finish(null));
          res.on("aborted", () => finish(null));
          if (res.statusCode !== 200) {
            finish(null); // a redirect included; the body is never read
            return;
          }
          const chunks: Buffer[] = [];
          let size = 0;
          res.on("data", (chunk: Buffer) => {
            size += chunk.byteLength;
            if (size > this.maxOutputBytes) finish(null);
            else chunks.push(chunk);
          });
          res.on("end", () => {
            if (res.complete) finish(new Uint8Array(Buffer.concat(chunks, size)));
            else finish(null);
          });
          res.on("close", () => finish(null)); // after "end": a no-op
        };
        send(true);
      } catch {
        finish(null);
      }
    });
  }

  /** Close the connection pool; later calls fail at once (`null`). */
  async close(): Promise<void> {
    this.#closed = true;
    this.#agent.destroy();
  }
}
