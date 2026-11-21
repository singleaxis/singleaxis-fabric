// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Fabric's private OTLP/HTTP delivery clients (spec 055 §3.4, §7.1), run only by the
 * Fabric worker, never on an application thread or from a hook.
 *
 * - **Private agents.** Every client owns its own `http.Agent`/`https.Agent`; nothing is
 *   sent through `fetch`, a global agent or a global OpenTelemetry provider, so the
 *   application's dispatcher, agents, `NODE_USE_ENV_PROXY` and trust settings are never
 *   read or changed.
 * - **No ambient proxy.** `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` and
 *   system proxy discovery are ignored. Only `FABRIC_WIRE_PROXY` selects a proxy, for an
 *   HTTPS endpoint only, as an HTTP(S) `CONNECT` tunnel: TLS is verified end to end with
 *   the Node, the ingress headers travel only inside the tunnel and the proxy credentials
 *   (the proxy URL's user info) go only to the proxy. A loopback endpoint is always
 *   reached directly (Python `pin_delivery_proxies`).
 * - **Never a redirect.** A 3xx is an ordinary `retry`: `Location` is never read, so no
 *   byte or header ever reaches another address (047/048 H1).
 * - **Verified TLS or loopback HTTP** (Python `check_content_endpoint_url`); certificate
 *   verification cannot be turned off.
 *
 * {@link DeliveryClient.post} never rejects and never throws: every failure is an outcome
 * class ({@link Outcome}) with the status and, at most, a fixed error code. No URL, header
 * or body is ever logged or carried in an error.
 */
import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import type { Duplex } from "node:stream";
import tls from "node:tls";
import { promisify } from "node:util";
import zlib from "node:zlib";

import { SDK_VERSION } from "../version.js";
import { checkContentEndpointUrl, isLoopbackEndpoint } from "./config.js";
import {
  encodeTraceRequest,
  OTLP_PROTOBUF,
  type OtlpSpan,
  partialSuccessRejected,
} from "./otlp.js";
import type { OtlpRoute } from "./types.js";

/** `ok` (2xx), `retry` (3xx, 408, 429, 5xx, any other status, a transport error), `rejected`. */
export type Outcome = "ok" | "retry" | "rejected";

/** Statuses that refuse a request for good (Python `_content._PERMANENT`). */
export const PERMANENT_STATUSES: ReadonlySet<number> = new Set([400, 413, 415, 422]);
/** First and largest retry delay (Python `_sender._BACKOFF_S`, `_BACKOFF_CAP_S`). */
export const BACKOFF_MS = 500;
export const BACKOFF_CAP_MS = 30_000;
/** At most this much of a response body is read (an OTLP export response is tiny). */
export const MAX_RESPONSE_BYTES = 1024 * 1024;
/** Sockets per client: one per content request in flight (`FABRIC_WIRE_CONTENT_CONCURRENCY` ≤ 16). */
export const MAX_SOCKETS = 16;

/** Where one signal is delivered, as plain data the Fabric worker can rebuild a client from. */
export interface DeliveryTarget {
  readonly url: string;
  /** The ingress headers (credentials): sent only to the Node, inside TLS when remote. */
  readonly headers: Readonly<Record<string, string>>;
  /** PEM CA bundle file; when set it replaces the default trust store, as Python's `verify`. */
  readonly certificate?: string | undefined;
  readonly clientCertificate?: string | undefined;
  readonly clientKey?: string | undefined;
  readonly timeoutMs: number;
  /** `gzip` or `deflate` (trace exports only, as Python's exporter); else none. */
  readonly compression?: string | undefined;
}

/** The outcome of one POST. */
export interface PostResult {
  readonly outcome: Outcome;
  /** The HTTP status; 0 when no response arrived. */
  readonly status: number;
  /** A bounded `Retry-After` (ms) of a refused or failed response, when it named one. */
  readonly retryAfterMs?: number;
  /** A 2xx whose `partial_success` rejected records (content only): their count. */
  readonly rejectedRecords?: bigint;
  /** A fixed transport error code (`ECONNREFUSED`, `timeout`, `proxy_refused`, …). */
  readonly errorCode?: string;
}

/** The class of a response (Python `NodeContentClient._post`). */
export function classify(status: number, rejectedRecords = 0n): Outcome {
  if (status >= 200 && status < 300 && rejectedRecords <= 0n) return "ok";
  if (PERMANENT_STATUSES.has(status) || (status >= 200 && status < 300)) return "rejected";
  return "retry";
}

/**
 * A `Retry-After` of delay-seconds form, bounded by {@link BACKOFF_CAP_MS}; `undefined`
 * for an absent, repeated, non-numeric or HTTP-date value (Python's metadata delivery
 * honours the digit form only).
 */
export function retryAfterMs(value: string | string[] | undefined): number | undefined {
  if (typeof value !== "string" || !/^[0-9]{1,10}$/.test(value.trim())) return undefined;
  return Math.min(BACKOFF_CAP_MS, Number(value.trim()) * 1000);
}

/**
 * Capped exponential backoff (Python sender: 0.5 s doubling to 30 s), raised to a
 * bounded `Retry-After` when the Node named one; {@link reset} after a success.
 */
export class Backoff {
  #delay = 0;

  next(retryAfter?: number): number {
    this.#delay = Math.min(BACKOFF_CAP_MS, this.#delay * 2 || BACKOFF_MS);
    const hinted = retryAfter === undefined ? 0 : Math.min(BACKOFF_CAP_MS, Math.max(0, retryAfter));
    return Math.max(this.#delay, hinted);
  }

  reset(): void {
    this.#delay = 0;
  }
}

/** A route's target: its signal URL (or `url`, the content endpoint) and settings. */
export function targetOf(route: OtlpRoute, url?: string): DeliveryTarget {
  const target = url ?? route.signalUrl;
  if (target === undefined) throw new Error("no delivery endpoint is configured");
  return {
    url: target,
    headers: { ...route.headers },
    certificate: route.certificate,
    clientCertificate: route.clientCertificate,
    clientKey: route.clientKey,
    timeoutMs: route.timeoutMs,
    compression: route.compression,
  };
}

const ERROR_CODE = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const codeOf = (error: unknown): string => {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && ERROR_CODE.test(code) ? code : "connection";
};

function readTls(path: string | undefined): Buffer | undefined {
  if (path === undefined) return undefined;
  try {
    return readFileSync(path);
  } catch {
    throw new Error(
      "an OTLP TLS file (certificate, client certificate or client key) is not readable: " +
        "check the *_CERTIFICATE and *_CLIENT_KEY variables",
    );
  }
}

/** A URL's percent-encoded user info, decoded; a malformed escape is kept as written. */
const decoded = (text: string): string => {
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
};

const unbracket = (host: string): string => host.replace(/^\[(.*)\]$/, "$1");
const isIp = (host: string): boolean => /^[0-9.]+$/.test(host) || host.includes(":");

interface TlsMaterial {
  readonly ca?: Buffer;
  readonly cert?: Buffer;
  readonly key?: Buffer;
}

/**
 * An HTTPS agent whose connections are `CONNECT` tunnels through `FABRIC_WIRE_PROXY`:
 * TLS to the Node runs inside the tunnel and is verified as a direct connection would be.
 * The proxy's user info becomes `Proxy-Authorization` on the `CONNECT` only.
 */
class TunnelAgent extends https.Agent {
  readonly #proxy: URL;
  readonly #tls: TlsMaterial;
  readonly #timeoutMs: number;

  constructor(proxy: string, material: TlsMaterial, timeoutMs: number) {
    super({ keepAlive: true, maxSockets: MAX_SOCKETS, scheduling: "fifo" });
    this.#proxy = new URL(proxy);
    this.#tls = material;
    this.#timeoutMs = timeoutMs;
  }

  override createConnection(
    options: http.ClientRequestArgs,
    callback?: (err: Error | null, stream: Duplex) => void,
  ): Duplex | null | undefined {
    const done = callback ?? (() => undefined);
    const host = unbracket(String(options.hostname ?? options.host ?? ""));
    const port = Number(options.port ?? 443);
    const authority = `${host.includes(":") ? `[${host}]` : host}:${port}`;
    const proxy = this.#proxy;
    const headers: http.OutgoingHttpHeaders = { host: authority };
    if (proxy.username !== "" || proxy.password !== "") {
      const user = `${decoded(proxy.username)}:${decoded(proxy.password)}`;
      headers["proxy-authorization"] = `Basic ${Buffer.from(user, "utf8").toString("base64")}`;
    }
    const secureProxy = proxy.protocol === "https:";
    const proxyHost = unbracket(proxy.hostname);
    // An https:// proxy is verified with the configured CA bundle (else the default
    // trust store), never shown the Node's client certificate: that is an ingress
    // credential and goes only inside the tunnel.
    const connect = (secureProxy ? https : http).request({
      host: proxyHost,
      port: Number(proxy.port || (secureProxy ? 443 : 80)),
      method: "CONNECT",
      path: authority,
      headers,
      agent: false,
      timeout: this.#timeoutMs,
      ...(secureProxy
        ? {
            ...(this.#tls.ca === undefined ? {} : { ca: this.#tls.ca }),
            rejectUnauthorized: true,
            ...(isIp(proxyHost) ? {} : { servername: proxyHost }),
          }
        : {}),
    });
    let settled = false;
    const fail = (code: string): void => {
      if (settled) return;
      settled = true;
      connect.destroy();
      done(
        Object.assign(new Error("the delivery proxy did not open a tunnel"), { code }),
        undefined as never,
      );
    };
    connect.once("timeout", () => fail("proxy_timeout"));
    connect.once("error", (error) => fail(codeOf(error)));
    connect.once("response", (res: http.IncomingMessage) => {
      res.resume();
      fail("proxy_refused"); // a non-CONNECT answer
    });
    connect.once("connect", (res: http.IncomingMessage, socket, head: Buffer) => {
      if (settled) {
        socket.destroy();
        return;
      }
      if (res.statusCode !== 200 || head.length > 0) {
        socket.destroy();
        fail("proxy_refused");
        return;
      }
      settled = true;
      const secure = tls.connect({
        socket,
        ...this.#tls,
        rejectUnauthorized: true,
        ...(isIp(host) ? {} : { servername: host }),
        ALPNProtocols: ["http/1.1"],
      });
      done(null, secure);
    });
    connect.end();
    return undefined;
  }
}

/**
 * One delivery client for one endpoint (traces or content logs): a private keep-alive
 * agent, the proxy rule, the redirect rule and the outcome classes of §7.1.
 */
export class DeliveryClient {
  readonly signal: "traces" | "logs";
  /** Whether requests go through the `FABRIC_WIRE_PROXY` tunnel. */
  readonly proxied: boolean;
  readonly #url: URL;
  readonly #target: DeliveryTarget;
  readonly #agent: http.Agent;
  readonly #tls: TlsMaterial;
  #closed = false;

  /**
   * @param name The variable the endpoint came from (named by a configuration error).
   * @param proxy `FABRIC_WIRE_PROXY` (already validated by the configuration).
   */
  constructor(
    target: DeliveryTarget,
    options: { signal: "traces" | "logs"; name?: string; proxy?: string | undefined },
  ) {
    checkContentEndpointUrl(options.name ?? "FABRIC_OTLP_ENDPOINT", target.url);
    if (!Number.isFinite(target.timeoutMs) || target.timeoutMs <= 0)
      throw new Error("the OTLP timeout must be a positive number of milliseconds");
    this.signal = options.signal;
    this.#url = new URL(target.url.trim());
    this.#target = Object.freeze({ ...target, headers: Object.freeze({ ...target.headers }) });
    const material: TlsMaterial = {
      ...(target.certificate === undefined ? {} : { ca: readTls(target.certificate) }),
      ...(target.clientCertificate === undefined
        ? {}
        : { cert: readTls(target.clientCertificate) }),
      ...(target.clientKey === undefined ? {} : { key: readTls(target.clientKey) }),
    };
    this.#tls = material;
    const secure = this.#url.protocol === "https:";
    this.proxied = secure && options.proxy !== undefined && !isLoopbackEndpoint(target.url);
    const agentOptions = { keepAlive: true, maxSockets: MAX_SOCKETS, scheduling: "fifo" as const };
    this.#agent = this.proxied
      ? new TunnelAgent(options.proxy!, material, target.timeoutMs)
      : secure
        ? new https.Agent(agentOptions)
        : new http.Agent(agentOptions);
  }

  /**
   * POSTs one encoded OTLP request; resolves within the timeout with its outcome. Never
   * rejects. A trace export is compressed when the route asks for it.
   */
  async post(payload: Uint8Array): Promise<PostResult> {
    if (this.#closed) return { outcome: "retry", status: 0, errorCode: "closed" };
    let body: Uint8Array = payload;
    let encoding: string | undefined;
    const compression = this.signal === "traces" ? this.#target.compression : undefined;
    try {
      if (compression === "gzip" || compression === "deflate") {
        body = await (compression === "gzip" ? gzip : deflate)(payload);
        encoding = compression;
      }
    } catch {
      return { outcome: "retry", status: 0, errorCode: "compression" };
    }
    return this.#send(body, encoding);
  }

  #send(body: Uint8Array, encoding: string | undefined): Promise<PostResult> {
    return new Promise<PostResult>((resolve) => {
      const url = this.#url;
      const secure = url.protocol === "https:";
      const host = unbracket(url.hostname);
      let settled = false;
      let request: http.ClientRequest | undefined;
      const finish = (result: PostResult): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(result);
      };
      const timer = setTimeout(() => {
        request?.destroy();
        finish({ outcome: "retry", status: 0, errorCode: "timeout" });
      }, this.#target.timeoutMs);
      try {
        const fixed = new Set([
          "content-type",
          "content-length",
          "content-encoding",
          "host",
          "transfer-encoding",
        ]);
        const headers: http.OutgoingHttpHeaders = {
          "user-agent": `singleaxis-fabric-node/${SDK_VERSION}`,
        };
        for (const [key, value] of Object.entries(this.#target.headers)) {
          if (!fixed.has(key.toLowerCase())) headers[key] = value;
        }
        headers["content-type"] = OTLP_PROTOBUF;
        headers["content-length"] = String(body.byteLength);
        if (encoding !== undefined) headers["content-encoding"] = encoding;
        const options: https.RequestOptions = {
          protocol: url.protocol,
          hostname: host,
          port: url.port === "" ? (secure ? 443 : 80) : Number(url.port),
          path: url.pathname,
          method: "POST",
          headers,
          agent: this.#agent,
          ...(secure
            ? {
                ...this.#tls,
                rejectUnauthorized: true,
                ...(isIp(host) ? {} : { servername: host }),
              }
            : {}),
        };
        request = (secure ? https : http).request(options, (res) => {
          const status = res.statusCode ?? 0;
          const chunks: Buffer[] = [];
          let size = 0;
          res.on("data", (chunk: Buffer) => {
            if (size < MAX_RESPONSE_BYTES) chunks.push(chunk);
            size += chunk.byteLength;
          });
          res.on("error", () => finish({ outcome: "retry", status: 0, errorCode: "response" }));
          res.on("aborted", () => finish({ outcome: "retry", status: 0, errorCode: "response" }));
          res.on("end", () => {
            const ok = status >= 200 && status < 300;
            const rejected =
              ok && this.signal === "logs" && size <= MAX_RESPONSE_BYTES
                ? partialSuccessRejected(Buffer.concat(chunks))
                : 0n;
            const outcome = classify(status, rejected);
            const hint =
              outcome === "retry" && status >= 400
                ? retryAfterMs(res.headers["retry-after"])
                : undefined;
            finish({
              outcome,
              status,
              ...(hint === undefined ? {} : { retryAfterMs: hint }),
              ...(rejected > 0n ? { rejectedRecords: rejected } : {}),
            });
          });
        });
        request.on("error", (error) =>
          finish({ outcome: "retry", status: 0, errorCode: codeOf(error) }),
        );
        request.end(Buffer.from(body.buffer, body.byteOffset, body.byteLength));
      } catch (error) {
        finish({ outcome: "retry", status: 0, errorCode: codeOf(error) });
      }
    });
  }

  /** Closes the connection pool; later posts resolve `retry` at once. */
  close(): void {
    this.#closed = true;
    this.#agent.destroy();
  }
}

/**
 * The span exporter of Fabric's own trace delivery (`/v1/traces`): one
 * `ExportTraceServiceRequest` per call, byte-equal to Python's exporter. A request that
 * cannot be encoded is `rejected` without a round trip. Whether a permanently refused
 * export is retried or retired is the sender's decision (Python's retries it).
 */
export class TraceClient {
  readonly #client: DeliveryClient;

  constructor(target: DeliveryTarget, options: { name?: string; proxy?: string | undefined } = {}) {
    this.#client = new DeliveryClient(target, { signal: "traces", ...options });
  }

  /** Whether requests go through the `FABRIC_WIRE_PROXY` tunnel. */
  get proxied(): boolean {
    return this.#client.proxied;
  }

  async export(spans: readonly OtlpSpan[]): Promise<PostResult> {
    let payload: Buffer;
    try {
      payload = encodeTraceRequest(spans);
    } catch {
      return { outcome: "rejected", status: 0, errorCode: "encode" };
    }
    return this.#client.post(payload);
  }

  close(): void {
    this.#client.close();
  }
}

const gzip = promisify(zlib.gzip);
const deflate = promisify(zlib.deflate);
