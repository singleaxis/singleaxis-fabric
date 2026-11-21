// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Content transport to the Fabric Node (spec 048 §3, 055 §7.1; Python
 * `wire/_content.py` after #289): OTLP/HTTP protobuf `LogRecord`s, one per body, several
 * bodies per request. A request the Node refuses as a whole (400, 413, 415, 422, or a
 * 2xx whose `partial_success` rejects records) is sent again one body per request, so
 * only the refused bodies count as rejected; an unencodable body is rejected on its own
 * without a round trip. Delivery goes through a private {@link DeliveryClient}: no
 * redirect is followed, no ambient proxy is used, TLS is always verified.
 *
 * Never logs a URL, a header, a body or a message: the optional `warn` sink receives
 * fixed text with an error class or an HTTP status only.
 */
import { DeliveryClient, type DeliveryTarget, type Outcome, type PostResult } from "./delivery.js";
import { type ContentItem, encodeLogRecord, encodeLogsRequest } from "./otlp.js";

/** The outcome of one body. */
export type ContentResult = Outcome;

export interface NodeContentOptions {
  /** The capture `service.name` of every request's resource. */
  readonly serviceName: string;
  /** `FABRIC_WIRE_PROXY` (already validated by the configuration). */
  readonly proxy?: string | undefined;
  /** Class-only warnings (fixed text), e.g. to the Fabric worker's notice sink. */
  readonly warn?: (text: string) => void;
}

const className = (error: unknown): string =>
  error instanceof Error && /^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(error.name) ? error.name : "Error";

/**
 * The Node content client (Python `NodeContentClient`): `send` and `sendMany` resolve
 * one {@link ContentResult} per body and never reject.
 */
export class NodeContentClient {
  readonly #client: DeliveryClient;
  readonly #service: string;
  readonly #warn: (text: string) => void;
  /** The last POST's result, for the sender's backoff (`Retry-After`). */
  lastResult: PostResult | undefined;

  /** Throws (fixed text) for an endpoint that is not verified HTTPS or loopback HTTP. */
  constructor(target: DeliveryTarget, options: NodeContentOptions) {
    this.#client = new DeliveryClient(target, {
      signal: "logs",
      name: "FABRIC_WIRE_CONTENT_ENDPOINT",
      proxy: options.proxy,
    });
    this.#service = options.serviceName;
    this.#warn = options.warn ?? (() => undefined);
  }

  /** Whether requests go through the `FABRIC_WIRE_PROXY` tunnel. */
  get proxied(): boolean {
    return this.#client.proxied;
  }

  #record(item: ContentItem): Buffer | undefined {
    try {
      return encodeLogRecord(item);
    } catch (error) {
      this.#warn(`fabric.wire: content record not encodable (${className(error)})`);
      return undefined;
    }
  }

  async #post(records: readonly Buffer[]): Promise<PostResult> {
    let payload: Buffer;
    try {
      payload = encodeLogsRequest(records, this.#service);
    } catch {
      return { outcome: "rejected", status: 0 };
    }
    const result = await this.#client.post(payload);
    this.lastResult = result;
    return result;
  }

  /**
   * One body in one request: `ok` (2xx), `rejected` (400/413/415/422, a rejected record
   * or an unencodable one; never retried) or `retry` (3xx included).
   */
  async send(item: ContentItem): Promise<ContentResult> {
    const record = this.#record(item);
    if (record === undefined) return "rejected";
    const result = await this.#post([record]);
    if (result.outcome === "rejected" && result.status !== 0)
      this.#warn(`fabric.wire: content record rejected by the Node (HTTP ${result.status})`);
    return result.outcome;
  }

  /**
   * Several bodies in one request; per body as {@link send}. The Node acknowledges a
   * request as a whole and stores identical bytes again as a replay, so a retried
   * request is idempotent. A request refused as a whole is sent again one body per
   * request, in order.
   */
  async sendMany(items: readonly ContentItem[]): Promise<ContentResult[]> {
    if (items.length <= 1) return Promise.all(items.map((item) => this.send(item)));
    const results: ContentResult[] = items.map(() => "rejected");
    const records: Buffer[] = [];
    const positions: number[] = [];
    items.forEach((item, index) => {
      const record = this.#record(item);
      if (record !== undefined) {
        records.push(record);
        positions.push(index);
      }
    });
    if (records.length === 0) return results;
    const outcome = (await this.#post(records)).outcome;
    records.length = 0; // the copies of the bodies: freed before any one-by-one resend
    if (outcome === "rejected") {
      for (const index of positions) results[index] = await this.send(items[index]!);
    } else {
      for (const index of positions) results[index] = outcome;
    }
    return results;
  }

  /** Closes the connection pool. */
  close(): void {
    this.#client.close();
  }
}
