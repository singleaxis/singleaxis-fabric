// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * `wire.ts.undici`: the undici diagnostics-channel capture hook (spec 055 §3.2, §4.5, §4.6).
 *
 * Global `fetch` and the undici package publish every request's lifecycle on seven
 * synchronous diagnostics channels. This hook subscribes to exactly those seven and does
 * only hook work (§4.5 rule 5): match the request, reserve and snapshot each published
 * body chunk into the shared payload arena, note the final status and the permitted
 * media and encoding metadata, and finish the exchange once. It never hashes, parses a
 * body, logs, touches a file or the network, or waits.
 *
 * Passivity (§3.2): Fabric never replaces `fetch`, installs a dispatcher, calls
 * `Response.clone()`, `tee()`, a reader or an iterator, reads a socket or changes a
 * request. A chunk is copied once before the subscriber returns, so the caller's buffer
 * can be reused or mutated afterwards without changing what was captured. Every
 * subscriber catches its own failures: an exception escaping a diagnostics-channel
 * subscriber would be rethrown on the application's event loop.
 *
 * Correlation is by undici's request object, in an isolate-local `WeakMap`: the hook
 * never holds the request, the message, the socket or a headers object. A bounded set of
 * open entries lets {@link UndiciHook.uninstall} finish what is still open, and a
 * `FinalizationRegistry` finishes an exchange whose request was collected unfinished
 * (a notice only, never a read).
 *
 * The hook writes the transport metadata of each exchange into the slot's hook-defined
 * bytes (layout {@link META}); {@link readUndiciMeta} decodes it for the Fabric worker.
 * Values only: never a URL, host, path, query, header block or error message.
 */
import { subscribe, unsubscribe } from "node:diagnostics_channel";
import { types } from "node:util";

import { context as otelContext, trace } from "@opentelemetry/api";

import {
  type ExchangeTable,
  type ExplicitOwnership,
  NO_EXCHANGE,
  type ParentContext,
  REQUEST,
  RESPONSE,
  type ResponseState,
} from "./exchange.js";
import { EndpointIndex, MODEL_PATH_SUFFIXES } from "./match.js";
import type { EndpointMatcher, WireApi } from "./types.js";

/** The capture point id (`fabric.capture.point` is this plus `@<sdk version>`). */
export const UNDICI_POINT = "wire.ts.undici";

/** The seven request channels the hook subscribes to (§3.2), and nothing else. */
export const UNDICI_CHANNELS = [
  "undici:request:create",
  "undici:request:bodyChunkSent",
  "undici:request:bodySent",
  "undici:request:headers",
  "undici:request:bodyChunkReceived",
  "undici:request:trailers",
  "undici:request:error",
] as const;

/** `fabric.wire.api` values, by the code stored in the slot. */
export const WIRE_APIS: readonly WireApi[] = Object.freeze([
  "openai.chat_completions",
  "openai.responses",
  "openai.completions",
  "openai.embeddings",
  "anthropic.messages",
]);

/**
 * Error classes the hook may name (Python records `type(exc).__name__`). Anything else is
 * `Error`: an application's abort reason or error class name can carry content, so it is
 * never copied (§9.2 plants a canary in `Error.name`).
 */
export const ERROR_TYPES = Object.freeze([
  "",
  "Error",
  "AbortError",
  "TimeoutError",
  "TypeError",
  "UndiciError",
  "SocketError",
  "ConnectTimeoutError",
  "HeadersTimeoutError",
  "HeadersOverflowError",
  "BodyTimeoutError",
  "ResponseContentLengthMismatchError",
  "RequestContentLengthMismatchError",
  "RequestAbortedError",
  "InformationalError",
  "ResponseExceededMaxSizeError",
  "ClientDestroyedError",
  "ClientClosedError",
  "SecureProxyConnectionError",
  "NotSupportedError",
  "InvalidArgumentError",
] as const);
const ERROR_CODES: ReadonlyMap<string, number> = new Map(ERROR_TYPES.map((name, i) => [name, i]));

/**
 * Byte offsets of the hook-defined part of an exchange slot (little endian). Strings are a
 * length byte (two for the request id) and ASCII.
 */
export const META = Object.freeze({
  VERSION: 0, // u8: 1
  POINT: 1, // u8: 1 = wire.ts.undici
  ENDPOINT: 2, // u16: index into the configured endpoint list
  API: 4, // u8: index into WIRE_APIS
  ERROR: 5, // u8: index into ERROR_TYPES (0: none)
  FLAGS: 6, // u8: FLAG_*
  INFORMATIONAL: 7, // u8: informational (1xx) responses seen, saturating
  STATUS: 8, // u16: final HTTP status (0: no final response)
  HEADERS_NS: 12, // u64: monotonic ns from create to the final response's headers
  FIRST_CHUNK_NS: 20, // u64: ... to the first response body chunk
  REQUEST_SENT_NS: 28, // u64: ... to the request body's end
  END_NS: 36, // u64: ... to finish
  REQUEST_MEDIA: 44, // u8 length + 128
  REQUEST_ENCODING: 173, // u8 length + 131
  RESPONSE_MEDIA: 305, // u8 length + 128
  RESPONSE_ENCODING: 434, // u8 length + 131
  PROVIDER_REQUEST_ID: 566, // u16 length + 256
  BYTES: 824,
});
export const META_VERSION = 1;
export const POINT_CODE_UNDICI = 1;
export const FLAG_HEADERS = 1;
export const FLAG_REQUEST_SENT = 2;
export const FLAG_FIRST_CHUNK = 4;
export const FLAG_UNREADABLE_CHUNK = 8;

const MAX_MEDIA = 128;
const MAX_ENCODING = 131;
const MAX_REQUEST_ID = 256;

/** The run and explicit-ownership scope of the calling context (units 055-t11, 055-t20). */
export interface CaptureScope {
  readonly runSlot?: number;
  /** The innermost open run scope's uuid4, as 16 bytes (`fabric.run.scope_id`). */
  readonly scopeId?: Uint8Array;
  readonly ownership?: ExplicitOwnership;
}

export interface UndiciHookOptions {
  readonly table: ExchangeTable;
  /** The configured endpoints; the slot stores the index of the one that matched. */
  readonly endpoints: readonly EndpointMatcher[];
  /** The caller's run scope; read once per matched request. Default: none. */
  readonly scope?: () => CaptureScope | undefined;
  /** The caller's clean parent context. Default: the active OpenTelemetry span, if any. */
  readonly parent?: () => ParentContext | undefined;
  /** C40 (`FABRIC_WIRE_PROVIDER_REQUEST_ID`): keep the provider's request id header. */
  readonly providerRequestId?: boolean;
  /**
   * Whether this runtime's undici publishes both body-chunk channels. Default:
   * {@link bundledUndiciPublishesBodies}. Without them a body would look empty, so the
   * hook subscribes to nothing rather than record an empty body as exact.
   */
  readonly publishesBodies?: boolean;
  /**
   * Which undici copies may publish a captured exchange. `bundled` (what `install()`
   * passes): only the undici inside this Node.js build, the one the qualification table
   * names. A matched request published by any other copy (an external `undici` package)
   * is never captured: its position is an `uninstrumented_client` loss, so the record
   * names the gap and the run cannot verify complete (spec 055 §3.1, TS-OD-6). `any`
   * (default) captures every publisher; tests that publish undici's messages themselves
   * use it.
   */
  readonly publishers?: "bundled" | "any";
}

/** Content-free counters (spec 055 §4.7 reads them for the status document). */
export interface UndiciHookStats {
  /** Requests that matched a configured endpoint. */
  matched: number;
  /** Matched requests that were not captured (the runtime refused or lost them). */
  notCaptured: number;
  /** POST requests to a model API path on no configured endpoint (FW-006). */
  unmatchedModelShaped: number;
  chunksRetained: number;
  /** Chunks forwarded without being retained (cap, budget, truncated side). */
  chunksNotRetained: number;
  /** Informational (1xx) responses, which never finish an exchange. */
  informational: number;
  /** Exchanges finished because their request was collected unfinished. */
  collected: number;
  /** Failures caught inside a subscriber; never seen by the application. */
  faults: number;
  /**
   * Matched requests published by an undici copy that is not this Node.js build's own
   * (an external `undici` package), recorded as `uninstrumented_client` losses (FW-035).
   */
  unqualifiedPublisher: number;
}

/**
 * One host model-looking requests went to that no endpoint covers (FW-006): the status
 * document lists it with the exact `FABRIC_WIRE_ENDPOINTS` value that records it. Local
 * output only (spec 055 §4.7); never on telemetry or in the spool.
 */
export interface UnmatchedHost {
  readonly scheme: string;
  readonly host: string;
  readonly port: number | undefined;
  /** The dialect the request path implies: `anthropic` for `/v1/messages`, else `openai`. */
  readonly dialect: "openai" | "anthropic";
  readonly count: number;
}

/** Hosts tracked by name, as Python's `_unmatched.py`; further hosts are still counted. */
export const MAX_UNMATCHED_HOSTS = 16;

export interface UndiciHook {
  /** False when nothing was subscribed (an undici without body publications, or a failure). */
  readonly installed: boolean;
  readonly stats: Readonly<UndiciHookStats>;
  /** The unmatched model hosts seen so far, in first-seen order (a copy). */
  unmatchedHosts(): readonly UnmatchedHost[];
  /** Open exchanges this isolate is following. */
  readonly open: number;
  /** Unsubscribes and finishes every open exchange as `abandoned`. Never throws. */
  uninstall(): void;
}

/** One followed request. Never holds the request, a message, a socket or headers. */
interface Entry {
  handle: number;
  endpoint: number;
  api: number;
  dialect: string;
  t0: number;
  flags: number;
  status: number;
  informational: number;
  error: number;
  headersNs: number;
  firstChunkNs: number;
  requestSentNs: number;
  requestMedia: string;
  requestEncoding: string;
  responseMedia: string;
  responseEncoding: string;
  requestId: string;
  done: boolean;
}

// ------------------------------------------------------------------------ normalisation

const MEDIA_RE = /^(?=.{3,128}$)[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;
const ENCODING_RE = /^[a-z0-9][a-z0-9._+-]{0,31}(,[a-z0-9][a-z0-9._+-]{0,31}){0,3}$/;

// Python's `str.isspace()` set, which `str.strip()` and `str.split()` use. JavaScript's
// `\s` and `trim()` differ: they omit U+001C-U+001F and U+0085 and add U+FEFF, so a
// header value carrying one of those would normalise differently from the Python reader.
const PY_SPACE =
  "\\t\\n\\v\\f\\r\\x1c-\\x20\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
const PY_STRIP_RE = new RegExp(`^[${PY_SPACE}]+|[${PY_SPACE}]+$`, "g");
const PY_SPACE_RE = new RegExp(`[${PY_SPACE}]+`, "g");

/** `Content-Type` without parameters, lowercased; octet-stream when invalid (Python). */
export function mediaTypeOf(value: string): string {
  const semi = value.indexOf(";");
  const media = (semi < 0 ? value : value.slice(0, semi)).replace(PY_STRIP_RE, "").toLowerCase();
  return MEDIA_RE.test(media) ? media : "application/octet-stream";
}

/** Lowercased, whitespace removed; `identity` when empty, `unknown` when invalid (Python). */
export function contentEncodingOf(value: string): string {
  const encoding = value.replace(PY_SPACE_RE, "").toLowerCase() || "identity";
  return ENCODING_RE.test(encoding) ? encoding : "unknown";
}

// ------------------------------------------------------------------------------ origin

interface Origin {
  readonly scheme: string;
  readonly host: string;
  readonly port: number | undefined;
}

const ORIGINS = new Map<string, Origin | null>();
const MAX_ORIGINS = 256;

/** `scheme://host[:port]` with no allocation after the first sight of an origin. */
function originOf(text: string): Origin | null {
  let origin = ORIGINS.get(text);
  if (origin !== undefined) return origin;
  origin = parseOrigin(text);
  if (ORIGINS.size >= MAX_ORIGINS) ORIGINS.clear();
  ORIGINS.set(text, origin);
  return origin;
}

function parseOrigin(text: string): Origin | null {
  const colon = text.indexOf("://");
  if (colon <= 0) return null;
  const scheme = text.slice(0, colon).toLowerCase();
  let rest = text.slice(colon + 3);
  const slash = rest.indexOf("/");
  if (slash >= 0) rest = rest.slice(0, slash);
  const at = rest.lastIndexOf("@");
  if (at >= 0) rest = rest.slice(at + 1);
  let host: string;
  let portText = "";
  if (rest.startsWith("[")) {
    const close = rest.indexOf("]");
    if (close < 0) return null;
    host = rest.slice(1, close);
    if (rest[close + 1] === ":") portText = rest.slice(close + 2);
  } else {
    const p = rest.lastIndexOf(":");
    host = p < 0 ? rest : rest.slice(0, p);
    if (p >= 0) portText = rest.slice(p + 1);
  }
  if (host === "") return null;
  let port: number | undefined;
  if (portText !== "") {
    if (!/^[0-9]{1,5}$/.test(portText)) return null;
    port = Number(portText);
  }
  return { scheme, host, port };
}

// ---------------------------------------------------------------------------- the hook

const UTF8 = "utf8";

/** The OpenTelemetry span active in the caller's context: ids, flags and remoteness only. */
export function activeSpanParent(): ParentContext | undefined {
  const span = trace.getSpanContext(otelContext.active());
  if (span === undefined || !/^[0-9a-f]{32}$/.test(span.traceId)) return undefined;
  if (!/^[0-9a-f]{16}$/.test(span.spanId) || /^0+$/.test(span.traceId)) return undefined;
  if (/^0+$/.test(span.spanId)) return undefined;
  return {
    traceId: Buffer.from(span.traceId, "hex"),
    spanId: Buffer.from(span.spanId, "hex"),
    flags: span.traceFlags & 0xff,
    remote: span.isRemote === true,
  };
}

/**
 * Subscribes the hook. Synchronous; never throws (a failure leaves nothing subscribed and
 * is reported by the caller as a disabled point).
 */
// ------------------------------------------------------------------- publishers

/** Request prototype -> whether this Node.js build's own undici publishes it. */
const PUBLISHERS = new WeakMap<object, boolean>();
/**
 * V8's own `Error.captureStackTrace`, taken when this module loads (before the
 * application runs, under the preload): an application or library may later replace the
 * static method, and the hook must never call application code.
 */
const captureStackTrace = Error.captureStackTrace.bind(Error);
/** Where Node.js keeps its bundled undici (`lib/internal/deps/undici/undici.js`). */
const BUNDLED_FILE = "node:internal/deps/undici/";

/**
 * Whether `request` (the `request` of an `undici:request:create` message) comes from the
 * undici bundled with this Node.js build. Each undici copy has its own core `Request`
 * class, so the answer is decided once per class, on its first matched request: the
 * first stack frame below `diagnostics_channel`'s publish names the publishing file.
 * Reads V8 call sites only (no file, no application code: `Error.prepareStackTrace` is
 * swapped for the read and put back, and left alone when the application made it an
 * accessor or read-only). A class that cannot be decided is not the bundled one.
 */
export function bundledPublisher(request: object): boolean {
  const proto = Object.getPrototypeOf(request) as object | null;
  if (proto === null) return false;
  const known = PUBLISHERS.get(proto);
  if (known !== undefined) return known;
  const decided = publisherFileIsBundled();
  // Undecidable now (the application made a stack property an accessor or read-only):
  // not captured this time, and not remembered, so a later call can still be decided.
  if (decided !== undefined) PUBLISHERS.set(proto, decided);
  return decided ?? false;
}

/** Whether the publisher is Node's bundled undici; `undefined` when it cannot be read. */
function publisherFileIsBundled(): boolean | undefined {
  const E = Error as unknown as { prepareStackTrace?: unknown; stackTraceLimit: number };
  for (const name of ["prepareStackTrace", "stackTraceLimit"]) {
    const d = Object.getOwnPropertyDescriptor(Error, name);
    if (d !== undefined && (d.get !== undefined || d.set !== undefined || d.writable !== true)) {
      return undefined;
    }
  }
  const prepare = E.prepareStackTrace;
  const limit = E.stackTraceLimit;
  const holder: { stack?: unknown } = {};
  try {
    E.prepareStackTrace = (_e: unknown, sites: unknown) => sites;
    E.stackTraceLimit = 32;
    captureStackTrace(holder);
    const sites = holder.stack;
    if (!Array.isArray(sites)) return undefined;
    let published = false;
    for (const site of sites as { getFileName(): unknown }[]) {
      const file = site.getFileName();
      if (typeof file !== "string") continue;
      if (file === "node:diagnostics_channel") {
        published = true;
        continue;
      }
      if (published) return file.startsWith(BUNDLED_FILE);
    }
    return false;
  } catch {
    return false;
  } finally {
    E.prepareStackTrace = prepare;
    E.stackTraceLimit = limit;
  }
}

export function installUndiciHook(options: UndiciHookOptions): UndiciHook {
  const table = options.table;
  const index = new EndpointIndex(options.endpoints);
  const endpoints = options.endpoints;
  const scopeOf = options.scope;
  const parentOf = options.parent ?? activeSpanParent;
  const keepRequestId = options.providerRequestId === true;
  const followed = new WeakMap<object, Entry>();
  const open = new Set<Entry>();
  const unmatched = new Map<string, { -readonly [K in keyof UnmatchedHost]: UnmatchedHost[K] }>();
  const stats: UndiciHookStats = {
    matched: 0,
    notCaptured: 0,
    unmatchedModelShaped: 0,
    chunksRetained: 0,
    chunksNotRetained: 0,
    informational: 0,
    collected: 0,
    faults: 0,
    unqualifiedPublisher: 0,
  };
  const bundledOnly = options.publishers === "bundled";
  const collected = new FinalizationRegistry<Entry>((entry) => {
    try {
      if (entry.done) return;
      stats.collected++;
      finish(entry, "abandoned");
    } catch {
      stats.faults++;
    }
  });

  const entryOf = (message: unknown): Entry | undefined => {
    if (typeof message !== "object" || message === null) return undefined;
    const request = (message as { request?: unknown }).request;
    if (typeof request !== "object" || request === null) return undefined;
    return followed.get(request);
  };

  // ------------------------------------------------------------------- the channels

  const onCreate = (message: unknown): void => {
    try {
      if (typeof message !== "object" || message === null) return;
      const request = (message as { request?: unknown }).request;
      if (typeof request !== "object" || request === null || types.isProxy(request)) return;
      const r = request as { method?: unknown; origin?: unknown; path?: unknown };
      if (r.method !== "POST") return;
      let path = r.path;
      if (typeof path !== "string") return;
      let origin: Origin | null;
      if (path.startsWith("http://") || path.startsWith("https://")) {
        // A request sent through an HTTP proxy names its target in the path.
        origin = parseOrigin(path);
        const slash = path.indexOf("/", path.indexOf("://") + 3);
        path = slash < 0 ? "/" : path.slice(slash);
      } else {
        const o = r.origin;
        if (typeof o === "string") origin = originOf(o);
        else if (o instanceof URL) origin = originOf(o.origin);
        else return;
      }
      if (origin === null) return;
      const p = path as string;
      let end = p.length;
      const query = p.indexOf("?");
      if (query >= 0) end = query;
      const hash = p.indexOf("#");
      if (hash >= 0 && hash < end) end = hash;
      const bare = end === p.length ? p : p.slice(0, end);
      const found = index.match("POST", origin.scheme, origin.host, origin.port, bare);
      if (found === undefined) {
        if (MODEL_PATH_SUFFIXES.some((suffix) => bare.endsWith(suffix))) {
          stats.unmatchedModelShaped++;
          // Plain fields only: the fix text is built when the status is read, not here.
          const key = `${origin.scheme}\0${origin.host.toLowerCase()}\0${origin.port ?? ""}`;
          const row = unmatched.get(key);
          if (row !== undefined) row.count++;
          else if (unmatched.size < MAX_UNMATCHED_HOSTS) {
            unmatched.set(key, {
              scheme: origin.scheme,
              host: origin.host.toLowerCase(),
              port: origin.port,
              dialect: bare.endsWith("/v1/messages") ? "anthropic" : "openai",
              count: 1,
            });
          }
        }
        return;
      }
      stats.matched++;
      const t0 = performance.now();
      let scope: CaptureScope | undefined;
      try {
        scope = scopeOf?.();
      } catch {
        // Without the caller's scope nobody can tell whether an explicit producer owns
        // this call, so it is not captured; counted, never the agent's problem.
        stats.faults++;
        stats.notCaptured++;
        return;
      }
      if (bundledOnly && !bundledPublisher(request)) {
        // Another undici copy published this call: its bytes are never taken as
        // qualified evidence. The position is a named gap instead of a silent miss.
        stats.unqualifiedPublisher++;
        stats.notCaptured++;
        table.uninstrumented(scope?.runSlot);
        return;
      }
      let parent: ParentContext | undefined;
      try {
        parent = parentOf();
      } catch {
        // A host OpenTelemetry failure is not the agent's problem: no parent.
        stats.faults++;
      }
      const handle = table.begin({
        runSlot: scope?.runSlot,
        scopeId: scope?.scopeId,
        ownership: scope?.ownership,
        parent,
      });
      if (handle === NO_EXCHANGE) {
        stats.notCaptured++;
        return;
      }
      const entry: Entry = {
        handle,
        endpoint: endpoints.indexOf(found.endpoint),
        api: WIRE_APIS.indexOf(found.api),
        dialect: found.endpoint.dialect,
        t0,
        flags: 0,
        status: 0,
        informational: 0,
        error: 0,
        headersNs: 0,
        firstChunkNs: 0,
        requestSentNs: 0,
        requestMedia: "",
        requestEncoding: "",
        responseMedia: "",
        responseEncoding: "",
        requestId: "",
        done: false,
      };
      // Followed before anything else can fail: an exchange that has a slot always
      // finishes, so its position never stays an unsettled gap.
      followed.set(request, entry);
      open.add(entry);
      collected.register(request, entry, entry);
      try {
        requestHeaders(entry, request as { contentType?: unknown; headers?: unknown });
      } catch {
        // Unreadable metadata is left at Python's defaults; the bytes are still captured.
        stats.faults++;
      }
    } catch {
      stats.faults++;
    }
  };

  const onBodyChunkSent = (message: unknown): void => {
    try {
      const entry = entryOf(message);
      if (entry === undefined || entry.done) return;
      admit(entry, REQUEST, (message as { chunk?: unknown }).chunk);
    } catch {
      stats.faults++;
    }
  };

  const onBodySent = (message: unknown): void => {
    try {
      const entry = entryOf(message);
      if (entry === undefined || entry.done) return;
      entry.flags |= FLAG_REQUEST_SENT;
      entry.requestSentNs = elapsed(entry);
    } catch {
      stats.faults++;
    }
  };

  const onHeaders = (message: unknown): void => {
    try {
      const entry = entryOf(message);
      if (entry === undefined || entry.done) return;
      const response = (message as { response?: unknown }).response;
      if (typeof response !== "object" || response === null) return;
      const status = (response as { statusCode?: unknown }).statusCode;
      if (typeof status !== "number" || !Number.isInteger(status)) return;
      if (status < 200) {
        // An informational response never finishes an exchange.
        stats.informational++;
        entry.informational = Math.min(255, entry.informational + 1);
        return;
      }
      if ((entry.flags & FLAG_HEADERS) !== 0) return;
      entry.flags |= FLAG_HEADERS;
      entry.status = status > 0xffff ? 0 : status;
      entry.headersNs = elapsed(entry);
      table.responseStarted(entry.handle);
      try {
        responseHeaders(entry, (response as { headers?: unknown }).headers);
      } catch {
        // Unreadable metadata is left at Python's defaults; the response is still kept.
        stats.faults++;
      }
    } catch {
      stats.faults++;
    }
  };

  const onBodyChunkReceived = (message: unknown): void => {
    try {
      const entry = entryOf(message);
      if (entry === undefined || entry.done) return;
      if ((entry.flags & FLAG_FIRST_CHUNK) === 0) {
        entry.flags |= FLAG_FIRST_CHUNK;
        entry.firstChunkNs = elapsed(entry);
      }
      admit(entry, RESPONSE, (message as { chunk?: unknown }).chunk);
    } catch {
      stats.faults++;
    }
  };

  const onTrailers = (message: unknown): void => {
    try {
      const entry = entryOf(message);
      if (entry === undefined || entry.done) return;
      // Trailer values are never read.
      finish(entry, "complete");
    } catch {
      stats.faults++;
    }
  };

  const onError = (message: unknown): void => {
    try {
      const entry = entryOf(message);
      if (entry === undefined || entry.done) return;
      const error = errorType((message as { error?: unknown }).error);
      entry.error = error;
      // An abort after the response headers is the application closing the response
      // early; anything else is a failure. An abort before the headers is `error`, as
      // Python records any exception raised before a response exists (`Exchange.fail`):
      // `closed_early` says a response was received (047 G2), so the reader would report
      // a response that never existed as `missing_object(response_not_recorded)`.
      const aborted = ERROR_TYPES[error] === "AbortError" && (entry.flags & FLAG_HEADERS) !== 0;
      finish(entry, aborted ? "closed_early" : "error");
    } catch {
      stats.faults++;
    }
  };

  // --------------------------------------------------------------------------- parts

  const elapsed = (entry: Entry): number =>
    Math.max(0, Math.round((performance.now() - entry.t0) * 1e6));

  const admit = (entry: Entry, side: typeof REQUEST | typeof RESPONSE, chunk: unknown): void => {
    let kept: boolean;
    if (chunk instanceof Uint8Array) {
      kept = table.admit(entry.handle, side, chunk);
    } else if (typeof chunk === "string") {
      // undici writes a string chunk with the socket's default encoding.
      kept = table.admit(entry.handle, side, chunk, UTF8);
    } else {
      // Bytes Fabric cannot see were sent: the side is incomplete, never exact.
      entry.flags |= FLAG_UNREADABLE_CHUNK;
      if (side === REQUEST) table.requestIncomplete(entry.handle);
      else table.responseIncomplete(entry.handle);
      kept = false;
    }
    if (kept) stats.chunksRetained++;
    else stats.chunksNotRetained++;
  };

  const requestHeaders = (entry: Entry, request: { contentType?: unknown; headers?: unknown }) => {
    const type = request.contentType;
    if (typeof type === "string") entry.requestMedia = mediaTypeOf(type);
    const headers = request.headers;
    if (!Array.isArray(headers)) return;
    // Repeated headers join with ", ", as Python's `headers.get` returns them.
    let encoding: string | undefined;
    for (let i = 0; i + 1 < headers.length; i += 2) {
      const name = headers[i];
      if (typeof name !== "string" || name.length !== 16) continue;
      if (name.toLowerCase() !== "content-encoding") continue;
      const value = headers[i + 1];
      const text = Array.isArray(value) ? value.join(", ") : value;
      if (typeof text !== "string") continue;
      encoding = encoding === undefined ? text : `${encoding}, ${text}`;
    }
    if (encoding !== undefined) entry.requestEncoding = contentEncodingOf(encoding);
  };

  const responseHeaders = (entry: Entry, headers: unknown): void => {
    if (!Array.isArray(headers)) return;
    const idName = keepRequestId
      ? entry.dialect === "anthropic"
        ? "request-id"
        : "x-request-id"
      : "";
    let media: string | undefined;
    let encoding: string | undefined;
    let requestId: string | undefined;
    for (let i = 0; i + 1 < headers.length; i += 2) {
      const raw = headers[i];
      const length = raw instanceof Uint8Array || typeof raw === "string" ? raw.length : -1;
      if (length !== 12 && length !== 16 && length !== idName.length) continue;
      const name = (
        typeof raw === "string" ? raw : Buffer.from(raw as Uint8Array).toString("latin1")
      ).toLowerCase();
      const isMedia = name === "content-type";
      const isEncoding = name === "content-encoding";
      const isId = idName !== "" && name === idName;
      if (!isMedia && !isEncoding && !isId) continue;
      const value = headerValue(headers[i + 1]);
      if (value === undefined) continue;
      if (isMedia) media = media === undefined ? value : `${media}, ${value}`;
      else if (isEncoding) encoding = encoding === undefined ? value : `${encoding}, ${value}`;
      else requestId = requestId === undefined ? value : `${requestId}, ${value}`;
    }
    // C40, as Python's `read_provider_request_id`: the (joined) value, kept only when
    // non-empty and at most 256 characters.
    if (requestId !== undefined && requestId.length > 0 && requestId.length <= MAX_REQUEST_ID) {
      entry.requestId = requestId;
    }
    if (media !== undefined) entry.responseMedia = mediaTypeOf(media);
    if (encoding !== undefined) entry.responseEncoding = contentEncodingOf(encoding);
  };

  const finish = (entry: Entry, state: ResponseState): void => {
    if (entry.done) return;
    entry.done = true;
    open.delete(entry);
    collected.unregister(entry);
    try {
      if ((entry.flags & FLAG_REQUEST_SENT) === 0) table.requestIncomplete(entry.handle);
      const meta = table.meta(entry.handle);
      if (meta !== undefined) writeMeta(meta, entry, elapsed(entry));
    } finally {
      // Finish-once is decided here (`done`), so the slot is always handed back.
      table.finish(entry.handle, state);
    }
  };

  const subscriptions: [string, (message: unknown) => void][] = [
    ["undici:request:create", onCreate],
    ["undici:request:bodyChunkSent", onBodyChunkSent],
    ["undici:request:bodySent", onBodySent],
    ["undici:request:headers", onHeaders],
    ["undici:request:bodyChunkReceived", onBodyChunkReceived],
    ["undici:request:trailers", onTrailers],
    ["undici:request:error", onError],
  ];
  const subscribed: typeof subscriptions = [];
  try {
    const bodies = options.publishesBodies ?? bundledUndiciPublishesBodies();
    for (const subscription of bodies ? subscriptions : []) {
      subscribe(subscription[0], subscription[1]);
      subscribed.push(subscription);
    }
  } catch {
    for (const [name, fn] of subscribed) unsubscribe(name, fn);
    subscribed.length = 0;
  }

  return {
    installed: subscribed.length === subscriptions.length,
    stats,
    unmatchedHosts() {
      return [...unmatched.values()].map((row) => ({ ...row }));
    },
    get open() {
      return open.size;
    },
    uninstall() {
      for (const [name, fn] of subscribed) {
        try {
          unsubscribe(name, fn);
        } catch {
          stats.faults++;
        }
      }
      subscribed.length = 0;
      for (const entry of [...open]) {
        try {
          finish(entry, "abandoned");
        } catch {
          stats.faults++;
        }
      }
    },
  };
}

/**
 * The first undici release whose request publishes both body-chunk channels, by the
 * audit of spec 055 §3.1 (`wire-qualification.json`: Node 24.4.0 bundles 7.11.0; Node 22
 * and 24.0.0 to 24.3.0 publish neither). A floor only: a build is captured when its exact
 * tuple is in the qualification table, which the installer checks (unit 055-t14).
 */
export const FIRST_BODY_PUBLISHING_UNDICI = "7.11.0";

/** Whether the bundled undici (`process.versions.undici`) is at least that release. */
export function bundledUndiciPublishesBodies(version = process.versions.undici): boolean {
  const parts = /^(\d+)\.(\d+)\.(\d+)/.exec(version ?? "");
  if (parts === null) return false;
  const [major, minor] = [Number(parts[1]), Number(parts[2])];
  return major > 7 || (major === 7 && minor >= 11);
}

/** A header value as undici publishes it (a `Buffer`, or a string), as latin1 text. */
function headerValue(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (value instanceof Uint8Array)
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString("latin1");
  return undefined;
}

/**
 * The error's class, from an allowlist, read without running application code: no
 * getter, proxy trap, `toString` or `message` is ever touched. Unknown classes are `Error`.
 */
export function errorType(error: unknown): number {
  try {
    if (typeof error !== "object" || error === null || types.isProxy(error)) return 1;
    // The built-in `name` getter of an exact DOMException (fetch's AbortError and
    // TimeoutError) reads an internal slot; a subclass could define its own, so only the
    // exact prototype is read, and only when the instance has no own `name` (an own
    // accessor would be application code; an own data property is read below).
    const domException = globalThis.DOMException;
    if (
      Object.getPrototypeOf(error) === domException.prototype &&
      Object.getOwnPropertyDescriptor(error, "name") === undefined
    ) {
      return ERROR_CODES.get((error as InstanceType<typeof domException>).name) ?? 1;
    }
    let target: object | null = error;
    for (let depth = 0; depth < 6 && target !== null; depth++) {
      if (types.isProxy(target)) return 1;
      const own = Object.getOwnPropertyDescriptor(target, "name");
      if (own !== undefined) {
        return "value" in own && typeof own.value === "string"
          ? (ERROR_CODES.get(own.value) ?? 1)
          : 1;
      }
      target = Object.getPrototypeOf(target) as object | null;
    }
  } catch {
    // Never the application's problem.
  }
  return 1;
}

// ----------------------------------------------------------------------- slot metadata

function u16(meta: Uint8Array, at: number, value: number): void {
  meta[at] = value & 0xff;
  meta[at + 1] = (value >>> 8) & 0xff;
}

function u64(meta: Uint8Array, at: number, value: number): void {
  const lo = value % 0x1_0000_0000;
  const hi = Math.floor(value / 0x1_0000_0000);
  for (let i = 0; i < 4; i++) {
    meta[at + i] = (lo >>> (8 * i)) & 0xff;
    meta[at + 4 + i] = (hi >>> (8 * i)) & 0xff;
  }
}

/** Writes ASCII text after a length byte; text outside printable ASCII is not kept. */
function text(meta: Uint8Array, at: number, value: string, max: number, wide = false): void {
  const start = at + (wide ? 2 : 1);
  if (value.length > max) return;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) return;
    meta[start + i] = code;
  }
  if (wide) u16(meta, at, value.length);
  else meta[at] = value.length;
}

function writeMeta(meta: Uint8Array, entry: Entry, endNs: number): void {
  meta[META.VERSION] = META_VERSION;
  meta[META.POINT] = POINT_CODE_UNDICI;
  u16(meta, META.ENDPOINT, entry.endpoint < 0 ? 0xffff : entry.endpoint);
  meta[META.API] = entry.api < 0 ? 0xff : entry.api;
  meta[META.ERROR] = entry.error;
  meta[META.FLAGS] = entry.flags;
  meta[META.INFORMATIONAL] = entry.informational;
  u16(meta, META.STATUS, entry.status);
  u64(meta, META.HEADERS_NS, entry.headersNs);
  u64(meta, META.FIRST_CHUNK_NS, entry.firstChunkNs);
  u64(meta, META.REQUEST_SENT_NS, entry.requestSentNs);
  u64(meta, META.END_NS, endNs);
  text(meta, META.REQUEST_MEDIA, entry.requestMedia, MAX_MEDIA);
  text(meta, META.REQUEST_ENCODING, entry.requestEncoding, MAX_ENCODING);
  text(meta, META.RESPONSE_MEDIA, entry.responseMedia, MAX_MEDIA);
  text(meta, META.RESPONSE_ENCODING, entry.responseEncoding, MAX_ENCODING);
  text(meta, META.PROVIDER_REQUEST_ID, entry.requestId, MAX_REQUEST_ID, true);
}

/** The transport metadata of a completed undici exchange, as the Fabric worker reads it. */
export interface UndiciMeta {
  readonly endpointIndex: number;
  readonly api: WireApi | undefined;
  readonly statusCode: number | undefined;
  readonly errorType: string | undefined;
  readonly informational: number;
  readonly requestSent: boolean;
  readonly unreadableChunk: boolean;
  readonly headersOffsetNs: bigint | undefined;
  readonly firstChunkOffsetNs: bigint | undefined;
  readonly requestSentOffsetNs: bigint | undefined;
  readonly endOffsetNs: bigint;
  /** Python's defaults when the header was absent: octet-stream and identity. */
  readonly requestMediaType: string;
  readonly requestContentEncoding: string;
  readonly responseMediaType: string;
  readonly responseContentEncoding: string;
  readonly providerRequestId: string | undefined;
}

/** Decodes the hook-defined bytes of a job record; `undefined` when not an undici record. */
export function readUndiciMeta(meta: Uint8Array): UndiciMeta | undefined {
  if (meta[META.VERSION] !== META_VERSION || meta[META.POINT] !== POINT_CODE_UNDICI) {
    return undefined;
  }
  const r16 = (at: number): number => meta[at]! | (meta[at + 1]! << 8);
  const r64 = (at: number): bigint => {
    let value = 0n;
    for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(meta[at + i]!);
    return value;
  };
  const str = (at: number, wide = false): string => {
    const length = wide ? r16(at) : meta[at]!;
    const start = at + (wide ? 2 : 1);
    return Buffer.from(meta.subarray(start, start + length)).toString("latin1");
  };
  const flags = meta[META.FLAGS]!;
  const status = r16(META.STATUS);
  const error = meta[META.ERROR]!;
  const requestId = str(META.PROVIDER_REQUEST_ID, true);
  return {
    endpointIndex: r16(META.ENDPOINT),
    api: WIRE_APIS[meta[META.API]!],
    statusCode: status === 0 ? undefined : status,
    errorType: error === 0 ? undefined : ERROR_TYPES[error],
    informational: meta[META.INFORMATIONAL]!,
    requestSent: (flags & FLAG_REQUEST_SENT) !== 0,
    unreadableChunk: (flags & FLAG_UNREADABLE_CHUNK) !== 0,
    headersOffsetNs: (flags & FLAG_HEADERS) !== 0 ? r64(META.HEADERS_NS) : undefined,
    firstChunkOffsetNs: (flags & FLAG_FIRST_CHUNK) !== 0 ? r64(META.FIRST_CHUNK_NS) : undefined,
    requestSentOffsetNs: (flags & FLAG_REQUEST_SENT) !== 0 ? r64(META.REQUEST_SENT_NS) : undefined,
    endOffsetNs: r64(META.END_NS),
    requestMediaType: str(META.REQUEST_MEDIA) || "application/octet-stream",
    requestContentEncoding: str(META.REQUEST_ENCODING) || "identity",
    responseMediaType: str(META.RESPONSE_MEDIA) || "application/octet-stream",
    responseContentEncoding: str(META.RESPONSE_ENCODING) || "identity",
    providerRequestId: requestId === "" ? undefined : requestId,
  };
}
