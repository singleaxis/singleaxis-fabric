// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * The validated wire configuration (spec 055 §4.2, §4.7): the Python environment names
 * and rules, read by TypeScript unchanged, so the environment file `fabric init` writes
 * (spec 058 §6.5) configures a Node agent as it configures a Python one.
 *
 * Precedence: explicit options, then the environment, then the pinned defaults. Only the
 * named variables are read (the environment is never enumerated). Unset and empty are
 * the same for every variable. Each `*_FILE` variant names a file holding the secret.
 * `FABRIC_OTLP_*` (058 §6.4) wins over `OTEL_EXPORTER_OTLP_*`: when any is set, nothing is
 * read from the `OTEL_*` names.
 *
 * Every malformed setting throws a {@link WireConfigError}: fixed text naming the variable
 * and the rule (never its value, a path or a key), and the catalogue id
 * (`contracts/diagnostics/v1/messages-v1.json`) Python's `wire/_diagnose.py` gives the
 * same setting, except that Python's generic id (its `capture_not_installed`) is `FW-025`
 * here, whose fix names the Node status command. A test runs the shared fixture `test/wire/fixtures/config-env.json`,
 * generated from `python -m fabric.wire status`, through {@link configStatus}.
 *
 * Install-time only: this module reads key, certificate, header and policy files, so it
 * never runs in a transport hook.
 */

import { closeSync, openSync, readSync, statSync } from "node:fs";

import { DeploymentPolicy } from "../deployment-policy.js";
import { identityModeFromEnv, utf8SurrogatePass } from "../identity.js";
import { readRedactionToken, redactionServiceFromEnv } from "../redaction.js";
import { CATALOGUE, type TypeScriptCatalogueId } from "./catalogue.generated.js";
import { PyFloat, parseJson } from "./codec.js";
import { BUILTIN_ENDPOINTS, endpointMatcher, isValidEndpoint } from "./match.js";
import { OPAQUE_ID_RE } from "./p1-types.js";
import { splitTokens } from "./p1.js";
import type { Dialect, EndpointMatcher, ExposureMode, OtlpRoute, WireSettings } from "./types.js";

type Env = Readonly<Record<string, string | undefined>>;

// ----------------------------------------------------------------- errors

/** Python's generic configuration id (`capture_not_installed`), as TypeScript reports it. */
export const GENERIC_REASON_ID: TypeScriptCatalogueId = "FW-025";

/** Every catalogue id a configuration error can carry. */
export const CONFIG_REASON_IDS: readonly TypeScriptCatalogueId[] = Object.freeze([
  "FW-010",
  "FW-012",
  "FW-013",
  "FW-014",
  "FW-015",
  "FW-017",
  "FW-018",
  "FW-019",
  "FW-020",
  "FW-024",
  "FW-025",
]);

/** A malformed setting: fixed text (never a value), its catalogue id and the fix. */
export class WireConfigError extends Error {
  readonly reasonId: TypeScriptCatalogueId;

  constructor(message: string, reasonId: TypeScriptCatalogueId = GENERIC_REASON_ID) {
    super(message);
    this.name = "WireConfigError";
    this.reasonId = reasonId;
  }

  /** The catalogue's fix for {@link reasonId}. */
  get fix(): string {
    return CATALOGUE.find((entry) => entry.id === this.reasonId)?.fix ?? "";
  }
}

const fail = (message: string, id?: TypeScriptCatalogueId): never => {
  throw new WireConfigError(message, id);
};

// ----------------------------------------------------------------- constants (Python's)

const MIB = 1024 * 1024;
export const MAX_BODY_BYTES_CAP = 64 * MIB;
export const NODE_MAX_BODY_BYTES = 63 * MIB;
export const SPOOL_RESERVE_BYTES = MIB;
export const QUEUE_MAX_ITEMS = 16384;
export const MAX_QUEUE_ITEMS = 65536;
export const MAX_DRAIN_ON_EXIT_S = 3600;
export const MAX_CONTENT_BATCH_BODIES = 256;
export const MAX_CONTENT_CONCURRENCY = 16;
export const SPOOL_KEY_BYTES = 32;
export const TOKEN_KEY_MIN_BYTES = 32;
export const MIN_ID_KEY_BYTES = 16;
export const RECORDS_MAX_OBJECT_BYTES = 16 * MIB;
export const OPEN_RUN_DEADLINE_DEFAULT_S = 604800;
export const CLOCK_UNCERTAINTY_DEFAULT_MS = 1000;
const INT62 = 1n << 62n;
const INT64_MAX = (1n << 63n) - 1n;
const MAX_KEY_FILE_BYTES = 4096;
const MAX_HEADERS_FILE_BYTES = 64 * 1024;
const MAX_POLICY_BYTES = 1 << 20;
const TENANT_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/;
const MODEL_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(["localhost", "127.0.0.1", "::1"]);
const FILE_SPOOL_DIR = ".fabric-wire-spool";
const SPOOL_OFF = "off";

/** Every environment variable this module reads (a test pins it to the mapping fixture). */
export const ENV_NAMES: readonly string[] = Object.freeze([
  "FABRIC_WIRE_AUTOLOAD",
  "FABRIC_WIRE_DIAGNOSTICS",
  "FABRIC_WIRE_UNDICI",
  "FABRIC_WIRE_NODE_HTTP",
  "FABRIC_WIRE_BUILTIN_ENDPOINTS",
  "FABRIC_WIRE_ENDPOINTS",
  "FABRIC_WIRE_LABELS",
  "FABRIC_IDENTITY_MODE",
  "FABRIC_WIRE_ID_KEY",
  "FABRIC_WIRE_ID_KEY_FILE",
  "FABRIC_WIRE_SPOOL_KEY",
  "FABRIC_WIRE_SPOOL_KEY_FILE",
  "FABRIC_TOKENIZATION_KEY",
  "FABRIC_TOKENIZATION_KEY_FILE",
  "FABRIC_WIRE_STORE",
  "FABRIC_WIRE_STORE_SSE",
  "FABRIC_WIRE_STORE_KMS_KEY_ID",
  "FABRIC_WIRE_CONTENT_ENDPOINT",
  "FABRIC_TENANT_ID",
  "FABRIC_SOURCE_ID",
  "FABRIC_WIRE_SPOOL_DIR",
  "FABRIC_WIRE_SPOOL_MAX_BYTES",
  "FABRIC_WIRE_SPOOL_MAX_RECEIPTS",
  "FABRIC_WIRE_SPOOL_DURABLE_BOUNDARY",
  "FABRIC_WIRE_SPOOL_MIGRATE_PLAINTEXT",
  "FABRIC_CAPTURE_POLICY",
  "FABRIC_REDACTION_ENDPOINT",
  "FABRIC_REDACTION_TOKEN_FILE",
  "FABRIC_WIRE_MODEL_ALLOWLIST",
  "FABRIC_WIRE_MAX_BODY_BYTES",
  "FABRIC_WIRE_MAX_RETAIN_BYTES",
  "FABRIC_WIRE_PART_MIN_BYTES",
  "FABRIC_WIRE_QUEUE_MAX_ITEMS",
  "FABRIC_WIRE_SHUTDOWN_TIMEOUT_S",
  "FABRIC_WIRE_DRAIN_ON_EXIT_S",
  "FABRIC_WIRE_CONTENT_BATCH_BODIES",
  "FABRIC_WIRE_CONTENT_CONCURRENCY",
  "FABRIC_WIRE_PROXY",
  "FABRIC_OTLP_ENDPOINT",
  "FABRIC_OTLP_CERTIFICATE",
  "FABRIC_OTLP_CLIENT_CERTIFICATE",
  "FABRIC_OTLP_CLIENT_KEY",
  "FABRIC_OTLP_HEADERS_FILE",
  ...["TRACES_", "LOGS_", ""].flatMap((signal) =>
    ["ENDPOINT", "HEADERS", "CERTIFICATE", "CLIENT_CERTIFICATE", "CLIENT_KEY", "TIMEOUT"]
      .concat(["COMPRESSION", "PROTOCOL"])
      .map((suffix) => `OTEL_EXPORTER_OTLP_${signal}${suffix}`),
  ),
  "OTEL_SDK_DISABLED",
  "FABRIC_RUN_ID",
  "FABRIC_RUN_RESUME_TOKEN",
  "FABRIC_RUN_OPEN_DEADLINE_S",
  "FABRIC_RECORDS_STRICT",
  "FABRIC_RECORDS_MAX_OBJECT_BYTES",
  "FABRIC_CLOCK_UNCERTAINTY_MS",
  "FABRIC_WIRE_PROVIDER_REQUEST_ID",
  "FABRIC_WIRE_STATUS_FILE",
]);

// ----------------------------------------------------------------- Python value parsing

/** `environ.get(name) or None`: unset and empty are the same. */
function get(env: Env, name: string): string | undefined {
  const value = env[name];
  return value === undefined || value === "" ? undefined : value;
}

/** `(environ.get(name) or "").strip() or None`. */
function getTrimmed(env: Env, name: string): string | undefined {
  const value = get(env, name)?.trim();
  return value === "" ? undefined : value;
}

const truthy = (value: string | undefined): boolean =>
  ["1", "true", "yes", "on"].includes((value ?? "").trim().toLowerCase());

/** Python `int(text)`: surrounding whitespace, a sign, digit groups joined by `_`. */
function pyInt(text: string): bigint | undefined {
  const m = /^\s*([+-]?)([0-9](?:_?[0-9])*)\s*$/.exec(text);
  return m === null ? undefined : BigInt(m[1]! + m[2]!.replaceAll("_", ""));
}

/** Python `float(text)` (finite or not); undefined when Python raises. */
function pyFloat(text: string): number | undefined {
  const t = text.trim();
  if (/^[+-]?(inf|infinity|nan)$/i.test(t))
    return Number(t.replace(/inf(inity)?/i, "Infinity").replace(/nan/i, "NaN"));
  const digits = "[0-9](?:_?[0-9])*";
  const re = new RegExp(
    `^[+-]?(?:${digits}(?:\\.(?:${digits})?)?|\\.${digits})(?:[eE][+-]?${digits})?$`,
  );
  return re.test(t) ? Number(t.replaceAll("_", "")) : undefined;
}

/** Python `base64.b64decode(text, validate=True)`; undefined when it raises. */
function b64decode(text: string): Buffer | undefined {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) return undefined;
  return Buffer.from(text, "base64");
}

/** Python `urllib.parse.unquote(text)` (invalid UTF-8 becomes U+FFFD). */
function unquote(text: string): string {
  if (!text.includes("%")) return text;
  const bytes: number[] = [];
  let out = "";
  const flush = (): void => {
    if (bytes.length > 0) out += new TextDecoder("utf-8").decode(Uint8Array.from(bytes));
    bytes.length = 0;
  };
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "%" && /^[0-9A-Fa-f]{2}$/.test(text.slice(i + 1, i + 3))) {
      bytes.push(parseInt(text.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      flush();
      out += text[i];
    }
  }
  flush();
  return out;
}

interface SplitUrl {
  readonly scheme: string;
  readonly netloc: string;
  readonly path: string;
  readonly query: string;
  readonly fragment: string;
  readonly hostname: string;
  readonly port: number | undefined;
}

/** Python `urlsplit` with `.hostname` and `.port`; undefined where Python raises. */
function urlsplit(text: string): SplitUrl | undefined {
  const m =
    /^(?:([A-Za-z][A-Za-z0-9+.-]*):)?(?:\/\/([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/s.exec(
      text,
    );
  if (m === null) return undefined;
  const netloc = m[2] ?? "";
  const hostport = netloc.slice(netloc.lastIndexOf("@") + 1);
  let hostname: string;
  let portText: string | undefined;
  if (hostport.startsWith("[")) {
    const end = hostport.indexOf("]");
    if (end < 0) return undefined;
    hostname = hostport.slice(1, end);
    const rest = hostport.slice(end + 1);
    if (rest !== "" && !rest.startsWith(":")) return undefined;
    portText = rest === "" ? undefined : rest.slice(1);
  } else {
    if (hostport.includes("[") || hostport.includes("]")) return undefined;
    const at = hostport.indexOf(":");
    hostname = at < 0 ? hostport : hostport.slice(0, at);
    portText = at < 0 ? undefined : hostport.slice(at + 1);
  }
  let port: number | undefined;
  if (portText !== undefined && portText !== "") {
    if (!/^[0-9]+$/.test(portText) || Number(portText) > 65535) return undefined;
    port = Number(portText);
  }
  return {
    scheme: (m[1] ?? "").toLowerCase(),
    netloc,
    path: m[3] ?? "",
    query: m[4] ?? "",
    fragment: m[5] ?? "",
    hostname: hostname.toLowerCase(),
    port,
  };
}

/** Python `posixpath.normpath`. */
function normpath(path: string): string {
  if (path === "") return ".";
  const initial =
    path.startsWith("//") && !path.startsWith("///") ? "//" : path.startsWith("/") ? "/" : "";
  const parts: string[] = [];
  for (const part of path.split("/")) {
    if (part === "" || part === ".") continue;
    if (
      part !== ".." ||
      (initial === "" && parts.length === 0) ||
      parts[parts.length - 1] === ".."
    ) {
      parts.push(part);
    } else if (parts.length > 0) {
      parts.pop();
    }
  }
  return initial + parts.join("/") || ".";
}

// eslint-disable-next-line no-control-regex -- Python's line boundaries include FS, GS, RS.
const SPLITLINES_RE = /\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]/;

/** Python `str.splitlines()`. */
const splitlines = (text: string): string[] =>
  text.split(SPLITLINES_RE).filter((line, i, all) => i < all.length - 1 || line !== "");

/** At most `max + 1` bytes of the file at `path` (so an oversized file is seen as such). */
function readBounded(path: string, max: number): Buffer | undefined {
  let fd: number | undefined;
  try {
    fd = openSync(path, "r");
    const buffer = Buffer.alloc(max + 1);
    let size = 0;
    for (;;) {
      const read = readSync(fd, buffer, size, buffer.length - size, null);
      if (read === 0 || (size += read) === buffer.length) break;
    }
    return buffer.subarray(0, size);
  } catch {
    return undefined;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

// ----------------------------------------------------------------- keys (Python `_keys.py`)

function keyFromEnv(env: Env, name: string, exact?: number, minimum = 1): Uint8Array | undefined {
  const value = get(env, name) ?? "";
  const path = get(env, `${name}_FILE`) ?? "";
  const size = exact !== undefined ? `${exact}-byte` : `${minimum}-byte or longer`;
  const accept = (key: Buffer | undefined): key is Buffer =>
    key !== undefined && (exact !== undefined ? key.length === exact : key.length >= minimum);
  if (value !== "" && path !== "") fail(`set ${name} or ${name}_FILE, not both`, "FW-018");
  if (value !== "") {
    const key = b64decode(
      value.trim().replace(/[^ -~\t\n\r\v\f]/g, (ch) => (ch.charCodeAt(0) < 0x80 ? ch : "?")),
    );
    if (!accept(key)) fail(`${name} must be base64 of a ${size} key`);
    return Uint8Array.from(key!);
  }
  if (path === "") return undefined;
  const raw = readBounded(path, MAX_KEY_FILE_BYTES);
  if (raw === undefined) fail(`${name}_FILE is not readable`, "FW-019");
  const text = raw!.toString("latin1");
  const decoded = b64decode(text.endsWith("\n") ? text.slice(0, -1) : text);
  for (const candidate of [decoded, raw]) {
    if (accept(candidate) && raw!.length <= MAX_KEY_FILE_BYTES) return Uint8Array.from(candidate);
  }
  return fail(`${name}_FILE must hold a ${size} key (raw or base64)`, "FW-019");
}

function checkIdKey(key: Uint8Array): Uint8Array {
  if (key.length < MIN_ID_KEY_BYTES)
    fail(`FABRIC_WIRE_ID_KEY must be at least ${MIN_ID_KEY_BYTES} bytes`);
  return key;
}

/** `FABRIC_WIRE_ID_KEY` (UTF-8, surrogatepass) or the file `FABRIC_WIRE_ID_KEY_FILE` names. */
function idKeyFromEnv(env: Env): Uint8Array | undefined {
  const name = "FABRIC_WIRE_ID_KEY";
  const value = get(env, name) ?? "";
  const path = get(env, `${name}_FILE`) ?? "";
  if (value !== "" && path !== "") fail(`set ${name} or ${name}_FILE, not both`, "FW-018");
  if (value !== "") return checkIdKey(Uint8Array.from(utf8SurrogatePass(value)));
  if (path === "") return undefined;
  const raw = readBounded(path, MAX_KEY_FILE_BYTES);
  if (raw === undefined) fail(`${name}_FILE is not readable`, "FW-019");
  if (raw!.length > MAX_KEY_FILE_BYTES) {
    fail(`${name}_FILE must hold a key of at most ${MAX_KEY_FILE_BYTES} bytes`, "FW-019");
  }
  const strip = raw!.subarray(-2).equals(Buffer.from("\r\n"))
    ? 2
    : raw!.subarray(-1).equals(Buffer.from("\n"))
      ? 1
      : 0;
  return checkIdKey(Uint8Array.from(raw!.subarray(0, raw!.length - strip)));
}

// ----------------------------------------------------------------- endpoints

const MATCHER_KEYS: Readonly<Record<string, keyof EndpointMatcher>> = {
  endpoint_id: "endpointId",
  dialect: "dialect",
  hosts: "hosts",
  host_suffixes: "hostSuffixes",
  ports: "ports",
  path_prefix: "pathPrefix",
  provider_name: "providerName",
  schemes: "schemes",
};
const SET_KEYS = new Set(["hosts", "host_suffixes", "schemes", "ports"]);

function invalidMatcher(): never {
  return fail("invalid endpoint matcher", "FW-015");
}

/** `FABRIC_WIRE_ENDPOINTS`: a JSON array of matcher objects (Python `parse_endpoints`). */
export function parseEndpoints(text: string): EndpointMatcher[] {
  let raw: unknown;
  try {
    raw = parseJson(text); // exact ints; 443.0 stays a float, as Python reads it
  } catch {
    return fail("FABRIC_WIRE_ENDPOINTS is not valid JSON", "FW-014");
  }
  if (!Array.isArray(raw)) fail("FABRIC_WIRE_ENDPOINTS must be a JSON array", "FW-014");
  return (raw as unknown[]).map((entry) => {
    const shape = (): never =>
      fail("FABRIC_WIRE_ENDPOINTS entries must be matcher objects", "FW-014");
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) shape();
    const fields = entry as Record<string, unknown>;
    if (Object.keys(fields).some((k) => !(k in MATCHER_KEYS))) shape();
    if (!("endpoint_id" in fields) || !("dialect" in fields)) shape();
    for (const key of SET_KEYS) {
      const value = fields[key];
      if (value === undefined) continue;
      // Python builds a frozenset: a list or object item is unhashable (a shape error).
      const unhashable = (v: unknown): boolean =>
        v !== null && typeof v === "object" && !(v instanceof PyFloat);
      if (!Array.isArray(value) || value.some(unhashable)) shape();
    }
    return checkedMatcher(fields);
  });
}

function checkedMatcher(fields: Record<string, unknown>): EndpointMatcher {
  const str = (value: unknown, fallback?: string): string =>
    value === undefined && fallback !== undefined
      ? fallback
      : typeof value === "string"
        ? value
        : invalidMatcher();
  const strings = (value: unknown, fallback: string[] = []): string[] =>
    value === undefined ? fallback : (value as unknown[]).map((v) => str(v));
  const ports = fields.ports as unknown[] | undefined;
  if (ports?.some((p) => typeof p !== "number" || !Number.isInteger(p)) === true) invalidMatcher();
  const matcher = endpointMatcher({
    endpointId: str(fields.endpoint_id),
    dialect: str(fields.dialect) as Dialect,
    hosts: strings(fields.hosts),
    hostSuffixes: strings(fields.host_suffixes),
    ports: ports as number[] | undefined,
    pathPrefix: str(fields.path_prefix, ""),
    providerName: str(fields.provider_name, "openai"),
    schemes: strings(fields.schemes, ["https"]) as ("http" | "https")[],
  });
  if (!isValidEndpoint(matcher)) invalidMatcher();
  return matcher;
}

/** An option's matcher: an {@link EndpointMatcher} or Python's snake_case JSON object. */
function optionMatcher(value: unknown): EndpointMatcher {
  if (value === null || typeof value !== "object") return invalidMatcher();
  const fields = value as Record<string, unknown>;
  if ("endpointId" in fields) {
    const snake: Record<string, unknown> = {};
    for (const [py, ts] of Object.entries(MATCHER_KEYS)) {
      if (fields[ts] !== undefined) snake[py] = fields[ts];
    }
    return checkedMatcher(snake);
  }
  return checkedMatcher(fields);
}

function builtinFromEnv(env: Env): "table" | "legacy" {
  const value = (get(env, "FABRIC_WIRE_BUILTIN_ENDPOINTS") ?? "table").trim().toLowerCase();
  if (value !== "table" && value !== "legacy") {
    fail("FABRIC_WIRE_BUILTIN_ENDPOINTS must be 'table' or 'legacy'", "FW-020");
  }
  return value as "table" | "legacy";
}

// ----------------------------------------------------------------- URLs and OTLP

function checkEndpointUrl(name: string, value: string): SplitUrl {
  const parts = urlsplit(value.trim());
  if (parts === undefined) return fail(`${name} is not a valid URL`);
  if (
    parts.netloc.includes("@") ||
    parts.query !== "" ||
    parts.fragment !== "" ||
    /[?#]/.test(value)
  ) {
    fail(`${name} must not carry credentials, a query or a fragment`, "FW-010");
  }
  return parts;
}

/** Verified HTTPS, or plain HTTP to a loopback host only (Python `check_content_endpoint_url`). */
export function checkContentEndpointUrl(name: string, value: string): void {
  const parts = checkEndpointUrl(name, value);
  const { scheme, hostname: host } = parts;
  if (
    host === "" ||
    (scheme !== "http" && scheme !== "https") ||
    (scheme === "http" && !LOOPBACK_HOSTS.has(host))
  ) {
    fail(`${name} requires verified HTTPS or loopback HTTP`, "FW-012");
  }
}

/** Whether `value` names a loopback host (delivery to it is always direct, never proxied). */
export function isLoopbackEndpoint(value: string): boolean {
  return LOOPBACK_HOSTS.has(urlsplit(value.trim())?.hostname ?? "");
}

const FABRIC_OTLP_NAMES = [
  "FABRIC_OTLP_ENDPOINT",
  "FABRIC_OTLP_CERTIFICATE",
  "FABRIC_OTLP_CLIENT_CERTIFICATE",
  "FABRIC_OTLP_CLIENT_KEY",
  "FABRIC_OTLP_HEADERS_FILE",
];
const HEADER_RE =
  /^[ \t]*[\x21\x23-\x27\x2a\x2b\x2d\x2e\x30-\x39\x41-\x5a\x5e-\x7a\x7c\x7e]+[ \t]*=[ \t]*[\x20\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*[ \t]*$/;
const SIGNAL_PATHS = { traces: "/v1/traces", logs: "/v1/logs" } as const;

/** Whether any `FABRIC_OTLP_*` variable is set (Fabric's own route wins, 058 §6.4). */
export function fabricOtlpSelected(env: Env): boolean {
  return FABRIC_OTLP_NAMES.some((name) => getTrimmed(env, name) !== undefined);
}

/** Whether capture has an OTLP traces endpoint (Python `capture_otlp_configured`). */
export function captureOtlpConfigured(env: Env): boolean {
  if (fabricOtlpSelected(env)) return getTrimmed(env, "FABRIC_OTLP_ENDPOINT") !== undefined;
  return ["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT"].some(
    (n) => get(env, n) !== undefined,
  );
}

const headerItems = (raw: string): string[] =>
  raw
    .trim()
    .split(/[ \t]*,[ \t]*/)
    .filter((item) => item !== "");

function parseHeaders(raw: string): Record<string, string> | undefined {
  const items = headerItems(raw);
  if (!items.every((item) => HEADER_RE.test(item))) return undefined;
  const headers: Record<string, string> = {};
  for (const item of items) {
    const at = item.indexOf("=");
    headers[unquote(item.slice(0, at)).trim().toLowerCase()] = unquote(item.slice(at + 1)).trim();
  }
  return headers;
}

function headersFromFile(path: string): Record<string, string> {
  const name = "FABRIC_OTLP_HEADERS_FILE";
  const raw = readBounded(path, MAX_HEADERS_FILE_BYTES);
  if (raw === undefined) fail(`the file named by ${name} is not readable`, "FW-019");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  } catch {
    return fail(`${name} must hold k=v pairs separated by commas`, "FW-019");
  }
  const joined = splitlines(text)
    .map((line) => line.trim())
    .filter((line) => line !== "")
    .join(",");
  const headers = raw!.length > MAX_HEADERS_FILE_BYTES ? undefined : parseHeaders(joined);
  return headers ?? fail(`${name} must hold k=v pairs separated by commas`, "FW-019");
}

function tlsFile(name: string, path: string): string {
  if (readBounded(path, 1 << 24) === undefined)
    fail(`the file named by ${name} is not readable`, "FW-019");
  return path;
}

/** The route of a process with nothing to deliver to (no endpoint, no spool). */
const NO_ROUTE: OtlpRoute = route(
  {
    route: "otel",
    endpoint: undefined,
    signalUrl: undefined,
    endpointName: undefined,
    certificate: undefined,
    clientCertificate: undefined,
    clientKey: undefined,
    timeoutMs: 10000,
    protocol: "http/protobuf",
    compression: undefined,
  },
  {},
);

const appendPath = (base: string, path: string): string => base.replace(/\/+$/, "") + path;

/**
 * One signal's OTLP settings (Python `otlp_signal_settings`): `FABRIC_OTLP_*` when any is
 * set (then nothing else), else `OTEL_EXPORTER_OTLP_<SIGNAL>_*` before `OTEL_EXPORTER_OTLP_*`.
 */
export function otlpSignalSettings(signal: "traces" | "logs", env: Env): OtlpRoute {
  if (fabricOtlpSelected(env)) {
    const base = getTrimmed(env, "FABRIC_OTLP_ENDPOINT");
    if (base === undefined)
      return fail("a FABRIC_OTLP_* setting needs FABRIC_OTLP_ENDPOINT", "FW-017");
    checkEndpointUrl("FABRIC_OTLP_ENDPOINT", base);
    const file = (suffix: string): string | undefined => {
      const path = getTrimmed(env, `FABRIC_OTLP_${suffix}`);
      return path === undefined ? undefined : tlsFile(`FABRIC_OTLP_${suffix}`, path);
    };
    const [certificate, clientCertificate, clientKey] = [
      "CERTIFICATE",
      "CLIENT_CERTIFICATE",
      "CLIENT_KEY",
    ].map(file);
    if ((clientKey === undefined) !== (clientCertificate === undefined)) {
      fail("OTLP client key and client certificate must be configured together", "FW-024");
    }
    const headersFile = getTrimmed(env, "FABRIC_OTLP_HEADERS_FILE");
    const endpoint = appendPath(base, SIGNAL_PATHS[signal]);
    return route(
      {
        route: "fabric",
        endpoint,
        signalUrl: endpoint,
        endpointName: "FABRIC_OTLP_ENDPOINT",
        certificate,
        clientCertificate,
        clientKey,
        timeoutMs: 10000,
        protocol: "http/protobuf",
        compression: undefined,
      },
      headersFile === undefined ? {} : headersFromFile(headersFile),
    );
  }
  const pick = (suffix: string): [string, string] | undefined => {
    for (const name of [
      `OTEL_EXPORTER_OTLP_${signal.toUpperCase()}_${suffix}`,
      `OTEL_EXPORTER_OTLP_${suffix}`,
    ]) {
      const value = (env[name] ?? "").trim();
      if (value !== "") return [name, value];
    }
    return undefined;
  };
  const endpoint = pick("ENDPOINT");
  if (endpoint !== undefined) checkEndpointUrl(...endpoint);
  let headers: Record<string, string> = {};
  const rawHeaders = pick("HEADERS");
  if (rawHeaders !== undefined) {
    headers =
      parseHeaders(rawHeaders[1]) ??
      fail(`${rawHeaders[0]} must be k=v pairs separated by commas`, "FW-024");
  }
  const files = ["CERTIFICATE", "CLIENT_CERTIFICATE", "CLIENT_KEY"].map((suffix) => {
    const found = pick(suffix);
    return found === undefined ? undefined : tlsFile(...found);
  });
  if ((files[2] === undefined) !== (files[1] === undefined)) {
    fail("OTLP client key and client certificate must be configured together", "FW-024");
  }
  const timeout = pick("TIMEOUT");
  const timeoutS = timeout === undefined ? 10 : pyFloat(timeout[1]);
  if (timeoutS === undefined) fail(`${timeout![0]} must be a number`);
  const compression = pick("COMPRESSION");
  if (
    compression !== undefined &&
    !["gzip", "deflate", "none"].includes(compression[1].toLowerCase())
  ) {
    fail(`${compression[0]} must be gzip, deflate or none`);
  }
  const fromSignal =
    endpoint?.[0].startsWith(`OTEL_EXPORTER_OTLP_${signal.toUpperCase()}_`) === true;
  return route(
    {
      route: "otel",
      endpoint: endpoint?.[1],
      signalUrl:
        endpoint === undefined
          ? undefined
          : fromSignal
            ? endpoint[1]
            : appendPath(endpoint[1], SIGNAL_PATHS[signal]),
      endpointName: endpoint?.[0],
      certificate: files[0],
      clientCertificate: files[1],
      clientKey: files[2],
      timeoutMs: Math.round(timeoutS! * 1000),
      protocol: pick("PROTOCOL")?.[1] ?? "http/protobuf",
      compression: compression?.[1].toLowerCase(),
    },
    headers,
  );
}

/** `FABRIC_WIRE_PROXY` (Python `delivery_proxy_from_env`): an http(s) proxy host and port. */
function proxyFromEnv(env: Env): string | undefined {
  const value = (env.FABRIC_WIRE_PROXY ?? "").trim();
  if (value === "") return undefined;
  const parts = urlsplit(value);
  if (parts === undefined) return fail("FABRIC_WIRE_PROXY is not a valid URL");
  if (
    !["http", "https"].includes(parts.scheme) ||
    parts.hostname === "" ||
    !["", "/"].includes(parts.path) ||
    parts.query !== "" ||
    parts.fragment !== "" ||
    /[?#]/.test(value)
  ) {
    fail("FABRIC_WIRE_PROXY must be an http:// or https:// proxy host and port");
  }
  return value;
}

// ----------------------------------------------------------------- options

/** Explicit `install()` options; each wins over its environment variable (§4.2). */
export interface WireOptions {
  readonly undici?: boolean;
  readonly nodeHttp?: boolean;
  readonly builtinEndpoints?: "table" | "legacy";
  /** Matchers beside the built-in rows (`FABRIC_WIRE_ENDPOINTS`). */
  readonly extraEndpoints?: readonly unknown[];
  readonly labels?: ExposureMode;
  readonly identityMode?: ExposureMode;
  readonly sourceId?: string;
  readonly tenantId?: string;
  readonly spoolDir?: string;
  readonly spoolMaxBytes?: number | bigint;
  readonly spoolMaxReceipts?: number;
  readonly modelAllowlist?: readonly string[];
  readonly maxBodyBytes?: number;
  readonly maxRetainBytes?: number;
  readonly partMinBytes?: number;
  readonly maxInflightBytes?: number | bigint;
  readonly queueMaxItems?: number;
  readonly shutdownTimeoutMs?: number;
  readonly drainOnExitMs?: number;
  readonly contentBatchBodies?: number;
  readonly contentConcurrency?: number;
  readonly providerRequestId?: boolean;
  readonly idKey?: string | Uint8Array;
  readonly spoolKey?: Uint8Array;
  readonly tokenizationKey?: Uint8Array;
}

function switchFromEnv(env: Env, name: string, fallback: boolean): boolean {
  const value = (get(env, name) ?? (fallback ? "1" : "0")).trim().toLowerCase();
  if (!["1", "true", "yes", "on", "0", "false", "no", "off"].includes(value))
    fail(`${name} must be 1 or 0`);
  return ["1", "true", "yes", "on"].includes(value);
}

function intSetting(
  name: string,
  value: bigint | number | undefined,
  low: bigint,
  high: bigint = INT62,
): bigint {
  const v = typeof value === "number" && Number.isSafeInteger(value) ? BigInt(value) : value;
  if (typeof v !== "bigint" || v < low || v > high)
    fail(`${name} must be an integer between ${low} and ${high}`);
  return v as bigint;
}

function envInt(env: Env, suffix: string): bigint | undefined {
  const value = get(env, `FABRIC_WIRE_${suffix}`);
  if (value === undefined) return undefined;
  return pyInt(value) ?? fail(`FABRIC_WIRE_${suffix} must be an integer`);
}

function envSeconds(env: Env, suffix: string): number | undefined {
  const value = get(env, `FABRIC_WIRE_${suffix}`);
  if (value === undefined) return undefined;
  return pyFloat(value) ?? fail(`FABRIC_WIRE_${suffix} must be a number of seconds`);
}

/** Python `_env_int` of `_manifest.py`: malformed or out of range is the default, noted. */
function envIntOrDefault(
  env: Env,
  name: string,
  fallback: number,
  low: bigint,
  high: bigint,
  notes: string[],
): bigint {
  const raw = getTrimmed(env, name);
  if (raw === undefined) return BigInt(fallback);
  const value = pyInt(raw);
  if (value === undefined || value < low || value > high) {
    notes.push(`${name} is not an integer between ${low} and ${high}; using ${fallback}`);
    return BigInt(fallback);
  }
  return value;
}

function modelAllowlist(entries: readonly string[]): readonly string[] {
  for (const entry of entries) {
    const name = entry.endsWith("*") ? entry.slice(0, -1) : entry;
    if (!MODEL_RE.test(name) || name.includes("://")) {
      fail("FABRIC_WIRE_MODEL_ALLOWLIST entries must be model names or prefix*");
    }
  }
  return Object.freeze([...entries]);
}

function capturePolicy(env: Env): DeploymentPolicy | undefined {
  const path = getTrimmed(env, "FABRIC_CAPTURE_POLICY");
  if (path === undefined) return undefined;
  const raw = readBounded(path, MAX_POLICY_BYTES);
  if (raw === undefined) fail("FABRIC_CAPTURE_POLICY is not readable", "FW-019");
  if (raw!.length > MAX_POLICY_BYTES) fail("FABRIC_CAPTURE_POLICY is too large");
  try {
    return new DeploymentPolicy(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)));
  } catch {
    return fail("FABRIC_CAPTURE_POLICY is not a valid deployment-policy/v1 document");
  }
}

/**
 * Python's `wire/_diagnose.py` rules (`_FIXES`) whose ids TypeScript emits: the id of a
 * fixed-text message another module throws (`redaction.ts`, `identity.ts`), which this
 * module cannot type at the throw site. First needle found wins, as in Python.
 */
const FOREIGN_REASONS: readonly (readonly [string, TypeScriptCatalogueId])[] = [
  ["requires verified HTTPS or loopback HTTP", "FW-012"],
  ["must not carry credentials, a query or a fragment", "FW-010"],
  ["_FILE, not both", "FW-018"],
  ["is not readable", "FW-019"],
  ["_FILE must hold", "FW-019"],
];

/** The catalogue id Python's `reason_id` gives a fixed-text message (its generic id: FW-025). */
export function foreignReasonId(message: string): TypeScriptCatalogueId {
  return FOREIGN_REASONS.find(([needle]) => message.includes(needle))?.[1] ?? GENERIC_REASON_ID;
}

/** Errors another module throws (fixed text by contract) become config errors. */
function wrap<T>(fn: () => T): T {
  try {
    return fn();
  } catch (error) {
    if (error instanceof WireConfigError) throw error;
    const message = error instanceof Error ? error.message : "a setting is malformed";
    throw new WireConfigError(message, foreignReasonId(message));
  }
}

/**
 * `value` frozen, with `hidden` as non-enumerable properties: readable by name, never
 * shown by `util.inspect`, `console.log`, `JSON.stringify`, spread or `Object.entries`
 * (Python keeps the same secrets out of `repr`).
 */
function withHidden<T extends object>(value: object, hidden: Record<string, unknown>): T {
  for (const [key, item] of Object.entries(hidden)) {
    Object.defineProperty(value, key, { value: item, enumerable: false });
  }
  return Object.freeze(value) as T;
}

/** A frozen OTLP route whose header values (credentials) are never printed. */
function route(
  fields: Omit<OtlpRoute, "headers">,
  headers: Readonly<Record<string, string>>,
): OtlpRoute {
  return withHidden<OtlpRoute>({ ...fields }, { headers: Object.freeze({ ...headers }) });
}

/**
 * The redaction bearer token (`redaction.ts` `readRedactionToken`), refused as Python's
 * `read_token_file` refuses it: unreadable (FW-019), not an owner-only regular file
 * (generic), or not one printable ASCII token of at most 4096 bytes (FW-019).
 */
function redactionTokenFrom(path: string): string {
  const name = "FABRIC_REDACTION_TOKEN_FILE";
  try {
    return readRedactionToken(path);
  } catch (error) {
    if (error instanceof Error && error.message.includes("is not readable")) {
      return fail(`${name} is not readable`, "FW-019");
    }
    let ownerOnly: boolean;
    try {
      // The open with O_NOFOLLOW succeeded, so `path` is no symlink and stat is fstat.
      const info = statSync(path);
      const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
      ownerOnly =
        info.isFile() && (info.mode & 0o077) === 0 && (uid === undefined || info.uid === uid);
    } catch {
      return fail(`${name} is not readable`, "FW-019");
    }
    return ownerOnly
      ? fail(`${name} must hold one printable ASCII token`, "FW-019")
      : fail(`${name} must be a 0600 file owned by this user`);
  }
}

// ----------------------------------------------------------------- resolution

function fileStoreRoot(uri: string, tenant: string | undefined): string {
  if (uri.startsWith("s3:")) fail("s3 content is written by the Fabric Node (spec 048)");
  const parts = urlsplit(uri);
  const path = unquote(parts?.path ?? "");
  if (
    parts === undefined ||
    parts.scheme !== "file" ||
    !["", "localhost"].includes(parts.netloc) ||
    parts.query !== "" ||
    parts.fragment !== "" ||
    !path.startsWith("/") ||
    tenant === undefined
  ) {
    fail("FABRIC_WIRE_STORE must be 'node' or file:///absolute/dir (+ tenant)");
  }
  return path;
}

/** Local file mode's spool (Python `default_file_spool`); undefined where it cannot deliver. */
function defaultFileSpool(
  storeUri: string,
  tenant: string | undefined,
  env: Env,
): string | undefined {
  if (tenant === undefined || !TENANT_RE.test(tenant) || !captureOtlpConfigured(env))
    return undefined;
  const parts = urlsplit(storeUri);
  const root = unquote(parts?.path ?? "");
  if (parts?.scheme !== "file" || !root.startsWith("/")) return undefined;
  return `${normpath(root)}/${FILE_SPOOL_DIR}/${tenant}`;
}

/**
 * The validated settings for `options` over `env` (default `process.env`), in Python's
 * order: `config_from_env`, `WireConfig` validation, the environment defaults, then the
 * delivery check `python -m fabric.wire status` makes (the OTLP span route when a spool
 * or an endpoint is set; the Node content route in node mode). Throws
 * {@link WireConfigError}. Sends nothing and installs nothing.
 */
export function resolveConfig(options: WireOptions = {}, env: Env = process.env): WireSettings {
  const notes: string[] = [];
  if (
    get(env, "FABRIC_WIRE_STORE_SSE") !== undefined ||
    get(env, "FABRIC_WIRE_STORE_KMS_KEY_ID") !== undefined
  ) {
    fail("encryption is configured on the Fabric Node");
  }
  const storeUri = (get(env, "FABRIC_WIRE_STORE") ?? "").trim();
  const endpoint = getTrimmed(env, "FABRIC_WIRE_CONTENT_ENDPOINT");
  const tenant = options.tenantId ?? get(env, "FABRIC_TENANT_ID");
  const node = storeUri === "node" || (storeUri === "" && endpoint !== undefined);
  if (node && endpoint === undefined) fail("node mode needs FABRIC_WIRE_CONTENT_ENDPOINT");
  if (storeUri !== "" && !node && endpoint !== undefined) {
    fail("FABRIC_WIRE_CONTENT_ENDPOINT is for node mode only");
  }
  let spoolDir = options.spoolDir ?? get(env, "FABRIC_WIRE_SPOOL_DIR");
  if (spoolDir === undefined && storeUri !== "" && !node)
    spoolDir = defaultFileSpool(storeUri, tenant, env);
  const store: WireSettings["store"] = node
    ? { kind: "node" }
    : storeUri !== ""
      ? { kind: "file", root: fileStoreRoot(storeUri, tenant) }
      : undefined;
  const sourceId = options.sourceId ?? get(env, "FABRIC_SOURCE_ID");
  const boundary = get(env, "FABRIC_WIRE_SPOOL_DURABLE_BOUNDARY");
  const allowlist = modelAllowlist(
    options.modelAllowlist ??
      (get(env, "FABRIC_WIRE_MODEL_ALLOWLIST") ?? "")
        .split(",")
        .map((e) => e.trim())
        .filter((e) => e !== ""),
  );
  const idKey =
    options.idKey !== undefined
      ? checkIdKey(
          typeof options.idKey === "string"
            ? Uint8Array.from(utf8SurrogatePass(options.idKey))
            : options.idKey,
        )
      : idKeyFromEnv(env);
  const labels = (options.labels ??
    (get(env, "FABRIC_WIRE_LABELS") ?? "pseudonymous").trim()) as ExposureMode;
  if (labels !== "pseudonymous" && labels !== "clear")
    fail("FABRIC_WIRE_LABELS must be 'pseudonymous' or 'clear'");
  const policy = capturePolicy(env);
  const tokenizationKey =
    options.tokenizationKey ??
    keyFromEnv(env, "FABRIC_TOKENIZATION_KEY", undefined, TOKEN_KEY_MIN_BYTES);
  const spoolKey = options.spoolKey ?? keyFromEnv(env, "FABRIC_WIRE_SPOOL_KEY", SPOOL_KEY_BYTES);
  const migrate = truthy(get(env, "FABRIC_WIRE_SPOOL_MIGRATE_PLAINTEXT"));
  const redaction = wrap(() => redactionServiceFromEnv(env));
  // Python's RedactionService reads its token file once, at configuration: a missing or
  // unsafe file is a configuration error there (FW-019 / generic), so it is here.
  const tokenFile = redaction?.tokenFile;
  const redactionToken = tokenFile === undefined ? undefined : redactionTokenFrom(tokenFile);
  const builtin = options.builtinEndpoints ?? builtinFromEnv(env);
  const endpointsText = get(env, "FABRIC_WIRE_ENDPOINTS");
  const extra =
    options.extraEndpoints !== undefined
      ? options.extraEndpoints.map(optionMatcher)
      : endpointsText !== undefined
        ? parseEndpoints(endpointsText)
        : [];
  const pick = <T>(option: T | undefined, fromEnv: () => T | undefined, fallback: T): T =>
    option ?? fromEnv() ?? fallback;
  const seconds = (option: number | undefined, suffix: string): number | undefined =>
    option !== undefined ? option / 1000 : envSeconds(env, suffix);
  // Python reads every numeric variable before it validates any of them.
  const raw = {
    maxBody: pick<number | bigint>(
      options.maxBodyBytes,
      () => envInt(env, "MAX_BODY_BYTES"),
      32 * MIB,
    ),
    maxRetain: pick<number | bigint>(
      options.maxRetainBytes,
      () => envInt(env, "MAX_RETAIN_BYTES"),
      64 * MIB,
    ),
    partMin: pick<number | bigint>(
      options.partMinBytes,
      () => envInt(env, "PART_MIN_BYTES"),
      64 * 1024,
    ),
    queue: pick<number | bigint>(
      options.queueMaxItems,
      () => envInt(env, "QUEUE_MAX_ITEMS"),
      QUEUE_MAX_ITEMS,
    ),
    spoolMax: pick<number | bigint>(
      options.spoolMaxBytes,
      () => envInt(env, "SPOOL_MAX_BYTES"),
      1n << 30n,
    ),
    receipts: pick<number | bigint>(
      options.spoolMaxReceipts,
      () => envInt(env, "SPOOL_MAX_RECEIPTS"),
      4096,
    ),
    batch: pick<number | bigint>(
      options.contentBatchBodies,
      () => envInt(env, "CONTENT_BATCH_BODIES"),
      32,
    ),
    concurrency: pick<number | bigint>(
      options.contentConcurrency,
      () => envInt(env, "CONTENT_CONCURRENCY"),
      4,
    ),
    shutdownS: seconds(options.shutdownTimeoutMs, "SHUTDOWN_TIMEOUT_S") ?? 2,
    drainS: seconds(options.drainOnExitMs, "DRAIN_ON_EXIT_S") ?? 0,
  };

  // WireConfig.__post_init__, in its order.
  const maxBody = intSetting(
    "max_body_bytes (FABRIC_WIRE_MAX_BODY_BYTES)",
    raw.maxBody,
    1n,
    BigInt(MAX_BODY_BYTES_CAP),
  );
  const maxRetain = intSetting(
    "max_retain_bytes (FABRIC_WIRE_MAX_RETAIN_BYTES)",
    raw.maxRetain,
    maxBody,
    BigInt(MAX_BODY_BYTES_CAP),
  );
  const partMin = intSetting(
    "part_min_bytes (FABRIC_WIRE_PART_MIN_BYTES)",
    raw.partMin,
    1n,
    BigInt(MAX_BODY_BYTES_CAP),
  );
  if (policy !== undefined && tenant !== undefined && policy.tenant_id !== tenant) {
    fail("the capture policy belongs to another tenant");
  }
  if (tokenizationKey !== undefined && tokenizationKey.length < TOKEN_KEY_MIN_BYTES) {
    fail(`tokenization_key must be at least ${TOKEN_KEY_MIN_BYTES} bytes`);
  }
  if (spoolKey !== undefined && spoolKey.length !== SPOOL_KEY_BYTES) {
    fail(`spool_key must be exactly ${SPOOL_KEY_BYTES} bytes`);
  }
  if (tenant !== undefined && !TENANT_RE.test(tenant)) {
    fail("tenant_id (FABRIC_TENANT_ID) must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$");
  }
  const spool = spoolDir === SPOOL_OFF ? undefined : spoolDir;
  let spoolMaxBytes = BigInt(1n << 30n);
  let receipts = 4096n;
  if (spool !== undefined) {
    if (!spool.startsWith("/"))
      fail("spool_dir (FABRIC_WIRE_SPOOL_DIR) must be an absolute directory");
    const low = 2n * maxBody + BigInt(SPOOL_RESERVE_BYTES);
    spoolMaxBytes = intSetting("spool_max_bytes (FABRIC_WIRE_SPOOL_MAX_BYTES)", raw.spoolMax, low);
    receipts = intSetting(
      "spool_max_receipts (FABRIC_WIRE_SPOOL_MAX_RECEIPTS)",
      raw.receipts,
      1n,
      1n << 20n,
    );
    if (boundary !== undefined) {
      const dir = spool.replace(/\/+$/, "") || "/";
      if (
        !boundary.startsWith("/") ||
        normpath(boundary) !== boundary ||
        !(dir === boundary || dir.startsWith(boundary.replace(/\/+$/, "") + "/"))
      ) {
        fail(
          "spool_durable_boundary (FABRIC_WIRE_SPOOL_DURABLE_BOUNDARY) must be spool_dir or an ancestor",
        );
      }
    }
  } else if (boundary !== undefined) {
    fail("spool_durable_boundary (FABRIC_WIRE_SPOOL_DURABLE_BOUNDARY) needs spool_dir");
  }
  const contentEndpoint = node ? endpoint : undefined;
  if (contentEndpoint !== undefined) {
    checkContentEndpointUrl("FABRIC_WIRE_CONTENT_ENDPOINT", contentEndpoint);
    if (tenant === undefined || tenant === "" || spool === undefined) {
      fail("node mode needs FABRIC_TENANT_ID, FABRIC_WIRE_SPOOL_DIR, no store");
    }
    intSetting(
      "max_body_bytes (FABRIC_WIRE_MAX_BODY_BYTES) in node mode",
      maxBody,
      1n,
      BigInt(NODE_MAX_BODY_BYTES),
    );
  }
  const inflight = intSetting("max_inflight_bytes", options.maxInflightBytes ?? 256 * MIB, 1n);
  const queue = intSetting(
    "queue_max_items (FABRIC_WIRE_QUEUE_MAX_ITEMS)",
    raw.queue,
    1n,
    BigInt(MAX_QUEUE_ITEMS),
  );
  if (!Number.isFinite(raw.shutdownS) || raw.shutdownS < 0 || raw.shutdownS > 300) {
    fail("shutdown_timeout_s (FABRIC_WIRE_SHUTDOWN_TIMEOUT_S) must be between 0 and 300 seconds");
  }
  if (!Number.isFinite(raw.drainS) || raw.drainS < 0 || raw.drainS > MAX_DRAIN_ON_EXIT_S) {
    fail("drain_on_exit_s (FABRIC_WIRE_DRAIN_ON_EXIT_S) must be between 0 and 3600 seconds");
  }
  const batch = intSetting(
    "content_batch_bodies (FABRIC_WIRE_CONTENT_BATCH_BODIES)",
    raw.batch,
    1n,
    BigInt(MAX_CONTENT_BATCH_BODIES),
  );
  const concurrency = intSetting(
    "content_concurrency (FABRIC_WIRE_CONTENT_CONCURRENCY)",
    raw.concurrency,
    1n,
    BigInt(MAX_CONTENT_CONCURRENCY),
  );
  if (sourceId !== undefined && !OPAQUE_ID_RE.test(sourceId)) {
    fail("source_id (FABRIC_SOURCE_ID) must match ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$");
  }
  const builtins = builtin === "legacy" ? BUILTIN_ENDPOINTS.legacy : BUILTIN_ENDPOINTS.table;
  const all = [...builtins, ...extra];
  if (new Set(all.map((m) => m.endpointId)).size !== all.length)
    fail("endpoint_id values must be unique");

  // TypeScript's own switches and the run, records and status settings.
  const identityMode = options.identityMode ?? wrap(() => identityModeFromEnv(env));
  const undici = options.undici ?? switchFromEnv(env, "FABRIC_WIRE_UNDICI", true);
  const nodeHttp = options.nodeHttp ?? switchFromEnv(env, "FABRIC_WIRE_NODE_HTTP", false);
  // Python's `records_max_object_bytes` (`_manifest.py` `_env_int`): malformed or out of
  // range is the default with a note, never a configuration error.
  const recordsMax = envIntOrDefault(
    env,
    "FABRIC_RECORDS_MAX_OBJECT_BYTES",
    RECORDS_MAX_OBJECT_BYTES,
    1n,
    BigInt(RECORDS_MAX_OBJECT_BYTES),
    notes,
  );
  const openDeadline = envIntOrDefault(
    env,
    "FABRIC_RUN_OPEN_DEADLINE_S",
    OPEN_RUN_DEADLINE_DEFAULT_S,
    60n,
    31536000n,
    notes,
  );
  const clockMs = envIntOrDefault(
    env,
    "FABRIC_CLOCK_UNCERTAINTY_MS",
    CLOCK_UNCERTAINTY_DEFAULT_MS,
    0n,
    INT64_MAX / 1000000n,
    notes,
  );
  const otelSdkDisabled = (env.OTEL_SDK_DISABLED ?? "").trim().toLowerCase() === "true";

  // The delivery check of `python -m fabric.wire status` (skipped when OTel is disabled).
  // Python parses the OTLP settings only for it, so a malformed OTLP variable with
  // nothing to deliver is not a configuration error there, nor here.
  let otlp: OtlpRoute = NO_ROUTE;
  let otlpLogs: OtlpRoute | undefined;
  let proxy: string | undefined;
  if (!otelSdkDisabled && (spool !== undefined || captureOtlpConfigured(env))) {
    otlp = otlpSignalSettings("traces", env);
    if (otlp.protocol !== "http/protobuf" && otlp.protocol !== "grpc") {
      fail("OTLP protocol must be http/protobuf or grpc for Fabric capture");
    }
    if (otlp.endpoint === undefined) fail("Fabric capture needs an OTLP traces endpoint", "FW-013");
    if (otlp.protocol === "grpc") {
      fail(
        `${otlp.endpointName ?? "OTEL_EXPORTER_OTLP_PROTOCOL"} selects grpc, which Node.js capture ` +
          "delivery does not speak: set FABRIC_OTLP_ENDPOINT to the Fabric Node's OTLP/HTTP address",
        "FW-024",
      );
    }
    checkContentEndpointUrl(
      otlp.endpointName ?? "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
      otlp.endpoint!,
    );
    proxy = proxyFromEnv(env);
  }
  if (!otelSdkDisabled && contentEndpoint !== undefined) {
    checkContentEndpointUrl("FABRIC_WIRE_CONTENT_ENDPOINT", contentEndpoint);
    otlpLogs = otlpSignalSettings("logs", env);
    proxy = proxyFromEnv(env);
  }
  const visible: Omit<WireSettings, "secrets"> = {
    autoload: ["1", "true"].includes((env.FABRIC_WIRE_AUTOLOAD ?? "").trim().toLowerCase()),
    undici,
    nodeHttp,
    diagnostics:
      (env.FABRIC_WIRE_DIAGNOSTICS ?? "").trim().toLowerCase() === "stderr" ? "stderr" : "silent",
    otelSdkDisabled,
    endpointTableVersion: BUILTIN_ENDPOINTS.version,
    builtinEndpoints: builtin,
    endpoints: Object.freeze([...builtins]),
    extraEndpoints: Object.freeze(extra),
    labels,
    identityMode,
    sourceId,
    tenantId: tenant,
    store,
    contentEndpoint,
    spoolDir: spool,
    spoolMaxBytes,
    spoolMaxReceipts: Number(receipts),
    spoolDurableBoundary: boundary,
    spoolMigratePlaintext: migrate,
    capturePolicyPath: getTrimmed(env, "FABRIC_CAPTURE_POLICY"),
    redactionEndpoint: redaction?.endpoint,
    redactionTokenFile: redaction?.tokenFile,
    modelAllowlist: allowlist,
    maxBodyBytes: Number(maxBody),
    maxRetainBytes: Number(maxRetain),
    partMinBytes: Number(partMin),
    maxInflightBytes: inflight,
    queueMaxItems: Number(queue),
    shutdownTimeoutMs: Math.round(raw.shutdownS * 1000),
    drainOnExitMs: Math.round(raw.drainS * 1000),
    contentBatchBodies: Number(batch),
    contentConcurrency: Number(concurrency),
    proxy,
    otlp,
    otlpLogs,
    runId: getTrimmed(env, "FABRIC_RUN_ID"),
    resumeTokens: Object.freeze(splitTokens(get(env, "FABRIC_RUN_RESUME_TOKEN") ?? "")),
    openDeadlineS: Number(openDeadline),
    recordsStrict: env.FABRIC_RECORDS_STRICT === "1",
    recordsMaxObjectBytes: Number(recordsMax),
    clockUncertaintyNs: clockMs * 1000000n,
    providerRequestId:
      options.providerRequestId ?? truthy(get(env, "FABRIC_WIRE_PROVIDER_REQUEST_ID")),
    statusFile: getTrimmed(env, "FABRIC_WIRE_STATUS_FILE"),
    settingWarnings: Object.freeze(notes),
  };
  return withHidden<WireSettings>(visible, {
    secrets: Object.freeze({ idKey, spoolKey, tokenizationKey, redactionToken }),
  });
}

/** What the status command decides for an environment (Python `_wire_status`, in part). */
export type ConfigStatus =
  | {
      readonly configuration: "valid";
      readonly capture: "enabled" | "disabled";
      readonly settings: WireSettings;
    }
  | {
      readonly configuration: "invalid";
      readonly capture: "not_installed";
      readonly reason: string;
      readonly reasonId: TypeScriptCatalogueId;
      readonly fix: string;
    };

/**
 * The configuration verdict for `env`: `valid` (capture `enabled`, or `disabled` by
 * `OTEL_SDK_DISABLED`) or `invalid` with the fixed-text reason, its catalogue id and fix.
 * Never throws.
 */
export function configStatus(env: Env = process.env, options: WireOptions = {}): ConfigStatus {
  try {
    const settings = resolveConfig(options, env);
    return {
      configuration: "valid",
      capture: settings.otelSdkDisabled ? "disabled" : "enabled",
      settings,
    };
  } catch (error) {
    const known =
      error instanceof WireConfigError
        ? error
        : new WireConfigError("the configuration is invalid");
    return {
      configuration: "invalid",
      capture: "not_installed",
      reason: known.message,
      reasonId: known.reasonId,
      fix: known.fix,
    };
  }
}
