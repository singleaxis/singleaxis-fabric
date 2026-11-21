// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * The span delivery rule shared with the Python SDK (docs/reference/privacy-and-security.md,
 * "Span delivery rule"): the OTLP traces endpoint the standard environment
 * selects must be verified TLS, or plaintext to a loopback host only, so the
 * ingress credential and the record never cross a network unencrypted.
 *
 * Python applies it when it builds its exporter (`fabric.tracing`
 * `check_content_endpoint_url` for OTLP/HTTP, `_grpc_options` for gRPC). The
 * TypeScript SDK ships no exporter (the host builds it, and the standard
 * OpenTelemetry exporters read the same variables), so the {@link Fabric}
 * client applies the same rule to the same variables at construction: a
 * refused endpoint turns Fabric capture off. Nothing is thrown into the
 * application; the reason and the fix are reported by
 * `Fabric.captureStatus()` / {@link captureStatus}, and printed on stderr
 * only when `FABRIC_WIRE_DIAGNOSTICS=stderr` asks for it. Messages name the
 * variable, never its value (an endpoint can carry credentials).
 *
 * Fabric's own route (spec 058 §6.4): when any `FABRIC_OTLP_*` variable is set,
 * the rule applies to `FABRIC_OTLP_ENDPOINT` and nothing is read from
 * `OTEL_EXPORTER_OTLP_*`, so `fabric run` never redirects the agent's own
 * OpenTelemetry export. {@link fabricExporterOptions} turns those variables
 * into the exporter's options.
 */

import { readFileSync } from "node:fs";

/** Environment variable that routes Fabric's diagnostics to stderr (`stderr`). */
export const DIAGNOSTICS_ENV = "FABRIC_WIRE_DIAGNOSTICS";

/** The loopback hosts plaintext delivery may use (the Python SDK's set). */
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(["localhost", "127.0.0.1", "::1"]);

const FIX =
  "use an https:// endpoint (set OTEL_EXPORTER_OTLP_CERTIFICATE to the CA bundle if the " +
  "Node's certificate is privately issued), or a loopback address (localhost, 127.0.0.1 " +
  "or [::1]), for example through a port forward to the Node";

/** The verdict of {@link otlpTraceTransport}. */
export type OtlpTraceTransport =
  | { allowed: true }
  | {
      allowed: false;
      /** The variable that selected the refused endpoint. */
      variable: string;
      /** Fixed text naming the variable and the rule; never the value. */
      reason: string;
      /** What to change. */
      fix: string;
    };

/** Fabric's local capture status (the TypeScript side of `fabric.wire status`). */
export type CaptureStatus =
  | { capture: "enabled" }
  | {
      capture: "disabled";
      /** Fixed text naming the variable and the rule; never the value. */
      reason: string;
      /** What to change. */
      fix: string;
    };

type Env = Record<string, string | undefined>;

function pick(env: Env, suffix: string): [string, string] | undefined {
  for (const name of [`OTEL_EXPORTER_OTLP_TRACES_${suffix}`, `OTEL_EXPORTER_OTLP_${suffix}`]) {
    const value = (env[name] ?? "").trim();
    if (value !== "") return [name, value];
  }
  return undefined;
}

function hostOf(url: URL): string {
  // WHATWG URL keeps the brackets on an IPv6 host; Python's urlsplit drops them.
  return url.hostname.replace(/^\[(.*)\]$/, "$1").toLowerCase();
}

function refuse(variable: string, rule: string): OtlpTraceTransport {
  return { allowed: false, variable, reason: `${variable} requires ${rule}`, fix: FIX };
}

function parse(value: string): URL | undefined {
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}

/**
 * Whether the OTLP traces endpoint that `env` selects
 * (`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, else `OTEL_EXPORTER_OTLP_ENDPOINT`)
 * satisfies the span delivery rule. No endpoint is allowed: the standard
 * exporters then default to a loopback address. Never throws.
 */
export function otlpTraceTransport(env: Env = process.env): OtlpTraceTransport {
  if (fabricOtlpSelected(env)) return fabricRouteTransport(env);
  const endpoint = pick(env, "ENDPOINT");
  if (endpoint === undefined) return { allowed: true };
  const [variable, value] = endpoint;
  const protocol = (pick(env, "PROTOCOL")?.[1] ?? "http/protobuf").toLowerCase();

  if (protocol === "grpc") {
    const rule = "verified TLS or loopback plaintext";
    let url = parse(value);
    let insecure: boolean;
    if (url !== undefined && /^https?:$/i.test(url.protocol) && url.host !== "") {
      insecure = url.protocol.toLowerCase() === "http:";
    } else {
      // A scheme-less host:port is plaintext only when *_INSECURE says so.
      url = parse(`http://${value}`);
      insecure = (pick(env, "INSECURE")?.[1] ?? "").toLowerCase() === "true";
    }
    const host = url === undefined ? "" : hostOf(url);
    if (host === "" || (insecure && !LOOPBACK_HOSTS.has(host))) return refuse(variable, rule);
    return { allowed: true };
  }

  const rule = "verified HTTPS or loopback HTTP";
  const url = parse(value);
  if (url === undefined) return refuse(variable, rule);
  const scheme = url.protocol.toLowerCase();
  const host = hostOf(url);
  if (host === "" || (scheme !== "http:" && scheme !== "https:")) return refuse(variable, rule);
  if (scheme === "http:" && !LOOPBACK_HOSTS.has(host)) return refuse(variable, rule);
  return { allowed: true };
}

// ---------------------------------------------------------------- FABRIC_OTLP_* (058 §6.4)

/** Fabric's own OTLP settings, read before the `OTEL_EXPORTER_OTLP_*` ones (Python parity). */
export const FABRIC_OTLP_NAMES = [
  "FABRIC_OTLP_ENDPOINT",
  "FABRIC_OTLP_CERTIFICATE",
  "FABRIC_OTLP_CLIENT_CERTIFICATE",
  "FABRIC_OTLP_CLIENT_KEY",
  "FABRIC_OTLP_HEADERS_FILE",
] as const;

const FABRIC_FIX =
  "set FABRIC_OTLP_ENDPOINT to the Node's https:// base URL with FABRIC_OTLP_CERTIFICATE naming " +
  "its CA file (fabric run sets both), or to a loopback http:// address";
const MAX_HEADERS_FILE_BYTES = 64 * 1024;

function get(env: Env, name: string): string | undefined {
  const value = (env[name] ?? "").trim();
  return value === "" ? undefined : value;
}

/** Whether any `FABRIC_OTLP_*` variable is set: then Fabric reads only those. */
export function fabricOtlpSelected(env: Env = process.env): boolean {
  return FABRIC_OTLP_NAMES.some((name) => get(env, name) !== undefined);
}

function fabricRefuse(variable: string, reason: string): OtlpTraceTransport {
  return { allowed: false, variable, reason, fix: FABRIC_FIX };
}

function readable(path: string): boolean {
  try {
    readFileSync(path);
    return true;
  } catch {
    return false;
  }
}

/** The `FABRIC_OTLP_*` route's verdict: the same rule, on Fabric's own variables. */
function fabricRouteTransport(env: Env): OtlpTraceTransport {
  const name = "FABRIC_OTLP_ENDPOINT";
  const value = get(env, name);
  if (value === undefined) {
    return fabricRefuse(name, "a FABRIC_OTLP_* setting is set without FABRIC_OTLP_ENDPOINT");
  }
  const url = parse(value);
  const rule = `${name} requires verified HTTPS or loopback HTTP`;
  if (url === undefined) return fabricRefuse(name, rule);
  const scheme = url.protocol.toLowerCase();
  const host = hostOf(url);
  if (host === "" || (scheme !== "http:" && scheme !== "https:")) return fabricRefuse(name, rule);
  if (scheme === "http:" && !LOOPBACK_HOSTS.has(host)) return fabricRefuse(name, rule);
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    return fabricRefuse(name, `${name} must not carry credentials, a query or a fragment`);
  }
  for (const file of FABRIC_OTLP_NAMES.slice(1)) {
    const path = get(env, file);
    if (path !== undefined && !readable(path)) {
      return fabricRefuse(file, `the file named by ${file} is not readable`);
    }
  }
  const cert = get(env, "FABRIC_OTLP_CLIENT_CERTIFICATE");
  const key = get(env, "FABRIC_OTLP_CLIENT_KEY");
  if ((cert === undefined) !== (key === undefined)) {
    return fabricRefuse(
      "FABRIC_OTLP_CLIENT_KEY",
      "FABRIC_OTLP_CLIENT_CERTIFICATE and FABRIC_OTLP_CLIENT_KEY must be set together",
    );
  }
  const headers = get(env, "FABRIC_OTLP_HEADERS_FILE");
  if (headers !== undefined && headersFromFile(headers) === undefined) {
    return fabricRefuse(
      "FABRIC_OTLP_HEADERS_FILE",
      "FABRIC_OTLP_HEADERS_FILE must hold k=v pairs separated by commas or newlines",
    );
  }
  return { allowed: true };
}

/**
 * `FABRIC_OTLP_HEADERS_FILE`: `k=v` pairs separated by commas or newlines (the
 * OTLP header syntax). It holds the ingress credential: never logged or echoed.
 * `undefined` when unreadable or malformed.
 */
function headersFromFile(path: string): Record<string, string> | undefined {
  let raw: Buffer;
  try {
    raw = readFileSync(path);
  } catch {
    return undefined;
  }
  if (raw.length > MAX_HEADERS_FILE_BYTES) return undefined;
  const text = raw.toString("utf-8");
  const headers: Record<string, string> = {};
  const items = text
    .split(/[\r\n]+|,/)
    .map((item) => item.trim())
    .filter((item) => item !== "");
  for (const item of items) {
    const at = item.indexOf("=");
    if (at <= 0) return undefined;
    try {
      const key = decodeURIComponent(item.slice(0, at)).trim().toLowerCase();
      if (key === "") return undefined;
      headers[key] = decodeURIComponent(item.slice(at + 1)).trim();
    } catch {
      return undefined;
    }
  }
  return headers;
}

/** Options for `new OTLPTraceExporter(...)` from `@opentelemetry/exporter-trace-otlp-http`. */
export interface FabricExporterOptions {
  /** The Node's traces URL (`FABRIC_OTLP_ENDPOINT` + `/v1/traces`). */
  url?: string;
  /** The ingress credential from `FABRIC_OTLP_HEADERS_FILE`. */
  headers?: Record<string, string>;
  /**
   * The CA and client certificate the Node is reached with, as PEM text. Strings,
   * not `Buffer`s, so a project without `@types/node` can typecheck against this.
   */
  httpAgentOptions?: { ca?: string; cert?: string; key?: string };
  timeoutMillis?: number;
}

/**
 * The exporter options for Fabric's own OTLP route (spec 058 §6.4), for
 * `new OTLPTraceExporter(fabricExporterOptions())`. When no `FABRIC_OTLP_*`
 * variable is set it returns `{}`, and the exporter reads the standard
 * `OTEL_EXPORTER_OTLP_*` variables exactly as before. When they are set
 * (`fabric run` sets them), the records go to the Fabric Node they name, over
 * the CA they name, and never to an `OTEL_*` endpoint the agent uses for its
 * own telemetry. A refused setting also returns `{}`: the `Fabric` client then
 * records nothing and `captureStatus()` says why. Never throws.
 */
export function fabricExporterOptions(env: Env = process.env): FabricExporterOptions {
  try {
    if (!fabricOtlpSelected(env) || !fabricRouteTransport(env).allowed) return {};
    const base = get(env, "FABRIC_OTLP_ENDPOINT") as string;
    const options: FabricExporterOptions = {
      url: `${base.replace(/\/+$/, "")}/v1/traces`,
      timeoutMillis: 10_000,
    };
    const agent: { ca?: string; cert?: string; key?: string } = {};
    const ca = get(env, "FABRIC_OTLP_CERTIFICATE");
    const cert = get(env, "FABRIC_OTLP_CLIENT_CERTIFICATE");
    const key = get(env, "FABRIC_OTLP_CLIENT_KEY");
    if (ca !== undefined) agent.ca = readFileSync(ca, "utf-8");
    if (cert !== undefined && key !== undefined) {
      agent.cert = readFileSync(cert, "utf-8");
      agent.key = readFileSync(key, "utf-8");
    }
    if (Object.keys(agent).length > 0) options.httpAgentOptions = agent;
    const headersFile = get(env, "FABRIC_OTLP_HEADERS_FILE");
    if (headersFile !== undefined) options.headers = headersFromFile(headersFile) ?? {};
    return options;
  } catch {
    return {};
  }
}

/**
 * Fabric's capture status for `env` (default `process.env`), as a
 * {@link Fabric} client built now would report it from
 * `fabric.captureStatus()`. Opens no connection and never throws.
 */
export function captureStatus(env: Env = process.env): CaptureStatus {
  let verdict: OtlpTraceTransport;
  try {
    verdict = otlpTraceTransport(env);
  } catch {
    // Unreachable by construction; fail closed like the Python install does.
    verdict = refuse("OTEL_EXPORTER_OTLP_ENDPOINT", "a valid endpoint");
  }
  if (verdict.allowed) return { capture: "enabled" };
  return { capture: "disabled", reason: verdict.reason, fix: verdict.fix };
}

const reported = new Set<string>();

/**
 * Print `status` once per process on stderr when `FABRIC_WIRE_DIAGNOSTICS=stderr`;
 * otherwise do nothing (the status API is the channel). A failing stderr
 * write is swallowed: diagnostics never reach the application as an error.
 */
export function reportCaptureStatus(status: CaptureStatus, env: Env = process.env): void {
  if (status.capture !== "disabled") return;
  if ((env[DIAGNOSTICS_ENV] ?? "").trim().toLowerCase() !== "stderr") return;
  const line = `singleaxis-fabric: capture off: ${status.reason}; fix: ${status.fix}\n`;
  if (reported.has(line)) return;
  reported.add(line);
  try {
    process.stderr.write(line);
  } catch {
    // Diagnostics must never alter or interrupt the monitored application.
  }
}

/** Test hook: forget which diagnostics were already printed. */
export function resetCaptureDiagnostics(): void {
  reported.clear();
}
