// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * The span delivery rule shared with the Python SDK (docs/privacy-and-security.md,
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
 */

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
