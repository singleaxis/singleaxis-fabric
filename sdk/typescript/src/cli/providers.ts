// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Model endpoints for the npm launcher (spec 058 §8.3), the same rules as the
 * Python CLI's `fabric/cli/_providers.py`: a provider client's base-URL
 * variable whose host neither the built-in table
 * (`contracts/providers/v1/builtin-endpoints.json`, bundled) nor fabric.yaml's
 * custom providers cover becomes one more `FABRIC_WIRE_ENDPOINTS` matcher.
 * Key variables are never read.
 */

import { isIP } from "node:net";

import table from "../../../../contracts/providers/v1/builtin-endpoints.json";

/** The standard base-URL variables of the provider clients -> dialect. */
export const BASE_URL_VARIABLES: ReadonlyArray<readonly [string, "openai" | "anthropic"]> = [
  ["OPENAI_BASE_URL", "openai"],
  ["OPENAI_API_BASE", "openai"],
  ["ANTHROPIC_BASE_URL", "anthropic"],
  ["AZURE_OPENAI_ENDPOINT", "openai"],
];

const DEFAULT_PORTS: Record<string, number> = { https: 443, http: 80 };
const SUFFIX_PATHS = [
  "/chat/completions",
  "/completions",
  "/responses",
  "/embeddings",
  "/messages",
];
const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const HOST_RE = /^[A-Za-z0-9.:[\]_-]{1,253}$/;

export interface Matcher {
  endpoint_id: string;
  dialect: "openai" | "anthropic";
  hosts: string[];
  host_suffixes: string[];
  ports: number[] | null;
  schemes: string[];
  path_prefix: string;
  provider_name: string;
}

interface TableRow {
  endpoint_id: string;
  provider_name?: string;
  dialect: "openai" | "anthropic";
  hosts?: string[];
  host_suffixes?: string[];
  ports?: number[];
  schemes?: string[];
  path_prefix?: string;
  default?: boolean;
}

/** The built-in rows on by default (the SDK's `DEFAULT_ENDPOINTS`). */
export function builtin(): Matcher[] {
  return (table.rows as TableRow[])
    .filter((row) => row.default === true)
    .map((row) => matcherFromJson(row as unknown as Record<string, unknown>));
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/** One `FABRIC_WIRE_ENDPOINTS` (or table) entry as a matcher. */
export function matcherFromJson(entry: Record<string, unknown>): Matcher {
  const ports = Array.isArray(entry.ports)
    ? entry.ports.filter((p): p is number => typeof p === "number")
    : null;
  const dialect = entry.dialect === "anthropic" ? "anthropic" : "openai";
  return {
    endpoint_id: String(entry.endpoint_id ?? ""),
    dialect,
    hosts: strings(entry.hosts),
    host_suffixes: strings(entry.host_suffixes),
    ports: ports && ports.length ? ports : null,
    schemes: entry.schemes === undefined ? ["https"] : strings(entry.schemes),
    path_prefix: typeof entry.path_prefix === "string" ? entry.path_prefix : "",
    provider_name: typeof entry.provider_name === "string" ? entry.provider_name : "openai",
  };
}

/** The custom matchers a compiled `FABRIC_WIRE_ENDPOINTS` value holds. */
export function parseEndpoints(value: string | undefined): Matcher[] {
  if (!value) return [];
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((e): e is Record<string, unknown> => typeof e === "object" && e !== null)
      .map(matcherFromJson);
  } catch {
    return [];
  }
}

function isLoopback(host: string): boolean {
  if (host === "localhost") return true;
  const kind = isIP(host);
  if (kind === 4) return host.startsWith("127.");
  if (kind === 6) return host === "::1" || /^(0{1,4}:){7}0{0,3}1$/.test(host);
  return false;
}

function endpointName(host: string, port: number, scheme: string): string {
  if (isLoopback(host)) return `local-${port}`;
  if (isIP(host)) {
    return (
      "ip-" +
      host
        .toLowerCase()
        .replace(/[^a-z0-9-]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 60)
    );
  }
  const label = (host.split(".", 1)[0] ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
  return label || `custom-${scheme}`;
}

/** Compile one base URL (§8.2); `null` when it is not a URL Fabric can match. */
export function parseProvider(text: string, dialect: "openai" | "anthropic"): Matcher | null {
  let raw = text.trim();
  const prefixed = /^(openai|anthropic)=(.+)$/.exec(raw);
  if (prefixed) {
    dialect = prefixed[1] as "openai" | "anthropic";
    raw = (prefixed[2] ?? "").trim();
  }
  const scheme = (/^([A-Za-z][A-Za-z0-9+.-]*):\/\//.exec(raw)?.[1] ?? "").toLowerCase();
  if (!(scheme in DEFAULT_PORTS)) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  const authority = raw.slice(scheme.length + 3).split(/[/?#]/, 1)[0] ?? "";
  if (authority.includes("@") || url.search || url.hash || raw.includes("?") || raw.includes("#")) {
    return null;
  }
  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host) return null;
  let path = url.pathname.replace(/\/+$/, "");
  for (const suffix of SUFFIX_PATHS) {
    if (path.endsWith(suffix)) {
      path = path.slice(0, -suffix.length);
      break;
    }
  }
  const port = url.port ? Number(url.port) : (DEFAULT_PORTS[scheme] as number);
  const matcher: Matcher = {
    endpoint_id: endpointName(host, port, scheme),
    dialect,
    hosts: [host],
    host_suffixes: [],
    ports: [port],
    schemes: [scheme],
    path_prefix: path,
    provider_name: dialect === "anthropic" ? "anthropic" : "openai",
  };
  const valid =
    NAME_RE.test(matcher.endpoint_id) &&
    HOST_RE.test(host) &&
    port > 0 &&
    port < 65536 &&
    (path === "" || path.startsWith("/"));
  return valid ? matcher : null;
}

/** Whether a request to this base URL is already recorded by `matchers`. */
export function covered(
  matchers: readonly Matcher[],
  scheme: string,
  host: string,
  port: number,
  path: string,
): boolean {
  return matchers.some(
    (m) =>
      (m.hosts.includes(host) || m.host_suffixes.some((s) => host.endsWith(s))) &&
      m.schemes.includes(scheme) &&
      (m.ports === null || m.ports.includes(port)) &&
      path.startsWith(m.path_prefix),
  );
}

/** §8.3: a matcher for each base-URL variable whose host `known` does not cover. */
export function fromEnvironment(
  environ: Record<string, string | undefined>,
  known: readonly Matcher[],
): Matcher[] {
  const derived: Matcher[] = [];
  for (const [variable, dialect] of BASE_URL_VARIABLES) {
    const value = (environ[variable] ?? "").trim();
    if (!value) continue;
    const matcher = parseProvider(value, dialect);
    if (matcher === null) continue;
    const everything = [...known, ...derived];
    if (
      !covered(
        everything,
        matcher.schemes[0] as string,
        matcher.hosts[0] as string,
        (matcher.ports ?? [443])[0] as number,
        matcher.path_prefix || "/",
      )
    ) {
      derived.push(matcher);
    }
  }
  return derived;
}

/** One `FABRIC_WIRE_ENDPOINTS` entry, with the Python CLI's field order. */
function matcherJson(m: Matcher): Record<string, unknown> {
  const entry: Record<string, unknown> = { endpoint_id: m.endpoint_id, dialect: m.dialect };
  if (m.hosts.length) entry.hosts = [...m.hosts].sort();
  if (m.host_suffixes.length) entry.host_suffixes = [...m.host_suffixes].sort();
  if (m.ports && m.ports.length) entry.ports = [...m.ports].sort((a, b) => a - b);
  entry.schemes = [...m.schemes].sort();
  if (m.path_prefix) entry.path_prefix = m.path_prefix;
  if (m.provider_name !== "openai") entry.provider_name = m.provider_name;
  return entry;
}

/** The `FABRIC_WIRE_ENDPOINTS` value (compact JSON, ASCII only, as Python's `json.dumps`). */
export function endpointsValue(matchers: readonly Matcher[]): string {
  return JSON.stringify(matchers.map(matcherJson)).replace(
    /[\u007f-￿]/g,
    (ch) => `\\u${(ch.codePointAt(0) ?? 0).toString(16).padStart(4, "0")}`,
  );
}
