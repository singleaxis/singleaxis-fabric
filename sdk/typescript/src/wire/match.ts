// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Endpoint matching (spec 055 §3.4; a port of Python `wire/_match.py` and the built-in
 * rows of `wire/_config.py`). The hook path calls {@link EndpointIndex.match}, which does
 * string compares only: POST only, an allowed scheme, a lowercase exact host or configured
 * suffix, an optional port (the scheme's default when the request names none), the
 * configured path prefix and one of the dialect's API suffixes. Queries are never part of
 * the path handed in here. A test checks every case against a table generated from
 * `wire/_match.py`, and the built-in rows against Python's for `table` and `legacy`.
 */

import { ENDPOINT_TABLE } from "./endpoint-table.generated.js";
import type { Dialect, EndpointMatcher, WireApi } from "./types.js";

/** `gen_ai.operation.name` of each API. */
export const OPERATION_NAMES: Readonly<Record<WireApi, string>> = Object.freeze({
  "openai.chat_completions": "chat",
  "openai.responses": "chat",
  "openai.completions": "text_completion",
  "openai.embeddings": "embeddings",
  "anthropic.messages": "chat",
});

const SUFFIXES: Readonly<Record<Dialect, readonly (readonly [string, WireApi])[]>> = {
  openai: [
    ["/chat/completions", "openai.chat_completions"],
    ["/responses", "openai.responses"],
    ["/completions", "openai.completions"],
    ["/embeddings", "openai.embeddings"],
  ],
  anthropic: [["/messages", "anthropic.messages"]],
};

/** Every API path suffix of every dialect (an unmatched model-shaped request, FW-006). */
export const MODEL_PATH_SUFFIXES: readonly string[] = Object.freeze([
  ...new Set(Object.values(SUFFIXES).flatMap((rows) => rows.map(([suffix]) => suffix))),
]);

const DEFAULT_PORTS: Readonly<Record<string, number>> = { https: 443, http: 80 };

/** The wire API of a request path (no query string) for `dialect`, if recognized. */
export function apiForPath(dialect: string, path: string): WireApi | undefined {
  const rows = (SUFFIXES as Record<string, readonly (readonly [string, WireApi])[]>)[dialect];
  return rows?.find(([suffix]) => path.endsWith(suffix))?.[1];
}

interface Entry {
  readonly matcher: EndpointMatcher;
  readonly hosts: ReadonlySet<string>;
  readonly suffixes: readonly string[];
  readonly ports: ReadonlySet<number> | undefined;
}

/** Lowercased hosts per matcher, scanned in order (a handful of matchers at most). */
export class EndpointIndex {
  readonly #entries: readonly Entry[];

  constructor(matchers: readonly EndpointMatcher[]) {
    this.#entries = Object.freeze(
      matchers.map((matcher) => ({
        matcher,
        hosts: new Set(matcher.hosts.map((h) => h.toLowerCase())),
        suffixes: matcher.hostSuffixes.map((s) => s.toLowerCase()),
        ports: matcher.ports === undefined ? undefined : new Set(matcher.ports),
      })),
    );
  }

  /** The first matching endpoint and API for a request, else `undefined`. */
  match(
    method: string,
    scheme: string,
    host: string,
    port: number | undefined | null,
    path: string,
  ): { readonly endpoint: EndpointMatcher; readonly api: WireApi } | undefined {
    if (method !== "POST") return undefined;
    const lower = host.toLowerCase();
    for (const { matcher, hosts, suffixes, ports } of this.#entries) {
      if (!hosts.has(lower) && !suffixes.some((s) => lower.endsWith(s))) continue;
      if (!matcher.schemes.includes(scheme as "http" | "https")) continue;
      if (!path.startsWith(matcher.pathPrefix)) continue;
      // Python: `port or default`, so an explicit port 0 also takes the default.
      const effective = port || DEFAULT_PORTS[scheme];
      if (ports !== undefined && (effective === undefined || !ports.has(effective))) continue;
      const api = apiForPath(matcher.dialect, path);
      if (api !== undefined) return { endpoint: matcher, api };
    }
    return undefined;
  }
}

// ----------------------------------------------------------------- endpoint validation

const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const HOST_RE = /^[A-Za-z0-9.:[\]_-]{1,253}$/;

/** Whether `m` is a usable endpoint (Python `validate_endpoint`, spec 047 §2). */
export function isValidEndpoint(m: EndpointMatcher): boolean {
  const hosts = [...m.hosts, ...m.hostSuffixes];
  return (
    typeof m.endpointId === "string" &&
    NAME_RE.test(m.endpointId) &&
    typeof m.providerName === "string" &&
    NAME_RE.test(m.providerName) &&
    (m.dialect === "openai" || m.dialect === "anthropic") &&
    hosts.length > 0 &&
    hosts.every((h) => typeof h === "string" && HOST_RE.test(h)) &&
    m.schemes.length > 0 &&
    m.schemes.every((s) => s === "http" || s === "https") &&
    (m.ports ?? []).every((p) => Number.isInteger(p) && p > 0 && p < 65536) &&
    typeof m.pathPrefix === "string" &&
    (m.pathPrefix === "" || m.pathPrefix.startsWith("/"))
  );
}

/** A frozen matcher; sets are sorted and deduplicated (Python keeps frozensets). */
export function endpointMatcher(fields: {
  readonly endpointId: string;
  readonly dialect: Dialect;
  readonly hosts?: readonly string[];
  readonly hostSuffixes?: readonly string[];
  readonly ports?: readonly number[] | undefined;
  readonly pathPrefix?: string;
  readonly providerName?: string;
  readonly schemes?: readonly ("http" | "https")[];
}): EndpointMatcher {
  const set = <T>(values: readonly T[]): readonly T[] =>
    Object.freeze([...new Set(values)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)));
  return Object.freeze({
    endpointId: fields.endpointId,
    dialect: fields.dialect,
    hosts: set(fields.hosts ?? []),
    hostSuffixes: set(fields.hostSuffixes ?? []),
    ports: fields.ports === undefined ? undefined : set(fields.ports),
    pathPrefix: fields.pathPrefix ?? "",
    providerName: fields.providerName ?? "openai",
    schemes: set<"http" | "https">(fields.schemes ?? ["https"]),
  });
}

// ----------------------------------------------------------------- built-in rows

interface TableRow {
  readonly endpoint_id: string;
  readonly provider_name: string;
  readonly dialect: string;
  readonly hosts?: readonly string[];
  readonly host_suffixes?: readonly string[];
  readonly ports?: readonly number[];
  readonly schemes: readonly string[];
  readonly path_prefix: string;
  readonly default?: boolean;
}

interface Table {
  readonly schema?: unknown;
  readonly table_version?: unknown;
  readonly legacy_endpoint_ids?: readonly string[];
  readonly rows: readonly TableRow[];
}

function rowMatcher(row: TableRow): EndpointMatcher {
  const matcher = endpointMatcher({
    endpointId: row.endpoint_id,
    dialect: row.dialect as Dialect,
    hosts: row.hosts ?? [],
    hostSuffixes: row.host_suffixes ?? [],
    ports: row.ports !== undefined && row.ports.length > 0 ? row.ports : undefined,
    pathPrefix: row.path_prefix,
    providerName: row.provider_name,
    schemes: row.schemes as ("http" | "https")[],
  });
  if (!isValidEndpoint(matcher)) throw new Error("invalid built-in endpoint row");
  return matcher;
}

/** The three rows of releases before the endpoint table, should the table not load. */
const LEGACY_FALLBACK: readonly EndpointMatcher[] = Object.freeze([
  endpointMatcher({ endpointId: "openai", dialect: "openai", hosts: ["api.openai.com"] }),
  endpointMatcher({
    endpointId: "anthropic",
    dialect: "anthropic",
    hosts: ["api.anthropic.com"],
    providerName: "anthropic",
  }),
  endpointMatcher({
    endpointId: "azure-openai",
    dialect: "openai",
    hostSuffixes: [".openai.azure.com"],
    providerName: "azure.ai.openai",
  }),
]);

/** The built-in endpoint sets of one table (Python `_load_table`). */
export interface BuiltinEndpoints {
  /** 0 when the table did not load (the legacy rows are then both sets). */
  readonly version: number;
  /** `FABRIC_WIRE_BUILTIN_ENDPOINTS=table`: the rows with `default: true`. */
  readonly table: readonly EndpointMatcher[];
  /** `FABRIC_WIRE_BUILTIN_ENDPOINTS=legacy`: the rows `legacy_endpoint_ids` names. */
  readonly legacy: readonly EndpointMatcher[];
}

/**
 * The default and legacy rows of a `fabric.builtin-endpoints/v1` table; a malformed table
 * yields version 0 and the legacy rows (capture never fails for it, as in Python).
 */
export function loadBuiltinEndpoints(table: unknown = ENDPOINT_TABLE): BuiltinEndpoints {
  try {
    const t = table as Table;
    if (t.schema !== "fabric.builtin-endpoints/v1") throw new Error("unknown table schema");
    const version = t.table_version;
    if (typeof version !== "number" || !Number.isInteger(version) || version < 1) {
      throw new Error("bad table version");
    }
    const all = t.rows.map(rowMatcher); // every row must be a usable matcher
    const defaults = all.filter((_m, i) => t.rows[i]!.default === true);
    const legacyIds = t.legacy_endpoint_ids ?? [];
    const legacy = legacyIds.map((id) => all.find((m) => m.endpointId === id));
    if (defaults.length === 0 || legacy.includes(undefined) || legacy.length === 0) {
      throw new Error("no default or legacy rows");
    }
    return Object.freeze({
      version,
      table: Object.freeze(defaults),
      legacy: Object.freeze(legacy as EndpointMatcher[]),
    });
  } catch {
    return Object.freeze({ version: 0, table: LEGACY_FALLBACK, legacy: LEGACY_FALLBACK });
  }
}

/** The packaged table's built-in rows. */
export const BUILTIN_ENDPOINTS: BuiltinEndpoints = loadBuiltinEndpoints();
