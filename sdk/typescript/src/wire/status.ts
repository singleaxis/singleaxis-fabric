// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The content-free status document (spec 055 §4.7; spec 058 §13.2): what `capture.status()`
 * and `envStatus()` return and what the status file at `FABRIC_WIRE_STATUS_FILE` holds, in
 * schema `fabric.wire-status/v1` (`contracts/diagnostics/v1/schema/wire-status-v1.schema.json`),
 * the document Python's `wire/_statusfile.py` writes. Every disabled or degraded state is a
 * catalogue id (`warning_ids`, `notice_ids`); texts and fixes come from the catalogue and
 * carry no value. The document names settings, capture points, reason codes and counts,
 * never a key, a header, a URL, a path or content.
 *
 * The file is written atomically (a temporary file renamed over it), mode 0600, by the
 * Fabric worker at install and at exit, or by the installing thread when capture did not
 * start (there is no worker then); never by a hook. A file that cannot be written is one
 * `FW-023` warning, never an error in the agent.
 */
import {
  accessSync,
  closeSync,
  constants,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { inspect } from "node:util";
import { dirname, join } from "node:path";
import { threadId } from "node:worker_threads";

import { DeploymentPolicy } from "../deployment-policy.js";
import { SDK_VERSION } from "../version.js";
import { CATALOGUE, type TypeScriptCatalogueId } from "./catalogue.generated.js";
import { configStatus } from "./config.js";
import {
  NODE_HTTP_POINT,
  type QualificationTable,
  type RuntimeBuild,
  type StateEntry,
  UNDICI_POINT,
  currentRuntime,
  initialStates,
} from "./manifest.js";
import { loadNative, nativeTarget } from "./native.js";
import { decideGate, maskingWithheld, type ContentGate } from "./protect.js";
import type { WireSettings } from "./types.js";
import type { UnmatchedHost } from "./undici.js";

export const STATUS_SCHEMA = "fabric.wire-status/v1";
export const STATUS_FILE_ENV = "FABRIC_WIRE_STATUS_FILE";

/** The wire capture points a status document reports. */
export const STATUS_POINTS = [UNDICI_POINT, NODE_HTTP_POINT] as const;

/** One `fabric.wire-status/v1` document (the schema's properties TypeScript writes). */
export interface StatusDocument {
  readonly schema: typeof STATUS_SCHEMA;
  readonly phase: "install" | "exit";
  readonly written_at: string;
  readonly pid: number;
  readonly sdk_version: string;
  readonly sdk_language: "typescript";
  readonly capture: "installed" | "disabled" | "not_installed" | "closed";
  readonly warning_ids: readonly string[];
  readonly notice_ids: readonly string[];
  readonly status?: Readonly<Record<string, unknown>>;
  readonly error?: string;
  readonly reason?: string;
  readonly reason_id?: string;
  readonly fix?: string;
  readonly delivered?: boolean;
  readonly stats?: Readonly<Record<string, number>>;
  /** FW-006: each unmatched model host and the exact value that records it (exit only). */
  readonly unmatched_model_hosts?: readonly UnmatchedModelHostRow[];
}

/** One `unmatched_model_hosts` row, as Python's `_unmatched.py` writes it. */
export interface UnmatchedModelHostRow {
  readonly host: string;
  readonly port: number;
  readonly count: number;
  readonly fix: string;
}

/** A catalogue message of a document, with its text and fix (local output only). */
export interface StatusMessage {
  readonly id: string;
  readonly severity: string;
  readonly text: string;
  readonly fix: string;
}

/** Content-free counters of the installing thread's hook (spec 055 §4.7). */
export interface HookCounters {
  readonly matched: number;
  readonly not_captured: number;
  readonly unmatched_model_shaped: number;
}

/** What decides an install-phase document. */
export interface StatusFacts {
  /** `installed`: a hook is subscribed and the Fabric worker runs; else `disabled`. */
  readonly capture: "installed" | "disabled";
  /** Why capture is not running (a reason code), when it is not. */
  readonly reason?: string | undefined;
  readonly settings?: WireSettings | undefined;
  readonly gate?: ContentGate | undefined;
  /** The wire points' states, when they were decided. */
  readonly states?: Readonly<Record<string, StateEntry>> | undefined;
  readonly runtime: RuntimeBuild;
  /** Whether the qualification table lists this Node patch and platform at all. */
  readonly listed: boolean;
  /** The native loader's catalogue id, when the module cannot be used. */
  readonly nativeReasonId?: "FW-027" | "FW-028" | undefined;
  /** A masking role has no redaction service or transformation (FW-032). */
  readonly maskedWithheld?: boolean | undefined;
  readonly counters?: HookCounters | undefined;
  /** The installing thread's unmatched model hosts (FW-006), when it has a hook. */
  readonly unmatched?: readonly UnmatchedHost[] | undefined;
  /** The status file could not be written, or cannot be (FW-023). */
  readonly statusFileUnwritable?: boolean | undefined;
  /** `FABRIC_WIRE_AUTOLOAD` is not 1: the preload would do nothing (FW-031). */
  readonly autoloadOff?: boolean | undefined;
}

/** Reasons the documents name, beside the point reasons of the registry. */
export const Reason = Object.freeze({
  autoloadOff: "autoload_off",
  otelSdkDisabled: "otel_sdk_disabled",
  noSpool: "no_spool",
  spoolUnusable: "spool_unusable",
  workerThread: "worker_without_process_runtime",
  fabricWorker: "fabric_worker",
  internalError: "internal_error",
  noActivePoint: "no_active_point",
} as const);

const SEVERITY = new Map(CATALOGUE.map((entry) => [entry.id, entry]));
const TOKEN = /^[A-Za-z0-9._:@/+=-]{0,160}$/;
const CODE = /^[a-z][a-z0-9_]{0,63}$/;

function now(): string {
  return new Date().toISOString();
}

function head(
  phase: "install" | "exit",
): Pick<
  StatusDocument,
  "schema" | "phase" | "written_at" | "pid" | "sdk_version" | "sdk_language"
> {
  return {
    schema: STATUS_SCHEMA,
    phase,
    written_at: now(),
    pid: process.pid,
    sdk_version: SDK_VERSION,
    sdk_language: "typescript" as const,
  };
}

/** Sorts ids into warnings (warning, error) and notices (info), unique, in catalogue order. */
function split(ids: Iterable<TypeScriptCatalogueId>): {
  warning_ids: string[];
  notice_ids: string[];
} {
  const unique = new Set(ids);
  const ordered = CATALOGUE.map((entry) => entry.id).filter((id) => unique.has(id as never));
  return {
    warning_ids: ordered.filter((id) => SEVERITY.get(id)?.severity !== "info"),
    notice_ids: ordered.filter((id) => SEVERITY.get(id)?.severity === "info"),
  };
}

/** The platform as the schema writes it (`linux-x64-glibc`, else `<platform>-<arch>`). */
function platformOf(runtime: RuntimeBuild): string {
  const text = runtime.platform ?? `${process.platform}-${process.arch}`;
  return /^[a-z0-9]+-[a-z0-9]+(-[a-z]+)?$/.test(text) ? text : "unknown-unknown";
}

function nodeOf(runtime: RuntimeBuild): string {
  return /^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$/.test(runtime.node) ? runtime.node : "0.0.0";
}

/** Whether `table` lists any tuple for this Node patch and platform. */
export function runtimeListed(table: QualificationTable, runtime: RuntimeBuild): boolean {
  return table.tuples.some((t) => t.node === runtime.node && t.platform === runtime.platform);
}

/** Whether the policy masks a model-exchange role that nothing can transform (FW-032). */
export function maskedWithheld(
  gate: ContentGate | undefined,
  settings: WireSettings,
  transformations: Readonly<Record<string, unknown>> = {},
): boolean {
  const policy = gate?.contentCapture === "enabled" ? gate.policy : undefined;
  if (policy === undefined) return false;
  // As the pipeline decides it (worker.ts): a masking role needs both the service and
  // the customer's transformation; the preload and envStatus() have no transformation.
  return maskingWithheld(policy, settings.redactionEndpoint !== undefined, transformations);
}

/** The content gate a configuration decides, read without installing (never throws). */
export function gateOf(settings: WireSettings): ContentGate | undefined {
  try {
    let policy: DeploymentPolicy | undefined;
    if (settings.capturePolicyPath !== undefined) {
      // Read through the same rule as the pipeline: a malformed policy is a config error.
      policy = new DeploymentPolicy(JSON.parse(readText(settings.capturePolicyPath)));
    }
    return decideGate({
      node: settings.contentEndpoint !== undefined,
      store: settings.store?.kind === "file",
      policy,
      idKey: settings.secrets.idKey !== undefined,
      spool: settings.spoolDir !== undefined,
      spoolKey: settings.secrets.spoolKey !== undefined,
    });
  } catch {
    return undefined;
  }
}

function readText(path: string): string {
  return readFileSync(path, "utf8");
}

/** The records waiting in a spool directory, read only (`*.rec`, never a dot file). */
export function spoolBacklog(
  dir: string | undefined,
): { records: number; bytes: number } | undefined {
  if (dir === undefined) return undefined;
  try {
    let records = 0;
    let bytes = 0;
    for (const name of readdirSync(dir)) {
      if (name.startsWith(".") || !name.endsWith(".rec")) continue;
      try {
        const info = statSync(join(dir, name));
        if (!info.isFile()) continue;
        records += 1;
        bytes += info.size;
      } catch {
        // gone between the listing and the stat
      }
    }
    return { records, bytes };
  } catch {
    return undefined;
  }
}

function spoolNoted(dir: string | undefined): boolean {
  if (dir === undefined) return false;
  try {
    return statSync(join(dir, ".exit-backlog")).isFile();
  } catch {
    return false;
  }
}

/** The catalogue ids and the `status` object of an install-phase document. */
export function describe(facts: StatusFacts): {
  status: Record<string, unknown>;
  warning_ids: string[];
  notice_ids: string[];
} {
  const ids: TypeScriptCatalogueId[] = [];
  const status: Record<string, unknown> = {};
  const settings = facts.settings;
  const undici = facts.states?.[UNDICI_POINT];
  status.capture = facts.capture === "installed" ? (undici?.[0] ?? "active") : "disabled";
  const reason = facts.capture === "installed" ? undefined : (facts.reason ?? undici?.[1]);
  if (reason !== undefined && CODE.test(reason)) status.capture_reason = reason;
  if (facts.states !== undefined) {
    const points: Record<string, string> = {};
    const reasons: Record<string, string> = {};
    for (const point of STATUS_POINTS) {
      const entry = facts.states[point];
      if (entry === undefined) continue;
      points[point] = entry[0];
      if (entry[1] !== undefined) reasons[point] = entry[1];
      if (entry[0] === "disabled" && entry[1] === "hook_disabled") ids.push("FW-029");
      if (entry[1] === "unsupported_version") ids.push("FW-026");
    }
    status.capture_points = points;
    status.capture_point_reasons = reasons;
  }
  status.runtime_qualification = {
    node: nodeOf(facts.runtime),
    undici: facts.runtime.undici ?? null,
    undici_origin: "bundled",
    platform: platformOf(facts.runtime),
    listed: facts.listed,
  };
  if (facts.nativeReasonId !== undefined) ids.push(facts.nativeReasonId);
  if (facts.reason === Reason.autoloadOff || facts.autoloadOff === true) ids.push("FW-031");
  if (facts.reason === Reason.otelSdkDisabled) ids.push("FW-007");
  if (facts.reason === Reason.workerThread) ids.push("FW-030");
  if (facts.reason === Reason.noSpool || facts.reason === Reason.spoolUnusable) ids.push("FW-034");
  if (facts.statusFileUnwritable === true) ids.push("FW-023");
  if (settings !== undefined) {
    status.autoload = settings.autoload;
    status.diagnostics = settings.diagnostics;
    if (facts.reason === Reason.noSpool && !captureOtlpConfiguredOf(settings)) ids.push("FW-002");
    const gate = facts.gate;
    if (gate !== undefined) {
      status.profile = gate.profile;
      status.content_capture = gate.contentCapture;
      if (gate.reason !== undefined && CODE.test(gate.reason)) {
        status.content_capture_reason = gate.reason;
      }
      if (gate.contentCapture === "disabled") ids.push("FW-008");
      else if (gate.contentCapture === "metadata_only" && gate.reason === "no_store")
        ids.push("FW-003");
      if (settings.spoolMigratePlaintext && gate.profile === "production") ids.push("FW-022");
    }
    if (facts.maskedWithheld === true) ids.push("FW-032");
    const endpoints = [...settings.extraEndpoints, ...settings.endpoints]
      .map((m) => m.endpointId)
      .filter((id) => TOKEN.test(id));
    status.endpoint_set = endpoints.slice(0, 64);
    status.endpoint_table_version = settings.endpointTableVersion;
    if (facts.capture === "installed") ids.push("FW-005");
    const backlog = spoolBacklog(settings.spoolDir);
    if (backlog !== undefined) {
      status.spool_backlog = backlog;
      if (backlog.records > 0 && spoolNoted(settings.spoolDir)) ids.push("FW-033");
    }
  }
  if (facts.counters !== undefined) {
    status.matched = facts.counters.matched;
    status.captured = Math.max(0, facts.counters.matched - facts.counters.not_captured);
    status.not_captured = facts.counters.not_captured;
    status.unmatched_model_shaped = facts.counters.unmatched_model_shaped;
    if (facts.counters.unmatched_model_shaped > 0) ids.push("FW-006");
  }
  const rows = unmatchedRows(facts.unmatched);
  if (rows.length > 0) {
    status.unmatched_model_hosts = rows;
    ids.push("FW-006");
  }
  return { status, ...split(ids) };
}

const DEFAULT_PORTS: Readonly<Record<string, number>> = { https: 443, http: 80 };
const HOST = /^[A-Za-z0-9.:[\]-]{1,253}$/;

/**
 * The `unmatched_model_hosts` rows (FW-006's "the status lists the exact value for each
 * host"): Python's `UnmatchedModelHosts.status()` byte for byte, `fix` being the one
 * `FABRIC_WIRE_ENDPOINTS` value that records the host. A host the schema cannot carry
 * (not a plain DNS name or address) is left out; its requests are still counted.
 */
export function unmatchedRows(
  hosts: readonly UnmatchedHost[] | undefined,
): UnmatchedModelHostRow[] {
  const rows: UnmatchedModelHostRow[] = [];
  for (const row of hosts ?? []) {
    if (rows.length >= 64) break;
    if (!HOST.test(row.host) || !/^https?$/.test(row.scheme)) continue;
    if (!Number.isSafeInteger(row.count) || row.count < 1) continue;
    const port = row.port ?? DEFAULT_PORTS[row.scheme] ?? 443;
    if (!Number.isInteger(port) || port < 1 || port > 65535) continue;
    // Python: json.dumps([entry], separators=(",", ":")), keys in insertion order.
    const entry = JSON.stringify([
      {
        endpoint_id: "my-model",
        dialect: row.dialect,
        hosts: [row.host],
        ports: [port],
        schemes: [row.scheme],
      },
    ]);
    rows.push({
      host: row.host,
      port,
      count: row.count,
      fix: `export FABRIC_WIRE_ENDPOINTS='${entry}'`,
    });
  }
  return rows;
}

/** `settings` names an OTLP traces endpoint (the route is resolved whenever one is set). */
function captureOtlpConfiguredOf(settings: WireSettings): boolean {
  return settings.otlp.endpoint !== undefined;
}

/** An install-phase document: capture `installed` or `disabled`. */
export function installDocument(facts: StatusFacts): StatusDocument {
  const { status, warning_ids, notice_ids } = describe(facts);
  return { ...head("install"), capture: facts.capture, warning_ids, notice_ids, status };
}

/** Capture was not installed because the configuration is invalid (fixed text, no value). */
export function notInstalledDocument(failure: {
  readonly error: string;
  readonly reason: string;
  readonly reasonId: string;
  readonly fix?: string | undefined;
}): StatusDocument {
  const error = /^[A-Za-z_][A-Za-z0-9_.]{0,127}$/.test(failure.error) ? failure.error : "Error";
  return {
    ...head("install"),
    capture: "not_installed",
    error,
    reason: failure.reason.slice(0, 500),
    reason_id: failure.reasonId,
    ...(failure.fix ? { fix: failure.fix.slice(0, 500) } : {}),
    warning_ids: ["FW-025"],
    notice_ids: [],
  };
}

/** The exit document: final counters (content-free integers) and whether all was delivered. */
export function exitDocument(
  install: Pick<StatusDocument, "warning_ids" | "notice_ids">,
  delivered: boolean,
  stats: Readonly<Record<string, number>>,
  unmatched?: readonly UnmatchedHost[],
): StatusDocument {
  const clean: Record<string, number> = {};
  for (const [name, value] of Object.entries(stats)) {
    if (!/^[a-z][a-z0-9_.-]{0,63}$/.test(name)) continue;
    if (!Number.isSafeInteger(value) || value < 0) continue;
    if (Object.keys(clean).length >= 128) break;
    clean[name] = value;
  }
  const ids = new Set<string>(
    [...install.warning_ids, ...install.notice_ids].filter(
      (id) => id !== "FW-033" && id !== "FW-006",
    ),
  );
  if ((clean.backlog ?? 0) > 0) ids.add("FW-033");
  if ((clean.unmatched_model_shaped ?? 0) > 0) ids.add("FW-006");
  const rows = unmatchedRows(unmatched);
  if (rows.length > 0) ids.add("FW-006");
  return {
    ...head("exit"),
    capture: "closed",
    delivered,
    stats: clean,
    ...(rows.length > 0 ? { unmatched_model_hosts: rows } : {}),
    ...split(ids as Set<TypeScriptCatalogueId>),
  };
}

/** The catalogue text and fix of every id a document carries. */
export function statusMessages(
  document: Pick<StatusDocument, "warning_ids" | "notice_ids">,
): StatusMessage[] {
  return [...document.warning_ids, ...document.notice_ids].flatMap((id) => {
    const entry = SEVERITY.get(id);
    return entry === undefined
      ? []
      : [{ id, severity: entry.severity, text: entry.text, fix: entry.fix }];
  });
}

/**
 * The document, printable with every message's text and fix: `node -p` (util.inspect)
 * shows them under `messages`; `JSON.stringify` and the status file carry the document only.
 */
export function printable<T extends StatusDocument>(document: T): T {
  Object.defineProperty(document, inspect.custom, {
    enumerable: false,
    value(depth: number, options: object) {
      const shown = { ...document, messages: statusMessages(document) };
      return inspect(shown, { ...options, depth: depth < 0 ? null : 8 });
    },
  });
  return document;
}

let unwritableWarned = false;

/** Writes `document` to `path` atomically, mode 0600; `false` on any failure. Never throws. */
export function writeStatusFile(
  path: string,
  document: StatusDocument,
  warn?: (text: string) => void,
): boolean {
  const tmp = `${path}.${process.pid}.${threadId}.tmp`;
  try {
    const data = Buffer.from(JSON.stringify(sorted(document)) + "\n", "utf8");
    const fd = openSync(
      tmp,
      constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    try {
      let at = 0;
      while (at < data.length) at += writeSync(fd, data, at);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, path);
    return true;
  } catch (error) {
    try {
      unlinkSync(tmp);
    } catch {
      // nothing was created
    }
    if (!unwritableWarned) {
      unwritableWarned = true;
      const entry = SEVERITY.get("FW-023");
      const cls =
        error instanceof Error && /^[A-Za-z]{1,64}$/.test(error.name) ? error.name : "Error";
      warn?.(`fabric.wire: ${entry?.text} (${cls}). Fix: ${entry?.fix} [FW-023]`);
    }
    return false;
  }
}

/** Keys in sorted order, recursively (Python writes `sort_keys=True`). */
function sorted(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sorted);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, sorted((value as Record<string, unknown>)[key])]),
  );
}

/** Whether a status file could be written at `path` (its directory exists and is writable). */
export function statusFileWritable(path: string): boolean {
  try {
    accessSync(dirname(path), constants.W_OK);
    return statSync(dirname(path)).isDirectory();
  } catch {
    return false;
  }
}

/**
 * The status document for an environment (Python `env_status`, as `python -m fabric.wire
 * status`): reads the configuration, the qualification table and the native module's
 * presence, installs no hook, starts no worker, writes and sends nothing. The one command:
 *
 *     node -p "require('@singleaxis/fabric/wire').envStatus()"
 */
export function envStatus(
  env: Readonly<Record<string, string | undefined>> = process.env,
  options: {
    readonly qualification?: QualificationTable;
    readonly native?: {
      readonly prebuildsDir?: string;
      readonly digests?: Readonly<Record<string, string>>;
    };
  } = {},
): StatusDocument {
  const verdict = configStatus(env);
  if (verdict.configuration === "invalid") {
    return printable(
      notInstalledDocument({
        error: "WireConfigError",
        reason: verdict.reason,
        reasonId: verdict.reasonId,
        fix: verdict.fix,
      }),
    );
  }
  const settings = verdict.settings;
  const native = loadNative({ ...options.native });
  const runtime = currentRuntime(native.ok ? native.target : nativeTarget());
  const table = options.qualification ?? packagedQualification();
  const statusFile = settings.statusFile;
  const unwritable = statusFile !== undefined && !statusFileWritable(statusFile);
  const base = {
    settings,
    runtime,
    listed: runtimeListed(table, runtime),
    statusFileUnwritable: unwritable,
    autoloadOff: !settings.autoload,
    nativeReasonId: native.ok ? undefined : native.reasonId,
  };
  if (settings.otelSdkDisabled) {
    return printable(
      installDocument({ ...base, capture: "disabled", reason: Reason.otelSdkDisabled }),
    );
  }
  const gate = gateOf(settings);
  const states = initialStates({
    runtime,
    table,
    nativeOk: native.ok,
    enabled: { [UNDICI_POINT]: settings.undici, [NODE_HTTP_POINT]: settings.nodeHttp },
    installed: { [UNDICI_POINT]: settings.undici },
    endpoints: settings.endpoints.length + settings.extraEndpoints.length,
  });
  const wire = {
    [UNDICI_POINT]: states[UNDICI_POINT]!,
    [NODE_HTTP_POINT]: states[NODE_HTTP_POINT]!,
  };
  const active = wire[UNDICI_POINT][0] === "active";
  // The most specific reason first, as install() decides it: no spool, then the native
  // module's own reason, then the capture point's.
  const reason =
    settings.spoolDir === undefined
      ? Reason.noSpool
      : !spoolUsable(settings.spoolDir)
        ? Reason.spoolUnusable
        : !native.ok
          ? native.reason
          : active
            ? undefined
            : wire[UNDICI_POINT][1];
  return printable(
    installDocument({
      ...base,
      capture: active && reason === undefined ? "installed" : "disabled",
      reason,
      gate,
      states: wire,
      maskedWithheld: maskedWithheld(gate, settings),
    }),
  );
}

/**
 * Read only, as `install()`'s `secureDir` decides it: a path that does not exist yet is
 * usable (install creates it, mode 0700); one that exists must be a real directory (not a
 * symlink) owned by this user.
 */
function spoolUsable(path: string): boolean {
  try {
    const info = lstatSync(path);
    if (info.isSymbolicLink() || !info.isDirectory()) return false;
    return process.getuid === undefined || info.uid === process.getuid();
  } catch (error) {
    return (error as { code?: unknown }).code === "ENOENT";
  }
}

let packaged: QualificationTable | undefined;

/** The package's qualification table (`dist/wire-qualification.json`), or an empty one. */
export function packagedQualification(base?: string): QualificationTable {
  if (packaged !== undefined && base === undefined) return packaged;
  let table: QualificationTable = { tuples: [] };
  const from = base ?? moduleDir();
  if (from !== undefined) {
    for (const candidate of [
      join(from, "..", "wire-qualification.json"),
      join(from, "..", "..", "wire-qualification.json"),
    ]) {
      try {
        const parsed = JSON.parse(readText(candidate)) as QualificationTable;
        if (Array.isArray(parsed?.tuples)) {
          table = parsed;
          break;
        }
      } catch {
        // try the next location
      }
    }
  }
  if (base === undefined) packaged = table;
  return table;
}

function moduleDir(): string | undefined {
  // The wire core is one CommonJS file in the package (`dist/wire/core.cjs`).
  // eslint-disable-next-line no-undef -- CommonJS only; `typeof` never throws in ESM
  return typeof __dirname === "string" ? __dirname : undefined;
}
