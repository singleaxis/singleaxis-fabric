// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * `fabric doctor` of the npm launcher (spec 058 §5.7): the checks a Node.js-only
 * machine can make, with the same catalogue ids as the Python CLI. In order:
 * the configuration (`fabric.yaml` found, the compiled environment current,
 * shell variables that override it, by name only, and the secret files); the
 * Python SDK in the agent's interpreter when there is one
 * (`python -I -m fabric.wire status`); the last run's record and status file;
 * the Node (a TLS handshake verified with the project's CA). It never changes
 * anything and contacts nothing but the project's Node (I4).
 *
 * Not checked here (the Python CLI and the image do): the host sensor's
 * container, the Node's log lines, the agent environment of a manual setup
 * with no fabric.yaml beyond the SDK check.
 */

import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import { connect as tcpConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { join } from "node:path";

import { SDK_VERSION } from "../version";
import { catalogued, Finding } from "./catalogue";
import { discover, projectOf, readCompiled, type Located, type Project } from "./project";
import { childEnvironment, upState, type Environ } from "./run";
import { which } from "./runtime";

const STATUS_TIMEOUT_MS = 30_000;
const RECORD_RE = /^([0-9]{1,20})-([A-Za-z0-9][A-Za-z0-9._-]{0,63})\.json$/;
export const REPORT_SCHEMA = "fabric.cli-report/v1";

export interface Report {
  schema: string;
  command: string;
  cli_version: string;
  exit_code: number;
  config: { path: string | null; source: string };
  findings: Finding[];
  data: Record<string, unknown>;
}

export interface DoctorOptions {
  config?: string;
}

export interface DoctorWorld {
  /** `python -I -m fabric.wire status` in `interpreter` with `env`: its JSON, or null. */
  sdkStatus: (interpreter: string, env: Record<string, string>) => Record<string, unknown> | null;
  /** Whether the Node answers over TLS (or plain TCP for http on loopback). */
  nodeAnswers: (endpoint: string, caFile: string | undefined) => Promise<boolean>;
  uid: () => number | undefined;
}

export function sdkStatus(
  interpreter: string,
  env: Record<string, string>,
): Record<string, unknown> | null {
  try {
    const result = spawnSync(interpreter, ["-I", "-m", "fabric.wire", "status"], {
      env,
      encoding: "utf-8",
      timeout: STATUS_TIMEOUT_MS,
      stdio: ["ignore", "pipe", "pipe"],
    });
    if (result.error || (result.status !== 0 && result.status !== 1)) return null;
    const lines = (result.stdout ?? "").trim().split("\n");
    const parsed: unknown = JSON.parse(lines[lines.length - 1] ?? "");
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/** A TLS handshake verified with the project's CA, then one HTTP request line. */
export function nodeAnswers(
  endpoint: string,
  caFile: string | undefined,
  timeoutMs = 3000,
): Promise<boolean> {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return Promise.resolve(false);
  }
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;
  return new Promise((done) => {
    let settled = false;
    const finish = (ok: boolean, socket?: { destroy(): void }): void => {
      if (settled) return;
      settled = true;
      socket?.destroy();
      done(ok);
    };
    try {
      if (url.protocol !== "https:") {
        const socket = tcpConnect({ host, port, timeout: timeoutMs }, () => finish(true, socket));
        socket.on("error", () => finish(false, socket));
        socket.on("timeout", () => finish(false, socket));
        return;
      }
      const ca = caFile ? readFileSync(caFile) : undefined;
      const socket = tlsConnect(
        { host, port, servername: host, ca, minVersion: "TLSv1.2", timeout: timeoutMs },
        () => {
          socket.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
        },
      );
      socket.once("data", (chunk: Buffer) =>
        finish(chunk.subarray(0, 5).toString("latin1") === "HTTP/", socket),
      );
      socket.on("error", () => finish(false, socket));
      socket.on("timeout", () => finish(false, socket));
      socket.on("end", () => finish(false, socket));
    } catch {
      finish(false);
    }
  });
}

/** §5.6 step 1: each secret file exists, is a regular file of this user, closed to others. */
export function secretFindings(
  compiled: Record<string, string>,
  uid: number | undefined,
): Finding[] {
  const out: Finding[] = [];
  for (const name of ["FABRIC_WIRE_ID_KEY_FILE", "FABRIC_OTLP_CERTIFICATE"]) {
    const path = compiled[name];
    if (!path) continue;
    const isPublic = name === "FABRIC_OTLP_CERTIFICATE";
    let info;
    try {
      info = lstatSync(path);
    } catch {
      out.push(new Finding("FC-031", `${name}: ${path} (run \`fabric init\`)`));
      continue;
    }
    if (info.isSymbolicLink()) {
      out.push(new Finding("FC-013", `${path}: is a symlink`));
    } else if (!info.isFile()) {
      out.push(new Finding("FC-013", `${path}: is not a regular file`));
    } else if (!isPublic && process.platform !== "win32" && uid !== undefined && info.uid !== uid) {
      out.push(new Finding("FC-013", `${path}: is owned by another user`));
    } else if (!isPublic && process.platform !== "win32" && (info.mode & 0o077) !== 0) {
      out.push(new Finding("FC-013", `${path}: is open to group or others`));
    }
  }
  return out;
}

/** The SDK status command's diagnostics as catalogue findings (13.2). */
export function sdkFindings(status: Record<string, unknown>): Finding[] {
  const wire = (status.wire && typeof status.wire === "object" ? status.wire : {}) as Record<
    string,
    unknown
  >;
  if (wire.configuration === "invalid") {
    const reasonId = String(wire.reason_id ?? "FW-001");
    let detail = String(wire.reason ?? "").slice(0, 600);
    if (wire.fix) detail += `; ${String(wire.fix)}`;
    return [new Finding(catalogued(reasonId) ? reasonId : "FW-001", detail)];
  }
  const out: Finding[] = [];
  const warnings = Array.isArray(status.warning_ids) ? status.warning_ids : [];
  for (const warning of warnings) {
    if (typeof warning !== "string" || !catalogued(warning) || warning === "FW-001") continue;
    const roles = Array.isArray(wire.content_withheld_roles) ? wire.content_withheld_roles : [];
    out.push(
      new Finding(
        warning,
        warning === "FW-004" && roles.length ? `roles: ${roles.map(String).join(", ")}` : undefined,
      ),
    );
  }
  return out;
}

/** The status file findings of a captured run (as `fabric verify` reads them). */
export function statusFindings(status: Record<string, unknown>): Finding[] {
  if (status.capture === "not_installed") {
    const reasonId = String(status.reason_id ?? "FW-001");
    const detail =
      (status.reason ? String(status.reason).slice(0, 600) : "") +
      (status.fix ? `; ${String(status.fix)}` : "");
    return [new Finding(catalogued(reasonId) ? reasonId : "FW-001", detail)];
  }
  const out: Finding[] = [];
  for (const warning of Array.isArray(status.warning_ids) ? status.warning_ids : []) {
    if (typeof warning === "string" && catalogued(warning)) out.push(new Finding(warning));
  }
  return out;
}

interface LastRun {
  label: string;
  command: string;
  runtime: string;
  capture: string;
  interpreter: string | null;
  findings: Array<{ id: string; detail?: string }>;
  statusPath: string;
}

export function lastRun(project: Project): LastRun | null {
  const runs = join(project.stateDir, "state", "runs");
  let names: string[];
  try {
    names = readdirSync(runs);
  } catch {
    return null;
  }
  const records = names
    .map((name) => RECORD_RE.exec(name))
    .filter((m): m is RegExpExecArray => m !== null && !m[0].endsWith(".status.json"))
    .sort((a, b) => (BigInt(a[1] as string) < BigInt(b[1] as string) ? 1 : -1));
  for (const match of records) {
    try {
      const raw: unknown = JSON.parse(readFileSync(join(runs, match[0]), "utf-8"));
      if (!raw || typeof raw !== "object") continue;
      const record = raw as Record<string, unknown>;
      if (record.schema !== "fabric.cli-run/v1" || typeof record.label !== "string") continue;
      const findings = Array.isArray(record.findings)
        ? record.findings.filter(
            (f): f is { id: string; detail?: string } =>
              !!f && typeof f === "object" && typeof (f as { id?: unknown }).id === "string",
          )
        : [];
      return {
        label: record.label,
        command: String(record.command ?? ""),
        runtime: String(record.runtime ?? "other"),
        capture: String(record.capture ?? "off"),
        interpreter: typeof record.interpreter === "string" ? record.interpreter : null,
        findings,
        statusPath: join(runs, match[0].replace(/\.json$/, ".status.json")),
      };
    } catch {
      continue;
    }
  }
  return null;
}

function interpreterFor(project: Project | null, environ: Environ, cwd: string): string | null {
  if (project !== null) {
    const record = lastRun(project);
    if (record?.interpreter && existsSync(record.interpreter)) return record.interpreter;
    for (const candidate of [
      join(project.directory, ".venv", "bin", "python"),
      join(project.directory, ".venv", "Scripts", "python.exe"),
    ]) {
      if (existsSync(candidate)) return candidate;
    }
  }
  for (const name of ["python3", "python"]) {
    const found = which(name, environ, cwd);
    if (found) return found;
  }
  return null;
}

const defaultWorld: DoctorWorld = {
  sdkStatus,
  nodeAnswers,
  uid: () => (typeof process.geteuid === "function" ? process.geteuid() : undefined),
};

/** `fabric doctor`: never changes anything. */
export async function doctor(
  options: DoctorOptions,
  environ: Environ,
  cwd: string,
  world: DoctorWorld = defaultWorld,
): Promise<{ report: Report; lines: string[] }> {
  const findings: Finding[] = [];
  const lines: string[] = [];
  const located: Located = discover(options.config, environ, cwd);
  const project = projectOf(located);
  let compiled: Record<string, string> = {};
  let settings: Record<string, string> = {};
  if (project === null) {
    findings.push(new Finding("FC-090"));
    lines.push("configuration: no fabric.yaml; checking this shell's environment");
  } else {
    lines.push(`configuration: ${project.configPath}`);
    const state = readCompiled(project);
    if (state.state === "current" || state.state === "stale") {
      compiled = state.compiled.env;
      settings = state.compiled.settings;
    }
    if (state.state !== "current") findings.push(new Finding("FC-060", project.compiledPath));
    for (const [name, value] of Object.entries(compiled)) {
      const shell = (environ[name] ?? "").trim();
      if (shell && shell !== value)
        findings.push(new Finding("FC-009", `${name} overrides fabric.yaml`));
    }
    findings.push(...secretFindings(compiled, world.uid()));
  }
  // The SDK, in the agent's Python interpreter when there is one.
  const interpreter = interpreterFor(project, environ, cwd);
  if (interpreter === null) {
    findings.push(new Finding("FC-099"));
    lines.push("sdk: no Python interpreter found");
  } else {
    const { env } = childEnvironment(environ, compiled, null);
    const status = world.sdkStatus(interpreter, env);
    if (status === null) {
      findings.push(
        new Finding(
          "FC-050",
          `${interpreter}; install with: ${interpreter} -m pip install "singleaxis-fabric[otlp]"`,
        ),
      );
      lines.push(`sdk: ${interpreter} cannot run \`python -m fabric.wire status\``);
    } else {
      const found = sdkFindings(status);
      findings.push(...found);
      const wire = (status.wire ?? {}) as Record<string, unknown>;
      lines.push(
        `sdk: ${interpreter}: capture ${String(wire.capture ?? "?")}, content ${String(wire.content_capture ?? "-")}, spans to ${String(wire.span_destination ?? "-")}`,
      );
      if (!found.some((f) => f.severity === "error" || f.severity === "warning")) {
        findings.push(new Finding("FC-091", interpreter));
      }
    }
  }
  if (project !== null) {
    const record = lastRun(project);
    if (record !== null) {
      lines.push(
        `last run: ${record.label} (${record.command}, ${record.runtime}), capture ${record.capture}`,
      );
      for (const stored of record.findings) {
        if (!catalogued(stored.id)) continue;
        const finding = new Finding(
          stored.id,
          `last run ${record.label}${stored.detail ? `: ${stored.detail}` : ""}`,
        );
        if (finding.severity === "error" || finding.severity === "warning") findings.push(finding);
      }
      if (record.capture === "on") {
        try {
          const status: unknown = JSON.parse(readFileSync(record.statusPath, "utf-8"));
          if (status && typeof status === "object")
            findings.push(...statusFindings(status as Record<string, unknown>));
        } catch {
          findings.push(new Finding("FC-096", record.label));
        }
      }
    }
    const endpoint = compiled.FABRIC_OTLP_ENDPOINT;
    if ((settings["node.mode"] ?? "docker") === "docker" && !upState(project).node_image) {
      findings.push(new Finding("FC-048"));
      lines.push("node: not started by `fabric up`");
    } else if (endpoint) {
      const answers = await world.nodeAnswers(endpoint, compiled.FABRIC_OTLP_CERTIFICATE);
      lines.push(`node: ${endpoint} ${answers ? "answers" : "does not answer"}`);
      findings.push(answers ? new Finding("FC-095") : new Finding("FC-061", endpoint));
    }
  }
  const problems = findings.filter((f) => f.severity === "error" || f.severity === "warning");
  if (!problems.length) findings.push(new Finding("FC-097"));
  const exitCode = findings.some((f) => f.severity === "error") ? 1 : 0;
  return {
    report: {
      schema: REPORT_SCHEMA,
      command: "doctor",
      cli_version: SDK_VERSION,
      exit_code: exitCode,
      config: { path: located.path, source: located.source },
      findings,
      data: {
        project: project ? (settings.project ?? null) : null,
        problems: problems.length,
        launcher: "npm",
      },
    },
    lines,
  };
}
