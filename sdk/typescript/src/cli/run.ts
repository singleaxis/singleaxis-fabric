// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * `fabric run` of the npm launcher (spec 058 §1.4, §5.5): turn on capture for
 * one agent command from `.fabric/compiled.env`, then start it.
 *
 * Passive (I2): the agent's argv, stdin, stdout, stderr, working directory and
 * exit code are its own. The only variables added are `FABRIC_*` and, for a
 * Python agent, the autoload directory first on `PYTHONPATH`; an `OTEL_*`
 * variable is never set, and a variable already set is never overridden. It
 * opens no socket. Messages go to stderr only when stderr is a terminal,
 * otherwise to the run's record under `.fabric/state/runs`.
 *
 * Fail-open (I3): any problem before the agent starts launches it with its
 * environment unchanged and records why.
 *
 * Node.js has no `exec`: the agent is started as a child with the same stdio,
 * SIGTERM and SIGHUP are forwarded, and the launcher exits with the agent's
 * code (or dies by the same signal). The PID differs from a bare run; the
 * Python CLI's `fabric run` keeps it.
 */

import { spawn, spawnSync, type SpawnSyncReturns } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  closeSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeSync,
  accessSync,
  constants,
} from "node:fs";
import { basename, delimiter, join } from "node:path";

import { SDK_VERSION } from "../version";
import { Finding, printable } from "./catalogue";
import { discover, projectOf, readCompiled, type Located, type Project } from "./project";
import { builtin, endpointsValue, fromEnvironment, parseEndpoints } from "./providers";
import { detect, type Runtime } from "./runtime";

export type Environ = Record<string, string | undefined>;

export const RUN_SCHEMA = "fabric.cli-run/v1";
export const LABEL_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
/** The variables the TypeScript SDK's explicit API reads today (before 055 TS-1U). */
export const NODE_VARIABLES = ["FABRIC_TENANT_ID", "FABRIC_AGENT_ID", "FABRIC_RUN_ID"] as const;
const PROBE_TIMEOUT_MS = 15_000;
const MAX_RUNS = 200;
const RECORD_RE = /^([0-9]{1,20})-([A-Za-z0-9][A-Za-z0-9._-]{0,63})\.json$/;
const CGROUP_ROOT = "/sys/fs/cgroup";

/** What `python -I -c` runs to ask an interpreter about its SDK (as the Python CLI asks). */
export const PROBE =
  "import importlib.metadata as m, importlib.util as u, json, os\n" +
  "s = u.find_spec('fabric')\n" +
  "d = list(s.submodule_search_locations or [])[0] if s else None\n" +
  "a = os.path.join(d, '_autoload') if d else None\n" +
  "ok = bool(a and os.path.isfile(os.path.join(a, 'sitecustomize.py')))\n" +
  "try:\n v = m.version('singleaxis-fabric')\n" +
  "except Exception:\n v = None\n" +
  "try:\n o = u.find_spec('opentelemetry.exporter.otlp.proto.http') is not None\n" +
  "except Exception:\n o = False\n" +
  "print(json.dumps({'sdk': ok, 'autoload': a if ok else None, 'sdk_version': v, 'otlp': o}))\n";

export interface ProbeAnswer {
  sdk: boolean;
  autoload: string | null;
  sdk_version: string | null;
  otlp: boolean;
  error?: string;
}

export type Prober = (interpreter: string) => ProbeAnswer;

export function probeInterpreter(interpreter: string): ProbeAnswer {
  let result: SpawnSyncReturns<string>;
  try {
    result = spawnSync(interpreter, ["-I", "-c", PROBE], {
      encoding: "utf-8",
      timeout: PROBE_TIMEOUT_MS,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch {
    return {
      sdk: false,
      autoload: null,
      sdk_version: null,
      otlp: false,
      error: "could not be started",
    };
  }
  if (result.error) {
    const timedOut = (result.error as NodeJS.ErrnoException).code === "ETIMEDOUT";
    return {
      sdk: false,
      autoload: null,
      sdk_version: null,
      otlp: false,
      error: timedOut ? `did not answer in ${PROBE_TIMEOUT_MS / 1000} s` : "could not be started",
    };
  }
  let answer: Record<string, unknown> = {};
  try {
    const lines = (result.stdout ?? "").trim().split("\n");
    const parsed: unknown = result.status === 0 ? JSON.parse(lines[lines.length - 1] ?? "") : {};
    if (parsed && typeof parsed === "object") answer = parsed as Record<string, unknown>;
  } catch {
    answer = {};
  }
  return {
    sdk: answer.sdk === true,
    autoload: typeof answer.autoload === "string" ? answer.autoload : null,
    sdk_version: typeof answer.sdk_version === "string" ? answer.sdk_version : null,
    otlp: answer.otlp === true,
  };
}

function minor(version: string | null): [number, number] | null {
  const match = /^([0-9]+)\.([0-9]+)/.exec(version ?? "");
  return match ? [Number(match[1]), Number(match[2])] : null;
}

/** §11.2: the agent's SDK and this launcher are more than one minor version apart. */
export function versionSkew(sdkVersion: string | null): boolean {
  const ours = minor(SDK_VERSION);
  const theirs = minor(sdkVersion);
  if (ours === null || theirs === null) return false;
  return ours[0] !== theirs[0] || Math.abs(ours[1] - theirs[1]) > 1;
}

export function installLine(interpreter: string | null): string {
  return `${interpreter ?? "python"} -m pip install "singleaxis-fabric[otlp]"`;
}

export interface RunOptions {
  config?: string;
  project?: string;
  runLabel?: string;
  noCapture: boolean;
  quiet: boolean;
}

export interface Plan {
  added: Record<string, string>;
  findings: Finding[];
  capture: boolean;
  runtime: Runtime;
  project: Project | null;
  located: Located | null;
  settings: Record<string, string>;
  prependPythonpath: string | null;
}

function readable(path: string): boolean {
  try {
    accessSync(path, constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Everything before the start that does not write: config, runtime, the
 * interpreter probe, the variables to add. Throws nothing: a problem becomes a
 * finding and capture off.
 */
export function build(
  options: RunOptions,
  command: readonly string[],
  environ: Environ,
  cwd: string,
  prober: Prober = probeInterpreter,
): Plan {
  const plan: Plan = {
    added: {},
    findings: [],
    capture: false,
    runtime: { kind: "other", interpreter: null, detail: null },
    project: null,
    located: null,
    settings: {},
    prependPythonpath: null,
  };
  const located = discover(options.config, environ, cwd);
  plan.located = located;
  const project = projectOf(located);
  const unusable = (first: Finding): Plan => {
    plan.findings.push(
      new Finding(
        "FC-052",
        `${first.id} ${first.entry.text}${first.detail ? ` (${first.detail})` : ""}`,
      ),
    );
    return plan;
  };
  if (project === null) return unusable(new Finding("FC-001"));
  const compiledState = readCompiled(project);
  if (compiledState.state === "missing" || compiledState.state === "unreadable") {
    return unusable(new Finding("FC-060", project.compiledPath));
  }
  const compiled = { ...compiledState.compiled.env };
  plan.settings = compiledState.compiled.settings;
  const named = plan.settings.project;
  if (options.project && named && options.project !== named) {
    return unusable(
      new Finding(
        "FC-032",
        `--project ${options.project}, but ${project.configPath} names ${named}`,
      ),
    );
  }
  for (const name of ["FABRIC_WIRE_ID_KEY_FILE", "FABRIC_OTLP_CERTIFICATE"]) {
    const path = compiled[name];
    if (path && !readable(path)) {
      return unusable(new Finding("FC-031", `${name}: ${path} (run \`fabric init\`)`));
    }
  }
  plan.project = project;
  if (compiledState.state === "stale")
    plan.findings.push(new Finding("FC-060", project.compiledPath));
  const runtime = command.length
    ? detect(command, environ, cwd)
    : { kind: "python" as const, interpreter: null, detail: null };
  plan.runtime = runtime;
  // §8.3: endpoints from the provider clients' base-URL variables.
  if ((plan.settings["providers.from_environment"] ?? "true") !== "false") {
    const custom = parseEndpoints(compiled.FABRIC_WIRE_ENDPOINTS);
    const derived = fromEnvironment(environ, [...builtin(), ...custom]);
    if (derived.length) compiled.FABRIC_WIRE_ENDPOINTS = endpointsValue([...custom, ...derived]);
  }
  if (runtime.kind === "python" && command.length) {
    if (runtime.interpreter === null) {
      plan.findings.push(new Finding("FC-050", runtime.detail ?? (command[0] as string)));
      return plan;
    }
    const answer = prober(runtime.interpreter);
    if (!answer.sdk) {
      const why = answer.error ?? "has no singleaxis-fabric";
      plan.findings.push(
        new Finding(
          "FC-050",
          `${runtime.interpreter} ${why}; install with: ${installLine(runtime.interpreter)}`,
        ),
      );
      return plan;
    }
    if (!answer.otlp) {
      plan.findings.push(
        new Finding("FC-051", `install with: ${installLine(runtime.interpreter)}`),
      );
      return plan;
    }
    if (versionSkew(answer.sdk_version)) {
      plan.findings.push(
        new Finding("FC-049", `agent SDK ${answer.sdk_version}, CLI ${SDK_VERSION}`),
      );
    }
    plan.prependPythonpath = answer.autoload;
  }
  if (runtime.kind === "python") {
    plan.added = { ...compiled, FABRIC_WIRE_AUTOLOAD: "1" };
  } else if (runtime.kind === "node") {
    for (const name of NODE_VARIABLES) {
      const value = compiled[name];
      if (value !== undefined) plan.added[name] = value;
    }
    plan.findings.push(
      new Finding(
        "FC-053",
        "Node.js: zero-code capture is not built yet; the explicit API gets the tenant, agent and run label",
      ),
    );
  } else {
    plan.findings.push(new Finding("FC-053", runtime.detail ?? (command[0] as string)));
  }
  plan.capture = runtime.kind === "python";
  if ((plan.settings["node.mode"] ?? "docker") === "docker" && !upState(project).node_image) {
    plan.findings.push(new Finding("FC-048"));
  }
  return plan;
}

export function upState(project: Project): Record<string, unknown> {
  try {
    const state: unknown = JSON.parse(
      readFileSync(join(project.stateDir, "state", "up.json"), "utf-8"),
    );
    return state && typeof state === "object" && !Array.isArray(state)
      ? (state as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

/**
 * The agent's environment: `environ` plus the plan's variables where unset,
 * and the autoload directory first on `PYTHONPATH`. Returns it and the names
 * a shell variable kept from fabric.yaml (§6.2: named, never their values).
 */
export function childEnvironment(
  environ: Environ,
  added: Record<string, string>,
  prependPythonpath: string | null,
): { env: Record<string, string>; kept: string[] } {
  const env: Record<string, string> = {};
  for (const [name, value] of Object.entries(environ)) {
    if (value !== undefined) env[name] = value;
  }
  const kept: string[] = [];
  for (const [name, value] of Object.entries(added)) {
    if (name.startsWith("OTEL_")) continue; // never (I2)
    // A key the shell gives by value wins over the file fabric.yaml names: the
    // SDK refuses a key set both ways (FW-018).
    if (name.endsWith("_FILE") && env[name.slice(0, -"_FILE".length)]) {
      kept.push(name.slice(0, -"_FILE".length));
      continue;
    }
    if (name in env) {
      if (env[name] !== value) kept.push(name);
      continue;
    }
    env[name] = value;
  }
  const autoload = ["1", "true"].includes((env.FABRIC_WIRE_AUTOLOAD ?? "").trim().toLowerCase());
  if (prependPythonpath && autoload) {
    const existing = env.PYTHONPATH;
    env.PYTHONPATH = prependPythonpath + (existing ? delimiter + existing : "");
  }
  return { env, kept };
}

// ---------------------------------------------------------------- the run record

export function newLabel(now: Date = new Date()): string {
  const pad = (n: number): string => String(n).padStart(2, "0");
  const stamp =
    `${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}-` +
    `${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}`;
  return `run-${stamp}-${randomBytes(2).toString("hex")}`;
}

export function nowNs(): bigint {
  return BigInt(Math.round((performance.timeOrigin + performance.now()) * 1e6));
}

export interface RunRecord {
  label: string;
  startedNs: bigint;
  command: string;
  runtime: string;
  capture: "on" | "off";
  project: string | null;
  interpreter: string | null;
  sensor: "scoped" | "not_scoped" | "off";
  findings: Array<{ id: string; detail?: string }>;
}

function isoMs(ns: bigint): string {
  return new Date(Number(ns / 1_000_000n)).toISOString();
}

export function recordJson(record: RunRecord): Record<string, unknown> {
  return {
    schema: RUN_SCHEMA,
    label: record.label,
    started_ns: Number(record.startedNs),
    started_at: isoMs(record.startedNs),
    command: record.command,
    runtime: record.runtime,
    capture: record.capture,
    project: record.project,
    interpreter: record.interpreter,
    sensor: record.sensor,
    findings: record.findings,
  };
}

/** `.fabric/state/runs` (0700); a symlink on the way is refused. */
export function ensureRunsDir(stateDir: string): string {
  let directory = stateDir;
  for (const part of ["state", "runs"]) {
    refuseSymlink(directory);
    mkdirIfMissing(directory);
    directory = join(directory, part);
  }
  refuseSymlink(directory);
  mkdirIfMissing(directory);
  return directory;
}

function refuseSymlink(path: string): void {
  try {
    if (lstatSync(path).isSymbolicLink()) throw new Error(`${path} is a symlink`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

function mkdirIfMissing(path: string): void {
  try {
    mkdirSync(path, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }
}

function sortedJson(value: unknown, indent = ""): string {
  // Python's json.dumps(indent=2, sort_keys=True), for the record's plain values.
  const next = indent + "  ";
  if (Array.isArray(value)) {
    if (!value.length) return "[]";
    return `[\n${value.map((v) => next + sortedJson(v, next)).join(",\n")}\n${indent}]`;
  }
  if (value && typeof value === "object") {
    const keys = Object.keys(value).sort();
    if (!keys.length) return "{}";
    return `{\n${keys
      .map(
        (k) =>
          `${next}${JSON.stringify(k)}: ${sortedJson((value as Record<string, unknown>)[k], next)}`,
      )
      .join(",\n")}\n${indent}}`;
  }
  return JSON.stringify(value) ?? "null";
}

export function statusFile(runsDir: string, record: RunRecord): string {
  return join(runsDir, `${record.startedNs}-${record.label}.status.json`);
}

/** Write the run record atomically (0600, never through a symlink) and prune old ones. */
export function saveRecord(record: RunRecord, stateDir: string): string {
  const runs = ensureRunsDir(stateDir);
  const path = join(runs, `${record.startedNs}-${record.label}.json`);
  const temporary = join(
    runs,
    `.${basename(path)}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`,
  );
  const fd = openSync(
    temporary,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  try {
    writeSync(fd, `${sortedJson(recordJson(record))}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(temporary, path);
  try {
    prune(runs);
  } catch {
    // best effort
  }
  return path;
}

function prune(runs: string): void {
  const records = readdirSync(runs)
    .map((name) => RECORD_RE.exec(name))
    .filter((m): m is RegExpExecArray => m !== null)
    .sort((a, b) => (BigInt(a[1] as string) < BigInt(b[1] as string) ? -1 : 1));
  for (const match of records.slice(0, Math.max(0, records.length - MAX_RUNS))) {
    rmSync(join(runs, match[0]), { force: true });
    rmSync(join(runs, match[0].replace(/\.json$/, ".status.json")), { force: true });
  }
}

// ---------------------------------------------------------------- the agent cgroup (OQ-14)

/** The project name: fabric.yaml's (from the compiled file), else the directory's. */
export function projectName(project: Project, settings: Record<string, string>): string {
  const named = (settings.project ?? "").trim();
  if (named) return named;
  const derived = basename(project.directory)
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63);
  return derived || "fabric";
}

/** Join the cgroup `fabric up` created for the host sensor (Linux, sensor running). */
export function joinAgentCgroup(
  project: Project,
  name: string,
): { sensor: RunRecord["sensor"]; finding: Finding | null } {
  const state = upState(project);
  if (state.sensor !== "running") return { sensor: "off", finding: null };
  if (state.sensor_cgroup_created === "vm" || process.platform !== "linux") {
    return {
      sensor: "not_scoped",
      finding: new Finding("FC-042", "the agent runs on this machine, the sensor in the Docker VM"),
    };
  }
  const cgroup = String(state.sensor_cgroup ?? "");
  if (
    cgroup.split("/").includes("..") ||
    !cgroup.startsWith(`${CGROUP_ROOT}/`) ||
    !cgroup.endsWith(`/fabric.slice/agent-${name}`)
  ) {
    return { sensor: "off", finding: null };
  }
  try {
    const fd = openSync(join(cgroup, "cgroup.procs"), "w");
    try {
      writeSync(fd, `${process.pid}\n`);
    } finally {
      closeSync(fd);
    }
  } catch (error) {
    return {
      sensor: "not_scoped",
      finding: new Finding(
        "FC-054",
        `${cgroup}: ${(error as NodeJS.ErrnoException).code ?? "error"}`,
      ),
    };
  }
  return { sensor: "scoped", finding: null };
}

// ---------------------------------------------------------------- preparing and launching

export interface Prepared {
  env: Record<string, string>;
  findings: Finding[];
}

/**
 * Build the plan, record the run, join the cgroup. The environment is changed
 * only when the run is recorded; every failure leaves it as it was.
 */
export function prepare(
  options: RunOptions,
  command: readonly string[],
  environ: Environ,
  cwd: string,
  prober: Prober = probeInterpreter,
  now: () => bigint = nowNs,
): Prepared {
  const unchanged = (): Record<string, string> =>
    Object.fromEntries(
      Object.entries(environ).filter((e): e is [string, string] => e[1] !== undefined),
    );
  const startedNs = now();
  const findings: Finding[] = [];
  let label = options.runLabel;
  if (label !== undefined && !LABEL_RE.test(label)) {
    findings.push(new Finding("FC-059", "letters, digits and ._-, at most 64"));
    label = undefined;
  }
  label = label ?? newLabel();
  let plan: Plan;
  if (options.noCapture) {
    findings.push(new Finding("FC-058"));
    const located = discover(options.config, environ, cwd);
    plan = {
      added: {},
      findings: [],
      capture: false,
      runtime: { kind: "other", interpreter: null, detail: null },
      project: projectOf(located),
      located,
      settings: {},
      prependPythonpath: null,
    };
  } else {
    plan = build(options, command, environ, cwd, prober);
    findings.push(...plan.findings);
  }
  const project = plan.project;
  if (project === null) return { env: unchanged(), findings };
  const compiledState = readCompiled(project);
  const settings =
    compiledState.state === "current" || compiledState.state === "stale"
      ? compiledState.compiled.settings
      : {};
  const name = projectName(project, settings);
  const record: RunRecord = {
    label,
    startedNs,
    command: basename(command[0] as string),
    runtime: plan.runtime.kind,
    capture: "off",
    project: name,
    interpreter: plan.runtime.interpreter,
    sensor: "off",
    findings: [],
  };
  let capture =
    plan.capture &&
    !options.noCapture &&
    !plan.findings.some((f) => ["FC-050", "FC-051", "FC-052"].includes(f.id));
  let runs: string;
  try {
    runs = ensureRunsDir(project.stateDir);
  } catch (error) {
    findings.push(new Finding("FC-057", (error as NodeJS.ErrnoException).code ?? "Error"));
    return { env: unchanged(), findings };
  }
  if (
    capture ||
    (!options.noCapture && (plan.runtime.kind === "node" || plan.runtime.kind === "other"))
  ) {
    plan.added.FABRIC_RUN_ID = label;
  }
  if (capture) plan.added.FABRIC_WIRE_STATUS_FILE = statusFile(runs, record);
  let env = unchanged();
  if (Object.keys(plan.added).length) {
    const child = childEnvironment(environ, plan.added, plan.prependPythonpath);
    env = child.env;
    for (const kept of child.kept)
      findings.push(new Finding("FC-009", `${kept} kept from this shell`));
  }
  if (capture && !["1", "true"].includes((env.FABRIC_WIRE_AUTOLOAD ?? "").trim().toLowerCase())) {
    capture = false;
  }
  if (
    !options.noCapture &&
    (process.platform === "linux" || upState(project).sensor === "running")
  ) {
    const joined = joinAgentCgroup(project, name);
    record.sensor = joined.sensor;
    if (joined.finding) findings.push(joined.finding);
  }
  record.capture = capture ? "on" : "off";
  record.findings = findings.map((f) => (f.detail ? { id: f.id, detail: f.detail } : { id: f.id }));
  try {
    saveRecord(record, project.stateDir);
  } catch (error) {
    findings.push(new Finding("FC-057", (error as NodeJS.ErrnoException).code ?? "Error"));
    return { env: unchanged(), findings };
  }
  return { env, findings };
}

/** Messages reach stderr only when it is a terminal (I2). */
export function say(findings: readonly Finding[], quiet: boolean): void {
  try {
    if (!process.stderr.isTTY) return;
    for (const finding of findings) {
      if (quiet && finding.severity !== "error") continue;
      process.stderr.write(`fabric run: ${printable(finding.line())}\n`);
    }
  } catch {
    // a message never stops the agent (I3)
  }
}

/** Start the agent with `env`; resolve with the launcher's exit code (the agent's). */
export function start(command: readonly string[], env: Record<string, string>): Promise<number> {
  return new Promise((resolveExit) => {
    let child;
    try {
      child = spawn(command[0] as string, command.slice(1), { stdio: "inherit", env });
    } catch (error) {
      resolveExit(notStarted(command, error as NodeJS.ErrnoException));
      return;
    }
    const forward = (signal: NodeJS.Signals) => () => {
      try {
        child.kill(signal);
      } catch {
        // the agent is gone
      }
    };
    // A terminal's Ctrl-C and Ctrl-\ already reach the agent (same process
    // group): the launcher only waits. SIGTERM and SIGHUP are forwarded.
    const handlers: Array<[NodeJS.Signals, () => void]> = [
      ["SIGINT", () => undefined],
      ["SIGQUIT", () => undefined],
      ["SIGTERM", forward("SIGTERM")],
      ["SIGHUP", forward("SIGHUP")],
    ];
    for (const [signal, handler] of handlers) process.on(signal, handler);
    const cleanup = (): void => {
      for (const [signal, handler] of handlers) process.removeListener(signal, handler);
    };
    child.on("error", (error: NodeJS.ErrnoException) => {
      cleanup();
      resolveExit(notStarted(command, error));
    });
    child.on("exit", (code, signal) => {
      cleanup();
      if (signal) {
        // Die by the same signal, as a shell reports the agent's own end.
        try {
          process.kill(process.pid, signal);
        } catch {
          // fall through to the shell convention
        }
        resolveExit(128 + (signalNumber(signal) ?? 0));
        return;
      }
      resolveExit(code ?? 0);
    });
  });
}

function signalNumber(signal: NodeJS.Signals): number | undefined {
  const numbers: Partial<Record<NodeJS.Signals, number>> = {
    SIGHUP: 1,
    SIGINT: 2,
    SIGQUIT: 3,
    SIGKILL: 9,
    SIGTERM: 15,
    SIGPIPE: 13,
    SIGABRT: 6,
    SIGSEGV: 11,
  };
  return numbers[signal];
}

function notStarted(command: readonly string[], error: NodeJS.ErrnoException): number {
  const missing = error.code === "ENOENT";
  const why = missing ? "command not found" : (error.code ?? "error");
  try {
    process.stderr.write(`fabric run: ${command[0]}: ${why} [FC-055]\n`);
  } catch {
    // nothing else to do
  }
  return missing ? 127 : 126;
}

/** `fabric run -- CMD`: prepare (fail-open), record, start. */
export async function launch(
  options: RunOptions,
  command: readonly string[],
  environ: Environ,
  cwd: string,
): Promise<number> {
  if (!command.length) {
    try {
      process.stderr.write(`fabric run: ${new Finding("FC-056").line()}\n`);
    } catch {
      // nothing else to do
    }
    return 2;
  }
  let prepared: Prepared;
  try {
    prepared = prepare(options, command, environ, cwd);
  } catch (error) {
    prepared = {
      env: Object.fromEntries(
        Object.entries(environ).filter((e): e is [string, string] => e[1] !== undefined),
      ),
      findings: [new Finding("FC-052", `internal error (${(error as Error).name})`)],
    };
  }
  say(prepared.findings, options.quiet);
  return start(command, prepared.env);
}
