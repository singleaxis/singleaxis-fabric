// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * The npm launcher `fabric` (spec 058 §1.4, §11.1): `run` and `doctor` for
 * machines without Python, reading the `.fabric/compiled.env` that
 * `fabric init` writes. The other commands of the operator CLI live in the
 * Python distribution (`pipx install "singleaxis-fabric[cli]"`) and in the
 * `ghcr.io/singleaxis/fabric-cli` image; here they say so (`FC-098`).
 *
 * The launcher runs outside the agent: the SDK entry point never imports it.
 */

import { SDK_VERSION } from "../version";
import { Finding, printable } from "./catalogue";
import { doctor, type DoctorWorld } from "./doctor";
import { launch, start, type Environ, type RunOptions } from "./run";

export const COMMANDS = [
  "plan",
  "init",
  "up",
  "down",
  "run",
  "verify",
  "doctor",
  "show",
  "version",
  "help",
] as const;
export const LAUNCHER_COMMANDS = ["run", "doctor", "version", "help"] as const;

const USAGE = `usage: fabric COMMAND [OPTIONS]

The npm launcher of the SingleAxis Fabric operator CLI.

commands:
  run       run an agent command with capture on: fabric run -- node agent.js
  doctor    check this machine and project for setup problems
  version   print the launcher and SDK version
  help      show this help

plan, init, up, down, verify and show are in the full CLI:
  pipx install "singleaxis-fabric[cli]"
  or the image ghcr.io/singleaxis/fabric-cli:${SDK_VERSION}

options on every command: --config PATH, --project NAME, --json, --quiet, --no-color
`;

interface Common {
  config?: string;
  project?: string;
  json: boolean;
  quiet: boolean;
}

class UsageError extends Error {}

/** Parse the options before `--` (run) or all of them (doctor). */
function parse(
  args: readonly string[],
  allowed: ReadonlySet<string>,
): { common: Common; flags: Map<string, string | true>; rest: string[] } {
  const common: Common = { json: false, quiet: false };
  const flags = new Map<string, string | true>();
  const withValue = new Set(["--config", "--project", "--run"]);
  let index = 0;
  for (; index < args.length; index += 1) {
    const arg = args[index] as string;
    if (arg === "--") {
      index += 1;
      break;
    }
    if (!arg.startsWith("--")) break;
    const [name, inline] = arg.includes("=")
      ? [arg.slice(0, arg.indexOf("=")), arg.slice(arg.indexOf("=") + 1)]
      : [arg, undefined];
    if (!allowed.has(name)) throw new UsageError(`unrecognized argument: ${name}`);
    if (withValue.has(name)) {
      const value = inline ?? args[(index += 1)];
      if (value === undefined) throw new UsageError(`${name} needs a value`);
      if (name === "--config") common.config = value;
      else if (name === "--project") common.project = value;
      else flags.set(name, value);
    } else if (name === "--json") common.json = true;
    else if (name === "--quiet") common.quiet = true;
    else flags.set(name, true);
  }
  return { common, flags, rest: args.slice(index) };
}

const COMMON_FLAGS = ["--config", "--project", "--json", "--quiet", "--no-color"];
const RUN_FLAGS = new Set([...COMMON_FLAGS, "--run", "--exec", "--no-exec", "--no-capture"]);
const DOCTOR_FLAGS = new Set([...COMMON_FLAGS]);

function write(stream: NodeJS.WriteStream, text: string): void {
  try {
    stream.write(text);
  } catch {
    // nothing else to do
  }
}

/** Run the launcher; resolves with the process exit code. */
export async function main(
  argv: readonly string[],
  environ: Environ = process.env,
  cwd: string = process.cwd(),
  world?: DoctorWorld,
): Promise<number> {
  const [command, ...args] = argv;
  if (command === undefined || command === "help" || command === "--help" || command === "-h") {
    write(process.stdout, USAGE);
    return command === undefined ? 2 : 0;
  }
  if (command === "version" || command === "--version") {
    write(process.stdout, `fabric ${SDK_VERSION} (npm launcher: run and doctor)\n`);
    return 0;
  }
  if (command === "run") return runCommand(args, environ, cwd);
  if (command === "doctor") return doctorCommand(args, environ, cwd, world);
  if ((COMMANDS as readonly string[]).includes(command)) {
    const finding = new Finding("FC-098", `fabric ${command}`);
    write(process.stderr, `${printable(finding.line()).replace("VERSION", SDK_VERSION)}\n`);
    return 2;
  }
  write(process.stderr, `${new Finding("FC-006", `unknown command ${command}`).line()}\n`);
  write(process.stderr, USAGE);
  return 2;
}

async function runCommand(args: readonly string[], environ: Environ, cwd: string): Promise<number> {
  const separator = args.indexOf("--");
  let parsed;
  try {
    parsed = parse(args, RUN_FLAGS);
  } catch (error) {
    // A mistyped flag never stops the agent (I3): it runs with its environment unchanged.
    if (separator >= 0 && separator < args.length - 1) {
      if (process.stderr.isTTY) {
        write(
          process.stderr,
          `fabric run: ${new Finding("FC-006", (error as Error).message).line()}\n`,
        );
      }
      const unchanged = Object.fromEntries(
        Object.entries(environ).filter((e): e is [string, string] => e[1] !== undefined),
      );
      return start(args.slice(separator + 1), unchanged);
    }
    write(process.stderr, `${new Finding("FC-006", (error as Error).message).line()}\n`);
    return 2;
  }
  const { common, flags, rest } = parsed;
  const options: RunOptions = {
    config: common.config,
    project: common.project,
    runLabel: typeof flags.get("--run") === "string" ? (flags.get("--run") as string) : undefined,
    noCapture: flags.has("--no-capture"),
    quiet: common.quiet,
  };
  return launch(options, rest, environ, cwd);
}

async function doctorCommand(
  args: readonly string[],
  environ: Environ,
  cwd: string,
  world?: DoctorWorld,
): Promise<number> {
  let parsed;
  try {
    parsed = parse(args, DOCTOR_FLAGS);
  } catch (error) {
    write(process.stderr, `${new Finding("FC-006", (error as Error).message).line()}\n`);
    return 2;
  }
  if (parsed.rest.length) {
    write(
      process.stderr,
      `${new Finding("FC-006", `unexpected argument ${parsed.rest[0]}`).line()}\n`,
    );
    return 2;
  }
  const { report, lines } = await doctor({ config: parsed.common.config }, environ, cwd, world);
  if (parsed.common.json) {
    write(
      process.stdout,
      `${JSON.stringify(sortKeys({ ...report, findings: report.findings.map((f) => f.toJSON()) }))}\n`,
    );
    return report.exit_code;
  }
  if (!parsed.common.quiet) for (const line of lines) write(process.stdout, `${printable(line)}\n`);
  for (const finding of report.findings) {
    if (parsed.common.quiet && finding.severity !== "error") continue;
    write(
      finding.severity === "error" ? process.stderr : process.stdout,
      `${printable(finding.line())}\n`,
    );
  }
  return report.exit_code;
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortKeys((value as Record<string, unknown>)[key])]),
    );
  }
  return value;
}
