// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * The full CLI from the npm launcher (spec 058 §1.4): on a machine without
 * Python, `npx fabric plan|init|up|down|verify|show` runs the same command in
 * the `ghcr.io/singleaxis/fabric-cli` image of this release, with Docker. It
 * is the image route §1.4 names for Node.js-only users, done for them:
 *
 * - the project directory (the nearest one holding `fabric.yaml`, else this
 *   directory) and the CLI's state home are mounted at the same paths, so the
 *   paths the CLI writes into `.fabric/compiled.env` and gives Docker are the
 *   host's (the npm `fabric run` reads that file);
 * - the command runs as this user (`--user`), so every file it writes is
 *   yours, with the Docker socket's group so it can start the Node;
 * - the host network, so `up`'s health check and `verify`'s canary reach the
 *   Node on loopback, as they do from the Python CLI;
 * - `FABRIC_*` and the standard model base-URL variables are passed by name
 *   (`-e NAME`): their values never appear on a command line.
 *
 * Nothing else is sent anywhere; Docker pulls the pinned image once. Without
 * Docker the launcher says where the full CLI is (`FC-098`).
 */

import { mkdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";

import { SDK_VERSION } from "../version";

/** Commands the npm launcher runs from the image. */
export const IMAGE_COMMANDS = ["plan", "init", "up", "down", "verify", "show"] as const;
/** Override of the image reference (a mirror, or a build under test). */
export const IMAGE_ENV = "FABRIC_CLI_IMAGE";
const DEFAULT_SOCKET = "/var/run/docker.sock";
/** The model base-URL variables `plan` and `init` read by name (spec 058 §8.3). */
const PASSED = [
  "OPENAI_BASE_URL",
  "OPENAI_API_BASE",
  "ANTHROPIC_BASE_URL",
  "AZURE_OPENAI_ENDPOINT",
  "AWS_ENDPOINT_URL_S3",
];

export type Environ = Record<string, string | undefined>;

/** What the command line depends on, read from this machine (a seam for tests). */
export interface Host {
  uid: number | null;
  gid: number | null;
  /** The group of the Docker socket, when it is a local socket. */
  socketGid: number | null;
  stdinTty: boolean;
  stdoutTty: boolean;
}

export function imageRef(env: Environ): string {
  const override = (env[IMAGE_ENV] ?? "").trim();
  return override !== "" ? override : `ghcr.io/singleaxis/fabric-cli:${SDK_VERSION}`;
}

/** The state home the Python CLI uses for secrets (`$XDG_STATE_HOME`, else ~/.local/state). */
export function stateHome(env: Environ): string {
  const value = (env.XDG_STATE_HOME ?? "").trim();
  if (value !== "" && isAbsolute(value)) return value;
  return join(env.HOME?.trim() || homedir(), ".local", "state");
}

function exists(path: string): boolean {
  try {
    statSync(path);
    return true;
  } catch {
    return false;
  }
}

/** The project directory: `--config`'s or `FABRIC_CONFIG`'s, else the nearest one with a
 * `fabric.yaml`, up to the git work tree's root or the home directory; else `cwd`. */
export function projectRoot(cwd: string, env: Environ, config?: string): string {
  const named = config ?? env.FABRIC_CONFIG?.trim();
  if (named) return dirname(resolve(cwd, named));
  const home = resolve(env.HOME?.trim() || homedir());
  let dir = resolve(cwd);
  for (;;) {
    if (exists(join(dir, "fabric.yaml"))) return dir;
    if (exists(join(dir, ".git")) || dir === home) break;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return resolve(cwd);
}

/** The local Docker socket (`DOCKER_HOST=unix://...`, else the default), or null for a
 * remote daemon (then `DOCKER_HOST` is passed through and nothing is mounted). */
export function dockerSocket(env: Environ): string | null {
  const host = (env.DOCKER_HOST ?? "").trim();
  if (host === "") return DEFAULT_SOCKET;
  return host.startsWith("unix://") ? host.slice("unix://".length) : null;
}

/** The `docker run` arguments (after `docker`) for `fabric COMMAND ARGS` in the image. */
export function imageArgs(
  command: string,
  args: readonly string[],
  env: Environ,
  cwd: string,
  host: Host,
  config?: string,
): string[] {
  const root = projectRoot(cwd, env, config);
  const state = join(stateHome(env), "fabric");
  const out = ["run", "--rm"];
  if (host.stdinTty) out.push("-i");
  if (host.stdinTty && host.stdoutTty) out.push("-t");
  out.push("--network", "host");
  if (host.uid !== null && host.gid !== null) out.push("--user", `${host.uid}:${host.gid}`);
  const socket = dockerSocket(env);
  if (socket !== null) {
    out.push("-v", `${socket}:${DEFAULT_SOCKET}`);
    if (host.socketGid !== null && host.socketGid !== host.gid) {
      out.push("--group-add", String(host.socketGid));
    }
  } else {
    out.push("-e", "DOCKER_HOST");
  }
  out.push("-v", `${root}:${root}`, "-w", resolve(cwd));
  out.push("-v", `${state}:${state}`, "-e", `XDG_STATE_HOME=${stateHome(env)}`);
  out.push("-e", "HOME=/tmp");
  const names = Object.keys(env)
    .filter((name) => env[name] !== undefined)
    .filter((name) => name.startsWith("FABRIC_") || PASSED.includes(name))
    .filter((name) => name !== IMAGE_ENV)
    .sort();
  for (const name of names) out.push("-e", name);
  out.push(imageRef(env), command, ...args);
  return out;
}

/** Whether `docker` is on PATH. */
export function dockerOnPath(env: Environ): boolean {
  for (const dir of (env.PATH ?? "").split(delimiter)) {
    if (dir !== "" && exists(join(dir, "docker"))) return true;
  }
  return false;
}

/** This machine's answers for {@link imageArgs}. */
export function thisHost(env: Environ): Host {
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  const gid = typeof process.getgid === "function" ? process.getgid() : null;
  let socketGid: number | null = null;
  const socket = dockerSocket(env);
  if (socket !== null) {
    try {
      socketGid = statSync(socket).gid;
    } catch {
      socketGid = null;
    }
  }
  return {
    uid,
    gid,
    socketGid,
    stdinTty: Boolean(process.stdin.isTTY),
    stdoutTty: Boolean(process.stdout.isTTY),
  };
}

/** Create the state directory as this user (0700) before Docker would create it as root. */
export function prepareState(env: Environ): void {
  try {
    mkdirSync(join(stateHome(env), "fabric"), { recursive: true, mode: 0o700 });
  } catch {
    // The CLI in the image reports a state directory it cannot use, with its fix.
  }
}
