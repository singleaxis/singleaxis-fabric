// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * The project as the npm launcher sees it (spec 058 §1.4, §6.2, §6.5): the
 * discovered `fabric.yaml`, and the compiled environment file `fabric init`
 * writes beside it (`.fabric/compiled.env`). The launcher never parses YAML:
 * the compiled file carries every variable `fabric run` gives an agent, the
 * digest of the `fabric.yaml` it came from, and the two settings a launcher
 * needs (`# fabric-setting:` lines).
 */

import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";

export const CONFIG_NAME = "fabric.yaml";
export const CONFIG_ENV = "FABRIC_CONFIG";
export const STATE_DIR = ".fabric";
export const COMPILED_ENV = "compiled.env";
const DIGEST_PREFIX = "# fabric-yaml-sha256: ";
const SETTING_PREFIX = "# fabric-setting: ";

export interface Located {
  path: string | null;
  source: "flag" | "env" | "cwd" | "parent" | "none";
}

function isFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function real(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}

function gitRoot(start: string): string | null {
  let directory = start;
  for (;;) {
    if (existsSync(join(directory, ".git"))) return directory;
    const parent = dirname(directory);
    if (parent === directory) return null;
    directory = parent;
  }
}

/**
 * §6.2 discovery, as the Python CLI does it: `--config PATH`, else
 * `FABRIC_CONFIG`, else `./fabric.yaml`, else the nearest parent directory's,
 * up to the git work-tree root or the home directory.
 */
export function discover(
  flag: string | undefined,
  environ: Record<string, string | undefined>,
  cwd: string,
  home: string = homedir(),
): Located {
  if (flag) return { path: resolve(cwd, flag), source: "flag" };
  const fromEnv = (environ[CONFIG_ENV] ?? "").trim();
  if (fromEnv) return { path: resolve(cwd, fromEnv), source: "env" };
  const here = real(resolve(cwd));
  if (isFile(join(here, CONFIG_NAME))) return { path: join(here, CONFIG_NAME), source: "cwd" };
  const homeDir = real(resolve(home));
  let boundary = gitRoot(here);
  if (boundary === null && (here === homeDir || here.startsWith(homeDir + "/"))) {
    boundary = homeDir;
  }
  if (boundary === null) return { path: null, source: "none" };
  let directory = here;
  for (;;) {
    const parent = dirname(directory);
    if (parent === directory) break;
    directory = parent;
    if (isFile(join(directory, CONFIG_NAME))) {
      return { path: join(directory, CONFIG_NAME), source: "parent" };
    }
    if (directory === boundary) break;
  }
  return { path: null, source: "none" };
}

export interface Compiled {
  /** The sha256 of the fabric.yaml the file came from. */
  digest: string | null;
  /** `# fabric-setting:` lines (`providers.from_environment`, `node.mode`). */
  settings: Record<string, string>;
  /** The variables, in file order. */
  env: Record<string, string>;
}

/** Parse `.fabric/compiled.env`: one `KEY=value` per line, the value is everything after the first `=`. */
export function parseCompiled(text: string): Compiled {
  const out: Compiled = { digest: null, settings: {}, env: {} };
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith(DIGEST_PREFIX)) {
      out.digest = line.slice(DIGEST_PREFIX.length).trim();
    } else if (line.startsWith(SETTING_PREFIX)) {
      const body = line.slice(SETTING_PREFIX.length);
      const at = body.indexOf("=");
      if (at > 0) out.settings[body.slice(0, at).trim()] = body.slice(at + 1).trim();
    } else if (line && !line.startsWith("#") && line.includes("=")) {
      const at = line.indexOf("=");
      out.env[line.slice(0, at)] = line.slice(at + 1);
    }
  }
  return out;
}

export function configDigest(configPath: string): string {
  return createHash("sha256").update(readFileSync(configPath)).digest("hex");
}

export interface Project {
  directory: string;
  configPath: string;
  stateDir: string;
  compiledPath: string;
}

export function projectOf(located: Located): Project | null {
  if (located.path === null) return null;
  const directory = dirname(located.path);
  const stateDir = join(directory, STATE_DIR);
  return {
    directory,
    configPath: located.path,
    stateDir,
    compiledPath: join(stateDir, COMPILED_ENV),
  };
}

export type CompiledState =
  | { state: "current"; compiled: Compiled }
  | { state: "stale"; compiled: Compiled }
  | { state: "missing" }
  | { state: "unreadable"; reason: string };

/** Read the compiled environment and tell whether it came from the current fabric.yaml. */
export function readCompiled(project: Project): CompiledState {
  let text: string;
  try {
    if (lstatSync(project.stateDir).isSymbolicLink()) {
      return { state: "unreadable", reason: `${project.stateDir} is a symlink` };
    }
    text = readFileSync(project.compiledPath, "utf-8");
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return { state: "missing" };
    return { state: "unreadable", reason: code ?? "error" };
  }
  const compiled = parseCompiled(text);
  let digest: string | null;
  try {
    digest = configDigest(project.configPath);
  } catch {
    digest = null;
  }
  return { state: digest !== null && digest === compiled.digest ? "current" : "stale", compiled };
}

export function absolute(directory: string, value: string): string {
  return isAbsolute(value) ? value : join(directory, value);
}
