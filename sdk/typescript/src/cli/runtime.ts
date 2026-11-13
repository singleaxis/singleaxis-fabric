// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * What an agent command runs (spec 058 §5.5 step 2), detected as the Python
 * CLI's `fabric run` does: by the command's name, a `uv run`-style runner, or
 * the first 256 bytes of the script's `#!` line. Never runs the command.
 */

import {
  accessSync,
  closeSync,
  constants,
  existsSync,
  openSync,
  readSync,
  statSync,
} from "node:fs";
import { basename, delimiter, isAbsolute, join, sep } from "node:path";

export type RuntimeKind = "python" | "node" | "other";

export interface Runtime {
  kind: RuntimeKind;
  interpreter: string | null;
  detail: string | null;
}

const PYTHON_RE = /^(python|pypy)([0-9]+(\.[0-9]+)*)?t?(\.exe)?$/i;
const NODE_NAMES = new Set(["node", "node.exe", "nodejs", "npx", "tsx", "ts-node"]);
const OTHER_JS = new Set(["bun", "deno"]);
const RUNNERS = new Set(["uv", "poetry", "pipenv", "pdm", "hatch"]);

function rt(
  kind: RuntimeKind,
  interpreter: string | null = null,
  detail: string | null = null,
): Runtime {
  return { kind, interpreter, detail };
}

/** `name` on `PATH` (or relative to `cwd` when it holds a separator). */
export function which(
  name: string,
  environ: Record<string, string | undefined>,
  cwd: string,
): string | null {
  if (name.includes(sep) || name.includes("/")) {
    const path = isAbsolute(name) ? name : join(cwd, name);
    return existsSync(path) ? path : null;
  }
  for (const directory of (environ.PATH ?? "").split(delimiter)) {
    if (!directory) continue;
    const candidate = join(directory, name);
    try {
      if (statSync(candidate).isFile()) {
        accessSync(candidate, constants.X_OK);
        return candidate;
      }
    } catch {
      // not here
    }
  }
  return null;
}

function shebang(path: string): string[] {
  let fd: number | undefined;
  try {
    fd = openSync(path, "r");
    const buffer = Buffer.alloc(256);
    const read = readSync(fd, buffer, 0, 256, 0);
    const head = buffer.subarray(0, read);
    if (head[0] !== 0x23 || head[1] !== 0x21) return [];
    const first = head.subarray(2).toString("utf-8").split("\n", 1)[0] ?? "";
    let words = first.split(/\s+/).filter(Boolean);
    if (words.length && basename(words[0] as string) === "env") {
      words = words.slice(1).filter((w) => !w.startsWith("-") && !w.includes("="));
    }
    return words;
  } catch {
    return [];
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function venvPython(directory: string): string | null {
  for (const candidate of [
    join(directory, "bin", "python"),
    join(directory, "Scripts", "python.exe"),
  ]) {
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

function runner(
  command: readonly string[],
  environ: Record<string, string | undefined>,
  cwd: string,
): Runtime {
  const name = basename(command[0] as string);
  const rest = command.slice(2).filter((word) => !word.startsWith("-"));
  let venv = join(cwd, ".venv");
  const custom = (environ.UV_PROJECT_ENVIRONMENT ?? "").trim();
  if (name === "uv" && custom) venv = isAbsolute(custom) ? custom : join(cwd, custom);
  const interpreter = venvPython(venv);
  const target = rest[0] ?? "";
  if (target && NODE_NAMES.has(basename(target))) return rt("node");
  const pythonish =
    !target ||
    PYTHON_RE.test(basename(target)) ||
    target.endsWith(".py") ||
    existsSync(join(venv, "bin", target)) ||
    existsSync(join(venv, "Scripts", `${target}.exe`));
  if (!pythonish) return rt("other", null, `\`${name} run ${target}\` is not a Python program`);
  if (interpreter === null) {
    return rt(
      "other",
      null,
      `could not tell which interpreter \`${name} run\` uses (no ${venv}); run that interpreter directly`,
    );
  }
  return rt("python", interpreter);
}

export function detect(
  command: readonly string[],
  environ: Record<string, string | undefined>,
  cwd: string,
): Runtime {
  const first = command[0] as string;
  const name = basename(first);
  if (PYTHON_RE.test(name)) {
    const found = which(first, environ, cwd);
    return rt("python", found, found ? null : `${first} not found`);
  }
  if (RUNNERS.has(name) && command.length > 1 && command[1] === "run") {
    return runner(command, environ, cwd);
  }
  if (NODE_NAMES.has(name)) return rt("node");
  if (OTHER_JS.has(name))
    return rt("other", null, `${name} is a JavaScript runtime Fabric does not capture`);
  const path = which(first, environ, cwd);
  let words: string[] = [];
  try {
    if (path !== null && statSync(path).isFile()) words = shebang(path);
  } catch {
    words = [];
  }
  if (words.length && PYTHON_RE.test(basename(words[0] as string))) {
    const word = words[0] as string;
    return rt("python", isAbsolute(word) ? word : which(word, environ, cwd));
  }
  if (words.length && NODE_NAMES.has(basename(words[0] as string))) return rt("node");
  return rt("other", null, `${name} is not a Python or Node.js program`);
}
