#!/usr/bin/env node
// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Builds, tests and digests the prebuilt Node-API lock module (spec 055 §4.4) for the six
// targets. Maintainers and CI only: nothing here runs at install or startup, and no
// binary is committed. The packaging unit copies the built files into the npm tarball.
//
//   prebuild.mjs build   --target <t> [--out <dir>]   compile release + fault variants, run the C tests
//   prebuild.mjs test    --target <t> [--out <dir>]   run test/wire/native against the built files
//   prebuild.mjs digests [--out <dir>] --check        the built files match the committed table
//   prebuild.mjs digests [--out <dir>] --write        rewrite the table from the built files
//   prebuild.mjs digests --require-all                (with --check) all six targets must be built
//
// Linux targets compile inside build images pinned by digest (gcc on Debian 10 for
// glibc 2.28, gcc on Alpine for musl), under QEMU when the host CPU differs, so the
// bytes are the same on every machine. macOS targets compile on the host's Xcode;
// the workflow pins the Xcode version. The default --out is sdk/typescript/prebuilds-build
// (git-ignored).
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..", "..");
const TS = join(REPO, "sdk", "typescript");
const TABLE = join(TS, "src", "wire", "native-digests.generated.ts");
const FILE = "fabric_wire.node";
const IMAGE_PREFIX = process.env.FABRIC_PREBUILD_IMAGE_PREFIX ?? "fabric-wire-prebuild";

// Per-platform image digests (an index digest cannot be pulled for two platforms on one
// machine). A change here changes the built bytes: rebuild and commit the digest table.
const GCC_BUSTER = {
  amd64: "gcc@sha256:e4462dd30f5c325a1045f36ed5e5f5dd1791358445f4414276e5d711e92e20c8",
  arm64: "gcc@sha256:d74acd6b586c6d40628b7fe0b2072e298c6dc5cf1c8c64dde51803f8b3d1b165",
};
const ALPINE = {
  amd64: "alpine@sha256:9db2934886712d877c932e07249c75a59e6ca27adfbccc05261987a17bef2d63",
  arm64: "alpine@sha256:e233f2058b0628266762f745a2c17e623b418e0090f47d223909d1f9a7d4367e",
};
const ALPINE_BUILD_PACKAGES = "gcc=14.2.0-r6 musl-dev=1.2.5-r13 binutils=2.44-r3";
const NODE_BOOKWORM = {
  amd64: "node@sha256:aca79828f8a4afc627f189387c965625bcc419233946210a3b9522d90a59b5c6",
  arm64: "node@sha256:9e7ec64106f43779ecb669cb299cce07a033ac6c41603c1039dea7b51119e550",
};
const NODE_ALPINE = {
  amd64: "node@sha256:d8d97e479cdc64f052f81f129362168717c59783ade8dcc1abd22e1cca8dbd7c",
  arm64: "node@sha256:f44b069ce4b5d00cb4f7dff81821a4a6953e3790420040abf300139b1d317c6c",
};

// The containers' scratch space is memory, not the image layer, so a build or test never
// depends on free space in the container runtime's disk.
const SCRATCH = ["--tmpfs", "/tmp:rw,exec,size=1536m"];

const TARGETS = {
  "linux-x64-glibc": { os: "linux", docker: "amd64", libc: "glibc" },
  "linux-arm64-glibc": { os: "linux", docker: "arm64", libc: "glibc" },
  "linux-x64-musl": { os: "linux", docker: "amd64", libc: "musl" },
  "linux-arm64-musl": { os: "linux", docker: "arm64", libc: "musl" },
  "darwin-x64": { os: "darwin", arch: "x64" },
  "darwin-arm64": { os: "darwin", arch: "arm64" },
};

function fail(message) {
  process.stderr.write(`prebuild.mjs: ${message}\n`);
  process.exit(1);
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { stdio: "inherit", ...options });
  if (result.error?.code === "ENOENT") {
    fail(`'${command}' is not installed or not on PATH; install it and run this again`);
  }
  if (result.status !== 0) {
    fail(`'${command} ${args.slice(0, 3).join(" ")} ...' failed (exit ${result.status ?? result.signal})`);
  }
}

function parse(argv) {
  const options = { command: argv[0], out: join(TS, "prebuilds-build") };
  for (let i = 1; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--target") options.target = argv[++i];
    else if (flag === "--out") options.out = resolve(argv[++i] ?? "");
    else if (flag === "--check" || flag === "--write") options.mode = flag.slice(2);
    else if (flag === "--require-all") options.requireAll = true;
    else fail(`unknown option '${flag}'; see the usage at the top of this file`);
  }
  return options;
}

function targetOf(options) {
  const target = TARGETS[options.target];
  if (target === undefined) {
    fail(`--target must be one of: ${Object.keys(TARGETS).join(", ")}`);
  }
  return target;
}

function requireHeaders() {
  if (!existsSync(join(TS, "node_modules", "node-api-headers", "include", "node_api.h"))) {
    fail("the pinned Node-API headers are missing; run 'npm ci' in sdk/typescript first");
  }
}

/** A derived image: the pinned base plus pinned packages. Returns its tag. */
function derivedImage(name, base, platform, packages) {
  const tag = `${IMAGE_PREFIX}-${name}:${platform}`;
  const dockerfile = `FROM ${base}\nRUN apk add --no-cache ${packages}\n`;
  run("docker", ["build", "--platform", `linux/${platform}`, "-t", tag, "-"], {
    input: dockerfile,
    stdio: ["pipe", "inherit", "inherit"],
  });
  return tag;
}

function docker(platform, image, mounts, script) {
  const user = typeof process.getuid === "function" ? `${process.getuid()}:${process.getgid()}` : "0:0";
  const args = ["run", "--rm", "--platform", `linux/${platform}`, "--user", user, "--network", "none", ...SCRATCH];
  for (const mount of mounts) args.push("-v", mount);
  run("docker", [...args, "-e", "HOME=/tmp", image, "sh", "-euc", script]);
}

function build(options) {
  const target = targetOf(options);
  requireHeaders();
  mkdirSync(options.out, { recursive: true });
  const compile = "scripts/typescript/prebuild/compile.sh";
  const steps = [
    [options.target, `${options.target}/${FILE}`, "release"],
    [options.target, `faults/${options.target}/${FILE}`, "faults"],
  ];
  if (target.os === "darwin") {
    if (process.platform !== "darwin") {
      fail(`${options.target} builds on macOS (Xcode command line tools), not on ${process.platform}`);
    }
    for (const [name, out, variant] of steps) {
      run("sh", [join(REPO, compile), name, join(options.out, out), variant]);
    }
    run("sh", [join(REPO, compile), "c-tests", join(options.out, "c-tests", options.target)]);
    return;
  }
  const image =
    target.libc === "glibc"
      ? GCC_BUSTER[target.docker]
      : derivedImage("musl-build", ALPINE[target.docker], target.docker, ALPINE_BUILD_PACKAGES);
  const script = [
    ...steps.map(([name, out, variant]) => `sh /src/${compile} ${name} /out/${out} ${variant}`),
    `mkdir -p /tmp/c-tests && sh /src/${compile} c-tests /tmp/c-tests`,
  ].join("\n");
  // The source is mounted read-only at a fixed path so no host path reaches the bytes.
  docker(target.docker, image, [`${REPO}:/src:ro`, `${options.out}:/out`], script);
}

function test(options) {
  const target = targetOf(options);
  if (!existsSync(join(options.out, options.target, FILE))) {
    fail(`${options.target} is not built in ${options.out}; run 'prebuild.mjs build --target ${options.target}' first`);
  }
  const env = { FABRIC_WIRE_NATIVE_BUILD: options.out, FABRIC_WIRE_NATIVE_TARGET: options.target };
  if (target.os === "darwin") {
    if (process.platform !== "darwin" || process.arch !== target.arch) {
      fail(`${options.target} tests need Node for darwin-${target.arch}; this Node is ${process.platform}-${process.arch}`);
    }
    run("npx", ["vitest", "run", "test/wire/native"], { cwd: TS, env: { ...process.env, ...env } });
    return;
  }
  const image =
    target.libc === "glibc"
      ? NODE_BOOKWORM[target.docker]
      : derivedImage("musl-test", NODE_ALPINE[target.docker], target.docker, "python3 binutils");
  // A private copy with its own node_modules: the host's are for another platform.
  const script = `
    mkdir -p /tmp/work/sdk /tmp/work/scripts
    cd /src/sdk/typescript
    tar -cf - --exclude ./node_modules --exclude ./dist --exclude ./prebuilds-build . | (mkdir /tmp/work/sdk/typescript && cd /tmp/work/sdk/typescript && tar -xf -)
    cp -R /src/scripts/typescript /tmp/work/scripts/typescript
    cd /tmp/work/sdk/typescript
    npm ci --no-audit --no-fund
    FABRIC_WIRE_NATIVE_BUILD=/out FABRIC_WIRE_NATIVE_TARGET=${options.target} npx vitest run test/wire/native
  `;
  const user = typeof process.getuid === "function" ? `${process.getuid()}:${process.getgid()}` : "0:0";
  run("docker", [
    ...["run", "--rm", "--platform", `linux/${target.docker}`, "--user", user, "-e", "HOME=/tmp", ...SCRATCH],
    ...["-v", `${REPO}:/src:ro`, "-v", `${options.out}:/out:ro`, image, "sh", "-euc", script],
  ]);
}

function committedTable() {
  const text = existsSync(TABLE) ? readFileSync(TABLE, "utf8") : "";
  const table = {};
  for (const match of text.matchAll(/^ {2}"([a-z0-9-]+)": "([0-9a-f]{64})",$/gm)) table[match[1]] = match[2];
  return table;
}

function digests(options) {
  const built = {};
  for (const name of Object.keys(TARGETS)) {
    const file = join(options.out, name, FILE);
    if (existsSync(file)) built[name] = createHash("sha256").update(readFileSync(file)).digest("hex");
  }
  const committed = committedTable();
  if (options.mode === "write") {
    const merged = { ...committed, ...built };
    const rows = Object.keys(TARGETS)
      .filter((name) => merged[name] !== undefined)
      .map((name) => `  "${name}": "${merged[name]}",\n`);
    writeFileSync(
      TABLE,
      `// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
// Code generated by scripts/typescript/prebuild/prebuild.mjs digests --write. DO NOT EDIT.
// SHA-256 of prebuilds/<target>/fabric_wire.node as CI builds it (spec 055 §4.4). The
// loader refuses a file whose digest is not the one listed here.

export const NATIVE_DIGESTS: Readonly<Record<string, string>> = {
${rows.join("")}};
`,
    );
    process.stdout.write(`prebuild.mjs: wrote ${rows.length} digest(s) to ${TABLE}\n`);
    return;
  }
  if (options.mode !== "check") fail("digests needs --check or --write");
  const problems = [];
  for (const name of Object.keys(TARGETS)) {
    if (built[name] === undefined) {
      if (options.requireAll) problems.push(`${name}: not built in ${options.out}`);
      continue;
    }
    if (committed[name] === undefined) {
      problems.push(`${name}: built ${built[name]} but the table has no entry`);
    } else if (committed[name] !== built[name]) {
      problems.push(`${name}: built ${built[name]} but the table says ${committed[name]}`);
    }
  }
  for (const name of Object.keys(TARGETS)) {
    process.stdout.write(`${name} ${built[name] ?? "(not built)"}\n`);
  }
  if (problems.length > 0) {
    fail(
      `the digest table differs from the built files:\n  ${problems.join("\n  ")}\n` +
        "If the native sources, compile flags or pinned build images changed on purpose, " +
        "download the 'fabric-wire-prebuilds' artifact of this workflow run (or build every " +
        "target), run 'node scripts/typescript/prebuild/prebuild.mjs digests --write' and commit " +
        "sdk/typescript/src/wire/native-digests.generated.ts",
    );
  }
  process.stdout.write("prebuild.mjs: the digest table matches the built files\n");
}

const options = parse(process.argv.slice(2));
if (options.command === "build") build(options);
else if (options.command === "test") test(options);
else if (options.command === "digests") digests(options);
else fail("usage: prebuild.mjs build|test|digests [--target <t>] [--out <dir>] [--check|--write] [--require-all]");
