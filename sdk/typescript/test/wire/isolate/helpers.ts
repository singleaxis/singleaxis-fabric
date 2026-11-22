// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Helpers of the application worker-thread tests (spec 055 §9.5, unit 055-t19).
 *
 * Worker threads and the preload need JavaScript files laid out as the package is, so
 * {@link buildPackage} bundles the source wire core with esbuild (the version the SDK
 * locks) into `<dir>/dist/wire/core.cjs`, writes the preload `dist/register.cjs`, puts the
 * native module compiled for this machine in `prebuilds/<target>/` with its digest in the
 * bundle's table, and writes `dist/wire-qualification.json` activating this machine's
 * build (spec 055 §9.5: tests activate capture through a table). The host processes
 * (`fixtures/*.cjs`) are plain CommonJS that load that core.
 */
import { spawn } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { build as esbuild } from "esbuild";

import { parseJson } from "../../../src/wire/codec.js";
import { unframeAll } from "../../../src/wire/spool-codec.js";
import { type NativeBuild, nativeBuild, sha256 } from "../native/build.js";
import { activeHere } from "../status/helpers.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = join(HERE, "..", "..", "..", "src");
export const FIXTURES = join(HERE, "fixtures");

export interface Package {
  /** The package root (holds `dist/` and `prebuilds/`). */
  readonly dir: string;
  /** `dist/wire/core.cjs`: the wire core, also the Fabric worker's entry. */
  readonly core: string;
  /** `dist/register.cjs`: the preload. */
  readonly register: string;
  readonly target: string;
}

let native: NativeBuild | undefined;
const made: string[] = [];

/** Bundles the source wire core as an installed package would lay it out. */
export async function buildPackage(variant: "release" | "faults" = "release"): Promise<Package> {
  native ??= nativeBuild();
  const dir = mkdtempSync(join(tmpdir(), "f055-t19-pkg-"));
  made.push(dir);
  const file = variant === "release" ? native.release : native.faults;
  const target = native.target;
  const digest = sha256(file);
  mkdirSync(join(dir, "prebuilds", target), { recursive: true });
  copyFileSync(file, join(dir, "prebuilds", target, "fabric_wire.node"));
  await esbuild({
    entryPoints: [join(SRC, "wire", "core.ts")],
    outfile: join(dir, "dist", "wire", "core.cjs"),
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node22",
    logLevel: "silent",
    plugins: [
      {
        // The digest of the module compiled here, in place of the release table.
        name: "native-digests",
        setup(b) {
          b.onLoad({ filter: /native-digests\.generated\.ts$/ }, () => ({
            contents: `export const NATIVE_DIGESTS = ${JSON.stringify({ [target]: digest })};`,
            loader: "ts",
          }));
        },
      },
    ],
  });
  writeFileSync(join(dir, "dist", "register.cjs"), 'require("./wire/core.cjs").autoload();\n');
  const table = {
    ...activeHere(target),
    gates: { "TS-1U": "passed", "TS-1D": "passed", "TS-1H": "not_passed" },
  };
  writeFileSync(join(dir, "dist", "wire-qualification.json"), JSON.stringify(table));
  return {
    dir,
    core: join(dir, "dist", "wire", "core.cjs"),
    register: join(dir, "dist", "register.cjs"),
    target,
  };
}

/** A private (0700) scratch directory for one host process. */
export function scratch(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), `f055-t19-${prefix}-`));
  made.push(dir);
  return dir;
}

export function cleanup(): void {
  for (const dir of made.splice(0)) rmSync(dir, { recursive: true, force: true });
  native?.cleanup();
  native = undefined;
}

/**
 * The environment of a host process: a local-profile capture whose endpoint is the host's
 * own scripted provider (`127.0.0.1`, the port the host picks, any port matches), its
 * spool and file store under `root`, and an OTLP endpoint nobody listens on (records stay
 * in the spool, where the tests read them).
 */
export function captureEnv(
  root: string,
  pkg: Package,
  extra: Record<string, string> = {},
): Record<string, string> {
  const base = Object.fromEntries(
    Object.entries(process.env).filter(
      ([k]) => !k.startsWith("FABRIC_") && !k.startsWith("OTEL_") && !k.startsWith("NODE_"),
    ),
  ) as Record<string, string>;
  mkdirSync(join(root, "spool"), { recursive: true, mode: 0o700 });
  return {
    ...base,
    FABRIC_TEST_CORE: pkg.core,
    FABRIC_TEST_REGISTER: pkg.register,
    FABRIC_TENANT_ID: "tenant-isolate",
    FABRIC_WIRE_SPOOL_DIR: join(root, "spool"),
    FABRIC_WIRE_STORE: `file://${join(root, "store")}`,
    FABRIC_OTLP_ENDPOINT: "http://127.0.0.1:9",
    FABRIC_WIRE_ENDPOINTS: JSON.stringify([
      { endpoint_id: "isolate-test", dialect: "openai", hosts: ["127.0.0.1"], schemes: ["http"] },
    ]),
    // As the hosts' close() budget (CLOSE_MS): a loaded machine still finishes the stop.
    FABRIC_WIRE_SHUTDOWN_TIMEOUT: "6",
    ...extra,
  };
}

export interface HostResult {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
  /** The last stdout line, parsed. */
  readonly report: any;
}

/** Runs `node [args] fixtures/<script>` and parses its last stdout line. */
export function runHost(
  script: string,
  env: Record<string, string>,
  args: readonly string[] = [],
  nodeArgs: readonly string[] = [],
  timeoutMs = 90_000,
): Promise<HostResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [...nodeArgs, join(FIXTURES, script), ...args], {
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString("utf8")));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString("utf8")));
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`${script} timed out: ${stderr.slice(-2000)}`));
    }, timeoutMs);
    child.once("error", reject);
    child.once("close", (code) => {
      clearTimeout(timer);
      const last = stdout.trim().split("\n").pop() ?? "";
      let report: any;
      try {
        report = JSON.parse(last);
      } catch {
        report = undefined;
      }
      resolve({ code, stdout, stderr, report });
    });
  });
}

/** Every record document left in a plaintext spool, in name order. */
export function spoolDocs(spoolDir: string): any[] {
  const out: any[] = [];
  for (const name of readdirSync(spoolDir)
    .filter((n) => n.endsWith(".rec"))
    .sort()) {
    for (const { doc } of unframeAll(readFileSync(join(spoolDir, name)))) out.push(doc);
  }
  return out;
}

/** The exchange records of a spool: sequence, epoch, segment and the request path. */
export function exchanges(docs: readonly any[]): {
  sequence: bigint;
  epoch: bigint;
  source: string;
  segment: string | undefined;
}[] {
  return docs
    .filter((d) => d.record_kind === "exchange")
    .map((d) => {
      const attrs = d.span.attributes as Record<string, unknown>;
      return {
        sequence: BigInt(attrs["fabric.source.sequence"] as number | bigint),
        epoch: BigInt(attrs["fabric.source.epoch"] as number | bigint),
        source: attrs["fabric.source_id"] as string,
        segment: attrs["fabric.run.segment_id"] as string | undefined,
      };
    });
}

/** The loss ranges of a spool. */
export function losses(docs: readonly any[]): {
  reason: string;
  first: bigint;
  last: bigint;
  segment: string | undefined;
}[] {
  return docs
    .filter((d) => d.record_kind === "loss")
    .map((d) => ({
      reason: d.loss.reason as string,
      first: BigInt(d.loss.first_sequence),
      last: BigInt(d.loss.last_sequence),
      segment: d.loss.segment_id as string | undefined,
    }));
}

/** The capture manifests (`fabric.manifest.*` attributes) of a spool, in chain order. */
export function manifests(docs: readonly any[]): Record<string, any>[] {
  return docs
    .filter((d) => d.record_kind === "marker" && d.marker.kind === "manifest")
    .map((d) => d.marker.manifest as Record<string, any>)
    .sort(
      (a, b) =>
        Number(a["fabric.manifest.manifest_seq"]) - Number(b["fabric.manifest.manifest_seq"]),
    );
}

export { parseJson };
