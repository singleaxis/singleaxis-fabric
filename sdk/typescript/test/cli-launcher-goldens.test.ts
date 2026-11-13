// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Spec 058 §1.4 and §11.1: the npm launcher's `fabric run` and `fabric doctor`
 * agree with the Python CLI's on the shared goldens
 * (`sdk/goldens/cli-launcher/launcher-v1.json`), which
 * `sdk/python/tests/test_cli_launcher_goldens.py` runs through the Python CLI.
 */

import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  unlinkSync,
  appendFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import { doctor } from "../src/cli/doctor";
import { prepare, type ProbeAnswer } from "../src/cli/run";
import { detect } from "../src/cli/runtime";

const HERE = dirname(fileURLToPath(import.meta.url));
const GOLDENS = resolve(HERE, "..", "..", "goldens", "cli-launcher", "launcher-v1.json");
const DOCUMENT: any = JSON.parse(readFileSync(GOLDENS, "utf-8"));
const STATUS_FILE = /^\{\{dir\}\}\/\.fabric\/state\/runs\/[0-9]+-[A-Za-z0-9._-]+\.status\.json$/;
const LABEL = /^run-[0-9]{8}-[0-9]{6}-[0-9a-f]{4}$/;
const posix = process.platform !== "win32";

const made: string[] = [];
afterEach(() => {
  for (const directory of made.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function materialize(name: string): string {
  const spec = DOCUMENT.projects[name];
  const root = mkdtempSync(join(tmpdir(), "fabric-golden-"));
  made.push(root);
  const directory = join(realpathSync(root), "project");
  mkdirSync(directory);
  for (const entry of spec.files) {
    const path = join(directory, entry.path);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, entry.content, "utf-8");
    chmodSync(path, parseInt(entry.mode, 8));
  }
  if (spec["fabric.yaml"] !== null) {
    writeFileSync(join(directory, "fabric.yaml"), spec["fabric.yaml"], "utf-8");
    const compiled = DOCUMENT.compile.find((c: { project: string }) => c.project === name);
    mkdirSync(join(directory, ".fabric"), { mode: 0o700 });
    const path = join(directory, ".fabric", "compiled.env");
    writeFileSync(path, compiled.compiled_env.replaceAll("{{dir}}", directory), "utf-8");
    chmodSync(path, 0o600);
  }
  return directory;
}

function prepareCase(directory: string, testCase: any): void {
  for (const relative of testCase.remove ?? []) unlinkSync(join(directory, relative));
  for (const [relative, mode] of Object.entries(testCase.chmod ?? {})) {
    chmodSync(join(directory, relative), parseInt(mode as string, 8));
  }
  if (testCase.edit_config)
    appendFileSync(join(directory, "fabric.yaml"), "# edited after fabric init\n");
}

function template(value: string, directory: string): string {
  return value.replaceAll(directory, "{{dir}}");
}

function lastRecord(directory: string): Record<string, unknown> | null {
  const runs = join(directory, ".fabric", "state", "runs");
  let names: string[];
  try {
    names = readdirSync(runs);
  } catch {
    return null;
  }
  const records = names.filter((n) => n.endsWith(".json") && !n.endsWith(".status.json")).sort();
  if (!records.length) return null;
  const raw = JSON.parse(readFileSync(join(runs, records[records.length - 1] as string), "utf-8"));
  return {
    capture: raw.capture,
    runtime: raw.runtime,
    sensor: raw.sensor,
    project: raw.project,
    finding_ids: raw.findings.map((f: { id: string }) => f.id),
  };
}

describe.runIf(posix)("npm launcher on the shared goldens", () => {
  it.each(DOCUMENT.detect.map((c: unknown, i: number) => [i, c]) as Array<[number, unknown]>)(
    "detects the runtime (case %i)",
    (_i, testCase) => {
      const c = testCase as any;
      const directory = materialize("detect");
      const command = c.command.map((w: string) => w.replaceAll("{{dir}}", directory));
      const runtime = detect(command, { PATH: join(directory, "bin") }, directory);
      expect([
        runtime.kind,
        runtime.interpreter ? template(runtime.interpreter, directory) : null,
      ]).toEqual([c.kind, c.interpreter]);
    },
  );

  it.each(DOCUMENT.run.map((c: { name: string }) => [c.name, c]) as Array<[string, unknown]>)(
    "run: %s",
    (_name, testCase) => {
      const c = testCase as any;
      const directory = materialize(c.project);
      prepareCase(directory, c);
      const environ: Record<string, string> = {
        PATH: join(directory, "bin"),
        HOME: directory,
        ...c.environ,
      };
      const prober = (interpreter: string): ProbeAnswer => {
        if (c.probe === null)
          throw new Error(`asked ${interpreter} although the case has no probe`);
        return c.probe as ProbeAnswer;
      };
      const { env, findings } = prepare(
        { runLabel: c.run_label, noCapture: Boolean(c.no_capture), quiet: true },
        c.command,
        { ...environ },
        directory,
        prober,
        () => 1_700_000_000_000_000_000n,
      );
      const added: Record<string, string> = {};
      for (const name of Object.keys(env).sort()) {
        const value = env[name] as string;
        if (environ[name] === value) continue;
        let templated = template(value, directory);
        if (name === "FABRIC_WIRE_STATUS_FILE") {
          expect(templated).toMatch(STATUS_FILE);
          templated = "<status-file>";
        }
        if (name === "FABRIC_RUN_ID" && LABEL.test(templated)) templated = "<generated-label>";
        added[name] = templated;
      }
      expect(Object.keys(environ).filter((name) => !(name in env))).toEqual([]);
      expect({
        added,
        finding_ids: findings.map((f) => f.id),
        record: lastRecord(directory),
      }).toEqual(c.expect);
    },
  );

  it.each(DOCUMENT.doctor.map((c: { name: string }) => [c.name, c]) as Array<[string, unknown]>)(
    "doctor: %s",
    async (_name, testCase) => {
      const c = testCase as any;
      const directory = materialize(c.project);
      prepareCase(directory, c);
      const environ: Record<string, string> = {
        PATH: join(directory, "bin"),
        HOME: directory,
        ...c.environ,
      };
      const status = c.sdk_status ? DOCUMENT.sdk_status[c.sdk_status] : null;
      const { report } = await doctor({}, environ, directory, {
        sdkStatus: () => status,
        nodeAnswers: async () => c.node_answers,
        uid: () => (typeof process.geteuid === "function" ? process.geteuid() : undefined),
      });
      const compare = new Set<string>(c.compare ?? DOCUMENT.doctor_compare);
      const ids = [...new Set(report.findings.map((f) => f.id))]
        .filter((id) => compare.has(id))
        .sort();
      expect({ ids, exit_code: report.exit_code }).toEqual(c.expect);
    },
  );
});
