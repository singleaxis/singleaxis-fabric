// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §4.5, §9.4, unit 055-t19: preload reach into worker threads, qualified as
 * actually launched, not assumed. For each way of giving Node the preload (`NODE_OPTIONS`
 * or the command line; `--import` or `--require`), the host creates Workers of every kind
 * (a file Worker, a nested one, `eval: true`, `execArgv: []`, `env: {}`) and each reports
 * whether the preload attached it.
 *
 * What must hold on every Node 24 build: every created thread is attached or counted
 * unattached (`workers_attached + workers_unattached` is the number created), FW-030 and a
 * chained manifest declaring `node_worker_unattached` appear exactly when one is
 * unattached, and the attached threads are the ones that said so. What reaches where is
 * Node's behaviour: on a build listed in `qualification/node-wire/worker-reach.json` (the
 * minimum claimed patch, 24.4.0, and the newest, 24.22.3) it must equal the table, so a
 * Node change is a reviewed diff. `FABRIC_WORKER_REACH_OUT` writes what this build did.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { REPO } from "../helpers.js";
import {
  type Package,
  buildPackage,
  captureEnv,
  cleanup,
  manifests,
  runHost,
  scratch,
  spoolDocs,
} from "./helpers.js";

const NODE_24 = Number(process.versions.node.split(".")[0]) >= 24;
const TABLE = join(REPO, "qualification", "node-wire", "worker-reach.json");
const LAUNCHES = [
  "node_options_import",
  "node_options_require",
  "cli_import",
  "cli_require",
] as const;
type Launch = (typeof LAUNCHES)[number];
const KINDS = ["default", "nested", "nested_child", "eval", "execargv_empty", "env_empty"] as const;

let pkg: Package;
const observed: Record<string, Record<string, boolean>> = {};
beforeAll(async () => {
  pkg = await buildPackage();
});
afterAll(() => {
  const out = process.env.FABRIC_WORKER_REACH_OUT;
  if (out) {
    writeFileSync(
      out,
      JSON.stringify({ node: process.versions.node, reach: observed }, null, 2) + "\n",
    );
  }
  cleanup();
});

function launch(how: Launch): { env: Record<string, string>; nodeArgs: string[] } {
  const url = pathToFileURL(pkg.register).href;
  const flag = how.endsWith("import") ? `--import=${url}` : `--require=${pkg.register}`;
  return how.startsWith("node_options")
    ? { env: { NODE_OPTIONS: flag }, nodeArgs: [] }
    : { env: {}, nodeArgs: [flag] };
}

function expected(): Record<string, Record<string, boolean>> | undefined {
  const table = JSON.parse(readFileSync(TABLE, "utf8")) as {
    builds: { node: string; reach: Record<string, Record<string, boolean>> }[];
  };
  return table.builds.find((b) => b.node === process.versions.node)?.reach;
}

describe.runIf(NODE_24)("preload reach into worker threads", { timeout: 120_000 }, () => {
  it.each(LAUNCHES)("%s: every thread is attached or counted and declared", async (how) => {
    const root = scratch(`reach-${how}`);
    const { env, nodeArgs } = launch(how);
    const done = await runHost(
      "host.cjs",
      captureEnv(root, pkg, { FABRIC_WIRE_AUTOLOAD: "1", ...env }),
      ["reach"],
      nodeArgs,
    );
    expect(done.code, done.stderr).toBe(0);
    const { capturing, kinds, status } = done.report;
    expect(capturing).toBe(true);
    const reach: Record<string, boolean> = {
      default: kinds.default.capturing,
      nested: kinds.nested.capturing,
      nested_child: kinds.nested.nested.capturing,
      eval: kinds.eval.capturing,
      execargv_empty: kinds.execArgvEmpty.capturing,
      env_empty: kinds.envEmpty.capturing,
    };
    observed[how] = reach;
    const attached = KINDS.filter((k) => reach[k]).length;
    // A nested child is followed only by an attached parent (its creator).
    const followed = reach.nested ? KINDS.length : KINDS.length - 1;
    expect(status.status.workers_attached ?? 0).toBe(attached);
    expect(status.status.workers_unattached ?? 0).toBe(followed - attached);
    const unattached = followed - attached > 0;
    expect(status.warning_ids.includes("FW-030")).toBe(unattached);
    const declared = manifests(spoolDocs(join(root, "spool"))).some((m) =>
      (m["fabric.manifest.uncaptured_classes"] ?? []).includes("node_worker_unattached"),
    );
    expect(declared).toBe(unattached);
    const table = expected();
    if (table !== undefined) expect(reach).toEqual(table[how]);
  });
});
