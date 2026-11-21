// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §6.3, §9.5 row `055-t16`: the ancestor directory barrier (Python
// `establish_barrier`): fsync top-down from the spool's parent to the durable boundary
// (the boundary too, never above it), then the `.barrier` marker; an unknown fsync
// failure is not a durable boundary; only a recorded walk lets a refused ancestor stop
// it; a planted symlink marker or a recreated root invalidates it; and `spool_undurable`
// until it holds, with no flush or close succeeding meanwhile.
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { Sender } from "../../../src/wire/sender.js";
import {
  BARRIER_MARKER,
  Spool,
  type SpoolIo,
  type SpoolOptions,
  nodeSpoolIo,
} from "../../../src/wire/spool.js";

import { type Native, native } from "../spool/helpers.js";

let lib: Native;
beforeAll(() => {
  lib = native();
}, 120_000);
afterAll(() => lib?.build.cleanup());

const opened: Spool[] = [];
const roots: string[] = [];
afterEach(() => {
  for (const spool of opened.splice(0)) spool.close();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

/** A private root holding `a/b`; the spool goes in `a/b/spool`. */
function tree(): { root: string; a: string; b: string; spool: string } {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "f055-t16-barrier-")));
  roots.push(root);
  const a = join(root, "a");
  const b = join(a, "b");
  mkdirSync(b, { recursive: true, mode: 0o700 });
  return { root, a, b, spool: join(b, "spool") };
}

/** The real I/O, recording each ancestor fsync and refusing those `refuse` names. */
function recording(refuse: (path: string) => string | undefined = () => undefined) {
  const base = nodeSpoolIo(lib.addon);
  const synced: string[] = [];
  const calls: string[] = [];
  const io: SpoolIo = {
    ...base,
    syncAncestor: (path) => {
      calls.push(`ancestor:${path}`);
      const code = refuse(path);
      if (code !== undefined) throw Object.assign(new Error(`injected ${code}`), { code });
      base.syncAncestor(path);
      synced.push(path);
    },
    syncDir: (path) => {
      calls.push(`dir:${path}`);
      base.syncDir(path);
    },
    openExclusive: (path) => {
      calls.push(`create:${path.slice(path.lastIndexOf("/") + 1)}`);
      return base.openExclusive(path);
    },
  };
  return { io, synced, calls };
}

let nextPid = 97_000;
function make(dir: string, options: Partial<SpoolOptions> = {}): Spool {
  nextPid += 1;
  const spool = new Spool(dir, {
    maxBytes: 1 << 20,
    addon: lib.addon,
    pid: nextPid,
    ledger: false,
    ...options,
  });
  opened.push(spool);
  return spool;
}

function sender(spool: Spool, warned: string[] = []): Sender {
  return new Sender({
    spool,
    content: undefined,
    serviceName: "svc",
    traces: { export: async () => ({ outcome: "ok", status: 200 }) },
    warn: (text) => warned.push(text),
  });
}

describe("the barrier walk", () => {
  it("fsyncs top-down from the boundary to the spool's parent, then writes the marker and fsyncs the spool", () => {
    const { a, b, spool } = tree();
    const { io, synced, calls } = recording();
    const s = make(spool, { io, durableBoundary: a });
    expect(s.durable).toBe(false);
    calls.length = 0;
    expect(s.establishBarrier()).toBe(true);
    expect(s.durable).toBe(true);
    expect(synced).toEqual([a, b]); // the boundary too, never its parent
    expect(calls).toEqual([
      `ancestor:${a}`,
      `ancestor:${b}`,
      `create:${BARRIER_MARKER}`,
      `dir:${spool}`,
    ]);
    expect(readFileSync(join(spool, BARRIER_MARKER), "ascii")).toBe(
      "fabric wire spool barrier v1\n",
    );
    calls.length = 0;
    expect(s.establishBarrier()).toBe(true); // once established, no new walk
    expect(calls).toEqual([]);
  });

  it("without a configured boundary it stops at the root of the spool's filesystem", () => {
    const { spool } = tree();
    const base = nodeSpoolIo(lib.addon);
    const { io, synced } = recording();
    const s = make(spool, { io });
    expect(s.establishBarrier()).toBe(true);
    const top = synced[0]!;
    expect(top === "/" || base.mountPoint(top)).toBe(true);
    // Every directory from there down to the spool's parent, in order.
    for (let i = 1; i < synced.length; i++) expect(dirname(synced[i]!)).toBe(synced[i - 1]);
    expect(synced.at(-1)).toBe(dirname(realpathSync(spool)));
  });

  for (const code of ["EIO", "EACCES", "EROFS"]) {
    it(`a first walk failing with ${code} is not a durable boundary: spool_undurable, flush fails, retried`, async () => {
      const { a, spool } = tree();
      let failing = true;
      const { io } = recording((path) => (failing && path === a ? code : undefined));
      const s = make(spool, { io, durableBoundary: a });
      const warned: string[] = [];
      const out = sender(s, warned);
      expect(out.ensureDurable()).toBe(false);
      expect(s.barrierFailures).toBe(1);
      expect(() => readFileSync(join(spool, BARRIER_MARKER))).toThrow(/ENOENT/);
      expect(out.health().spool_undurable).toBe(1);
      expect(out.stats().spool_undurable).toBe(1);
      // Records are still written and delivered meanwhile; only the claim is withheld.
      expect(await out.flush(performance.now() + 500)).toBe(false);
      expect(await out.close(performance.now() + 500)).toBe(false);
      expect(warned).toHaveLength(1);
      expect(warned[0]).toMatch(/not durable.*Fix: put FABRIC_WIRE_SPOOL_DIR on a local volume/);
      failing = false;
      expect(out.ensureDurable()).toBe(true);
      expect(out.health().spool_undurable).toBe(0);
      expect(warned.at(-1)).toBe("fabric.wire: spool directory barrier established");
    });
  }

  it("after a recorded walk, a refused ancestor (a restart without rights there) may stop the walk; an unknown failure may not", () => {
    const { a, b, spool } = tree();
    make(spool, { durableBoundary: a }).establishBarrier(); // the first, complete walk
    const refused = recording((path) => (path === a ? "EACCES" : undefined));
    const restarted = make(spool, { io: refused.io, durableBoundary: a });
    expect(restarted.establishBarrier()).toBe(true);
    expect(refused.synced).toEqual([b]); // below the refused one, every fsync still succeeds
    const broken = recording((path) => (path === a ? "EIO" : undefined));
    expect(make(spool, { io: broken.io, durableBoundary: a }).establishBarrier()).toBe(false);
    const below = recording((path) => (path === b ? "EIO" : undefined));
    expect(make(spool, { io: below.io, durableBoundary: a }).establishBarrier()).toBe(false);
  });

  it("a planted symlink marker invalidates the barrier", () => {
    const { root, a, spool } = tree();
    make(spool, { durableBoundary: a, ledger: false }).close();
    const target = join(root, "elsewhere");
    mkdirSync(target);
    symlinkSync(join(target, "x"), join(spool, BARRIER_MARKER));
    const s = make(spool, { durableBoundary: a });
    expect(s.establishBarrier()).toBe(false);
    expect(s.barrierFailures).toBe(1);
  });

  it("a recreated spool root invalidates the barrier: the walk starts over", () => {
    const { a, spool } = tree();
    make(spool, { durableBoundary: a }).establishBarrier();
    for (const one of opened.splice(0)) one.close();
    rmSync(spool, { recursive: true });
    const refused = recording((path) => (path === a ? "EACCES" : undefined));
    const s = make(spool, { io: refused.io, durableBoundary: a });
    expect(s.establishBarrier()).toBe(false); // no recorded walk: a refusal is a failure
  });

  it("the boundary must be the spool directory or an ancestor; the spool itself as boundary walks nothing above it", () => {
    const { spool } = tree();
    make(spool).close();
    const { io, synced } = recording();
    const s = make(spool, { io, durableBoundary: spool });
    expect(s.establishBarrier()).toBe(true);
    expect(synced).toEqual([]);
  });
});
