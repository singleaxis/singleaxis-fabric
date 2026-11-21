// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Run scopes (spec 055 §4.3, §6.4; spec 050 §3.6): one {@link RunScope} per `run()` block
 * entry, carried by `AsyncLocalStorage`.
 *
 * What the storage holds is only a scope reference and safe identity (the emitted run id,
 * the scope's uuid4 and the run's slot in the shared run table); the canonical run and
 * segment state is the run table's (`segments.ts`, the control block). Promises, timers
 * and `queueMicrotask` keep the scope of the code that scheduled them; a callback queued
 * by code that captured another context, and work posted to `worker_threads`, run
 * outside it (§4.3 "Intentional language differences").
 *
 * A scope is closed when its block exits. A continuation that outlives the block (a timer
 * set inside it) still sees the scope in storage, so the current scope is the innermost
 * one that is still open: a closed scope never names a run.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";

/** The run a scope belongs to, as the run table keeps it (`segments.ts`). */
export interface RunRef {
  /** The run's slot in the shared run table, or -1 when it holds none. */
  slot: number;
}

/** One `run()` block entry. Mutated only by the run table. */
export interface RunScope {
  /** The emitted run id (never the caller's clear id in the pseudonymous mode). */
  readonly runId: string;
  /** uuid4 of this block entry (`fabric.run.scope_id`). */
  readonly scopeId: string;
  /** The same uuid as 16 bytes, for exchange slots. */
  readonly scopeBytes: Uint8Array;
  readonly parent: RunScope | undefined;
  readonly run: RunRef;
  closed: boolean;
}

const storage = new AsyncLocalStorage<RunScope>();

/** A new scope of `runId` inside the current one. */
export function newScope(runId: string, run: RunRef): RunScope {
  const scopeId = randomUUID();
  return {
    runId,
    scopeId,
    scopeBytes: Buffer.from(scopeId.replace(/-/g, ""), "hex"),
    parent: currentRunScope(),
    run,
    closed: false,
  };
}

/** Runs `fn` with `scope` current; returns what `fn` returns or throws what it throws. */
export function withScope<T>(scope: RunScope, fn: () => T): T {
  return storage.run(scope, fn);
}

/** The innermost open run scope of the calling context, or `undefined`. */
export function currentRunScope(): RunScope | undefined {
  let scope = storage.getStore();
  while (scope !== undefined && scope.closed) scope = scope.parent;
  return scope;
}

/** The open scopes of the calling context, innermost first. */
export function scopeChain(): RunScope[] {
  const out: RunScope[] = [];
  for (let scope = storage.getStore(); scope !== undefined; scope = scope.parent) {
    if (!scope.closed) out.push(scope);
  }
  return out;
}
