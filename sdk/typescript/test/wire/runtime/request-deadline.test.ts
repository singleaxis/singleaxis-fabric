// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The Fabric worker's deadline for a flush or stop request (spec 055 §4.5, §9.4): it ends
 * where the installing thread's budget ends, not `budgetMs` after the request was received.
 * A stop that waited behind a busy pass otherwise ran past the installing thread's timer,
 * which terminated the worker before it wrote the exit status (found by the 055-t19 review).
 */
import { describe, expect, it } from "vitest";

import { requestDeadline } from "../../../src/wire/worker.js";

describe("requestDeadline", () => {
  const origin = 1_700_000_000_000;

  it("a request received at once keeps its whole budget", () => {
    // Sent at worker-clock 100 (wall origin + 100), received at 100.
    expect(requestDeadline({ budgetMs: 2000, deadlineAt: origin + 100 + 2000 }, 100, origin)).toBe(
      2100,
    );
  });

  it("a request that waited in the queue ends where the caller's budget ends", () => {
    // Sent at 100, received 900 ms later: 1,100 ms of the 2,000 are left.
    expect(requestDeadline({ budgetMs: 2000, deadlineAt: origin + 2100 }, 1000, origin)).toBe(2100);
  });

  it("never later than budgetMs after receipt (a wall clock stepped forward)", () => {
    expect(requestDeadline({ budgetMs: 2000, deadlineAt: origin + 60_000 }, 100, origin)).toBe(
      2100,
    );
  });

  it("never sooner than a quarter of the budget (a wall clock stepped back)", () => {
    expect(requestDeadline({ budgetMs: 2000, deadlineAt: origin - 60_000 }, 100, origin)).toBe(600);
  });

  it("a request without deadlineAt (an older sender) keeps the relative budget", () => {
    expect(requestDeadline({ budgetMs: 2000 }, 100, origin)).toBe(2100);
    expect(requestDeadline({ budgetMs: Number.NaN }, 100, origin)).toBe(100);
  });
});
