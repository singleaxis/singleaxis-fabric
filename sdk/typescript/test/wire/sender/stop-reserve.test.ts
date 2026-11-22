// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §9.4 (unit 055-t17 review): the orderly stop keeps enough of its budget for
 * what follows delivery (the exit note, the exit status file, the result), because the
 * installing thread terminates the Fabric worker when the budget ends.
 */
import { describe, expect, it } from "vitest";

import { deliveryDeadline } from "../../../src/wire/fabric-main.js";

describe("the stop's delivery deadline", () => {
  it("keeps at least 500 ms back from the default 2 s budget (10% was 200 ms)", () => {
    expect(deliveryDeadline(1000, 3000)).toBe(2500);
  });

  it("keeps 10% back from a long budget", () => {
    expect(deliveryDeadline(0, 30_000)).toBe(27_000);
  });

  it("never keeps back more than half of a short budget, and never goes past it", () => {
    expect(deliveryDeadline(0, 400)).toBe(200);
    expect(deliveryDeadline(0, 0)).toBe(0);
    expect(deliveryDeadline(100, 50)).toBe(100);
  });
});
