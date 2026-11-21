// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/** The model-name exposure rule (spec 048 §7) against the shared vectors (unit 055-t8). */
import { describe, expect, it } from "vitest";

import {
  DEFAULT_MODEL_ALLOWLIST,
  exposeModel,
  modelAllowed,
} from "../../../src/wire/model-names.js";
import { cases, contract } from "../helpers.js";

const VECTORS = contract("contracts/capture/v1/fixtures/model-names/model-exposure-v1.json");

describe("model-exposure-v1", () => {
  it("the default allowlist is the contract's", () => {
    expect([...DEFAULT_MODEL_ALLOWLIST]).toEqual(VECTORS.default_allowlist);
  });

  it.each(cases(VECTORS.cases))("%s", (_name, vector) => {
    expect(modelAllowed(vector.value, vector.allowlist)).toBe(vector.allowed);
    expect(exposeModel(vector.value, vector.allowlist)).toBe(vector.exposed);
  });

  it("a non-string or empty model is omitted", () => {
    expect(exposeModel(undefined)).toBeUndefined();
    expect(exposeModel("")).toBeUndefined();
    expect(exposeModel(42)).toBeUndefined();
  });
});
