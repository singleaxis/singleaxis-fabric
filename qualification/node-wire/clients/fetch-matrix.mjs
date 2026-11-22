// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §9.3 global `fetch` row, ES module entry: the scenarios of
// fetch-scenarios.cjs from an ES module application. Knows nothing about Fabric.
//
//   MODEL_BASE_URL=http://127.0.0.1:PORT node fetch-matrix.mjs

import scenarios from "./fetch-scenarios.cjs";

const transcript = await scenarios.run(process.env.MODEL_BASE_URL);
process.stdout.write(JSON.stringify({ format: "esm", ...transcript }) + "\n");
