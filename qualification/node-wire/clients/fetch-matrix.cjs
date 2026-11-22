// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §9.3 global `fetch` row, CommonJS entry: the scenarios of
// fetch-scenarios.cjs from a CommonJS application. Knows nothing about Fabric.
//
//   MODEL_BASE_URL=http://127.0.0.1:PORT node fetch-matrix.cjs
"use strict";

const scenarios = require("./fetch-scenarios.cjs");

scenarios.run(process.env.MODEL_BASE_URL).then((transcript) => {
    process.stdout.write(JSON.stringify({ format: "cjs", ...transcript }) + "\n");
});
