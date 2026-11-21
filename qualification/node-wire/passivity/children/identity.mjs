// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Behaviour identity as an ES module application (see identity-scenarios.cjs).
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const config = JSON.parse(process.argv[2]);
const { main } = require("./identity-scenarios.cjs");
const startCapture = config.capture === "on" ? require(config.bundle).startCapture : undefined;
await main(config, startCapture);
