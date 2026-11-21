// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Behaviour identity as a CommonJS application (see identity-scenarios.cjs).
"use strict";

const config = JSON.parse(process.argv[2]);
const { main } = require("./identity-scenarios.cjs");
const startCapture = config.capture === "on" ? require(config.bundle).startCapture : undefined;
void main(config, startCapture);
