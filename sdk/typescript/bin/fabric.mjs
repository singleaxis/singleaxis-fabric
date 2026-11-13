#!/usr/bin/env node
// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/* global process */
// The npm launcher of the SingleAxis Fabric operator CLI (`run` and `doctor`).
import { main } from "../dist/cli.js";

process.exitCode = await main(process.argv.slice(2));
