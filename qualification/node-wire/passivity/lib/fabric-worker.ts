// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The Fabric worker of the passivity harness: the SDK's own consume loop with no
 * pipeline (units 055-t7 and 055-t8 add one), so each completed exchange is drained and
 * its slabs are released, off the application's thread.
 */
import { runFabricWorker } from "../../../../sdk/typescript/src/wire/worker.js";

void runFabricWorker({});
