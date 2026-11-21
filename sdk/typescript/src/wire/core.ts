// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The wire core (spec 055 §4.1): one module that is both the explicit API and the Fabric
 * worker's entry. Loaded on an application thread it only exports; loaded as the Fabric
 * worker (`install()` starts it with this file) it runs the pipeline and the sender.
 * Unit 055-t14 packages it as one CommonJS file behind `@singleaxis/fabric/wire`.
 */
import { runFabricMain } from "./fabric-main.js";

export { install, type InstallOptions, type WireHandle } from "./install.js";
export { endRun, resumeToken, resumeTokens, run } from "./run-api.js";

void runFabricMain();
