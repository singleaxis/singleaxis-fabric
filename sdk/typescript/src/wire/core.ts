// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The wire core (spec 055 §4.1): one module that is the explicit API, the preload's work
 * and the Fabric worker's entry. The package builds it once, as one CommonJS file
 * (`dist/wire/core.cjs`), which both module formats of `@singleaxis/fabric/wire` and
 * `@singleaxis/fabric/register` load, so a process holds exactly one wire runtime
 * whichever format the application uses. Loaded on an application thread it only
 * exports; loaded as the Fabric worker (`install()` starts it with this file) it runs the
 * pipeline and the sender. The root package never imports it.
 */
import { runFabricMain } from "./fabric-main.js";

export { autoload, preloadedHandle } from "./autoload.js";
export { WireConfigError, type WireOptions } from "./config.js";
export { install, type InstallOptions, type WireHandle } from "./install.js";
export type { StopResult } from "./fabric-main.js";
export {
  endRun,
  resumeToken,
  resumeTokens,
  run,
  type EndRunOptions,
  type RunOptions,
} from "./run-api.js";
export { envStatus, statusMessages, type StatusDocument, type StatusMessage } from "./status.js";

void runFabricMain();
