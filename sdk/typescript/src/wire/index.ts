// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * `@singleaxis/fabric/wire` (spec 055 §4.2): the explicit wire API, an alternative to the
 * zero-code preload (`@singleaxis/fabric/register`), and `envStatus()`, the one command that
 * says why a Node.js agent records nothing:
 *
 *     node -p "require('@singleaxis/fabric/wire').envStatus()"
 *
 * Both module formats of this entry load the one CommonJS wire core (`./core.js`, packaged
 * as `dist/wire/core.cjs`), shared with the preload: the preload and an explicit
 * `install()` share one runtime per process.
 */
export {
  WireConfigError,
  endRun,
  envStatus,
  install,
  resumeToken,
  resumeTokens,
  run,
  statusMessages,
  type EndRunOptions,
  type InstallOptions,
  type RunOptions,
  type StatusDocument,
  type StatusMessage,
  type StopResult,
  type WireHandle,
  type WireOptions,
} from "./core.js";
