// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * `@singleaxis/fabric/register` (spec 055 §9.4, the name spec 058 §5.5 uses): the zero-code
 * preload for both module formats.
 *
 *     FABRIC_WIRE_AUTOLOAD=1 NODE_OPTIONS="--import=@singleaxis/fabric/register" node agent.mjs
 *     FABRIC_WIRE_AUTOLOAD=1 NODE_OPTIONS="--import=@singleaxis/fabric/register" node agent.cjs
 *
 * It installs model-call capture synchronously, before the application's entry point runs,
 * with no top-level await. Without `FABRIC_WIRE_AUTOLOAD=1` it does nothing. It never throws
 * and never writes to the agent's stdout or stderr unless `FABRIC_WIRE_DIAGNOSTICS=stderr`.
 * Append the flag to an existing `NODE_OPTIONS`; never replace it.
 */
import { autoload } from "./wire/core.js";

autoload();
