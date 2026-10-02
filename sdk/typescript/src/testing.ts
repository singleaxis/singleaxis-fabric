// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Test-support surface — reachable as `import { testing } from
 * "@singleaxis/fabric"`, deliberately NOT flattened onto the package
 * root so test helpers stay out of the production API namespace
 * (mirrors Python, where `reset_coverage_registry` is importable from
 * `fabric.decision` but not re-exported at the package root).
 */

export { resetCoverageRegistry, resetCaptureHealthWarnings } from "./decision.js";
