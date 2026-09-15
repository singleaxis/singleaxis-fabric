// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * SDK build version + OTel schema identity. `SDK_VERSION` mirrors the
 * package version (and Python's `fabric._version.__version__`) so emitted
 * tracers carry the same instrumentation identity.
 */

/** SDK build version; kept in lockstep with `package.json` `version`. */
export const SDK_VERSION = "0.8.0-rc.1";

/**
 * Schema URL for the GenAI semantic conventions emitted by Fabric.
 * Passed to `getTracer` so every produced span is tagged with the
 * semconv schema it was written against (mirrors Python
 * `fabric.tracing.GEN_AI_SCHEMA_URL`).
 */
export const GEN_AI_SCHEMA_URL = "https://opentelemetry.io/schemas/gen-ai/1.42.0";
