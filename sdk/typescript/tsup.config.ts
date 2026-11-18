// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from "tsup";

// `npm run build` empties dist/ first; neither build cleans, so the two never
// delete each other's output.
const shared = {
  sourcemap: true,
  // Published maps preserve source locations without embedding the repository
  // source tree. This keeps unshipped modules/constants out of the npm artifact.
  esbuildOptions(options: { sourcesContent?: boolean }) {
    options.sourcesContent = false;
  },
  clean: false,
  target: "es2022",
} as const;

export default defineConfig([
  // The SDK: what an application imports.
  { ...shared, entry: ["src/index.ts"], format: ["esm", "cjs"], dts: true },
  // The npm launcher (`fabric run`, `fabric doctor`), started by bin/fabric.mjs.
  // A separate bundle: the SDK entry point never imports it.
  { ...shared, entry: { cli: "src/cli/index.ts" }, format: ["esm"], dts: false },
]);
