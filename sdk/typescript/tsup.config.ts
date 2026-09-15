// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  // Published maps preserve source locations without embedding the repository
  // source tree. This keeps unshipped modules/constants out of the npm artifact.
  esbuildOptions(options) {
    options.sourcesContent = false;
  },
  clean: true,
  target: "es2022",
});
