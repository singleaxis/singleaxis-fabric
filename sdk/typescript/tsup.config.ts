// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
import { copyFileSync, mkdirSync, rmSync } from "node:fs";

import { defineConfig, type Options } from "tsup";

// Published maps preserve source locations without embedding the repository source tree.
// This keeps unshipped modules/constants out of the npm artifact.
const noSources: Options["esbuildOptions"] = (options) => {
  options.sourcesContent = false;
};

/**
 * The wire entry points (`./wire`, `./register`) load the one CommonJS wire core
 * (`dist/wire/core.cjs`, spec 055 §4.1) instead of bundling their own copy: each isolate
 * then has exactly one wire module instance whatever the module format.
 */
const wireCoreExternal = {
  name: "fabric-wire-core-external",
  setup(build: {
    onResolve: (o: { filter: RegExp }, cb: (a: { path: string }) => unknown) => void;
  }) {
    build.onResolve({ filter: /^\.\/(wire\/)?core\.js$/ }, () => ({
      path: "./wire/core.cjs",
      external: true,
    }));
  },
};

// tsup builds the configurations below concurrently, so none of them may clean dist/: a
// clean in one could delete what another already wrote (dist/wire/core.cjs). dist/ is
// emptied once, here, before any of them starts.
rmSync("dist", { recursive: true, force: true });

export default defineConfig([
  {
    // The root package: inert, it never imports the wire core.
    entry: ["src/index.ts"],
    format: ["esm", "cjs"],
    dts: true,
    sourcemap: true,
    esbuildOptions: noSources,
    clean: false,
    target: "es2022",
  },
  {
    // The wire core: one CommonJS file, also the Fabric worker's entry. It loads on
    // Node 22 (the package's floor) to report capture unsupported there.
    entry: { "wire/core": "src/wire/core.ts" },
    format: ["cjs"],
    outExtension: () => ({ js: ".cjs" }),
    platform: "node",
    target: "node22",
    dts: false,
    sourcemap: true,
    esbuildOptions: noSources,
    clean: false,
    onSuccess: async () => {
      // The qualification table ships beside the wire core's directory (spec 055 §9.4).
      mkdirSync("dist", { recursive: true });
      copyFileSync("wire-qualification.json", "dist/wire-qualification.json");
    },
  },
  {
    entry: { wire: "src/wire/index.ts", register: "src/register.ts" },
    format: ["esm", "cjs"],
    platform: "node",
    target: "node22",
    dts: { entry: { wire: "src/wire/index.ts" } },
    sourcemap: true,
    esbuildOptions: noSources,
    esbuildPlugins: [wireCoreExternal],
    clean: false,
  },
]);
