// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
import js from "@eslint/js";
import tseslint from "@typescript-eslint/eslint-plugin";
import tsparser from "@typescript-eslint/parser";

export default [
  {
    ignores: ["dist/**", "node_modules/**"],
  },
  js.configs.recommended,
  {
    files: ["**/*.ts"],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: "module",
      },
      globals: {
        // Node.js runtime globals used by the SDK (telemetry warnings,
        // env config, base64 packing). Listed explicitly because the
        // recommended JS config assumes a browser-free but also
        // globals-free environment.
        console: "readonly",
        process: "readonly",
        Buffer: "readonly",
        performance: "readonly",
        TextEncoder: "readonly",
        TextDecoder: "readonly",
        URL: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
      },
    },
    plugins: {
      "@typescript-eslint": tseslint,
    },
    rules: {
      ...tseslint.configs.recommended.rules,
      "@typescript-eslint/no-explicit-any": "off",
      // TypeScript's own checker handles declaration merging (a const and
      // a type sharing one name is the enum-shaped pattern used for the
      // closed vocabularies); the base rule does not understand it.
      "no-redeclare": "off",
    },
  },
];
