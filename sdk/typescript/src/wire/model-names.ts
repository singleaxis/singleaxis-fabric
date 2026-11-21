// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The model-name exposure rule (spec 048 §7, H4; Python `fabric._model_names`): a provider
 * `model` value is emitted as is only when it matches the 047 pattern, has no `://` and is
 * allowlisted; any other string becomes `m-` + 16 hex of its SHA-256. A `prefix*` entry
 * matches only a suffix of version tokens (J2, J2b). Pinned by
 * `contracts/capture/v1/fixtures/model-names/model-exposure-v1.json`.
 */
import { createHash } from "node:crypto";

import { utf8SurrogatePass } from "../identity.js";

const MODEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
export const DEFAULT_MODEL_ALLOWLIST: readonly string[] = Object.freeze([
  "gpt-*", "o1*", "o3*", "o4*", "chatgpt-*", "claude-*", "gemini-*", "text-embedding-*",
  "llama*", "meta-llama/*", "mistral*", "mixtral*", "codestral*", "command*", "deepseek*",
  "qwen*", "grok*", "anthropic/*", "openai/*", "google/*",
]); // prettier-ignore
const SUFFIX_TOKEN = /[^-._:/@]+/g;
const VERSION_TOKEN = /^(?:v?[0-9]+[a-z]{0,2}|[0-9]+[a-z][0-9]*|[a-z][0-9]+)$/;
const NUMBER = /^[0-9]+$/;
const DATE = /^20[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])$/;
const LONG_DIGIT_RUN = /[0-9]{5}/;
const MAX_SUFFIX_NUMBERS = 2;
const MAX_NUMBER_DIGITS = 4;
const MAX_SUFFIX_DATES = 1;
const MAX_SUFFIX_DIGITS = 6;
const SUFFIX_WORDS: ReadonlySet<string> = new Set([
  "mini", "nano", "micro", "turbo", "preview", "latest", "instruct", "chat", "vision",
  "audio", "realtime", "search", "codex", "embedding", "embed", "large", "small", "medium",
  "base", "pro", "flash", "lite", "ultra", "sonnet", "opus", "haiku", "exp", "thinking",
  "reasoning", "coder", "code", "omni", "hd", "fast", "high", "low", "it", "hf", "gguf",
  "fp8", "fp16", "bf16", "awq", "gptq", "q4", "q8",
]); // prettier-ignore

const validName = (value: string): boolean => MODEL_PATTERN.test(value) && !value.includes("://");
const digits = (token: string | undefined, most = MAX_NUMBER_DIGITS): boolean =>
  token !== undefined && NUMBER.test(token) && token.length <= most;

/** Whether `suffix` (what follows a `prefix*` entry's prefix) is only version tokens. */
export function versionSuffix(suffix: string): boolean {
  const matches = [...suffix.matchAll(SUFFIX_TOKEN)];
  const tokens = matches.map((m) => m[0]);
  const seps = matches.slice(1).map((m, i) => {
    const prev = matches[i]!;
    return suffix.slice(prev.index + prev[0].length, m.index);
  });
  let numbers = 0;
  let dates = 0;
  let index = 0;
  while (index < tokens.length) {
    const token = tokens[index]!;
    const ahead = tokens.slice(index, index + 3);
    const between = seps.slice(index, index + 2);
    if (
      between.length === 2 &&
      between[0] === "-" &&
      between[1] === "-" &&
      DATE.test(ahead.join("")) &&
      ahead.map((t) => t.length).join() === "4,2,2" &&
      ahead.every((t) => digits(t))
    ) {
      dates += 1; // 20YY-MM-DD as three tokens: one date
      index += 3;
    } else if (between[0] === "." && digits(token, 2) && digits(ahead[1], 2)) {
      numbers += 1; // a decimal version N.N: one number
      index += 2;
    } else if (NUMBER.test(token)) {
      if (DATE.test(token)) dates += 1;
      else if (token.length <= MAX_NUMBER_DIGITS) numbers += 1;
      else return false;
      index += 1;
    } else if (
      (VERSION_TOKEN.test(token) || SUFFIX_WORDS.has(token)) &&
      !LONG_DIGIT_RUN.test(token)
    ) {
      index += 1;
    } else {
      return false;
    }
  }
  if (numbers > MAX_SUFFIX_NUMBERS || dates > MAX_SUFFIX_DATES) return false;
  const count = [...suffix].filter((c) => c >= "0" && c <= "9").length;
  return count - 8 * dates <= MAX_SUFFIX_DIGITS;
}

/** Whether `value` is emitted as is under the default list plus `allowlist`. */
export function modelAllowed(value: unknown, allowlist: readonly string[] = []): boolean {
  if (typeof value !== "string" || !validName(value)) return false;
  for (const entry of [...DEFAULT_MODEL_ALLOWLIST, ...allowlist]) {
    if (value === entry) return true;
    const prefix = entry.slice(0, -1);
    if (
      entry.endsWith("*") &&
      value.startsWith(prefix) &&
      versionSuffix(value.slice(prefix.length))
    ) {
      return true;
    }
  }
  return false;
}

/** `m-` + 16 hex of the value's SHA-256. */
export function hashedModel(value: string): string {
  return "m-" + createHash("sha256").update(utf8SurrogatePass(value)).digest("hex").slice(0, 16);
}

/** The telemetry form of a model value; `undefined` (omitted) unless a non-empty string. */
export function exposeModel(value: unknown, allowlist: readonly string[] = []): string | undefined {
  if (typeof value !== "string" || value === "") return undefined;
  return modelAllowed(value, allowlist) ? value : hashedModel(value);
}
