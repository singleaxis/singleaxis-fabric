// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * How `decision()` emits externally meaningful ids (spec 049 §2.9,
 * decisions 7-8). Mirrors Python `fabric._sequence` (`pseudonym_v2`,
 * `key_id`, `operator_label`, `identity_mode_from_env`, `V2_TYPES`) and
 * `fabric._identity.IdentityPolicy`.
 *
 * `pseudonymous` (default): each id is its keyed v2 pseudonym (`sess-`,
 * `usr-`, `agt-`, `mkey-`, `tgt-` ...), and omitted when no
 * `FABRIC_WIRE_ID_KEY` is set — an unkeyed hash of a low-entropy id is not a
 * pseudonym. `clear` (`FABRIC_IDENTITY_MODE=clear`) reproduces the pre-049
 * output. The key is a secret: never logged and never in an error.
 */

import { createHash, createHmac } from "node:crypto";

/** Environment variable naming the identity mode (049 §2.9 rule 7). */
export const ENV_IDENTITY_MODE = "FABRIC_IDENTITY_MODE";
/** Environment variable holding the pseudonym key (a secret). */
export const ENV_ID_KEY = "FABRIC_WIRE_ID_KEY";
/** `FABRIC_WIRE_LABELS=clear`: operator labels exported as chosen (049 §2.9 rule 7). */
export const ENV_WIRE_LABELS = "FABRIC_WIRE_LABELS";
/** Minimum id-key length in bytes; a shorter key is a configuration error. */
export const MIN_ID_KEY_BYTES = 16;

/** `pseudonymous` (default) or `clear`. */
export type IdentityMode = "pseudonymous" | "clear";

/** Function v2 prefix -> type string (049 §2.9 rule 2), pinned by `pseudonym-v2.json`. */
export const V2_TYPES: Readonly<Record<string, string>> = Object.freeze({
  sess: "session",
  usr: "user",
  act: "actor",
  conv: "conversation",
  turn: "turn",
  trg: "trigger",
  dsp: "dispatch",
  agt: "agent",
  tgt: "target",
  hst: "host",
  sbx: "sandbox",
  mcps: "mcp_session",
  rpc: "jsonrpc",
  dbn: "db_namespace",
  txn: "db_transaction",
  mst: "memory_store",
  mkey: "memory_key",
  p: "provider",
});

/**
 * UTF-8 bytes of `value`, encoding a lone surrogate as its 3-byte form —
 * Python's `value.encode("utf-8", "surrogatepass")`. A well-formed string
 * encodes exactly as `Buffer.from(value, "utf-8")`.
 */
export function utf8SurrogatePass(value: string): Buffer {
  const out: number[] = [];
  for (let i = 0; i < value.length; i++) {
    let code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < value.length) {
      const low = value.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
        i += 1;
      }
    }
    if (code < 0x80) {
      out.push(code);
    } else if (code < 0x800) {
      out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code < 0x10000) {
      out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      out.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f),
      );
    }
  }
  return Buffer.from(out);
}

function keyBytes(key: string | Uint8Array): Uint8Array {
  return typeof key === "string" ? utf8SurrogatePass(key) : key;
}

function typeKey(prefix: string, key: Uint8Array): Buffer {
  const type = V2_TYPES[prefix];
  if (type === undefined) {
    throw new Error("unknown pseudonym v2 prefix");
  }
  return createHmac("sha256", key).update(`fabric-id/v2/${type}`, "utf8").digest();
}

/**
 * Function v1 label pseudonym: `prefix-` + the first 32 hex of
 * HMAC-SHA256(key, value), or of SHA-256(value) without a key. One function
 * for `r-`, `s-`, `svc-` and `lbl-` (pinned by `run-id-pseudonym-v1.json`).
 */
export function labelPseudonym(prefix: string, value: string, key?: string | Uint8Array): string {
  const data = utf8SurrogatePass(value);
  const digest =
    key !== undefined && keyBytes(key).length > 0
      ? createHmac("sha256", keyBytes(key)).update(data).digest("hex")
      : createHash("sha256").update(data).digest("hex");
  return `${prefix}-${digest.slice(0, 32)}`;
}

/**
 * An operator label (049 §4.2: policy ids, workflow nodes) as emitted:
 * `lbl-` + {@link labelPseudonym} (keyed when `key` is set), unchanged only
 * when `clear`.
 */
export function operatorLabel(
  value: string,
  key?: string | Uint8Array,
  options: { clear?: boolean } = {},
): string {
  return options.clear === true ? value : labelPseudonym("lbl", value, key);
}

/**
 * Function v2 (049 §2.9): `prefix-` + the first 32 hex of
 * HMAC-SHA256(k_type, value), k_type = HMAC-SHA256(key, `"fabric-id/v2/" +
 * type`). `value` is used exactly as given (no trimming or case folding).
 * `undefined` without a key: the id is omitted.
 */
export function pseudonymV2(
  prefix: string,
  value: string,
  key: string | Uint8Array | undefined,
): string | undefined {
  if (key === undefined) {
    return undefined;
  }
  const digest = createHmac("sha256", typeKey(prefix, keyBytes(key)))
    .update(utf8SurrogatePass(value))
    .digest("hex");
  return `${prefix}-${digest.slice(0, 32)}`;
}

/** The id key's public id (049 §2.9 rule 6): `kid-` + 8 hex; never the key. */
export function keyId(key: string | Uint8Array): string {
  const digest = createHmac("sha256", keyBytes(key)).update("fabric-id/v2/kid", "utf8").digest();
  return "kid-" + digest.toString("hex").slice(0, 8);
}

/**
 * Validate an identity mode. Fixed-text error: never echoes the value.
 * `source` names the config surface in the message.
 */
export function checkIdentityMode(value: unknown, source: string = "identityMode"): IdentityMode {
  if (value !== "pseudonymous" && value !== "clear") {
    throw new Error(`${source} must be 'pseudonymous' or 'clear'`);
  }
  return value;
}

/**
 * `FABRIC_IDENTITY_MODE`: unset/empty/`pseudonymous` (default) or `clear`;
 * anything else throws (fixed text, never the value).
 */
export function identityModeFromEnv(env: Record<string, string | undefined>): IdentityMode {
  const value = (env[ENV_IDENTITY_MODE] || "pseudonymous").trim();
  return checkIdentityMode(value, ENV_IDENTITY_MODE);
}

/** The key's bytes when at least {@link MIN_ID_KEY_BYTES}, else a fixed-text error. */
export function checkIdKey(key: string | Uint8Array): Uint8Array {
  const bytes = typeof key === "string" || key instanceof Uint8Array ? keyBytes(key) : undefined;
  if (bytes === undefined || bytes.length < MIN_ID_KEY_BYTES) {
    throw new Error(`${ENV_ID_KEY} must be at least ${MIN_ID_KEY_BYTES} bytes`);
  }
  return bytes;
}

/** `FABRIC_WIRE_ID_KEY` as UTF-8 bytes (unset or empty: `undefined`); a secret. */
export function idKeyFromEnv(env: Record<string, string | undefined>): Uint8Array | undefined {
  const value = env[ENV_ID_KEY];
  return value ? checkIdKey(value) : undefined;
}

let warnedMissingKey = false;

/**
 * The resolved identity mode and id key of one Fabric client. The key and
 * the per-type derived keys live in `#private` fields: no enumerable or
 * serialized secret state (`JSON.stringify` and `util.inspect` show only
 * `mode` and `keyed`).
 */
export class IdentityPolicy {
  readonly mode: IdentityMode;
  readonly keyed: boolean;
  /** `FABRIC_WIRE_LABELS=clear`: operator labels as chosen (ids stay mapped). */
  readonly labelsClear: boolean;
  readonly #key: Uint8Array | undefined;
  readonly #typeKeys = new Map<string, Buffer>();

  constructor(mode: IdentityMode, key?: Uint8Array, labelsClear = false) {
    this.mode = checkIdentityMode(mode);
    this.#key = key === undefined ? undefined : checkIdKey(key);
    this.keyed = this.#key !== undefined;
    this.labelsClear = labelsClear;
  }

  /**
   * `mode`/`key` as given, else from `FABRIC_IDENTITY_MODE` and
   * `FABRIC_WIRE_ID_KEY`; an invalid value throws (fixed text). Warns once
   * per process when pseudonymous without a key (class-only text).
   */
  static resolve(
    mode: IdentityMode | undefined,
    key: string | Uint8Array | undefined,
    env: Record<string, string | undefined>,
  ): IdentityPolicy {
    const policy = new IdentityPolicy(
      mode !== undefined ? checkIdentityMode(mode) : identityModeFromEnv(env),
      key !== undefined ? checkIdKey(key) : idKeyFromEnv(env),
      (env[ENV_WIRE_LABELS] ?? "").trim() === "clear",
    );
    if (policy.mode === "pseudonymous" && !policy.keyed && !warnedMissingKey) {
      warnedMissingKey = true;
      console.warn(
        "Warning: fabric: identity mode is pseudonymous and FABRIC_WIRE_ID_KEY is not set; " +
          "session, user and other caller-supplied ids are omitted from telemetry",
      );
    }
    return policy;
  }

  get clear(): boolean {
    return this.mode === "clear";
  }

  /** `value` as emitted: clear, its v2 pseudonym, or `undefined` (omitted). */
  id(prefix: string, value: string): string | undefined {
    if (this.clear) {
      return value;
    }
    if (this.#key === undefined) {
      return undefined;
    }
    let kType = this.#typeKeys.get(prefix);
    if (kType === undefined) {
      kType = typeKey(prefix, this.#key);
      this.#typeKeys.set(prefix, kType);
    }
    const digest = createHmac("sha256", kType).update(utf8SurrogatePass(value)).digest("hex");
    return `${prefix}-${digest.slice(0, 32)}`;
  }

  /**
   * A caller id whose type has no v2 prefix yet (idempotency key, document
   * id) as emitted: clear, the keyed generic label `lbl-` (049 §2.9 rule 3),
   * or `undefined` without a key (an unkeyed hash of a low-entropy id is not
   * a pseudonym).
   */
  opaque(value: string): string | undefined {
    if (this.clear) {
      return value;
    }
    return this.#key === undefined ? undefined : labelPseudonym("lbl", value, this.#key);
  }

  /**
   * An operator label (step name, tool name, tag; 049 §4.2) as emitted:
   * clear in `clear` mode or with `FABRIC_WIRE_LABELS=clear`, else the keyed
   * `lbl-` label, or `undefined` without a key.
   */
  label(value: string): string | undefined {
    return this.labelsClear ? value : this.opaque(value);
  }

  /** Each of `values` as {@link label} emits it; the omitted ones dropped. */
  labels(values: readonly string[]): string[] {
    const out: string[] = [];
    for (const value of values) {
      const emitted = this.label(value);
      if (emitted !== undefined) out.push(emitted);
    }
    return out;
  }

  toJSON(): Record<string, unknown> {
    return { mode: this.mode, keyed: this.keyed };
  }
}

/** Re-arm the once-per-process missing-key warning (tests only). */
export function resetIdentityWarningsForTesting(): void {
  warnedMissingKey = false;
}

const MINT = Symbol("fabric.emitted-id");
const ISSUERS = new WeakMap<EmittedId, string>();

/**
 * An id a Fabric recorder emitted or minted (spec 049 §2.9; Sol P0-A round 6 #1), in
 * parity with Python `fabric._sequence.EmittedId`. Provenance is carried by the value's
 * type, never looked up in a bounded cache: the recorder that issued it (or one holding
 * the same id key) passes it through unchanged for as long as the caller holds it, so
 * joins never drift. A plain string is always caller input and is always mapped, whatever
 * its shape. Only Fabric mints these; `String(id)`, `` `${id}` `` and JSON give the value.
 */
export class EmittedId {
  readonly #value: string;

  constructor(token: symbol, value: string, issuer: string) {
    if (token !== MINT)
      throw new Error("EmittedId values are minted by Fabric; pass caller ids as plain strings");
    this.#value = value;
    ISSUERS.set(this, issuer);
  }

  get value(): string {
    return this.#value;
  }

  toString(): string {
    return this.#value;
  }

  valueOf(): string {
    return this.#value;
  }

  toJSON(): string {
    return this.#value;
  }
}

/** Mint an {@link EmittedId} for `issuer` (internal: not exported from the package). */
export function mintEmittedId(value: string, issuer: string): EmittedId {
  return new EmittedId(MINT, value, issuer);
}

/** Whether `value` is an {@link EmittedId} issued by `issuer` (internal). */
export function issuedBy(value: unknown, issuer: string): value is EmittedId {
  return value instanceof EmittedId && ISSUERS.get(value) === issuer;
}
