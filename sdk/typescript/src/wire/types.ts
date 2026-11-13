// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Immutable internal DTOs of the wire core (spec 055 §4.1, §4.2): endpoint matchers, the
 * validated configuration, the OTLP delivery route and the registry check shapes the
 * generated tables use. Plain data only: no class carries a secret in a printable field,
 * and every value is frozen by the code that builds it.
 */

/** Wire API dialect of an endpoint (047 §2). */
export type Dialect = "openai" | "anthropic";

/** A recognized model API (`fabric.wire.api`). */
export type WireApi =
  | "openai.chat_completions"
  | "openai.responses"
  | "openai.completions"
  | "openai.embeddings"
  | "anthropic.messages";

/** One endpoint matcher (Python `wire/_model.py` `EndpointMatcher`). */
export interface EndpointMatcher {
  readonly endpointId: string;
  readonly dialect: Dialect;
  readonly hosts: readonly string[];
  readonly hostSuffixes: readonly string[];
  /** Absent: any port of an allowed scheme (its default port included). */
  readonly ports: readonly number[] | undefined;
  readonly pathPrefix: string;
  readonly providerName: string;
  readonly schemes: readonly ("http" | "https")[];
}

/** `FABRIC_IDENTITY_MODE` and `FABRIC_WIRE_LABELS` values. */
export type ExposureMode = "pseudonymous" | "clear";

/**
 * One OTLP signal's resolved delivery settings (Python `tracing.OtlpSettings`; spec 048 §3,
 * spec 058 §6.4). Only header *names* are ever shown; values are credentials.
 */
export interface OtlpRoute {
  /** `fabric`: `FABRIC_OTLP_*` (then nothing from `OTEL_EXPORTER_OTLP_*`); `otel`. */
  readonly route: "fabric" | "otel";
  /**
   * The endpoint as Python resolves it: the signal URL on the `fabric` route, the
   * variable's value on the `otel` route; undefined when none is set.
   */
  readonly endpoint: string | undefined;
  /** The URL Fabric posts this signal to (a general endpoint gets `/v1/<signal>`). */
  readonly signalUrl: string | undefined;
  /** The variable the endpoint came from (a diagnostic names it). */
  readonly endpointName: string | undefined;
  readonly headers: Readonly<Record<string, string>>;
  readonly certificate: string | undefined;
  readonly clientCertificate: string | undefined;
  readonly clientKey: string | undefined;
  readonly timeoutMs: number;
  readonly protocol: string;
  readonly compression: string | undefined;
}

/** Secrets, kept apart from everything printable. */
export interface WireSecrets {
  readonly idKey: Uint8Array | undefined;
  readonly spoolKey: Uint8Array | undefined;
  readonly tokenizationKey: Uint8Array | undefined;
}

/**
 * The validated wire configuration (Python `WireConfig` plus the run, records and
 * delivery settings of `install_from_env`). Built only by `config.ts`.
 */
export interface WireSettings {
  readonly autoload: boolean;
  readonly undici: boolean;
  readonly nodeHttp: boolean;
  readonly diagnostics: "silent" | "stderr";
  readonly otelSdkDisabled: boolean;
  readonly endpointTableVersion: number;
  readonly builtinEndpoints: "table" | "legacy";
  readonly endpoints: readonly EndpointMatcher[];
  readonly extraEndpoints: readonly EndpointMatcher[];
  readonly labels: ExposureMode;
  readonly identityMode: ExposureMode;
  readonly sourceId: string | undefined;
  readonly tenantId: string | undefined;
  /** `node` (content goes to the Fabric Node), a `file:///abs/dir` store, or undefined. */
  readonly store:
    { readonly kind: "node" } | { readonly kind: "file"; readonly root: string } | undefined;
  readonly contentEndpoint: string | undefined;
  readonly spoolDir: string | undefined;
  readonly spoolMaxBytes: bigint;
  readonly spoolMaxReceipts: number;
  readonly spoolDurableBoundary: string | undefined;
  readonly spoolMigratePlaintext: boolean;
  readonly capturePolicyPath: string | undefined;
  readonly redactionEndpoint: string | undefined;
  readonly redactionTokenFile: string | undefined;
  readonly modelAllowlist: readonly string[];
  readonly maxBodyBytes: number;
  readonly maxRetainBytes: number;
  readonly partMinBytes: number;
  readonly maxInflightBytes: bigint;
  readonly queueMaxItems: number;
  readonly shutdownTimeoutMs: number;
  readonly drainOnExitMs: number;
  readonly contentBatchBodies: number;
  readonly contentConcurrency: number;
  readonly proxy: string | undefined;
  /** Capture span delivery (`traces`). */
  readonly otlp: OtlpRoute;
  /** Node content delivery (`logs`); undefined outside node mode. */
  readonly otlpLogs: OtlpRoute | undefined;
  readonly runId: string | undefined;
  readonly resumeTokens: readonly string[];
  readonly openDeadlineS: number;
  readonly recordsStrict: boolean;
  readonly recordsMaxObjectBytes: number;
  readonly clockUncertaintyNs: bigint;
  readonly providerRequestId: boolean;
  readonly statusFile: string | undefined;
  /**
   * Fixed-text notes for settings Python also tolerates by falling back to the default
   * (`FABRIC_RUN_OPEN_DEADLINE_S`, `FABRIC_CLOCK_UNCERTAINTY_MS` out of range).
   */
  readonly settingWarnings: readonly string[];
  readonly secrets: WireSecrets;
}

/** One diagnostics catalogue entry (`contracts/diagnostics/v1/messages-v1.json`). */
export interface CatalogueEntry {
  readonly id: string;
  readonly name: string;
  readonly severity: "error" | "warning" | "info";
  /** Absent: a Python entry (spec 055 §4.7). */
  readonly sdk?: readonly ("python" | "typescript")[];
  readonly text: string;
  readonly fix: string;
  readonly retired?: boolean;
}

// ----------------------------------------------------------------- registry check shapes

/** One closed telemetry-key check (`telemetry-keys-v1.json` `check`/`capture_check`). */
export type KeyCheck =
  | { readonly type: "never" }
  | { readonly type: "bool" }
  | { readonly type: "datetime" }
  | { readonly type: "enum"; readonly values: readonly string[]; readonly source?: string }
  | { readonly type: "const"; readonly value: string | number | boolean; readonly span?: string }
  | { readonly type: "int"; readonly min: number | bigint; readonly max?: number | bigint }
  | { readonly type: "number"; readonly min: number; readonly max?: number }
  | {
      readonly type: "string";
      /** JavaScript syntax (`(?<name>...)`); the generator converts Python's `(?P<name>`. */
      readonly pattern: string;
      readonly int64_groups?: readonly string[];
      readonly capture_labels?: { readonly group?: string; readonly pseudonymous_pattern: string };
    }
  | {
      readonly type: "array";
      readonly items: KeyCheck;
      readonly max_items: number;
      readonly min_items?: number;
      readonly unique?: boolean;
    };

/** The part of a check every shape may carry. */
export interface KeyCheckCommon {
  readonly identity_mode?: { readonly clear?: string };
}

/** One telemetry key row, as the generated table carries it. */
export interface TelemetryKeyRow {
  readonly check?: KeyCheck & KeyCheckCommon;
  readonly capture_check?: KeyCheck & KeyCheckCommon;
  readonly placement?: readonly string[];
  readonly capture_points?: readonly string[];
  readonly capture_point_kinds?: readonly string[];
  readonly manifest_property?: string;
}
