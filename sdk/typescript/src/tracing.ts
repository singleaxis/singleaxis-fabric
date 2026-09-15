// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * OTel tracer/provider helpers for the recorder SDK.
 *
 * Mirrors Python `fabric.tracing`: the package's tracer identity, a
 * one-shot "no provider configured" warning so a silent no-op install is
 * loud exactly once, and {@link installDefaultProvider} for hosts that
 * want to install a provider + context manager through the SDK rather
 * than wiring OTel globals by hand.
 *
 * The SDK ships no OTLP exporter itself (exporter choice belongs to the
 * host): pair a `NodeTracerProvider` with a `BatchSpanProcessor` wrapping
 * `OTLPTraceExporter` — or set `OTEL_EXPORTER_OTLP_ENDPOINT` per the
 * README recipe — and register it here.
 */

import {
  context as otelContext,
  trace,
  type ContextManager,
  type Tracer,
  type TracerProvider,
} from "@opentelemetry/api";

import { GEN_AI_SCHEMA_URL, SDK_VERSION } from "./version.js";

/** The tracer name every Fabric span is created under. */
export const TRACER_NAME = "@singleaxis/fabric";

// One-shot latch so a quiet no-op install warns exactly once per process,
// matching Python's `warn_if_noop_provider` (warnings dedupe).
let warnedNoopProvider = false;

/**
 * True when `provider` cannot produce real spans.
 *
 * In JS the global object is a `ProxyTracerProvider` both before AND
 * after registration — `trace.setGlobalTracerProvider` only sets its
 * delegate. So the check must look through the proxy: a proxy whose
 * delegate is still the `NoopTracerProvider` is a no-op; a proxy with a
 * real delegate, or a real provider directly, is not. Mirrors Python's
 * `type(provider).__name__ == "ProxyTracerProvider"` intent.
 */
function isNoopTracerProvider(provider: TracerProvider): boolean {
  const delegate = (provider as { getDelegate?: () => TracerProvider }).getDelegate;
  const resolved = typeof delegate === "function" ? delegate.call(provider) : provider;
  return resolved.constructor?.name === "NoopTracerProvider";
}

/**
 * Return the Fabric tracer. Fetches the global provider when `provider`
 * is omitted, warning once (like Python's `get_tracer`) when it is still
 * the OTel no-op API proxy — the classic footgun where the SDK emits
 * telemetry that silently goes nowhere. Passing an explicit provider
 * skips the check: the host obviously knows what it is doing.
 *
 * The tracer is bound to the SDK {@link SDK_VERSION} and the GenAI
 * semconv {@link GEN_AI_SCHEMA_URL} so produced spans carry the schema
 * they were written against (mirrors Python).
 */
export function getTracer(provider?: TracerProvider): Tracer {
  const resolved = provider ?? trace.getTracerProvider();
  if (provider === undefined && isNoopTracerProvider(resolved) && !warnedNoopProvider) {
    warnedNoopProvider = true;
    console.warn(
      "singleaxis-fabric: no OpenTelemetry TracerProvider is configured; " +
        "emitted telemetry will be silently dropped. Install one — e.g. " +
        "`new NodeTracerProvider({spanProcessors: [new BatchSpanProcessor(new OTLPTraceExporter())]})`" +
        " registered with `provider.register({contextManager: new AsyncLocalStorageContextManager()})`, " +
        "or via `installDefaultProvider({provider, contextManager})` — see the README's " +
        "OpenTelemetry wiring section.",
    );
  }
  return resolved.getTracer(TRACER_NAME, SDK_VERSION, { schemaUrl: GEN_AI_SCHEMA_URL });
}

/** Options for {@link installDefaultProvider}. */
export interface InstallDefaultProviderOptions {
  /**
   * The provider to install globally (e.g. a `NodeTracerProvider` built
   * with an OTLP exporter by the host).
   */
  provider: TracerProvider;
  /**
   * The context manager that keeps span parenting correct across
   * `await`s — for Node this is `AsyncLocalStorageContextManager` from
   * `@opentelemetry/context-async-hooks`. Without one, child spans
   * opened after an `await` lose their parent. Strongly recommended.
   */
  contextManager?: ContextManager;
}

/**
 * Install `options.provider` as the global tracer provider, plus the
 * supplied context manager — the one-line on-ramp for hosts that do not
 * want to touch OTel globals directly.
 *
 * If a real provider is already installed this warns and returns the
 * existing one (mirroring Python's `install_default_provider`). If no
 * context manager is supplied it warns once — `provider.register(...)`
 * normally wires one; without it, span parenting breaks after `await`.
 */
export function installDefaultProvider(options: InstallDefaultProviderOptions): TracerProvider {
  const existing = trace.getTracerProvider();
  if (!isNoopTracerProvider(existing)) {
    console.warn(
      "singleaxis-fabric: a TracerProvider is already installed; " +
        "installDefaultProvider() is a no-op and returns the existing provider. " +
        "Register it yourself first if you intend to replace it.",
    );
    return existing;
  }
  if (options.contextManager !== undefined) {
    options.contextManager.enable();
    otelContext.setGlobalContextManager(options.contextManager);
  } else {
    console.warn(
      "singleaxis-fabric: no contextManager supplied to installDefaultProvider(); " +
        "async span parenting will break after `await`. Pass " +
        "`new AsyncLocalStorageContextManager()` from " +
        "@opentelemetry/context-async-hooks.",
    );
  }
  trace.setGlobalTracerProvider(options.provider);
  warnedNoopProvider = true;
  return options.provider;
}
