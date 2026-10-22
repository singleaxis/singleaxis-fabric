// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Fail-open span recording (spec 049 §7.1 rules 2, 3 and 6), in parity with
 * Python `fabric._safe_span`.
 *
 * Every span the decision line starts goes through {@link safeStartSpan}: a
 * tracer that throws yields a non-recording span, and every recording call on
 * the returned span (attributes, events, status, exception, end) catches a
 * failure, reports it to the span's error handler and returns. A recording
 * failure therefore never escapes into the application, and never replaces
 * the application's own error.
 */

import {
  INVALID_SPAN_CONTEXT,
  trace,
  type Context,
  type Span,
  type SpanOptions,
  type Tracer,
} from "@opentelemetry/api";

type ErrorHandler = (err: unknown) => void;

const HANDLERS = new WeakMap<object, ErrorHandler[]>();
const SAFE = Symbol("fabric.safe-span");

function failed(proxy: object): void {
  for (const handler of HANDLERS.get(proxy) ?? []) {
    try {
      handler(undefined);
    } catch {
      // A handler must not change the application either.
    }
  }
}

const FALLBACKS: Record<string, (proxy: Span) => unknown> = {
  spanContext: () => INVALID_SPAN_CONTEXT,
  isRecording: () => false,
};

/** Wrap `span` so that no method call on it throws. Idempotent. */
export function safeSpan(span: Span): Span {
  if ((span as unknown as Record<symbol, unknown>)[SAFE] === true) return span;
  const proxy: Span = new Proxy(span, {
    get(target, prop, receiver) {
      if (prop === SAFE) return true;
      // A property read (a diagnostic counter) is forwarded as is: its reader
      // guards it. Only recording calls are fail-open and counted.
      const value: unknown = Reflect.get(target, prop, receiver);
      if (typeof value !== "function") return value;
      const method = value as (...args: unknown[]) => unknown;
      return (...args: unknown[]) => {
        try {
          const result = method.apply(target, args);
          return result === target ? proxy : result;
        } catch {
          failed(proxy);
          const fallback = typeof prop === "string" ? FALLBACKS[prop] : undefined;
          return fallback !== undefined ? fallback(proxy) : proxy;
        }
      };
    },
  });
  HANDLERS.set(proxy, []);
  return proxy;
}

/** Report this span's recording failures to `handler` as well. */
export function onRecordingError(span: Span, handler: ErrorHandler): void {
  HANDLERS.get(span)?.push(handler);
}

/** `tracer.startSpan(...)` that never throws: a failing tracer yields a non-recording span. */
export function safeStartSpan(
  tracer: Tracer,
  name: string,
  options?: SpanOptions,
  context?: Context,
): Span {
  let span: Span;
  let tracerFailed = false;
  try {
    span = tracer.startSpan(name, options, context);
  } catch {
    tracerFailed = true;
    span = trace.wrapSpanContext(INVALID_SPAN_CONTEXT);
  }
  const safe = safeSpan(span);
  if (tracerFailed) PENDING_FAILURES.add(safe);
  return safe;
}

const PENDING_FAILURES = new WeakSet<object>();

/** Whether the tracer failed to start `span` (counted once by its owner). */
export function takeStartFailure(span: Span): boolean {
  const failedStart = PENDING_FAILURES.has(span);
  PENDING_FAILURES.delete(span);
  return failedStart;
}
