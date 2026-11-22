// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Spec 055 §3.1 (unit 055-t17 review): the hook decides whether Node's bundled undici
 * published a call by reading V8 call sites, and must run no application code while it
 * does. An application or library may replace the static `Error.captureStackTrace`; the
 * hook uses V8's own, taken when the module loads. Its own file, so that no earlier test
 * has already decided (and cached) the bundled `Request` class.
 */
import { afterEach, expect, it } from "vitest";

import {
  CHAT,
  type Capture,
  PUBLISHES_BODIES,
  type Provider,
  capture,
  provider,
  settle,
} from "./helpers.js";

let server: Provider | undefined;
let cap: Capture | undefined;
afterEach(async () => {
  cap?.close();
  cap = undefined;
  await server?.close();
  server = undefined;
});

it.runIf(PUBLISHES_BODIES)(
  "an application's replacement Error.captureStackTrace is never called; global fetch is still captured",
  async () => {
    server = await provider();
    server.route(CHAT, (_req, res) => res.end('{"ok":true}'));
    cap = capture(server.port, { publishers: "bundled" });
    const E = Error as unknown as { captureStackTrace: (target: object) => void };
    const original = E.captureStackTrace;
    let called = 0;
    E.captureStackTrace = (target: object): void => {
      called++;
      original(target);
    };
    try {
      const response = await fetch(server.base + CHAT, { method: "POST", body: '{"q":2}' });
      expect(await response.text()).toBe('{"ok":true}');
    } finally {
      E.captureStackTrace = original;
    }
    await settle();
    expect(called).toBe(0);
    const out = cap.drained();
    expect(out.losses).toEqual([]);
    expect(out.jobs.map((j) => j.requestBytes.toString())).toEqual(['{"q":2}']);
  },
);
