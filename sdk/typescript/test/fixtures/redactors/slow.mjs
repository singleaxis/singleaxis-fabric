// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/* global TextEncoder */
// A slow customer transformer: blocks its own thread for 200 ms, then masks.
export function redact() {
    const end = Date.now() + 200;
    while (Date.now() < end) {
        // busy: a synchronous redactor that would block the application's event loop
    }
    return new TextEncoder().encode("[slow-redacted]");
}
