// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
// A customer transformer that never returns (a synchronous infinite loop).
export function redact() {
    for (;;) {
        // never yields
    }
}
