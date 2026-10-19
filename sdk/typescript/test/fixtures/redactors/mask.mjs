// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/* global TextEncoder */
// A customer transformer module: replaces the whole object with a fixed mask.
export function redact() {
    return new TextEncoder().encode("[redacted]");
}

export default redact;
