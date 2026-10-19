// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/* global TextDecoder */
// A customer transformer that throws with the content in its message.
export function redact(data) {
    throw new Error("redactor failed on " + new TextDecoder().decode(data));
}
