// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Package fabricenvelopeextension encrypts a Fabric Node's persistent sending
// queue at rest (spec 049 §7.8, decision 19).
//
// The fabriccontent exporter's persistent queue holds content before backend
// delivery: under retain_original, original model bytes. This storage
// extension wraps another storage extension (file_storage) and seals every
// value it persists in the AES-256-GCM customer-key envelope of the agent's
// byte spool (magic | 12-byte nonce | ciphertext and tag), with additional
// authenticated data that binds the value to its storage client and key. Keys
// (queue indexes) are not content and stay as the queue wrote them. The queue
// itself is unchanged, so delivery semantics (backpressure, retry until the
// store accepts) are unchanged.
//
// The key comes from a file (a mounted Secret), never from a configuration
// literal; it is 32 raw bytes or their standard base64 with an optional
// trailing newline. A value that fails authentication (tampered, truncated,
// another key) is an error, never plaintext: the queue then discards that
// item or, for its own index metadata, starts a new queue. Nothing is ever
// delivered unauthenticated. Errors carry no value, key or path.
package fabricenvelopeextension
