// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package hostrecords

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"unicode/utf8"
)

// The id key file (id-key-file-v1.json).
const (
	idKeyMin = 16
	idKeyMax = 4096
)

// KeyFileError is a refused key file. Reason is one of the id-key-file-v1
// reasons (mode, too_short, too_long, trailing_newline, nul_byte, not_utf8),
// or unreadable, or for a state key value. It never holds the file's
// contents.
type KeyFileError struct {
	File   string // "id key" or "state key"
	Reason string
}

func (e *KeyFileError) Error() string {
	return "hostrecords: " + e.File + " file refused: " + e.Reason
}

// keyFileMode accepts a regular file of mode 0400 or 0440, reached through
// symlinks as Kubernetes Secret mounts are.
func keyFileMode(path, file string) error {
	info, err := os.Stat(path)
	if err != nil {
		return &KeyFileError{File: file, Reason: "unreadable"}
	}
	if !info.Mode().IsRegular() {
		return &KeyFileError{File: file, Reason: "mode"}
	}
	if perm := info.Mode().Perm(); perm != 0o400 && perm != 0o440 {
		return &KeyFileError{File: file, Reason: "mode"}
	}
	return nil
}

func readBounded(path, file string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, &KeyFileError{File: file, Reason: "unreadable"}
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, &KeyFileError{File: file, Reason: "unreadable"}
	}
	return data, nil
}

// ReadIDKeyFile reads the id key (spec 056 §7.3.3 (b), id-key-file-v1.json):
// the file's bytes unchanged, the key exactly as FABRIC_WIRE_ID_KEY holds it
// (Python uses its UTF-8 bytes). There is no hex or base64 decoding and no
// trimming. The file must be a regular file of mode 0400 or 0440 holding 16
// to 4096 bytes of UTF-8 with no NUL and no final "\n" or "\r"; refusals are
// checked in that order and returned as *KeyFileError.
func ReadIDKeyFile(path string) ([]byte, error) {
	const file = "id key"
	if err := keyFileMode(path, file); err != nil {
		return nil, err
	}
	data, err := readBounded(path, file, idKeyMax)
	if err != nil {
		return nil, err
	}
	return checkIDKey(data)
}

// checkIDKey applies the id-key-file-v1 content rules after the mode check.
func checkIDKey(data []byte) ([]byte, error) {
	const file = "id key"
	switch {
	case len(data) < idKeyMin:
		return nil, &KeyFileError{File: file, Reason: "too_short"}
	case len(data) > idKeyMax:
		return nil, &KeyFileError{File: file, Reason: "too_long"}
	case bytes.HasSuffix(data, []byte("\n")) || bytes.HasSuffix(data, []byte("\r")):
		return nil, &KeyFileError{File: file, Reason: "trailing_newline"}
	case bytes.IndexByte(data, 0) >= 0:
		return nil, &KeyFileError{File: file, Reason: "nul_byte"}
	case !utf8.Valid(data):
		return nil, &KeyFileError{File: file, Reason: "not_utf8"}
	}
	return data, nil
}

// ReadStateKeyFile reads the 32-byte state key that seals epoch.state,
// staging, spool and cursor (053 §6.2.5): a regular file of mode 0400 or 0440
// holding exactly 32 raw bytes, or the standard base64 of 32 bytes followed by
// at most one "\n" (the fabricenvelope extension's key format).
func ReadStateKeyFile(path string) ([]byte, error) {
	const file = "state key"
	if err := keyFileMode(path, file); err != nil {
		return nil, err
	}
	data, err := readBounded(path, file, 64)
	if err != nil {
		return nil, err
	}
	if len(data) == stateKeyBytes {
		return data, nil
	}
	text := bytes.TrimSuffix(data, []byte("\n"))
	if len(text) == base64.StdEncoding.EncodedLen(stateKeyBytes) {
		key, err := base64.StdEncoding.Strict().DecodeString(string(text))
		if err == nil && len(key) == stateKeyBytes {
			return key, nil
		}
	}
	return nil, &KeyFileError{File: file, Reason: "value"}
}
