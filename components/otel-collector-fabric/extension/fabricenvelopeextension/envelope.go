// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricenvelopeextension

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
)

// The queue envelope (spec 049 §7.8): the construction of the agent's byte
// spool (byte_spool.py) with its own magic and schema, so a queue value can
// never be mistaken for a spool record or a Node content object.
const (
	queueMagic  = "FABRIC-NODE-QUEUE-1\n"
	queueSchema = "fabric.node-queue-envelope/v1"
	keyBytes    = 32
	nonceBytes  = 12
	// maxKeyFile bounds what is read from the key file.
	maxKeyFile = 64
)

var (
	errKeyFile  = errors.New("fabricenvelope: key file is not readable")
	errKeyMode  = errors.New("fabricenvelope: key file must be a regular file without group-write or other permissions")
	errKeyValue = errors.New("fabricenvelope: key file must hold 32 raw bytes or their base64")
	errOpen     = errors.New("fabricenvelope: stored value failed authentication")
)

// loadKey reads a 32-byte AES-256 key from path: exactly 32 raw bytes, or
// the standard base64 of 32 bytes followed by at most one newline. The file
// may be reached through symlinks (Kubernetes Secret mounts are) but must be
// a regular file that neither group-writes nor grants other access.
func loadKey(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, errKeyFile
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o027 != 0 {
		return nil, errKeyMode
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errKeyFile
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, errKeyFile
	}
	return parseKey(data)
}

// parseKey accepts 32 raw bytes, or 44 base64 characters (optionally with
// one trailing "\n") that decode to 32 bytes.
func parseKey(data []byte) ([]byte, error) {
	if len(data) == keyBytes {
		return append([]byte(nil), data...), nil
	}
	text := bytes.TrimSuffix(data, []byte("\n"))
	if len(text) != base64.StdEncoding.EncodedLen(keyBytes) {
		return nil, errKeyValue
	}
	key, err := base64.StdEncoding.Strict().DecodeString(string(text))
	if err != nil || len(key) != keyBytes {
		return nil, errKeyValue
	}
	return key, nil
}

// sealer is one AES-256-GCM key with a fixed magic and schema.
type sealer struct {
	aead   cipher.AEAD
	magic  string
	schema string
}

func newSealer(key []byte, magic, schema string) (*sealer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errKeyValue
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errKeyValue
	}
	return &sealer{aead: aead, magic: magic, schema: schema}, nil
}

// aad is the canonical JSON array [schema, scope...] (Python's
// json.dumps(..., sort_keys=True, separators=(",", ":"))).
func (s *sealer) aad(scope ...string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(append([]string{s.schema}, scope...))
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

// seal returns magic | nonce | ciphertext+tag.
func (s *sealer) seal(plaintext []byte, scope ...string) ([]byte, error) {
	nonce := make([]byte, nonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("fabricenvelope: no randomness")
	}
	out := make([]byte, 0, len(s.magic)+nonceBytes+len(plaintext)+s.aead.Overhead())
	out = append(out, s.magic...)
	out = append(out, nonce...)
	return s.aead.Seal(out, nonce, plaintext, s.aad(scope...)), nil
}

// open authenticates and decrypts an envelope; anything else is errOpen.
func (s *sealer) open(envelope []byte, scope ...string) ([]byte, error) {
	header := len(s.magic) + nonceBytes
	if len(envelope) < header+s.aead.Overhead() || string(envelope[:len(s.magic)]) != s.magic {
		return nil, errOpen
	}
	plaintext, err := s.aead.Open(nil, envelope[len(s.magic):header], envelope[header:], s.aad(scope...))
	if err != nil {
		return nil, errOpen
	}
	return plaintext, nil
}
