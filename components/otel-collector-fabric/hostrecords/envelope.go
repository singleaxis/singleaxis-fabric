// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package hostrecords

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
)

// The host-state envelope (053 §6.2.5 revision 3, host-state-envelope-v1.json):
// fabricenvelopeextension's construction with the host-records magic and
// schema, magic | 12-byte nonce | AES-256-GCM ciphertext and tag, the
// additional data the canonical JSON array [schema, state kind].
const (
	envelopeMagic  = "FABRIC-HOST-RECORDS-1\n"
	envelopeSchema = "fabric.host-records/v1"
	nonceBytes     = 12
	stateKeyBytes  = 32
	// maxSealBytes bounds one sealed state object, far above any staged batch
	// and small enough that the envelope's length cannot overflow an int,
	// even on a 32-bit build.
	maxSealBytes = 1 << 30
)

// The state kinds a host sensor seals.
const (
	StateEpoch   = "epoch"
	StateStaging = "staging"
	StateSpool   = "spool"
	StateCursor  = "cursor"
)

var (
	errStateKey   = errors.New("hostrecords: the state key must be 32 bytes")
	errStateKind  = errors.New("hostrecords: unknown state kind")
	errStateOpen  = errors.New("hostrecords: sealed state failed authentication")
	errStateSize  = errors.New("hostrecords: state object too large to seal")
	errRandomness = errors.New("hostrecords: no randomness")
)

// randReader is the CSPRNG; tests replace it to fix nonces, epochs and ids.
var randReader io.Reader = rand.Reader

func stateKind(kind string) bool {
	switch kind {
	case StateEpoch, StateStaging, StateSpool, StateCursor:
		return true
	}
	return false
}

func envelopeAAD(kind string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode([]string{envelopeSchema, kind})
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != stateKeyBytes {
		return nil, errStateKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errStateKey
	}
	return cipher.NewGCM(block)
}

// Seal seals one state object of the given kind (epoch, staging, spool or
// cursor) with the 32-byte state key and a fresh random nonce.
func Seal(key []byte, kind string, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, nonceBytes)
	if _, err := io.ReadFull(randReader, nonce); err != nil {
		return nil, errRandomness
	}
	return sealWithNonce(key, kind, nonce, plaintext)
}

func sealWithNonce(key []byte, kind string, nonce, plaintext []byte) ([]byte, error) {
	if !stateKind(kind) {
		return nil, errStateKind
	}
	if len(plaintext) > maxSealBytes {
		return nil, errStateSize
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(envelopeMagic)+nonceBytes+len(plaintext)+aead.Overhead())
	out = append(out, envelopeMagic...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, envelopeAAD(kind)), nil
}

// Unseal authenticates and opens a state object of the expected kind. An
// envelope of another kind, another magic, a changed byte or a short envelope
// is refused; a refused state refuses start (the sensor never runs on
// unauthenticated state).
func Unseal(key []byte, kind string, envelope []byte) ([]byte, error) {
	if !stateKind(kind) {
		return nil, errStateKind
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	header := len(envelopeMagic) + nonceBytes
	if len(envelope) < header+aead.Overhead() || !bytes.HasPrefix(envelope, []byte(envelopeMagic)) {
		return nil, errStateOpen
	}
	plaintext, err := aead.Open(nil, envelope[len(envelopeMagic):header], envelope[header:], envelopeAAD(kind))
	if err != nil {
		return nil, errStateOpen
	}
	return plaintext, nil
}
