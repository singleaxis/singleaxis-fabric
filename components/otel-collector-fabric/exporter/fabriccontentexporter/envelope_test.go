// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/component/componenttest"
)

const (
	envelopeVector = "../../../../contracts/content/v2/fixtures/node-envelope-v1.json"
	contentCanary  = "PRIVATE-CONTENT-CANARY-Jane-Doe-0042"
)

var envelopeKey = bytes.Repeat([]byte{0x5a}, keyBytes)

func keyFile(t *testing.T, data []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "content.key")
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func testSealer(t *testing.T, key []byte) *sealer {
	t.Helper()
	s, err := newSealer(key, contentMagic, contentSchema)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The contract vector pins the construction for every reader (the SDK's
// fabric.reconstruct opens exactly these bytes).
func TestNodeEnvelopeVector(t *testing.T) {
	var v struct {
		Schema string `json:"schema_version"`
		Cases  []struct {
			Name      string `json:"name"`
			KeyB64    string `json:"key_base64"`
			Rel       string `json:"path"`
			AAD       string `json:"aad"`
			Plaintext string `json:"plaintext_base64"`
			Envelope  string `json:"envelope_base64"`
			Valid     bool   `json:"valid"`
		} `json:"cases"`
	}
	decodeFile(t, envelopeVector, &v)
	if v.Schema != "fabric.node-envelope-vectors/v1" || len(v.Cases) < 3 {
		t.Fatalf("unexpected vector file: %s, %d cases", v.Schema, len(v.Cases))
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			key, _ := base64.StdEncoding.DecodeString(c.KeyB64)
			s := testSealer(t, key)
			if got := string(s.aad(c.Rel)); got != c.AAD {
				t.Fatalf("aad %q, vector %q", got, c.AAD)
			}
			envelope, _ := base64.StdEncoding.DecodeString(c.Envelope)
			plaintext, err := s.open(envelope, c.Rel)
			if c.Valid {
				want, _ := base64.StdEncoding.DecodeString(c.Plaintext)
				if err != nil || !bytes.Equal(plaintext, want) {
					t.Fatalf("vector does not open: %v", err)
				}
			} else if !errors.Is(err, errOpen) {
				t.Fatalf("invalid vector opened: %v", err)
			}
		})
	}
}

func TestKeyFileFormatsAndModes(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString(envelopeKey)
	for _, data := range [][]byte{envelopeKey, []byte(b64), []byte(b64 + "\n")} {
		if key, err := loadKey(keyFile(t, data, 0o400)); err != nil || !bytes.Equal(key, envelopeKey) {
			t.Fatalf("key not loaded: %v", err)
		}
	}
	for _, data := range [][]byte{envelopeKey[:16], []byte(hex.EncodeToString(envelopeKey)), []byte(b64 + "\n\n"), {}} {
		if _, err := loadKey(keyFile(t, data, 0o600)); !errors.Is(err, errKeyValue) {
			t.Fatalf("malformed key accepted: %v", err)
		}
	}
	if _, err := loadKey(keyFile(t, envelopeKey, 0o644)); !errors.Is(err, errKeyMode) {
		t.Fatalf("world-readable key accepted: %v", err)
	}
}

func readSealed(t *testing.T, s *sealer, path, rel string) []byte {
	t.Helper()
	raw := readFile(t, path)
	if !bytes.HasPrefix(raw, []byte(contentMagic)) || bytes.Contains(raw, []byte(contentCanary)) {
		t.Fatalf("%s is not sealed", filepath.Base(path))
	}
	plain, err := s.open(raw, rel)
	if err != nil {
		t.Fatalf("%s does not open: %v", filepath.Base(path), err)
	}
	return plain
}

// Spec 049 §7.8: with a Node-side key the directory backend writes every
// object and descriptor in the envelope; replay and conflict compare
// plaintext; a corrupt or foreign envelope is never overwritten or read.
func TestEncryptedDirectoryBackend(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "content")
	cfg := boundConfig(dir)
	cfg.File.EncryptionKeyFile = keyFile(t, []byte(base64.StdEncoding.EncodeToString(envelopeKey)+"\n"), 0o600)
	e, logs := observedExporter(t, cfg, nil)
	body := []byte(`{"messages":"` + contentCanary + `"}`)
	if err := e.pushLogs(context.Background(), makeLogs(t, withBody(boundAttrs(body), body))); err != nil {
		t.Fatal(err)
	}
	s := testSealer(t, envelopeKey)
	obj := shardedObject(dir, testTenant, testObjectID)
	meta := shardedMeta(dir, testTenant, testObjectID)
	if got := readSealed(t, s, obj, testTenant+"/evidence/"+testObjectID); !bytes.Equal(got, body) {
		t.Fatalf("object plaintext = %q", got)
	}
	descriptor := readSealed(t, s, meta, testTenant+"/evidence/meta/"+testObjectID+".json")
	if !strings.Contains(string(descriptor), `"ref": "file://`+filepath.Join(dir, testTenant, "evidence", testObjectID)+`"`) || !strings.Contains(string(descriptor), `"source_authenticated": true`) {
		t.Fatalf("descriptor plaintext = %s", descriptor)
	}
	// The body envelope does not open as the descriptor (AAD binds the path).
	if _, err := s.open(readFile(t, obj), testTenant+"/evidence/meta/"+testObjectID+".json"); !errors.Is(err, errOpen) {
		t.Fatal("an envelope opened under another path")
	}
	before := readFile(t, obj)

	// Replay of identical plaintext (fresh nonce) is success, unchanged file.
	if err := e.pushLogs(context.Background(), makeLogs(t, withBody(boundAttrs(body), body))); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, obj), before) {
		t.Fatal("replay rewrote the object")
	}
	// Different plaintext under the same id is a conflict.
	other := []byte(`{"messages":"different"}`)
	if err := e.pushLogs(context.Background(), makeLogs(t, withBody(boundAttrs(other), other))); err != nil {
		t.Fatal(err)
	}
	assertDropped(t, e, logs, map[string]uint64{reasonConflict: 1})

	// A corrupt object is never overwritten: a replay is a conflict.
	corrupt := append([]byte(nil), before...)
	corrupt[len(corrupt)-1] ^= 0x01
	if err := os.WriteFile(obj, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.pushLogs(context.Background(), makeLogs(t, withBody(boundAttrs(body), body))); err != nil {
		t.Fatal(err)
	}
	assertDropped(t, e, logs, map[string]uint64{reasonConflict: 2})
	if !bytes.Equal(readFile(t, obj), corrupt) {
		t.Fatal("corrupt object was overwritten")
	}

	// Another key cannot read or replace what this key wrote.
	cfg2 := boundConfig(dir)
	cfg2.File.EncryptionKeyFile = keyFile(t, bytes.Repeat([]byte{0x11}, keyBytes), 0o600)
	e2, logs2 := observedExporter(t, cfg2, nil)
	if err := e2.pushLogs(context.Background(), makeLogs(t, withBody(boundAttrs(body), body))); err != nil {
		t.Fatal(err)
	}
	assertDropped(t, e2, logs2, map[string]uint64{reasonConflict: 1})

	// No plaintext anywhere below the content root.
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && bytes.Contains(readFile(t, path), []byte(contentCanary)) {
			t.Errorf("%s holds plaintext", path)
		}
		return nil
	})
}

// A configured key that cannot be loaded fails start: the backend never
// writes unencrypted instead.
func TestEncryptedBackendFailsClosedOnABadKey(t *testing.T) {
	for name, path := range map[string]string{
		"missing":        filepath.Join(t.TempDir(), "absent.key"),
		"world readable": keyFile(t, envelopeKey, 0o644),
		"short":          keyFile(t, envelopeKey[:31], 0o600),
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "content")
			cfg := fileConfig(dir)
			cfg.File.EncryptionKeyFile = path
			e, err := newContentExporter(cfg, componenttest.NewNopTelemetrySettings())
			if err != nil {
				t.Fatal(err)
			}
			err = e.start(context.Background(), componenttest.NewNopHost())
			if err == nil {
				t.Fatal("started without a usable key")
			}
			if strings.Contains(err.Error(), path) {
				t.Fatal("error names the key path")
			}
			if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
				t.Fatal("content root created without a usable key")
			}
		})
	}
}
