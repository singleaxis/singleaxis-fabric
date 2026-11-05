// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package hostrecords

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestLabelPseudonymVectors(t *testing.T) {
	var doc struct {
		Cases []struct {
			Name      string  `json:"name"`
			RunID     string  `json:"run_id"`
			Key       *string `json:"key"`
			Pseudonym string  `json:"pseudonym"`
		} `json:"cases"`
	}
	readJSON(t, repoPath(t, "contracts/capture/v1/fixtures/run-ids/run-id-pseudonym-v1.json"), &doc)
	if len(doc.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range doc.Cases {
		var key []byte
		if c.Key != nil {
			key = []byte(*c.Key)
		}
		if got := LabelPseudonym("r-", c.RunID, key); got != c.Pseudonym {
			t.Errorf("%s: got %s, want %s", c.Name, got, c.Pseudonym)
		}
		// J1: the same hex names the source, service and tenant labels.
		for _, prefix := range []string{"s", "svc-", "t"} {
			want := strings.TrimSuffix(prefix, "-") + "-" + c.Pseudonym[2:]
			if got := LabelPseudonym(prefix, c.RunID, key); got != want {
				t.Errorf("%s (%s): got %s, want %s", c.Name, prefix, got, want)
			}
		}
	}
}

func TestV2Vectors(t *testing.T) {
	var doc struct {
		Cases []struct {
			Name      string  `json:"name"`
			Function  string  `json:"function"`
			Prefix    string  `json:"prefix"`
			Type      string  `json:"type"`
			Value     string  `json:"value"`
			Key       *string `json:"key"`
			Pseudonym *string `json:"pseudonym"`
		} `json:"cases"`
		KeyIDs []struct {
			Key   string `json:"key"`
			KeyID string `json:"key_id"`
		} `json:"key_ids"`
	}
	readJSON(t, repoPath(t, "contracts/coverage/v1/fixtures/vectors/pseudonym-v2.json"), &doc)
	checked := 0
	for _, c := range doc.Cases {
		var key []byte
		if c.Key != nil {
			key = []byte(*c.Key)
		}
		want := ""
		if c.Pseudonym != nil {
			want = *c.Pseudonym
		}
		var got string
		switch c.Function {
		case "v2":
			if v2Types[c.Prefix] != c.Type {
				t.Errorf("%s: prefix %s maps to %q, the vector says %q", c.Name, c.Prefix, v2Types[c.Prefix], c.Type)
			}
			got = V2(c.Prefix, c.Value, key)
		case "v1":
			got = LabelPseudonym(c.Prefix, c.Value, key)
		default:
			continue // the legacy unkeyed provider form is read-only; no host record emits it
		}
		checked++
		if got != want {
			t.Errorf("%s: got %q, want %q", c.Name, got, want)
		}
	}
	if checked == 0 || len(doc.KeyIDs) == 0 {
		t.Fatal("no cases")
	}
	for _, k := range doc.KeyIDs {
		if got := keyID([]byte(k.Key)); got != k.KeyID {
			t.Errorf("key_id: got %s, want %s", got, k.KeyID)
		}
	}
	if V2("hst-", "h", []byte(testKey)) != V2("hst", "h", []byte(testKey)) {
		t.Error("a prefix with its dash names the same prefix")
	}
	if V2("nope", "h", []byte(testKey)) != "" {
		t.Error("an unknown v2 prefix gives no id")
	}
}

func TestIDKeyFileVectors(t *testing.T) {
	var doc struct {
		Reasons []string `json:"reasons"`
		Cases   []struct {
			Name     string `json:"name"`
			File     string `json:"file_base64"`
			Mode     string `json:"mode"`
			Key      string `json:"key_base64"`
			Refused  string `json:"refused"`
			HostID   string `json:"host_id"`
			SourceID string `json:"source_id"`
		} `json:"cases"`
	}
	readJSON(t, repoPath(t, "contracts/capture/v1/fixtures/host/id-key-file-v1.json"), &doc)
	if strings.Join(doc.Reasons, ",") != "mode,too_short,too_long,trailing_newline,nul_byte,not_utf8" {
		t.Fatalf("reasons changed: %v", doc.Reasons)
	}
	dir := t.TempDir()
	for i, c := range doc.Cases {
		data, err := base64.StdEncoding.DecodeString(c.File)
		if err != nil {
			t.Fatal(err)
		}
		mode, err := strconv.ParseUint(c.Mode, 8, 32)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "key-"+strconv.Itoa(i))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, os.FileMode(mode)); err != nil {
			t.Fatal(err)
		}
		key, err := ReadIDKeyFile(path)
		if c.Refused != "" {
			var kf *KeyFileError
			if !errors.As(err, &kf) || kf.Reason != c.Refused {
				t.Errorf("%s: got %v, want refusal %s", c.Name, err, c.Refused)
				continue
			}
			if len(data) >= 4 && strings.Contains(err.Error(), string(data[:4])) {
				t.Errorf("%s: the error holds the file's contents", c.Name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		want, _ := base64.StdEncoding.DecodeString(c.Key)
		if !bytes.Equal(key, want) || !bytes.Equal(key, data) {
			t.Errorf("%s: the key is not the file's bytes", c.Name)
		}
		if got := V2("hst", "ar1-host", key); got != c.HostID {
			t.Errorf("%s: host id %s, want %s", c.Name, got, c.HostID)
		}
		if got := LabelPseudonym("s-", "node-a/ebpf", key); got != c.SourceID {
			t.Errorf("%s: source id %s, want %s", c.Name, got, c.SourceID)
		}
	}
	missing := filepath.Join(dir, "missing")
	if _, err := ReadIDKeyFile(missing); err == nil {
		t.Error("a missing file is refused")
	}
	if _, err := ReadIDKeyFile(dir); err == nil {
		t.Error("a directory is refused")
	}
}

func TestStateKeyFile(t *testing.T) {
	dir := t.TempDir()
	raw := testStateKey()
	cases := []struct {
		name string
		data []byte
		mode os.FileMode
		ok   bool
	}{
		{"32 raw bytes", raw, 0o400, true},
		{"base64 with a newline", []byte(base64.StdEncoding.EncodeToString(raw) + "\n"), 0o440, true},
		{"base64 without a newline", []byte(base64.StdEncoding.EncodeToString(raw)), 0o400, true},
		{"31 bytes", raw[:31], 0o400, false},
		{"hex is not a key", []byte(hex.EncodeToString(raw)), 0o400, false},
		{"mode 0600", raw, 0o600, false},
	}
	for i, c := range cases {
		path := filepath.Join(dir, "state-"+strconv.Itoa(i))
		if err := os.WriteFile(path, c.data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, c.mode); err != nil {
			t.Fatal(err)
		}
		key, err := ReadStateKeyFile(path)
		if c.ok != (err == nil) || (c.ok && !bytes.Equal(key, raw)) {
			t.Errorf("%s: key %x, error %v", c.name, key, err)
		}
	}
}

func TestPeerTextVectors(t *testing.T) {
	var doc struct {
		Key   string `json:"key"`
		Cases []struct {
			Name     string  `json:"name"`
			Input    string  `json:"input"`
			BytesHex *string `json:"bytes_hex"`
			Text     *string `json:"text"`
			HostID   *string `json:"host_id"`
		} `json:"cases"`
	}
	readJSON(t, repoPath(t, "contracts/coverage/v1/fixtures/vectors/peer-address-v1.json"), &doc)
	if len(doc.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range doc.Cases {
		want := ""
		if c.Text != nil {
			want = *c.Text
		}
		got := ""
		if addr, err := netip.ParseAddr(c.Input); err == nil {
			got = PeerText(addr)
		}
		if got != want {
			t.Errorf("%s: text %q, want %q", c.Name, got, want)
		}
		if c.BytesHex != nil {
			raw, err := hex.DecodeString(*c.BytesHex)
			if err != nil {
				t.Fatal(err)
			}
			addr, ok := netip.AddrFromSlice(raw)
			if !ok || PeerText(addr) != want {
				t.Errorf("%s: from bytes %q, want %q", c.Name, PeerText(addr), want)
			}
		}
		wantID := ""
		if c.HostID != nil {
			wantID = *c.HostID
		}
		gotID := ""
		if got != "" {
			gotID = V2("hst", got, []byte(doc.Key))
		}
		if gotID != wantID {
			t.Errorf("%s: host id %q, want %q", c.Name, gotID, wantID)
		}
	}
	if PeerText(netip.Addr{}) != "" {
		t.Error("the zero Addr has no text")
	}
}

func TestSandboxIDVectors(t *testing.T) {
	var doc struct {
		Key     string `json:"key"`
		Cgroups []struct {
			Name        string            `json:"name"`
			Path        string            `json:"path"`
			LastTwo     string            `json:"last_two"`
			ContainerID *string           `json:"container_id"`
			PodUID      *string           `json:"pod_uid"`
			Clear       map[string]string `json:"clear"`
			IDs         map[string]string `json:"ids"`
		} `json:"cgroups"`
	}
	readJSON(t, repoPath(t, "contracts/coverage/v1/fixtures/vectors/sandbox-id-v1.json"), &doc)
	if len(doc.Cgroups) == 0 {
		t.Fatal("no cases")
	}
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	for _, c := range doc.Cgroups {
		for _, path := range []string{c.Path, c.LastTwo} {
			container, pod := SandboxIDs(path)
			if container != deref(c.ContainerID) || pod != deref(c.PodUID) {
				t.Errorf("%s (%s): got (%q, %q)", c.Name, path, container, pod)
			}
		}
		container, pod := SandboxIDs(c.Path)
		ids := map[string]string{}
		if container != "" {
			ids["fabric.execution.sandbox_id"] = V2("sbx", "container:"+container, []byte(doc.Key))
		}
		if pod != "" {
			ids["fabric.sensor.pod_id"] = V2("sbx", "k8s-pod:"+pod, []byte(doc.Key))
		}
		if len(ids) != len(c.IDs) {
			t.Errorf("%s: ids %v, want %v", c.Name, ids, c.IDs)
		}
		for k, v := range c.IDs {
			if ids[k] != v {
				t.Errorf("%s: %s = %q, want %q", c.Name, k, ids[k], v)
			}
		}
	}
}

func TestEnvelopeVectors(t *testing.T) {
	var doc struct {
		Magic      string   `json:"magic"`
		Schema     string   `json:"schema"`
		StateKinds []string `json:"state_kinds"`
		Key        string   `json:"key_base64"`
		Cases      []struct {
			Name      string  `json:"name"`
			Kind      string  `json:"state_kind"`
			AAD       string  `json:"aad"`
			Envelope  string  `json:"envelope_base64"`
			Plaintext *string `json:"plaintext_base64"`
			Valid     bool    `json:"valid"`
		} `json:"cases"`
	}
	readJSON(t, repoPath(t, "contracts/capture/v1/fixtures/host/host-state-envelope-v1.json"), &doc)
	if doc.Magic != envelopeMagic || doc.Schema != envelopeSchema {
		t.Fatalf("magic or schema differ: %q %q", doc.Magic, doc.Schema)
	}
	if strings.Join(doc.StateKinds, ",") != strings.Join([]string{StateEpoch, StateStaging, StateSpool, StateCursor}, ",") {
		t.Fatalf("state kinds differ: %v", doc.StateKinds)
	}
	key, _ := base64.StdEncoding.DecodeString(doc.Key)
	for _, c := range doc.Cases {
		if string(envelopeAAD(c.Kind)) != c.AAD {
			t.Errorf("%s: aad %s, want %s", c.Name, envelopeAAD(c.Kind), c.AAD)
		}
		envelope, _ := base64.StdEncoding.DecodeString(c.Envelope)
		plain, err := Unseal(key, c.Kind, envelope)
		if !c.Valid {
			if err == nil {
				t.Errorf("%s: opened", c.Name)
			}
			continue
		}
		want, _ := base64.StdEncoding.DecodeString(*c.Plaintext)
		if err != nil || !bytes.Equal(plain, want) {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		// Sealing with the vector's nonce gives the vector's bytes.
		nonce := envelope[len(envelopeMagic) : len(envelopeMagic)+nonceBytes]
		sealed, err := sealWithNonce(key, c.Kind, nonce, want)
		if err != nil || !bytes.Equal(sealed, envelope) {
			t.Errorf("%s: sealing differs", c.Name)
		}
	}
	// A fresh seal opens only as its own kind and draws a fresh nonce.
	a, err := Seal(key, StateCursor, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Seal(key, StateCursor, []byte("x"))
	if bytes.Equal(a, b) {
		t.Error("two seals share a nonce")
	}
	if _, err := Unseal(key, StateSpool, a); err == nil {
		t.Error("a cursor envelope opened as spool")
	}
	if _, err := Seal(key, "other", nil); err == nil {
		t.Error("an unknown kind sealed")
	}
	if _, err := Seal(key[:16], StateEpoch, nil); err == nil {
		t.Error("a 16-byte key sealed")
	}
}
