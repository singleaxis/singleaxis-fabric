// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricenvelopeextension

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/storage/filestorage"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/config/configretry"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/extensiontest"
	"go.opentelemetry.io/collector/extension/xextension/storage"
	"go.opentelemetry.io/collector/pdata/plog"
)

const canary = "PRIVATE-QUEUE-CANARY-4f1c2e3d"

var testKey = bytes.Repeat([]byte{0x42}, keyBytes)

func writeKey(t *testing.T, data []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadKeyFormats(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString(testKey)
	for name, data := range map[string][]byte{
		"raw":            testKey,
		"base64":         []byte(b64),
		"base64 newline": []byte(b64 + "\n"),
	} {
		t.Run(name, func(t *testing.T) {
			key, err := loadKey(writeKey(t, data, 0o600))
			if err != nil || !bytes.Equal(key, testKey) {
				t.Fatalf("key not loaded: %v", err)
			}
		})
	}
	for name, data := range map[string][]byte{
		"short raw":       testKey[:31],
		"long raw":        append(append([]byte(nil), testKey...), 1),
		"base64 of 31":    []byte(base64.StdEncoding.EncodeToString(testKey[:31])),
		"two newlines":    []byte(b64 + "\n\n"),
		"hex":             []byte(strings.Repeat("42", keyBytes)),
		"empty":           {},
		"invalid base64":  []byte(strings.Repeat("!", 44)),
		"url-safe base64": []byte(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, keyBytes))),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadKey(writeKey(t, data, 0o600)); !errors.Is(err, errKeyValue) {
				t.Fatalf("malformed key accepted: %v", err)
			}
		})
	}
	for _, mode := range []os.FileMode{0o604, 0o620, 0o606, 0o666} {
		if _, err := loadKey(writeKey(t, testKey, mode)); !errors.Is(err, errKeyMode) {
			t.Fatalf("key file mode %o accepted: %v", mode, err)
		}
	}
	if _, err := loadKey(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, errKeyFile) {
		t.Fatalf("missing key file: %v", err)
	}
	if _, err := loadKey(t.TempDir()); !errors.Is(err, errKeyMode) {
		t.Fatalf("directory accepted as key file: %v", err)
	}
}

func TestEnvelopeRoundTripAndTamper(t *testing.T) {
	s, err := newSealer(testKey, queueMagic, queueSchema)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.seal([]byte(canary), "Exporter", "fabriccontent", "", "7")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(canary)) || !bytes.HasPrefix(sealed, []byte(queueMagic)) {
		t.Fatal("envelope leaks plaintext or lacks its magic")
	}
	if len(sealed) != len(queueMagic)+nonceBytes+len(canary)+16 {
		t.Fatalf("unexpected envelope length %d", len(sealed))
	}
	plain, err := s.open(sealed, "Exporter", "fabriccontent", "", "7")
	if err != nil || string(plain) != canary {
		t.Fatalf("round trip failed: %v", err)
	}
	again, _ := s.seal([]byte(canary), "Exporter", "fabriccontent", "", "7")
	if bytes.Equal(again, sealed) {
		t.Fatal("nonce reused")
	}
	other, _ := newSealer(bytes.Repeat([]byte{0x43}, keyBytes), queueMagic, queueSchema)
	for name, tc := range map[string]struct {
		s     *sealer
		data  []byte
		scope []string
	}{
		"wrong key":       {other, sealed, []string{"Exporter", "fabriccontent", "", "7"}},
		"moved to key 8":  {s, sealed, []string{"Exporter", "fabriccontent", "", "8"}},
		"other component": {s, sealed, []string{"Exporter", "fabriccontent/s3", "", "7"}},
		"flipped byte":    {s, flip(sealed, len(sealed)-1), []string{"Exporter", "fabriccontent", "", "7"}},
		"flipped nonce":   {s, flip(sealed, len(queueMagic)), []string{"Exporter", "fabriccontent", "", "7"}},
		"truncated":       {s, sealed[:len(sealed)-1], []string{"Exporter", "fabriccontent", "", "7"}},
		"header only":     {s, sealed[:len(queueMagic)+nonceBytes], []string{"Exporter", "fabriccontent", "", "7"}},
		"plaintext":       {s, []byte(canary), []string{"Exporter", "fabriccontent", "", "7"}},
		"other magic":     {s, append([]byte("FABRIC-BYTE-SPOOL-1\n"), sealed[len(queueMagic):]...), []string{"Exporter", "fabriccontent", "", "7"}},
	} {
		t.Run(name, func(t *testing.T) {
			if out, err := tc.s.open(tc.data, tc.scope...); !errors.Is(err, errOpen) || out != nil {
				t.Fatalf("tampered envelope opened: %v", err)
			}
		})
	}
}

func flip(data []byte, i int) []byte {
	out := append([]byte(nil), data...)
	out[i] ^= 0x01
	return out
}

func TestAADIsCanonicalJSON(t *testing.T) {
	s, _ := newSealer(testKey, queueMagic, queueSchema)
	got := string(s.aad("Exporter", "fabriccontent", "", "k<&>"))
	want := `["fabric.node-queue-envelope/v1","Exporter","fabriccontent","","k<&>"]`
	if got != want {
		t.Fatalf("aad %q, want %q", got, want)
	}
}

func TestConfigValidate(t *testing.T) {
	ok := &Config{Storage: component.MustNewIDWithName("file_storage", "content"), KeyFile: "/run/secrets/key"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]*Config{
		"no storage":     {KeyFile: "/run/secrets/key"},
		"self":           {Storage: component.MustNewIDWithName("fabricenvelope", "x"), KeyFile: "/run/secrets/key"},
		"no key file":    {Storage: ok.Storage},
		"relative key":   {Storage: ok.Storage, KeyFile: "key"},
		"unclean key":    {Storage: ok.Storage, KeyFile: "/run/../key"},
		"trailing slash": {Storage: ok.Storage, KeyFile: "/run/key/"},
	} {
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// memStorage is an in-memory storage extension that records what it holds.
type memStorage struct {
	mu   sync.Mutex
	data map[string][]byte
}

func (m *memStorage) Start(context.Context, component.Host) error { return nil }
func (m *memStorage) Shutdown(context.Context) error              { return nil }
func (m *memStorage) GetClient(context.Context, component.Kind, component.ID, string) (storage.Client, error) {
	return m, nil
}
func (m *memStorage) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.data[key], nil
}
func (m *memStorage) Set(_ context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = append([]byte(nil), value...)
	return nil
}
func (m *memStorage) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}
func (m *memStorage) Batch(ctx context.Context, ops ...*storage.Operation) error {
	for _, op := range ops {
		switch op.Type {
		case storage.Get:
			op.Value, _ = m.Get(ctx, op.Key)
		case storage.Set:
			_ = m.Set(ctx, op.Key, op.Value)
		case storage.Delete:
			_ = m.Delete(ctx, op.Key)
		}
	}
	return nil
}
func (m *memStorage) Close(context.Context) error { return nil }

func (m *memStorage) holds(needle []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.data {
		if bytes.Contains(v, needle) {
			return true
		}
	}
	return false
}

// plainExtension is an extension that is not a storage extension.
type plainExtension struct {
	component.StartFunc
	component.ShutdownFunc
}

type host struct {
	component.Host
	exts map[component.ID]component.Component
}

func (h host) GetExtensions() map[component.ID]component.Component { return h.exts }

var (
	innerID    = component.MustNewIDWithName("file_storage", "content")
	envelopeID = component.MustNewIDWithName(typeStr, "content")
)

func startEnvelope(t *testing.T, inner extension.Extension, keyPath string) (*envelopeStorage, host) {
	t.Helper()
	cfg := &Config{Storage: innerID, KeyFile: keyPath}
	ext, err := NewFactory().Create(context.Background(), extensiontest.NewNopSettings(component.MustNewType(typeStr)), cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := host{Host: componenttest.NewNopHost(), exts: map[component.ID]component.Component{innerID: inner, envelopeID: ext}}
	if err := ext.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	return ext.(*envelopeStorage), h
}

func TestClientSealsEveryValue(t *testing.T) {
	mem := &memStorage{data: map[string][]byte{}}
	env, _ := startEnvelope(t, mem, writeKey(t, testKey, 0o600))
	if deps := env.Dependencies(); len(deps) != 1 || deps[0] != innerID {
		t.Fatalf("dependencies %v", deps)
	}
	ctx := context.Background()
	client, err := env.GetClient(ctx, component.KindExporter, component.MustNewID("fabriccontent"), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Set(ctx, "0", []byte(canary)); err != nil {
		t.Fatal(err)
	}
	set := storage.SetOperation("1", []byte(canary+"-batch"))
	if err := client.Batch(ctx, set, storage.SetOperation("ri", []byte{1})); err != nil {
		t.Fatal(err)
	}
	if string(set.Value) != canary+"-batch" {
		t.Fatal("Batch replaced the caller's plaintext")
	}
	if mem.holds([]byte(canary)) || bytes.Equal(mem.data["ri"], []byte{1}) {
		t.Fatal("inner storage holds plaintext")
	}
	if v, err := client.Get(ctx, "0"); err != nil || string(v) != canary {
		t.Fatalf("Get: %q %v", v, err)
	}
	get, missing := storage.GetOperation("1"), storage.GetOperation("absent")
	if err := client.Batch(ctx, get, missing); err != nil || string(get.Value) != canary+"-batch" || missing.Value != nil {
		t.Fatalf("Batch get: %q %v", get.Value, err)
	}
	if v, err := client.Get(ctx, "absent"); v != nil || err != nil {
		t.Fatalf("absent key: %q %v", v, err)
	}
	// A value moved to another key, or tampered, never reads back.
	mem.data["2"] = mem.data["0"]
	if v, err := client.Get(ctx, "2"); !errors.Is(err, errOpen) || v != nil {
		t.Fatalf("moved value opened: %v", err)
	}
	mem.data["0"] = flip(mem.data["0"], len(mem.data["0"])-3)
	bad := storage.GetOperation("0")
	if err := client.Batch(ctx, get, bad); !errors.Is(err, errOpen) || bad.Value != nil || string(get.Value) != canary+"-batch" {
		t.Fatalf("tampered batch value: %q %v", bad.Value, err)
	}
	// Another component's client cannot read this one's values.
	other, _ := env.GetClient(ctx, component.KindExporter, component.MustNewIDWithName("fabriccontent", "s3"), "")
	if _, err := other.Get(ctx, "1"); !errors.Is(err, errOpen) {
		t.Fatalf("cross-client read: %v", err)
	}
	if err := client.Delete(ctx, "1"); err != nil || mem.data["1"] != nil {
		t.Fatal("delete not forwarded")
	}
}

func TestStartFailsClosed(t *testing.T) {
	ctx := context.Background()
	mem := &memStorage{data: map[string][]byte{}}
	create := func(keyPath string) extension.Extension {
		ext, err := NewFactory().Create(ctx, extensiontest.NewNopSettings(component.MustNewType(typeStr)), &Config{Storage: innerID, KeyFile: keyPath})
		if err != nil {
			t.Fatal(err)
		}
		return ext
	}
	good := writeKey(t, testKey, 0o600)
	for name, tc := range map[string]struct {
		key  string
		exts map[component.ID]component.Component
	}{
		"missing key":      {filepath.Join(t.TempDir(), "absent"), map[component.ID]component.Component{innerID: mem}},
		"readable key":     {writeKey(t, testKey, 0o644), map[component.ID]component.Component{innerID: mem}},
		"no inner":         {good, map[component.ID]component.Component{}},
		"inner no storage": {good, map[component.ID]component.Component{innerID: plainExtension{}}},
	} {
		t.Run(name, func(t *testing.T) {
			ext := create(tc.key)
			if err := ext.Start(ctx, host{Host: componenttest.NewNopHost(), exts: tc.exts}); err == nil {
				t.Fatal("started without a usable key or storage")
			} else if strings.Contains(err.Error(), tc.key) {
				t.Fatal("error names the key path")
			}
			if _, err := ext.(*envelopeStorage).GetClient(ctx, component.KindExporter, component.MustNewID("fabriccontent"), ""); err == nil {
				t.Fatal("client handed out before a successful start")
			}
		})
	}
	if _, err := NewFactory().Create(ctx, extensiontest.NewNopSettings(component.MustNewType(typeStr)), &Config{KeyFile: good}); err == nil {
		t.Fatal("invalid configuration created")
	}
}

// TestPersistentQueueOverFileStorage runs the exporterhelper persistent queue
// (the fabriccontent queue's machinery) on the real file_storage through the
// envelope: delivery is unchanged, items survive a restart, and the bbolt
// file never holds the plaintext.
func TestPersistentQueueOverFileStorage(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	keyPath := writeKey(t, []byte(base64.StdEncoding.EncodeToString(testKey)+"\n"), 0o600)

	startStack := func(next func(context.Context, plog.Logs) error) (exporter.Logs, func()) {
		fsFactory := filestorage.NewFactory()
		fsCfg := fsFactory.CreateDefaultConfig().(*filestorage.Config)
		fsCfg.Directory = dir
		fsCfg.Compaction.Directory = dir
		fsCfg.FSync = true
		fsExt, err := fsFactory.Create(ctx, extensiontest.NewNopSettings(fsFactory.Type()), fsCfg)
		if err != nil {
			t.Fatal(err)
		}
		h := host{Host: componenttest.NewNopHost(), exts: map[component.ID]component.Component{innerID: fsExt}}
		if err := fsExt.Start(ctx, h); err != nil {
			t.Fatal(err)
		}
		env, err := NewFactory().Create(ctx, extensiontest.NewNopSettings(component.MustNewType(typeStr)), &Config{Storage: innerID, KeyFile: keyPath})
		if err != nil {
			t.Fatal(err)
		}
		h.exts[envelopeID] = env
		if err := env.Start(ctx, h); err != nil {
			t.Fatal(err)
		}
		queue := exporterhelper.NewDefaultQueueConfig()
		queue.StorageID = &envelopeID
		queue.NumConsumers = 1
		queue.QueueSize = 16
		queue.BlockOnOverflow = true
		retry := configretry.NewDefaultBackOffConfig()
		retry.InitialInterval = 10 * time.Millisecond
		retry.MaxElapsedTime = 0
		set := exportertest.NewNopSettings(component.MustNewType("fabriccontent"))
		set.ID = component.MustNewID("fabriccontent") // the same queue across restarts
		exp, err := exporterhelper.NewLogs(ctx, set, &struct{}{}, next,
			exporterhelper.WithQueue(configoptional.Some(queue)),
			exporterhelper.WithRetry(retry),
			exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}))
		if err != nil {
			t.Fatal(err)
		}
		if err := exp.Start(ctx, h); err != nil {
			t.Fatal(err)
		}
		return exp, func() {
			_ = exp.Shutdown(ctx)
			_ = env.Shutdown(ctx)
			_ = fsExt.Shutdown(ctx)
		}
	}
	logs := func(body string) plog.Logs {
		ld := plog.NewLogs()
		ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty().Body().SetEmptyBytes().FromRaw([]byte(body))
		return ld
	}

	// First run: the store is down, so the item stays queued on disk.
	stuck := errors.New("store unavailable")
	exp, stop := startStack(func(context.Context, plog.Logs) error { return stuck })
	if err := exp.ConsumeLogs(ctx, logs(canary)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	stop()
	assertNoPlaintext(t, dir)

	// Second run: the store is back; the restarted queue delivers the item.
	var mu sync.Mutex
	var got []string
	exp, stop = startStack(func(_ context.Context, ld plog.Logs) error {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, string(ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().Bytes().AsRaw()))
		return nil
	})
	defer stop()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != canary {
		t.Fatalf("queued item not delivered after restart: %q", got)
	}
}

func assertNoPlaintext(t *testing.T, dir string) {
	t.Helper()
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if bytes.Contains(data, []byte(canary)) {
			t.Fatalf("queue file %s holds plaintext", filepath.Base(path))
		}
		return nil
	})
}
