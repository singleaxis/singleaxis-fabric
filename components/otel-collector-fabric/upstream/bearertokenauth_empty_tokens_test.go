// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package bearertokenauthextension

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/config/configopaque"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/internal/credentialsfile"
)

func fabricAccepts(t *testing.T, auth *bearerTokenAuth, value string) bool {
	t.Helper()
	_, err := auth.Authenticate(context.Background(), map[string][]string{"authorization": {value}})
	return err == nil
}

func fabricEventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(what)
}

// v0.150.0 turned every blank file line into an accepted "Bearer " credential.
// Upstream's credentials-file resolver (v0.151.0+) skips blank lines; keep the
// regression guard on the non-strict path across load and rotation.
func TestFabricEmptyTokenEntriesNeverAuthenticate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("valid-token\n\n  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := createDefaultConfig().(*Config)
	cfg.Filename = path
	cfg.RetryOnFailure = credentialsfile.RetryOnFailureConfig{Enabled: true, MaxRetries: 1, Interval: 10 * time.Millisecond}
	cfg.WaitForTokenFile = true
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	auth := newBearerTokenAuth(cfg, zap.NewNop())
	if err := auth.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := auth.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	if !fabricAccepts(t, auth, "Bearer valid-token") || fabricAccepts(t, auth, "Bearer ") {
		t.Fatal("initial non-strict credential acceptance is incorrect")
	}

	if err := os.WriteFile(path, []byte("\nrotated-token\n \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fabricEventually(t, "non-strict rotation did not load only the new credential", func() bool {
		return fabricAccepts(t, auth, "Bearer rotated-token") &&
			!fabricAccepts(t, auth, "Bearer valid-token") &&
			!fabricAccepts(t, auth, "Bearer ")
	})
}

func TestFabricStrictTokenConfigValidation(t *testing.T) {
	retry := credentialsfile.RetryOnFailureConfig{Enabled: true, Interval: time.Second}
	for name, mutate := range map[string]func(*Config){
		"no filename":   func(c *Config) { c.Filename = "" },
		"inline token":  func(c *Config) { c.BearerToken = "inline" },
		"inline tokens": func(c *Config) { c.Tokens = []configopaque.String{"inline"} },
		"retry":         func(c *Config) { c.RetryOnFailure = retry },
		"wait":          func(c *Config) { c.RetryOnFailure = retry; c.WaitForTokenFile = true },
	} {
		cfg := createDefaultConfig().(*Config)
		cfg.Filename = "/run/secrets/token"
		cfg.RequireSingleToken = true
		mutate(cfg)
		if cfg.Validate() == nil {
			t.Errorf("%s: require_single_token config accepted", name)
		}
	}
}

func TestFabricStrictTokenReloadFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	first := strings.Repeat("a", 48)
	second := strings.Repeat("b", 48)
	if err := os.WriteFile(path, []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := createDefaultConfig().(*Config)
	cfg.Filename = path
	cfg.RequireSingleToken = true
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	auth := newBearerTokenAuth(cfg, zap.NewNop())
	check := func(value string, allowed bool) {
		t.Helper()
		if fabricAccepts(t, auth, value) != allowed {
			t.Fatalf("credential accepted=%v, want %v", !allowed, allowed)
		}
	}
	check("Bearer "+first, true)
	check("Bearer ", false)

	for _, invalid := range []string{
		first + "\n", first + "\n" + second, " \n", strings.Repeat("c", 31),
		strings.Repeat("d", 4097), first + " ", first + " # comment", "",
	} {
		if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
			t.Fatal(err)
		}
		auth.strict.refresh()
		check("Bearer "+first, false)
		check("Bearer "+second, false)
		check("Bearer ", false)
	}
	if err := os.WriteFile(path, []byte(second), 0o600); err != nil {
		t.Fatal(err)
	}
	auth.strict.refresh()
	check("Bearer "+second, true)
	check("Bearer "+first, false)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	auth.strict.refresh()
	check("Bearer "+second, false)
	check("Bearer ", false)
}

// The watch must outlive the context passed to Start.
func TestFabricStrictWatchSurvivesStartContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	first := strings.Repeat("a", 48)
	if err := os.WriteFile(path, []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := createDefaultConfig().(*Config)
	cfg.Filename = path
	cfg.RequireSingleToken = true
	auth := newBearerTokenAuth(cfg, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	if err := auth.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	cancel()
	defer func() {
		if err := auth.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	if err := os.WriteFile(path, []byte(first+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fabricEventually(t, "malformed rewrite after Start returned did not fail closed", func() bool {
		return !fabricAccepts(t, auth, "Bearer "+first)
	})
}

func TestFabricProjectedSecretAtomicSymlinkRotation(t *testing.T) {
	root := t.TempDir()
	first := strings.Repeat("a", 48)
	second := strings.Repeat("b", 48)
	writeVersion := func(name, token string) {
		t.Helper()
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "token"), []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeVersion("..version-1", first)
	if err := os.Symlink("..version-1", filepath.Join(root, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..data/token", filepath.Join(root, "token")); err != nil {
		t.Fatal(err)
	}
	cfg := createDefaultConfig().(*Config)
	cfg.Filename = filepath.Join(root, "token")
	cfg.RequireSingleToken = true
	auth := newBearerTokenAuth(cfg, zap.NewNop())
	if err := auth.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := auth.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	accepted := func(token string) bool { return fabricAccepts(t, auth, "Bearer "+token) }
	if !accepted(first) || accepted(second) || accepted("") {
		t.Fatal("initial projected credential acceptance is incorrect")
	}
	rotate := func(version string) {
		t.Helper()
		tmpLink := filepath.Join(root, "..data_tmp")
		if err := os.Symlink(version, tmpLink); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmpLink, filepath.Join(root, "..data")); err != nil {
			t.Fatal(err)
		}
	}
	writeVersion("..version-2", second)
	rotate("..version-2")
	fabricEventually(t, "projected Secret swap did not load only the new credential", func() bool {
		return accepted(second) && !accepted(first) && !accepted("")
	})

	// A malformed projected replacement must remove the previously accepted
	// credential rather than retaining it until the supervisor polls again.
	writeVersion("..version-3", second+"\n")
	rotate("..version-3")
	fabricEventually(t, "malformed projected Secret swap did not fail closed", func() bool {
		return !accepted(first) && !accepted(second) && !accepted("")
	})
}
