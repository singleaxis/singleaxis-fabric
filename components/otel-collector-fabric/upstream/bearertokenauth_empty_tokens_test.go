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

	"go.uber.org/zap"
)

// The pinned upstream v0.150.0 used to turn every blank file line into an
// accepted "Bearer " credential. Exercise the exact refresh path used on
// startup and by the file watcher after rotation.
func TestFabricEmptyTokenEntriesNeverAuthenticate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("valid-token\n\n  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := createDefaultConfig().(*Config)
	cfg.Filename = path
	auth := newBearerTokenAuth(cfg, zap.NewNop())
	check := func(value string, allowed bool) {
		t.Helper()
		_, err := auth.Authenticate(context.Background(), map[string][]string{"authorization": {value}})
		if (err == nil) != allowed {
			t.Fatalf("credential accepted=%v, want %v", err == nil, allowed)
		}
	}
	check("Bearer valid-token", true)
	check("Bearer ", false)

	if err := os.WriteFile(path, []byte("\n \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	auth.refreshToken()
	check("Bearer valid-token", false)
	check("Bearer ", false)

	if err := os.WriteFile(path, []byte("rotated-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	auth.refreshToken()
	check("Bearer rotated-token", true)
	check("Bearer valid-token", false)
	check("Bearer ", false)
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
		_, err := auth.Authenticate(context.Background(), map[string][]string{"authorization": {value}})
		if (err == nil) != allowed {
			t.Fatalf("credential accepted=%v, want %v", err == nil, allowed)
		}
	}
	check("Bearer "+first, true)
	check("Bearer ", false)

	for _, invalid := range []string{
		first + "\n", first + "\n" + second, " \n", strings.Repeat("c", 31),
		strings.Repeat("d", 4097), first + " ", "",
	} {
		if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
			t.Fatal(err)
		}
		auth.refreshToken()
		check("Bearer "+first, false)
		check("Bearer "+second, false)
		check("Bearer ", false)
	}
	if err := os.WriteFile(path, []byte(second), 0o600); err != nil {
		t.Fatal(err)
	}
	auth.refreshToken()
	check("Bearer "+second, true)
	check("Bearer "+first, false)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	auth.refreshToken()
	check("Bearer "+second, false)
	check("Bearer ", false)
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
	accepted := func(token string) bool {
		_, err := auth.Authenticate(context.Background(), map[string][]string{
			"authorization": {"Bearer " + token},
		})
		return err == nil
	}
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
	waitFor := func(want string, old string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if accepted(want) && !accepted(old) && !accepted("") {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("projected Secret swap did not load only the new credential: new=%v old=%v empty=%v", accepted(want), accepted(old), accepted(""))
	}
	writeVersion("..version-2", second)
	rotate("..version-2")
	waitFor(second, first)

	// A malformed projected replacement must remove the previously accepted
	// credential rather than retaining it until the supervisor polls again.
	writeVersion("..version-3", second+"\n")
	rotate("..version-3")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !accepted(first) && !accepted(second) && !accepted("") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("malformed projected Secret swap did not fail closed")
}
