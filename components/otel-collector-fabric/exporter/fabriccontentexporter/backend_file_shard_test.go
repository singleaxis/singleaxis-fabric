// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// onDisk is where the directory backend stores the logical key (an absolute,
// slash-separated path below dir).
func onDisk(dir, key string) string {
	rel := strings.TrimPrefix(key, filepath.ToSlash(dir)+"/")
	physical, ok := shardedRel(rel)
	if !ok {
		panic("not a layout key: " + key)
	}
	return filepath.Join(dir, filepath.FromSlash(physical))
}

// shard is the independent spelling of the shard directories: the first
// four hex characters of SHA-256(object id).
func shard(objectID string) (string, string) {
	sum := sha256.Sum256([]byte(objectID))
	h := hex.EncodeToString(sum[:])
	return h[0:2], h[2:4]
}

func shardedObject(dir, tenant, objectID string) string {
	a, b := shard(objectID)
	return filepath.Join(dir, tenant, "evidence", a, b, objectID)
}

func shardedMeta(dir, tenant, objectID string) string {
	a, b := shard(objectID)
	return filepath.Join(dir, tenant, "evidence", "meta", a, b, objectID+".json")
}

func TestShardedRel(t *testing.T) {
	a, b := shard(testObjectID)
	for _, tc := range []struct{ rel, want string }{
		// Pinned vectors every reader (the SDK's LocalFilesystemContentStore)
		// must reproduce: sha256("0b8e1c52-...-5c9a2e7d1a01") starts 975b.
		{"tenant-a/evidence/" + testObjectID, "tenant-a/evidence/97/5b/" + testObjectID},
		{"tenant-a/evidence/meta/" + testObjectID + ".json", "tenant-a/evidence/meta/97/5b/" + testObjectID + ".json"},
		{"tenant-a/evidence/" + testObjectID, "tenant-a/evidence/" + a + "/" + b + "/" + testObjectID},
		// An id "meta" is a body id like any other (sha256 starts ea3b): the
		// shard separates it from the descriptor directory.
		{"t/evidence/meta", "t/evidence/ea/3b/meta"},
	} {
		got, ok := shardedRel(tc.rel)
		if !ok || got != tc.want {
			t.Errorf("shardedRel(%q) = %q, %v; want %q", tc.rel, got, ok, tc.want)
		}
	}
	for _, rel := range []string{
		"", "t", "t/evidence", "t/evidence/", "t/evidence/..", "t/evidence/.", "../evidence/x",
		"t/evidence/a/b", "t/other/x", "t/evidence/meta/x.txt", "t/evidence/meta/.json",
		"t/evidence/meta/../x.json", "t/evidence/meta/x.json/y", "t//evidence/x", `t/evidence/a\..\b`,
		"t/evidence/meta/a/b.json",
	} {
		if got, ok := shardedRel(rel); ok {
			t.Errorf("shardedRel(%q) = %q, want refused", rel, got)
		}
	}
}

// New writes land in the shard, never at the flat name, and every newly
// created shard directory is made durable in its parent before the put is
// acknowledged.
func TestFileBackendWritesShardedAndSyncsNewShardDirs(t *testing.T) {
	root := physicalTempDir(t)
	markRoot(t, root)
	b := newFileBackend(root)
	fail := false
	synced := syncLog(t, "", &fail)
	id := "0b1c2d3e-0000-4000-8000-000000000040"
	key := filepath.ToSlash(filepath.Join(root, "acme", "evidence", id))
	if err := b.put(context.Background(), key, []byte("body")); err != nil {
		t.Fatal(err)
	}
	obj := shardedObject(root, "acme", id)
	if got := readFile(t, obj); string(got) != "body" {
		t.Fatalf("sharded object = %q", got)
	}
	if got := perm(t, obj); got != 0o600 {
		t.Errorf("object mode %o", got)
	}
	if _, err := os.Lstat(filepath.Join(root, "acme", "evidence", id)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a new write landed at the flat legacy name")
	}
	leaf := filepath.Dir(obj)
	mid := filepath.Dir(leaf)
	evidence := filepath.Dir(mid)
	for _, d := range []string{leaf, mid} {
		if got := perm(t, d); got != 0o700 {
			t.Errorf("%s mode %o, want 700", d, got)
		}
	}
	// evidence holds mid's entry, mid holds leaf's, leaf holds the object's.
	for _, d := range []string{evidence, mid, leaf} {
		if countOf(*synced, d) == 0 {
			t.Errorf("%s not fsync'd; synced %v", d, *synced)
		}
	}
	meta := filepath.ToSlash(filepath.Join(root, "acme", "evidence", "meta", id+".json"))
	if err := b.put(context.Background(), meta, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, shardedMeta(root, "acme", id)); string(got) != "{}" {
		t.Fatalf("sharded descriptor = %q", got)
	}
}

// writeLegacy places an object at its flat, pre-shard name, as an earlier
// Node version did.
func writeLegacy(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// An object written before the upgrade, at the flat name, is a replay when
// the bytes match (nothing is written in the shard) and a conflict when they
// differ (the flat object is unchanged and nothing lands in the shard).
func TestFileBackendLegacyFlatObjectReplayAndConflict(t *testing.T) {
	dir := filepath.Join(physicalTempDir(t), "content")
	b := newFileBackend(dir)
	id := "0b1c2d3e-0000-4000-8000-000000000041"
	key := filepath.ToSlash(filepath.Join(dir, "acme", "evidence", id))
	legacy := filepath.FromSlash(key)
	writeLegacy(t, legacy, []byte("before upgrade"))
	if err := b.put(context.Background(), key, []byte("before upgrade")); err != nil {
		t.Fatalf("identical replay of a legacy object = %v", err)
	}
	if err := b.put(context.Background(), key, []byte("different")); !errors.Is(err, errConflict) {
		t.Fatalf("different bytes against a legacy object = %v, want errConflict", err)
	}
	if _, err := os.Lstat(shardedObject(dir, "acme", id)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an id already stored at the legacy name was written again in its shard")
	}
	if got := readFile(t, legacy); string(got) != "before upgrade" {
		t.Fatalf("legacy object changed: %q", got)
	}
	// A crash after link(2) in the old writer left a second link: the
	// replay heals it at the legacy name.
	tmp := filepath.Join(filepath.Dir(legacy), "."+id+".9.tmp")
	if err := os.Link(legacy, tmp); err != nil {
		t.Fatal(err)
	}
	if err := b.put(context.Background(), key, []byte("before upgrade")); err != nil {
		t.Fatal(err)
	}
	if n := nlink(t, legacy); n != 1 {
		t.Errorf("legacy nlink after replay = %d, want 1", n)
	}
}

// A symlink planted at the legacy name is never followed or compared.
func TestFileBackendLegacySymlinkIsRefused(t *testing.T) {
	dir := filepath.Join(physicalTempDir(t), "content")
	b := newFileBackend(dir)
	id := "0b1c2d3e-0000-4000-8000-000000000042"
	key := filepath.ToSlash(filepath.Join(dir, "acme", "evidence", id))
	outside := filepath.Join(physicalTempDir(t), "secret")
	if err := os.WriteFile(outside, []byte("body"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "acme", "evidence"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.FromSlash(key)); err != nil {
		t.Fatal(err)
	}
	err := b.put(context.Background(), key, []byte("body"))
	var se *storeError
	if !errors.As(err, &se) {
		t.Fatalf("put over a legacy symlink = %v, want a retryable storeError", err)
	}
	if _, err := os.Lstat(shardedObject(dir, "acme", id)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("written in the shard past a planted legacy symlink")
	}
}

// With the envelope, a legacy object sealed under its (logical) key opens
// for the replay comparison: the AAD does not depend on the shard.
func TestFileBackendLegacySealedObject(t *testing.T) {
	dir := filepath.Join(physicalTempDir(t), "content")
	b := newFileBackend(dir)
	b.sealer = testSealer(t, envelopeKey)
	id := "0b1c2d3e-0000-4000-8000-000000000043"
	rel := "acme/evidence/meta/" + id + ".json"
	key := filepath.ToSlash(dir) + "/" + rel
	sealed, err := b.sealer.seal([]byte("{}\n"), rel)
	if err != nil {
		t.Fatal(err)
	}
	writeLegacy(t, filepath.FromSlash(key), sealed)
	if err := b.put(context.Background(), key, []byte("{}\n")); err != nil {
		t.Fatalf("sealed legacy replay = %v", err)
	}
	if err := b.put(context.Background(), key, []byte("{\"x\": 1}\n")); !errors.Is(err, errConflict) {
		t.Fatalf("sealed legacy conflict = %v", err)
	}
	if _, err := os.Lstat(shardedMeta(dir, "acme", id)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("legacy sealed descriptor rewritten in its shard")
	}
	// A new sealed write lands in the shard and opens under the logical key.
	other := "0b1c2d3e-0000-4000-8000-000000000044"
	if err := b.put(context.Background(), filepath.ToSlash(filepath.Join(dir, "acme", "evidence", other)), []byte("x")); err != nil {
		t.Fatal(err)
	}
	if got := readSealed(t, b.sealer, shardedObject(dir, "acme", other), "acme/evidence/"+other); string(got) != "x" {
		t.Fatalf("sealed sharded object = %q", got)
	}
}

// Through the exporter: a record whose body and descriptor were stored flat
// before the upgrade replays cleanly (the descriptor's ref is the logical,
// unchanged key, so its bytes match) and a different body is a conflict.
func TestExporterLegacyFlatLayoutReplayAndConflict(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "content")
	body := []byte("pre-upgrade body")
	// Produce the exact pre-upgrade bytes with the current writer, then
	// move them to the flat names an earlier Node used.
	seed, _ := observedExporter(t, fileConfig(dir), nil)
	if err := seed.pushLogs(context.Background(), makeLogs(t, withBody(validAttrs(body), body))); err != nil {
		t.Fatal(err)
	}
	flatObj := filepath.Join(dir, testTenant, "evidence", testObjectID)
	flatMeta := filepath.Join(dir, testTenant, "evidence", "meta", testObjectID+".json")
	if err := os.Rename(shardedObject(dir, testTenant, testObjectID), flatObj); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(shardedMeta(dir, testTenant, testObjectID), flatMeta); err != nil {
		t.Fatal(err)
	}

	e, logs := observedExporter(t, fileConfig(dir), nil)
	if err := e.pushLogs(context.Background(), makeLogs(t, withBody(validAttrs(body), body))); err != nil {
		t.Fatal(err)
	}
	if e.written.Load() != 1 {
		t.Fatalf("legacy replay written = %d, want 1", e.written.Load())
	}
	other := []byte("a different body")
	if err := e.pushLogs(context.Background(), makeLogs(t, withBody(validAttrs(other), other))); err != nil {
		t.Fatal(err)
	}
	assertDropped(t, e, logs, map[string]uint64{reasonConflict: 1})
	for _, p := range []string{shardedObject(dir, testTenant, testObjectID), shardedMeta(dir, testTenant, testObjectID)} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s written although the id is stored at the legacy name", p)
		}
	}
	if got := readFile(t, flatObj); string(got) != string(body) {
		t.Fatalf("legacy object changed: %q", got)
	}
}

// Keys that are not the SDK layout, or that try to leave it, are refused
// before any directory is created.
func TestFileBackendRefusesNonLayoutAndTraversalKeys(t *testing.T) {
	base := physicalTempDir(t)
	dir := filepath.Join(base, "content")
	b := newFileBackend(dir)
	for _, rel := range []string{
		"acme/evidence/../../escape",
		"acme/evidence/..",
		"../escape/evidence/x",
		"acme/evidence/meta/../../x.json",
		"acme/evidence/a/b/c",
		"acme/notevidence/x",
		"acme/evidence/meta/x",
	} {
		err := b.put(context.Background(), filepath.ToSlash(dir)+"/"+rel, []byte("x"))
		var se *storeError
		if !errors.As(err, &se) || se.op != "file layout" {
			t.Errorf("put(%q) = %v, want a file layout error", rel, err)
		}
	}
	if err := b.put(context.Background(), filepath.ToSlash(base)+"/elsewhere/evidence/x", []byte("x")); err == nil {
		t.Error("a key outside the content root was accepted")
	}
	if _, err := os.Lstat(filepath.Join(base, "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a traversal key created a directory outside the content root")
	}
	if _, err := os.Lstat(filepath.Join(base, "elsewhere")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a key outside the root created a directory")
	}
}
