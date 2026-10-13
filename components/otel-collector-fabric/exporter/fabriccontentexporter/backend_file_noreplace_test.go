// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabriccontentexporter

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Multi-process no-replace qualification (Sol data-exposure #5). Several
// exporter processes sharing one content directory race to write different
// bodies under the same object keys. For every key exactly one write may be
// accepted, every other writer must get errConflict, and the stored bytes
// must be the accepted body. The "rename" mode makes link(2) fail as on a
// filesystem without hard links, so the fallback path is what races.

const (
	helperEnv     = "FABRICCONTENT_NOREPLACE_HELPER"
	helperDirEnv  = "FABRICCONTENT_NOREPLACE_DIR"
	helperIDEnv   = "FABRICCONTENT_NOREPLACE_ID"
	helperModeEnv = "FABRICCONTENT_NOREPLACE_MODE"
	helperGoEnv   = "FABRICCONTENT_NOREPLACE_GO"
	raceKeys      = 40
	raceProcs     = 6
)

// errLinkUnsupported is what link(2) returns on filesystems without hard
// links (vfat, some FUSE and network filesystems).
var errLinkUnsupported = &os.LinkError{Op: "link", Err: syscall.EPERM}

// TestNoReplaceHelperProcess is the child body; it does nothing unless
// started by runNoReplaceRace.
func TestNoReplaceHelperProcess(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		t.Skip("helper process")
	}
	dir, id, mode := os.Getenv(helperDirEnv), os.Getenv(helperIDEnv), os.Getenv(helperModeEnv)
	if mode == "rename" {
		linkFile = func(string, string) error { return errLinkUnsupported }
	}
	gate := os.Getenv(helperGoEnv)
	for deadline := time.Now().Add(30 * time.Second); ; {
		if _, err := os.Stat(gate); err == nil {
			break
		}
		if time.Now().After(deadline) {
			fmt.Println("timeout")
			os.Exit(2)
		}
		time.Sleep(time.Millisecond)
	}
	b := newFileBackend(dir)
	for k := 0; k < raceKeys; k++ {
		key := filepath.ToSlash(filepath.Join(dir, "tenant-a", "evidence", "object-"+strconv.Itoa(k)))
		err := b.put(context.Background(), key, []byte(raceBody(id, k)))
		switch {
		case err == nil:
			fmt.Printf("%d ok\n", k)
		case errors.Is(err, errConflict):
			fmt.Printf("%d conflict\n", k)
		default:
			fmt.Printf("%d error %s\n", k, err)
		}
	}
	os.Exit(0)
}

func raceBody(id string, k int) string {
	return fmt.Sprintf("distinct body from writer %s for object %d", id, k)
}

func runNoReplaceRace(t *testing.T, mode string) {
	dir := filepath.Join(t.TempDir(), "content")
	gate := filepath.Join(t.TempDir(), "go")
	type child struct {
		id  string
		cmd *exec.Cmd
		out *strings.Builder
	}
	children := make([]child, 0, raceProcs)
	for i := 0; i < raceProcs; i++ {
		id := strconv.Itoa(i)
		cmd := exec.Command(os.Args[0], "-test.run=^TestNoReplaceHelperProcess$", "-test.count=1")
		cmd.Env = append(os.Environ(), helperEnv+"=1", helperDirEnv+"="+dir, helperIDEnv+"="+id, helperModeEnv+"="+mode, helperGoEnv+"="+gate)
		out := &strings.Builder{}
		cmd.Stdout = out
		cmd.Stderr = out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		children = append(children, child{id, cmd, out})
	}
	time.Sleep(200 * time.Millisecond) // let every child reach the barrier
	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	accepted := map[int][]string{}
	for _, c := range children {
		if err := c.cmd.Wait(); err != nil {
			t.Fatalf("writer %s failed: %v\n%s", c.id, err, c.out.String())
		}
		lines := 0
		sc := bufio.NewScanner(strings.NewReader(c.out.String()))
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 {
				continue
			}
			k, err := strconv.Atoi(fields[0])
			if err != nil {
				continue
			}
			lines++
			switch fields[1] {
			case "ok":
				accepted[k] = append(accepted[k], c.id)
			case "conflict":
			default:
				t.Errorf("writer %s object %d: unexpected result %q", c.id, k, sc.Text())
			}
		}
		if lines != raceKeys {
			t.Fatalf("writer %s reported %d results, want %d\n%s", c.id, lines, raceKeys, c.out.String())
		}
	}
	for k := 0; k < raceKeys; k++ {
		winners := accepted[k]
		if len(winners) != 1 {
			t.Errorf("object %d: %d writers accepted (%v), want exactly 1: an accepted body was overwritten", k, len(winners), winners)
			continue
		}
		got, err := os.ReadFile(filepath.Join(dir, "tenant-a", "evidence", "object-"+strconv.Itoa(k)))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != raceBody(winners[0], k) {
			t.Errorf("object %d holds a body other than the accepted one", k)
		}
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "tenant-a", "evidence"))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestFileBackendNoReplaceAcrossProcessesLink(t *testing.T) {
	runNoReplaceRace(t, "link")
}

func TestFileBackendNoReplaceAcrossProcessesWithoutHardLinks(t *testing.T) {
	if !renameNoReplaceSupported() {
		t.Skip("no atomic no-replace rename on this platform")
	}
	runNoReplaceRace(t, "rename")
}

// When the filesystem supports neither link(2) nor an atomic no-replace
// rename, the write fails with a retryable error and nothing is stored:
// there is no check-then-rename fallback.
func TestFileBackendWithoutAtomicNoReplaceFailsRetryably(t *testing.T) {
	saveLink, saveRename := linkFile, renameNoReplace
	t.Cleanup(func() { linkFile, renameNoReplace = saveLink, saveRename })
	linkFile = func(string, string) error { return errLinkUnsupported }
	renameNoReplace = func(string, string) error { return &os.LinkError{Op: "renameat2", Err: syscall.EINVAL} }

	dir := filepath.Join(t.TempDir(), "content")
	b := newFileBackend(dir)
	key := filepath.ToSlash(filepath.Join(dir, "tenant-a", "evidence", "object"))
	err := b.put(context.Background(), key, []byte("body"))
	var se *storeError
	if !errors.As(err, &se) {
		t.Fatalf("put = %v, want a retryable storeError", err)
	}
	if errors.Is(err, errConflict) {
		t.Fatal("unsupported no-replace reported as a conflict")
	}
	if _, statErr := os.Lstat(filepath.FromSlash(key)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("object written without an atomic no-replace primitive (stat err %v)", statErr)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "tenant-a", "evidence"))
	for _, e := range entries {
		t.Errorf("file left behind: %s", e.Name())
	}
}

// The rename fallback keeps replay semantics: identical bytes are success,
// different bytes a conflict, and the stored object is never replaced.
func TestFileBackendRenameFallbackReplayAndConflict(t *testing.T) {
	if !renameNoReplaceSupported() {
		t.Skip("no atomic no-replace rename on this platform")
	}
	saveLink := linkFile
	t.Cleanup(func() { linkFile = saveLink })
	linkFile = func(string, string) error { return errLinkUnsupported }

	dir := filepath.Join(t.TempDir(), "content")
	b := newFileBackend(dir)
	key := filepath.ToSlash(filepath.Join(dir, "tenant-a", "evidence", "object"))
	if err := b.put(context.Background(), key, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := b.put(context.Background(), key, []byte("first")); err != nil {
		t.Fatalf("identical replay = %v", err)
	}
	if err := b.put(context.Background(), key, []byte("second")); !errors.Is(err, errConflict) {
		t.Fatalf("different bytes = %v, want errConflict", err)
	}
	got, _ := os.ReadFile(filepath.FromSlash(key))
	if string(got) != "first" {
		t.Fatalf("stored object replaced: %q", got)
	}
	if mode := perm(t, filepath.FromSlash(key)); mode != 0o600 {
		t.Fatalf("object mode %o, want 600", mode)
	}
}
