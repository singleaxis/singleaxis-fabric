// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRoots is the BPF root map of the tests.
type fakeRoots struct {
	mu    sync.Mutex
	roots map[uint64]uint32
	log   []string
}

func newFakeRoots() *fakeRoots { return &fakeRoots{roots: map[uint64]uint32{}} }

func (f *fakeRoots) setRoot(id uint64, scope uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roots[id] = scope
	f.log = append(f.log, fmt.Sprintf("set %d", id))
	return nil
}

func (f *fakeRoots) deleteRoot(id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.roots, id)
	f.log = append(f.log, fmt.Sprintf("delete %d", id))
	return nil
}

func (f *fakeRoots) has(id uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.roots[id]
	return ok
}

func (f *fakeRoots) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.roots)
}

// fakeIDs gives every directory a stable id, as the cgroup inode would.
type fakeIDs struct {
	mu  sync.Mutex
	ids map[string]uint64
}

func (f *fakeIDs) id(path string) (uint64, error) {
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		return 0, fmt.Errorf("not a cgroup directory")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ids == nil {
		f.ids = map[string]uint64{}
	}
	if id, ok := f.ids[path]; ok {
		return id, nil
	}
	f.ids[path] = uint64(1000 + len(f.ids))
	return f.ids[path], nil
}

func pod(uid, node string, labels map[string]string, containers ...string) map[string]any {
	var statuses []map[string]string
	for _, c := range containers {
		statuses = append(statuses, map[string]string{"containerID": "containerd://" + c})
	}
	return map[string]any{
		"metadata": map[string]any{"uid": uid, "labels": labels, "resourceVersion": "7"},
		"spec":     map[string]any{"nodeName": node},
		"status":   map[string]any{"containerStatuses": statuses},
	}
}

// fakeAPIServer answers the pod list and streams watch events from a
// channel, checking the request the emitter sends.
type fakeAPIServer struct {
	t      *testing.T
	srv    *httptest.Server
	events chan map[string]any
	list   []map[string]any
	mu     sync.Mutex
	paths  []string
}

func newFakeAPIServer(t *testing.T, list ...map[string]any) *fakeAPIServer {
	f := &fakeAPIServer{t: t, events: make(chan map[string]any, 16), list: list}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPIServer) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.String())
	f.mu.Unlock()
	if r.Method != http.MethodGet || r.URL.Path != "/api/v1/pods" || r.Header.Get("Authorization") != "Bearer sa-token" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	q := r.URL.Query()
	if q.Get("fieldSelector") != "spec.nodeName=node-a" || q.Get("labelSelector") != "app=agent,tier=ai" {
		http.Error(w, "bad selector", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if q.Get("watch") == "" {
		_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"resourceVersion": "5"}, "items": f.list})
		return
	}
	flusher := w.(http.Flusher)
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-f.events:
			_ = json.NewEncoder(w).Encode(ev)
			flusher.Flush()
		}
	}
}

func (f *fakeAPIServer) client(t *testing.T) *kubeClient {
	t.Helper()
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("sa-token\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "ca.crt")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}
	if err := os.WriteFile(ca, pem.EncodeToMemory(block), 0o400); err != nil {
		t.Fatal(err)
	}
	k, err := newKubeClient(f.srv.URL, token, ca, "node-a", "app=agent,tier=ai")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

const (
	uidA = "6a1d9c2e-4b7f-4e10-9a3c-2f5d8e7b1c04"
	uidB = "7b2e0d3f-5c80-4f21-8b4d-3a6e9f8c2d15"
	uidC = "8c3f1e40-6d91-4032-9c5e-4b7f0a9d3e26"
)

func mkdirs(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// TestPodWatcherInstallsAndRemovesRoots: a fake API server and a fake
// cgroupfs. A matching pod's slice is installed as an agent root when it
// appears and removed after the pod's deletion; a non-matching pod and
// another node's pod are not installed.
func TestPodWatcherInstallsAndRemovesRoots(t *testing.T) {
	cgroot := t.TempDir()
	mkdirs(t, filepath.Join(cgroot, "kubepods.slice/kubepods-burstable.slice"), filepath.Join(cgroot, "kubepods.slice/kubepods-besteffort.slice"))
	api := newFakeAPIServer(t)
	roots, ids := newFakeRoots(), &fakeIDs{}
	late := 0
	scope := newPodScope(cgroot, roots, ids.id, func() { late++ }, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go api.client(t).run(ctx, scope)
	go scope.watchSlices(ctx, 20*time.Millisecond)

	match := map[string]string{"app": "agent", "tier": "ai", "extra": "x"}
	api.events <- map[string]any{"type": "ADDED", "object": pod(uidA, "node-a", match)}
	// The API server filters; the emitter checks again on its side.
	api.events <- map[string]any{"type": "ADDED", "object": pod(uidB, "node-a", map[string]string{"app": "agent"})}
	api.events <- map[string]any{"type": "ADDED", "object": pod(uidC, "node-b", match)}
	api.events <- map[string]any{"type": "BOOKMARK", "object": map[string]any{"metadata": map[string]any{"resourceVersion": "9"}}}
	time.Sleep(100 * time.Millisecond)
	if roots.count() != 0 {
		t.Fatal("a root was installed before any pod slice existed")
	}

	sliceA := filepath.Join(cgroot, "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod"+strings.ReplaceAll(uidA, "-", "_")+".slice")
	sliceB := filepath.Join(cgroot, "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod"+strings.ReplaceAll(uidB, "-", "_")+".slice")
	sliceC := filepath.Join(cgroot, "kubepods.slice/kubepods-pod"+strings.ReplaceAll(uidC, "-", "_")+".slice")
	mkdirs(t, sliceB, sliceC)
	mkdirs(t, sliceA, filepath.Join(sliceA, "cri-containerd-"+strings.Repeat("aa", 32)+".scope"))
	idA, _ := ids.id(sliceA)
	idB, _ := ids.id(sliceB)
	idC, _ := ids.id(sliceC)
	eventually(t, "pod A's slice installed", func() bool { return roots.has(idA) })
	time.Sleep(100 * time.Millisecond)
	if roots.has(idB) || roots.has(idC) || roots.count() != 1 {
		t.Fatalf("roots = %v; want only pod A's slice", roots.log)
	}
	if roots.roots[idA] != scopeAgent {
		t.Fatal("a pod root is not an agent root")
	}
	if late != 0 {
		t.Fatal("a root installed with only the sandbox container reported scope_late")
	}

	api.events <- map[string]any{"type": "MODIFIED", "object": pod(uidA, "node-a", match, strings.Repeat("bb", 32))}
	api.events <- map[string]any{"type": "DELETED", "object": pod(uidA, "node-a", match)}
	eventually(t, "pod A's root removed", func() bool { return !roots.has(idA) })
	if scope.installedCount() != 0 || scope.rootsInstalled.Load() != 1 || scope.rootsRemoved.Load() != 1 {
		t.Fatalf("installed=%d counters installed=%d removed=%d", scope.installedCount(), scope.rootsInstalled.Load(), scope.rootsRemoved.Load())
	}
	// The cgroupfs driver's layout resolves too.
	uidD := "9d402f51-7ea2-4143-ad6f-5c80b1ae4f37"
	sliceD := filepath.Join(cgroot, "kubepods/burstable/pod"+uidD)
	mkdirs(t, sliceD)
	idD, _ := ids.id(sliceD)
	api.events <- map[string]any{"type": "ADDED", "object": pod(uidD, "node-a", match)}
	eventually(t, "pod D's cgroupfs slice installed", func() bool { return roots.has(idD) })

	api.mu.Lock()
	defer api.mu.Unlock()
	for _, p := range api.paths {
		if !strings.HasPrefix(p, "/api/v1/pods?") {
			t.Fatalf("request outside the pods list and watch: %s", p)
		}
	}
}

// TestPodWatcherRelistsAndKeepsRoots: after the watch expires the emitter
// relists; a pod gone from the list loses its root, others keep theirs. An
// API error never removes installed roots.
func TestPodWatcherRelistsAndKeepsRoots(t *testing.T) {
	cgroot := t.TempDir()
	match := map[string]string{"app": "agent", "tier": "ai"}
	sliceA := filepath.Join(cgroot, "kubepods.slice/kubepods-pod"+strings.ReplaceAll(uidA, "-", "_")+".slice")
	sliceB := filepath.Join(cgroot, "kubepods.slice/kubepods-pod"+strings.ReplaceAll(uidB, "-", "_")+".slice")
	mkdirs(t, sliceA, sliceB)
	api := newFakeAPIServer(t, pod(uidA, "node-a", match), pod(uidB, "node-a", match))
	roots, ids := newFakeRoots(), &fakeIDs{}
	scope := newPodScope(cgroot, roots, ids.id, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go api.client(t).run(ctx, scope)
	idA, _ := ids.id(sliceA)
	idB, _ := ids.id(sliceB)
	eventually(t, "both listed pods installed", func() bool { return roots.has(idA) && roots.has(idB) })

	api.mu.Lock()
	api.list = []map[string]any{pod(uidB, "node-a", match)}
	api.mu.Unlock()
	api.events <- map[string]any{"type": "ERROR", "object": map[string]any{"code": 410}}
	eventually(t, "pod A dropped after the relist", func() bool { return !roots.has(idA) })
	if !roots.has(idB) {
		t.Fatal("a pod still listed lost its root")
	}
	if scope.apiErrors.Load() == 0 {
		t.Fatal("the expired watch was not counted")
	}
}

// TestScopeLateIsUpstreamLoss: a pod root installed after a container other
// than the sandbox container exists in its slice gives upstream loss
// scope_late with an unknown count on the next heartbeat.
func TestScopeLateIsUpstreamLoss(t *testing.T) {
	cfg := productionConfig(t, t.TempDir())
	src := openTestSource(t, cfg)
	defer src.Close(false)
	prod := newProduction(src, &fakeSender{})
	cgroot := t.TempDir()
	roots, ids := newFakeRoots(), &fakeIDs{}
	scope := newPodScope(cgroot, roots, ids.id, func() { prod.upstreamLoss(lossScopeLate, -1) }, nil)

	heartbeats := func() []map[string]any {
		t.Helper()
		before := len(pendingSpans(t, src))
		if err := prod.heartbeat(); err != nil {
			t.Fatal(err)
		}
		var out []map[string]any
		for _, s := range pendingSpans(t, src)[before:] {
			out = append(out, s.attrs)
		}
		return out
	}

	// On time: the slice holds only the sandbox (pause) container.
	onTime := filepath.Join(cgroot, "kubepods.slice/kubepods-pod"+strings.ReplaceAll(uidA, "-", "_")+".slice")
	mkdirs(t, filepath.Join(onTime, "cri-containerd-"+strings.Repeat("11", 32)+".scope"))
	scope.upsert(&podInfo{uid: uidA, containers: map[string]bool{}})
	if scope.installedCount() != 1 {
		t.Fatal("on-time pod root not installed")
	}
	hb := heartbeats()
	if len(hb) != 1 || hb[0]["fabric.sensor.upstream_lost"] != int64(0) || hb[0]["fabric.sensor.upstream_loss_reason"] != nil {
		t.Fatalf("on-time heartbeat = %v", hb)
	}

	// Late: a second container cgroup already exists.
	late := filepath.Join(cgroot, "kubepods/besteffort/pod"+uidB)
	mkdirs(t, filepath.Join(late, strings.Repeat("22", 32)), filepath.Join(late, strings.Repeat("33", 32)))
	scope.upsert(&podInfo{uid: uidB, containers: map[string]bool{}})
	// Late: the API server already lists a created container whose cgroup
	// is gone (an init container), with only the sandbox left.
	gone := filepath.Join(cgroot, "kubepods.slice/kubepods-pod"+strings.ReplaceAll(uidC, "-", "_")+".slice")
	mkdirs(t, gone)
	scope.upsert(&podInfo{uid: uidC, containers: map[string]bool{strings.Repeat("44", 32): true}})
	if scope.installedCount() != 3 || scope.rootsLate.Load() != 2 {
		t.Fatalf("installed=%d late=%d", scope.installedCount(), scope.rootsLate.Load())
	}
	hb = heartbeats()
	if len(hb) != 1 || hb[0]["fabric.sensor.upstream_loss_reason"] != lossScopeLate || hb[0]["fabric.sensor.upstream_lost"] != int64(-1) {
		t.Fatalf("scope_late heartbeat = %v", hb)
	}
	if hb := heartbeats(); len(hb) != 1 || hb[0]["fabric.sensor.upstream_lost"] != int64(0) {
		t.Fatalf("the loss was reported twice: %v", hb)
	}
}

// TestPodRootLimit: at most 64 pod roots; a further matching pod is refused
// once and reported.
func TestPodRootLimit(t *testing.T) {
	cgroot := t.TempDir()
	roots, ids := newFakeRoots(), &fakeIDs{}
	refused := 0
	scope := newPodScope(cgroot, roots, ids.id, nil, func() { refused++ })
	for i := 0; i <= maxPodRoots; i++ {
		uid := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		mkdirs(t, filepath.Join(cgroot, "kubepods/pod"+uid))
		scope.upsert(&podInfo{uid: uid, containers: map[string]bool{}})
	}
	scope.resync()
	if roots.count() != maxPodRoots || refused != 1 {
		t.Fatalf("roots=%d refused=%d", roots.count(), refused)
	}
}
