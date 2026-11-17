// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
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

// runtimeAPIServer answers the pod list and RuntimeClass reads.
type runtimeAPIServer struct {
	srv     *httptest.Server
	mu      sync.Mutex
	pods    []map[string]any
	classes map[string]string // name -> handler
	denied  bool              // RuntimeClass reads answer 403
	reads   map[string]int
}

func newRuntimeAPIServer(t *testing.T) *runtimeAPIServer {
	f := &runtimeAPIServer{classes: map[string]string{}, reads: map[string]int{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method != http.MethodGet {
			http.Error(w, "read only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if name, ok := strings.CutPrefix(r.URL.Path, "/apis/node.k8s.io/v1/runtimeclasses/"); ok {
			f.reads[name]++
			handler, found := f.classes[name]
			switch {
			case f.denied:
				http.Error(w, "forbidden", http.StatusForbidden)
			case !found:
				http.Error(w, "not found", http.StatusNotFound)
			default:
				_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"name": name}, "handler": handler})
			}
			return
		}
		if r.URL.Path != "/api/v1/pods" || r.URL.Query().Get("watch") != "" {
			http.Error(w, "not served", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"resourceVersion": "5"}, "items": f.pods})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *runtimeAPIServer) client(t *testing.T) *kubeClient {
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
	k, err := newKubeClient(f.srv.URL, token, ca, "node-a", "app=agent")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func classPod(uid, class string) map[string]any {
	p := pod(uid, "node-a", map[string]string{"app": "agent"})
	if class != "" {
		p["spec"].(map[string]any)["runtimeClassName"] = class
	}
	return p
}

// TestUnsupportedRuntimeIsReportedNotScoped (spec 058 §10.5, E2 acceptance):
// a pod whose RuntimeClass handler is gVisor or Kata is never installed as a
// root, even when a cgroup of it exists, and is counted unsupported_runtime,
// not cgroup_not_found. A pod under an ordinary RuntimeClass is scoped.
func TestUnsupportedRuntimeIsReportedNotScoped(t *testing.T) {
	cgroot := t.TempDir()
	api := newRuntimeAPIServer(t)
	api.classes["gvisor"] = "runsc"
	api.classes["kata"] = "kata-qemu"
	api.classes["plain"] = "runc"
	api.pods = []map[string]any{classPod(uidA, "gvisor"), classPod(uidB, "kata"), classPod(uidC, "plain")}
	for _, uid := range []string{uidA, uidB, uidC} {
		mkdirs(t, filepath.Join(cgroot, "kubepods/besteffort/pod"+uid))
	}
	roots, ids := newFakeRoots(), &fakeIDs{}
	scope := newPodScope(cgroot, roots, ids.id, nil, nil)
	k := api.client(t)
	pods, _, err := k.list(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	scope.replace(pods)

	idC, _ := ids.id(filepath.Join(cgroot, "kubepods/besteffort/pod"+uidC))
	if roots.count() != 1 || !roots.has(idC) {
		t.Fatalf("roots = %v; want only the runc pod's cgroup", roots.log)
	}
	c := scope.counts()
	if c.selected != 3 || c.scoped != 1 || c.unscoped[unscopedUnsupportedRuntime] != 2 || c.unscoped[unscopedCgroupNotFound] != 0 {
		t.Fatalf("counts = %+v", c)
	}
	want := "pods_selected=3 pods_scoped=1 pods_unscoped=2 pods_unscoped_cgroup_not_found=0 pods_unscoped_unsupported_runtime=2 pods_unscoped_node_not_supported=0 pods_unscoped_pod_limit=0"
	if got := c.fields(); got != want {
		t.Fatalf("health fields\n got %s\nwant %s", got, want)
	}
	warn := podsUnscopedWarning(c, scope.kubepodsDirs())
	for _, part := range []string{"WARN", "unsupported_runtime", "gVisor or Kata", "wire capture"} {
		if !strings.Contains(warn, part) {
			t.Fatalf("warning lacks %q: %s", part, warn)
		}
	}
	for _, uid := range []string{uidA, uidB, uidC} {
		if strings.Contains(warn, uid) {
			t.Fatal("the warning names a pod")
		}
	}
	// One read per class: the handler of a RuntimeClass never changes.
	if _, _, err := k.list(context.Background()); err != nil {
		t.Fatal(err)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	for name, n := range api.reads {
		if n != 1 {
			t.Fatalf("RuntimeClass %s read %d times", name, n)
		}
	}
}

// TestUnscopedReasons: a selected pod with no cgroup is cgroup_not_found (the
// kind layout bug, F4, when it persists), one over the root limit is
// pod_limit, and the WARN names each reason with its fix. All scoped: silent.
func TestUnscopedReasons(t *testing.T) {
	cgroot := t.TempDir()
	roots, ids := newFakeRoots(), &fakeIDs{}
	scope := newPodScope(cgroot, roots, ids.id, nil, func() {})
	scope.upsert(&podInfo{uid: uidA, containers: map[string]bool{}})
	c := scope.counts()
	if c.selected != 1 || c.scoped != 0 || c.unscoped[unscopedCgroupNotFound] != 1 {
		t.Fatalf("counts = %+v", c)
	}
	warn := podsUnscopedWarning(c, scope.kubepodsDirs())
	if !strings.Contains(warn, "matched 1 pods on this node, 0 scoped, 1 not captured") ||
		!strings.Contains(warn, "EMIT_AGENT_CGROUP_ROOTS") || !strings.Contains(warn, "kubepods.slice") {
		t.Fatalf("warning: %s", warn)
	}
	mkdirs(t, filepath.Join(cgroot, "kubepods/pod"+uidA))
	scope.resync()
	c = scope.counts()
	if c.scoped != 1 || c.unscopedTotal() != 0 || podsUnscopedWarning(c, nil) != "" {
		t.Fatalf("after the cgroup appeared: %+v", c)
	}
	for i := 0; i < maxPodRoots; i++ {
		uid := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		mkdirs(t, filepath.Join(cgroot, "kubepods/pod"+uid))
		scope.upsert(&podInfo{uid: uid, containers: map[string]bool{}})
	}
	c = scope.counts()
	if c.selected != maxPodRoots+1 || c.scoped != maxPodRoots || c.unscoped[unscopedPodLimit] != 1 {
		t.Fatalf("at the limit: %+v", c)
	}
	if warn := podsUnscopedWarning(c, nil); !strings.Contains(warn, "pod_limit") || !strings.Contains(warn, "EMIT_AGENT_POD_SELECTOR") {
		t.Fatalf("limit warning: %s", warn)
	}
}

// TestRuntimeClassUnreadable: without the get permission (an older
// ClusterRole) or for a class that does not exist, the pod is treated like
// any other and the failure is counted; the read is not repeated per pod.
func TestRuntimeClassUnreadable(t *testing.T) {
	api := newRuntimeAPIServer(t)
	api.denied = true
	k := api.client(t)
	now := time.Unix(1_800_000_000, 0)
	k.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if h := k.runtimeHandler(context.Background(), "gvisor"); h != "" {
			t.Fatalf("handler %q from a refused read", h)
		}
	}
	if k.runtimeClassErrors.Load() != 1 || api.reads["gvisor"] != 1 {
		t.Fatalf("errors=%d reads=%d; want one of each", k.runtimeClassErrors.Load(), api.reads["gvisor"])
	}
	now = now.Add(runtimeClassRetry + time.Second)
	api.mu.Lock()
	api.denied = false
	api.classes["gvisor"] = "runsc"
	api.mu.Unlock()
	if h := k.runtimeHandler(context.Background(), "gvisor"); h != "runsc" {
		t.Fatalf("handler %q after the permission was granted", h)
	}
	// A name that is not a RuntimeClass name is never sent to the API server.
	if h := k.runtimeHandler(context.Background(), "../secrets"); h != "" || api.reads["../secrets"] != 0 {
		t.Fatal("an invalid RuntimeClass name was read")
	}
	scope := newPodScope(t.TempDir(), newFakeRoots(), (&fakeIDs{}).id, nil, nil)
	scope.upsert(&podInfo{uid: uidA, containers: map[string]bool{}, runtimeClass: "unknown"})
	if c := scope.counts(); c.unscoped[unscopedCgroupNotFound] != 1 {
		t.Fatalf("an unreadable class must count as cgroup_not_found: %+v", c)
	}
}

func TestUnsupportedRuntimeHandlers(t *testing.T) {
	for handler, want := range map[string]bool{
		"runsc": true, "gvisor": true, "kata": true, "kata-qemu": true, "kata-clh": true, "Kata-FC": true,
		"runc": false, "": false, "crun": false, "nvidia": false, "katacoda": false, "runsc2": false,
	} {
		if got := unsupportedRuntimeHandler(handler); got != want {
			t.Errorf("unsupportedRuntimeHandler(%q) = %v, want %v", handler, got, want)
		}
	}
}

// TestNodeNotSupportedLine: a BPF load failure caused by the node carries the
// reason and the fix; another start-up error does not claim it.
func TestNodeNotSupportedLine(t *testing.T) {
	if !errors.Is(fmt.Errorf("load eBPF objects: %w: %w", errNodeNotSupported, errors.New("no BTF")), errNodeNotSupported) {
		t.Fatal("the load error does not carry errNodeNotSupported")
	}
	for _, part := range []string{"node_supported=false", "pods_unscoped_reason=node_not_supported", "BTF", "hostSensor.nodeSelector"} {
		if !strings.Contains(nodeNotSupportedLine, part) {
			t.Fatalf("line lacks %q", part)
		}
	}
}
