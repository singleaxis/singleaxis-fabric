// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// cgroupTree builds a fixture cgroup hierarchy under a temporary root. Each
// path is a directory; v2 directories get cgroup.controllers and
// cgroup.procs, v1 directories cgroup.procs only, as the kernel shows them.
func cgroupTree(t *testing.T, root string, v1 bool, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		cur := root
		for _, part := range strings.Split(d, "/") {
			cur = filepath.Join(cur, part)
			if err := os.MkdirAll(cur, 0o755); err != nil {
				t.Fatal(err)
			}
			files := []string{"cgroup.procs"}
			if !v1 {
				files = append(files, "cgroup.controllers")
			}
			for _, f := range files {
				if err := os.WriteFile(filepath.Join(cur, f), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func underscored(uid string) string { return strings.ReplaceAll(uid, "-", "_") }

// TestPodCgroupLayouts: the pod's cgroup is found for every kubelet layout
// the emitter supports, including a non-default --cgroup-root (kind's
// kubelet.slice/kubelet-kubepods.slice) under both drivers. Before
// discovery, only kubepods.slice and kubepods at the cgroup root were
// searched and the nested layouts scoped no pod.
func TestPodCgroupLayouts(t *testing.T) {
	u := underscored(uidA)
	cases := map[string]string{
		"systemd default root, burstable":            "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + u + ".slice",
		"systemd default root, guaranteed":           "kubepods.slice/kubepods-pod" + u + ".slice",
		"cgroupfs default root, besteffort":          "kubepods/besteffort/pod" + uidA,
		"kind: systemd --cgroup-root=/kubelet":       "kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod" + u + ".slice",
		"systemd --cgroup-root=/kubelet, guaranteed": "kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod" + u + ".slice",
		"cgroupfs --cgroup-root=/kubelet":            "kubelet/kubepods/burstable/pod" + uidA,
		"systemd two-level --cgroup-root=/a/b":       "a.slice/a-b.slice/a-b-kubepods.slice/a-b-kubepods-burstable.slice/a-b-kubepods-burstable-pod" + u + ".slice",
		"cgroupfs two-level --cgroup-root":           "system/k8s/kubepods/pod" + uidA,
		"hybrid v1/v2: the unified hierarchy":        "unified/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + u + ".slice",
	}
	for name, rel := range cases {
		t.Run(name, func(t *testing.T) {
			cgroot := t.TempDir()
			// Unrelated cgroups next to the kubelet's, as on a real node.
			cgroupTree(t, cgroot, false, "system.slice/containerd.service", "user.slice/user-0.slice")
			cgroupTree(t, cgroot, false, rel)
			roots, ids := newFakeRoots(), &fakeIDs{}
			scope := newPodScope(cgroot, roots, ids.id, nil, nil)
			scope.upsert(&podInfo{uid: uidA, containers: map[string]bool{}})
			want, _ := ids.id(filepath.Join(cgroot, rel))
			if !roots.has(want) || roots.count() != 1 {
				t.Fatalf("pod cgroup %s not installed (roots %v; searched %v)", rel, roots.log, scope.kubepodsDirs())
			}
			if matched, found := scope.scopeReport(); matched != 1 || found != 1 {
				t.Fatalf("report matched=%d found=%d", matched, found)
			}
		})
	}
}

// TestPodCgroupNeverFromV1OrContainers: a cgroup v1 hierarchy is never
// searched (its inode is not a v2 cgroup id), nor is a kubelet tree inside a
// container (a nested cluster's node); the health report then says the
// selector matched a pod whose cgroup was not found.
func TestPodCgroupNeverFromV1OrContainers(t *testing.T) {
	u := underscored(uidA)
	cgroot := t.TempDir()
	cgroupTree(t, cgroot, true, "memory/kubepods.slice/kubepods-pod"+u+".slice", "cpu/kubepods/pod"+uidA)
	cgroupTree(t, cgroot, false, "system.slice/docker-"+strings.Repeat("ab", 32)+".scope/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod"+u+".slice")
	roots, ids := newFakeRoots(), &fakeIDs{}
	scope := newPodScope(cgroot, roots, ids.id, nil, nil)
	scope.upsert(&podInfo{uid: uidA, containers: map[string]bool{}})
	if roots.count() != 0 {
		t.Fatalf("a v1 or nested-container cgroup was installed: %v", roots.log)
	}
	for _, d := range scope.kubepodsDirs() {
		if strings.Contains(d, "memory") || strings.Contains(d, "cpu/") || strings.Contains(d, ".scope") {
			t.Fatalf("searched %s", d)
		}
	}
	matched, found := scope.scopeReport()
	if matched != 1 || found != 0 {
		t.Fatalf("report matched=%d found=%d", matched, found)
	}
	msg := podScopeMismatch(matched, found, scope.kubepodsDirs())
	if !strings.Contains(msg, "selector matched 1 pods on this node, found 0 cgroups") || strings.Contains(msg, uidA) {
		t.Fatalf("mismatch line = %q", msg)
	}
	if podScopeMismatch(2, 2, nil) != "" {
		t.Fatal("a mismatch line when every pod was found")
	}
}

// TestKubeletRootAppearsLater: the kubelet creates its hierarchy after the
// emitter started; the pod is installed once discovery runs again, and the
// new hierarchy's QoS directories are watched from then on.
func TestKubeletRootAppearsLater(t *testing.T) {
	cgroot := t.TempDir()
	cgroupTree(t, cgroot, false, "system.slice")
	roots, ids := newFakeRoots(), &fakeIDs{}
	scope := newPodScope(cgroot, roots, ids.id, nil, nil)
	clock := time.Now()
	scope.now = func() time.Time { return clock }
	_, gen := scope.qosDirs()

	rel := "kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod" + underscored(uidA) + ".slice"
	cgroupTree(t, cgroot, false, rel)
	scope.upsert(&podInfo{uid: uidA, containers: map[string]bool{}})
	if roots.count() != 0 {
		t.Fatal("discovery ran again before rediscoverEvery")
	}
	clock = clock.Add(rediscoverEvery)
	scope.resync()
	want, _ := ids.id(filepath.Join(cgroot, rel))
	if !roots.has(want) {
		t.Fatalf("pod not installed after the kubelet hierarchy appeared (searched %v)", scope.kubepodsDirs())
	}
	dirs, next := scope.qosDirs()
	if next == gen || !contains(dirs, filepath.Join(cgroot, "kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice")) {
		t.Fatalf("new hierarchy not watched: gen %d->%d dirs %v", gen, next, dirs)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// TestDiscoveryIsBounded: a deep or wide tree is not walked past the depth
// and directory budget.
func TestDiscoveryIsBounded(t *testing.T) {
	cgroot := t.TempDir()
	cgroupTree(t, cgroot, false, "a/b/c/d/e/kubepods")
	for _, r := range discoverKubepods(cgroot) {
		if strings.HasSuffix(r.dir, "e/kubepods") {
			t.Fatal("a hierarchy deeper than kubepodsMaxDepth was searched")
		}
	}
}

// TestPodWatcherOnKindLayout: the pod watcher end to end (fake API server)
// on kind's cgroup layout installs the pod and reports it found.
func TestPodWatcherOnKindLayout(t *testing.T) {
	cgroot := t.TempDir()
	qos := "kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice"
	cgroupTree(t, cgroot, false, qos)
	api := newFakeAPIServer(t)
	roots, ids := newFakeRoots(), &fakeIDs{}
	scope := newPodScope(cgroot, roots, ids.id, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go api.client(t).run(ctx, scope)
	go scope.watchSlices(ctx, 20*time.Millisecond)

	match := map[string]string{"app": "agent", "tier": "ai"}
	api.events <- map[string]any{"type": "ADDED", "object": pod(uidA, "node-a", match)}
	slice := filepath.Join(cgroot, qos, "kubelet-kubepods-besteffort-pod"+underscored(uidA)+".slice")
	eventually(t, "the pod is matched", func() bool { m, _ := scope.scopeReport(); return m == 1 })
	if _, found := scope.scopeReport(); found != 0 {
		t.Fatal("a cgroup found before the kubelet created it")
	}
	cgroupTree(t, slice, false, "cri-containerd-"+strings.Repeat("cd", 32)+".scope")
	id, _ := ids.id(slice)
	eventually(t, "kind pod slice installed", func() bool { return roots.has(id) })
	if m, f := scope.scopeReport(); m != 1 || f != 1 {
		t.Fatalf("report matched=%d found=%d", m, f)
	}
}
