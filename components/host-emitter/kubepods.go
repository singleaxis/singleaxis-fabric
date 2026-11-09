// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// kubepodsRoot is one kubelet pod hierarchy found under the cgroup mount.
//
// The kubelet places pods under <cgroup-root>/kubepods, where <cgroup-root> is
// its --cgroup-root ("/" by default). With the systemd driver every level is a
// slice whose unit name joins all its ancestors with "-": --cgroup-root=/kubelet
// (kind, some managed distributions) gives
// kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/
// kubelet-kubepods-besteffort-pod<uid>.slice. With the cgroupfs driver the
// levels are plain directories: kubelet/kubepods/besteffort/pod<uid>.
type kubepodsRoot struct {
	// dir is the absolute kubepods directory (kubepods.slice,
	// <prefix>-kubepods.slice, or kubepods).
	dir string
	// unit is the systemd slice's unit name without ".slice"
	// ("kubepods", "kubelet-kubepods"); empty for the cgroupfs driver.
	unit string
}

// candidates lists where this hierarchy places a pod's cgroup, for every QoS
// class (056 §4.3 "Kubernetes sandbox roots").
func (r kubepodsRoot) candidates(uid string) []string {
	if r.unit == "" {
		return []string{
			filepath.Join(r.dir, "burstable", "pod"+uid),
			filepath.Join(r.dir, "besteffort", "pod"+uid),
			filepath.Join(r.dir, "pod"+uid),
		}
	}
	// systemd escapes "-" in a unit name component as "_".
	u := strings.ReplaceAll(uid, "-", "_")
	return []string{
		filepath.Join(r.dir, r.unit+"-burstable.slice", r.unit+"-burstable-pod"+u+".slice"),
		filepath.Join(r.dir, r.unit+"-besteffort.slice", r.unit+"-besteffort-pod"+u+".slice"),
		filepath.Join(r.dir, r.unit+"-pod"+u+".slice"),
	}
}

// qosDirs are the directories a new pod cgroup of this hierarchy appears in.
func (r kubepodsRoot) qosDirs() []string {
	if r.unit == "" {
		return []string{r.dir, filepath.Join(r.dir, "burstable"), filepath.Join(r.dir, "besteffort")}
	}
	return []string{r.dir, filepath.Join(r.dir, r.unit+"-burstable.slice"), filepath.Join(r.dir, r.unit+"-besteffort.slice")}
}

// defaultKubepods are the hierarchies of a kubelet with the default
// --cgroup-root, under either driver. They are always searched, so a pod
// whose cgroup appears there is found even before discovery saw the
// directory (the kubelet may start after the emitter).
func defaultKubepods(cgroupRoot string) []kubepodsRoot {
	return []kubepodsRoot{
		{dir: filepath.Join(cgroupRoot, "kubepods.slice"), unit: "kubepods"},
		{dir: filepath.Join(cgroupRoot, "kubepods")},
	}
}

// Discovery bounds: a kubelet --cgroup-root is a few levels deep at most, and
// a host can hold thousands of service and container cgroups, so the search
// stops at a depth and a directory budget instead of walking the whole tree.
const (
	kubepodsMaxDepth = 4
	kubepodsMaxDirs  = 4096
)

// discoverKubepods finds every kubelet pod hierarchy under the cgroup mount:
// the defaults first, then any kubepods.slice, <prefix>-kubepods.slice or
// kubepods directory at most kubepodsMaxDepth levels down (a non-default
// --cgroup-root). It reads directory names only. cgroup v1 hierarchies (a
// cgroup.procs file but no cgroup.controllers) are never entered: the BPF
// scope compares cgroup v2 ids, and a v1 directory's inode is not one. On a
// hybrid host the v2 hierarchy (usually "unified") is searched.
func discoverKubepods(cgroupRoot string) []kubepodsRoot {
	roots := defaultKubepods(cgroupRoot)
	seen := map[string]bool{}
	for _, r := range roots {
		seen[r.dir] = true
	}
	var found []kubepodsRoot
	type level struct {
		dir   string
		depth int
	}
	queue := []level{{cgroupRoot, 0}}
	visited := 0
	for len(queue) > 0 && visited < kubepodsMaxDirs {
		cur := queue[0]
		queue = queue[1:]
		visited++
		entries, err := os.ReadDir(cur.dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			path := filepath.Join(cur.dir, name)
			if cgroupV1Dir(path) {
				continue
			}
			switch {
			case name == "kubepods":
				if !seen[path] {
					seen[path] = true
					found = append(found, kubepodsRoot{dir: path})
				}
				continue
			case name == "kubepods.slice" || strings.HasSuffix(name, "-kubepods.slice"):
				if !seen[path] {
					seen[path] = true
					found = append(found, kubepodsRoot{dir: path, unit: strings.TrimSuffix(name, ".slice")})
				}
				continue
			case strings.HasSuffix(name, ".scope"):
				// A container or session: never holds a kubelet hierarchy.
				continue
			}
			if cur.depth+1 < kubepodsMaxDepth {
				queue = append(queue, level{path, cur.depth + 1})
			}
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].dir < found[j].dir })
	return append(roots, found...)
}

// cgroupV1Dir reports whether path is a cgroup v1 directory: it has
// cgroup.procs but no cgroup.controllers (a v2-only file).
func cgroupV1Dir(path string) bool {
	if _, err := os.Stat(filepath.Join(path, "cgroup.controllers")); err == nil {
		return false
	}
	_, err := os.Stat(filepath.Join(path, "cgroup.procs"))
	return err == nil
}
