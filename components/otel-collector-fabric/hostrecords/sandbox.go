// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package hostrecords

import (
	"regexp"
	"strings"
)

var (
	containerLeaf = regexp.MustCompile(`^(?:(?:docker|cri-containerd|crio|libpod)-([0-9a-f]{64})\.scope|([0-9a-f]{64}))$`)
	podSystemd    = regexp.MustCompile(`^kubepods(?:-(?:burstable|besteffort))?-pod([0-9a-f_]{36})\.slice$`)
	podCgroupfs   = regexp.MustCompile(`^pod([0-9a-f-]{36})$`)
	lowerUUID     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hex64         = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func containerOf(component string) string {
	m := containerLeaf.FindStringSubmatch(component)
	if m == nil {
		return ""
	}
	if m[1] != "" {
		return m[1]
	}
	return m[2]
}

func podOf(component string) string {
	m := podSystemd.FindStringSubmatch(component)
	if m == nil {
		m = podCgroupfs.FindStringSubmatch(component)
	}
	if m == nil {
		return ""
	}
	uid := strings.ReplaceAll(m[1], "_", "-")
	if !lowerUUID.MatchString(uid) {
		return ""
	}
	return uid
}

// SandboxIDs derives the container id (64 lowercase hex) and the pod uid from
// the last two components of a cgroup v2 path, the leaf first (spec 056 §4.3
// rule H5, vector sandbox-id-v1.json). These are the event's cgroup and its
// parent, which is all the BPF program reads; a full path and its last two
// components give the same ids. A container component is docker-,
// cri-containerd-, crio- or libpod- + 64 hex + .scope, or exactly 64 lowercase
// hex (cgroupfs drivers under any parent). A pod component is
// kubepods[-<qos>]-pod<uid>.slice (systemd driver, "_" read as "-") or
// pod<uid> (cgroupfs driver). Either value is "" when no component names it.
func SandboxIDs(cgroupPath string) (container, podUID string) {
	var parts []string
	for _, p := range strings.Split(cgroupPath, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	for i := len(parts) - 1; i >= 0; i-- {
		if container == "" {
			container = containerOf(parts[i])
		}
		if podUID == "" {
			podUID = podOf(parts[i])
		}
	}
	return container, podUID
}
