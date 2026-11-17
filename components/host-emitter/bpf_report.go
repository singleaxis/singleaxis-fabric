// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"log"
)

// errNodeNotSupported marks a BPF load failure that the node itself causes:
// its kernel, its BTF, or the capabilities the container was given.
var errNodeNotSupported = errors.New("node not supported")

// nodeNotSupportedLine is the start-up failure line a reader of the emitter's
// log (fabric verify --kubernetes, fabric doctor --kubernetes) turns into
// pods_unscoped{reason="node_not_supported"} for this node. It carries no
// value from the node.
const nodeNotSupportedLine = "fabric-host-emitter: health node_supported=false pods_unscoped_reason=" + unscopedNodeNotSupported +
	": the BPF programs cannot load on this node, so no pod on it is captured by the host sensor. " +
	"The node needs Linux 5.8 or later with BTF (/sys/kernel/btf/vmlinux) and a container allowed CAP_BPF, CAP_PERFMON and CAP_SYS_RESOURCE; " +
	"a serverless or sandboxed node pool cannot run it: keep the DaemonSet off those nodes (hostSensor.nodeSelector) and rely on wire capture there"

// reportNodeNotSupported logs the line when err is a node cause. The emitter
// still exits with the error: it never runs partially.
func reportNodeNotSupported(err error) {
	if errors.Is(err, errNodeNotSupported) {
		log.Print(nodeNotSupportedLine)
	}
}
