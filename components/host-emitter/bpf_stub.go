// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import "fmt"

// bpfRuntime is a stub off Linux so `go build`/`go test` work on developer
// machines; the real CO-RE loader lives in bpf.go behind the linux tag.
type bpfRuntime struct{}

func loadBPF(cfg *Config) (*bpfRuntime, error) {
	return nil, fmt.Errorf("fabric-host-emitter requires Linux (eBPF tracepoints, kernel >= 5.8 with BTF)")
}

func (rt *bpfRuntime) next() (*event, error)      { return nil, fmt.Errorf("unsupported") }
func (rt *bpfRuntime) close()                     {}
func (rt *bpfRuntime) lossCount() (uint64, error) { return 0, fmt.Errorf("unsupported") }
