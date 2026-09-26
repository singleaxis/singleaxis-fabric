// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import "fmt"

func cgroupIDFromPath(path string) (uint64, error) {
	return 0, fmt.Errorf("cgroup resolution requires Linux")
}
