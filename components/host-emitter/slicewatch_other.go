// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import "context"

// sliceChanges has no inotify off Linux; the periodic resync covers it.
func sliceChanges(context.Context, []string) <-chan struct{} {
	return make(chan struct{})
}
