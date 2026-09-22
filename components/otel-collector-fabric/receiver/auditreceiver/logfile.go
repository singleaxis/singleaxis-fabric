// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import (
	"bufio"
	"context"
	"io"
	"os"
	"time"
)

// tailFile streams audit.log lines, following rotation: when the file shrinks
// or is replaced it reopens at the start of the new file.
func tailFile(ctx context.Context, path string, out chan<- string) {
	defer close(out)
	var (
		f      *os.File
		reader *bufio.Reader
		offset int64
	)
	open := func() bool {
		nf, err := os.Open(path)
		if err != nil {
			return false
		}
		f = nf
		reader = bufio.NewReaderSize(f, 64<<10)
		offset = 0
		return true
	}
	if !open() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
	for {
		select {
		case <-ctx.Done():
			if f != nil {
				f.Close()
			}
			return
		default:
		}
		if f == nil && !open() {
			time.Sleep(time.Second)
			continue
		}
		line, err := reader.ReadString('\n')
		if err == nil {
			offset += int64(len(line))
			select {
			case out <- line:
			case <-ctx.Done():
				f.Close()
				return
			}
			continue
		}
		if err == io.EOF {
			// Rotation check: if the file on disk is now a different inode or
			// smaller than our offset, reopen.
			if fi, statErr := os.Stat(path); statErr != nil {
				f.Close()
				f = nil
			} else if fi.Size() < offset {
				f.Close()
				if !open() {
					time.Sleep(time.Second)
				}
				continue
			} else if self, serr := f.Stat(); serr != nil || !os.SameFile(fi, self) {
				f.Close()
				f = nil
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		f.Close()
		f = nil
		time.Sleep(200 * time.Millisecond)
	}
}
