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
	tailFileObserved(ctx, path, out, nil)
}

func tailFileObserved(ctx context.Context, path string, out chan<- string, onIssue func(string)) {
	defer close(out)
	report := func(reason string) {
		if onIssue != nil {
			onIssue(reason)
		}
	}
	var (
		f       *os.File
		reader  *bufio.Reader
		offset  int64
		partial string
	)
	open := func() bool {
		nf, err := os.Open(path)
		if err != nil {
			report("logfile_unavailable")
			return false
		}
		if partial != "" {
			report("partial_line_discarded")
		}
		f = nf
		reader = bufio.NewReaderSize(f, 64<<10)
		offset = 0
		partial = ""
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
		offset += int64(len(line))
		if err == nil {
			line = partial + line
			partial = ""
			select {
			case out <- line:
			case <-ctx.Done():
				f.Close()
				return
			}
			continue
		}
		if err == io.EOF {
			// A writer may append the remainder of a line later. ReadString
			// consumes bytes even on EOF, so retain them until newline.
			partial += line
			// Rotation check: if the file on disk is now a different inode or
			// smaller than our offset, reopen.
			if fi, statErr := os.Stat(path); statErr != nil {
				report("logfile_unavailable")
				f.Close()
				f = nil
			} else if self, serr := f.Stat(); serr != nil || !os.SameFile(fi, self) {
				report("logfile_replaced")
				f.Close()
				f = nil
			} else if fi.Size() < offset {
				report("logfile_truncated")
				f.Close()
				f = nil
				if !open() {
					time.Sleep(time.Second)
				}
				continue
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		report("logfile_read_error")
		f.Close()
		f = nil
		time.Sleep(200 * time.Millisecond)
	}
}
