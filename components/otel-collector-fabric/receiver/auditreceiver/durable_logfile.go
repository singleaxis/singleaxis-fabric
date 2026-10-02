// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package auditreceiver

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"
)

func waitLog(ctx context.Context, delay time.Duration) bool {
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
func (r *auditReceiver) runDurableLog(ctx context.Context, d *durableLog) {
	for ctx.Err() == nil {
		if d.state.Pending != nil {
			ld, err := (&plog.JSONUnmarshaler{}).UnmarshalLogs(d.state.Pending.Logs)
			if err != nil {
				r.noteSourceIssue("durable_replay_corrupt")
				return
			}
			// A fresh decode protects the durable payload from mutating consumers.
			err = r.next.ConsumeLogs(ctx, ld)
			if err == nil {
				err = d.acknowledge()
			}
			if err != nil {
				r.stats.mu.Lock()
				r.stats.failedAttempts++
				r.stats.mu.Unlock()
				r.noteSourceIssue("durable_delivery_or_checkpoint_blocked")
				if r.backoff == 0 {
					r.backoff = 100 * time.Millisecond
				} else {
					r.backoff *= 2
					if r.backoff > 5*time.Second {
						r.backoff = 5 * time.Second
					}
				}
				if !waitLog(ctx, r.backoff) {
					return
				}
				continue
			}
			r.deliverySucceeded()
			// Durable mode paces rather than discards observations. Dedupe folding is
			// deliberately disabled; stable IDs support destination-side replay dedup.
			if r.cfg.MaxEventsPerSec > 0 {
				delay := float64(ld.LogRecordCount()) / r.cfg.MaxEventsPerSec * float64(time.Second)
				if delay > float64(time.Hour) {
					delay = float64(time.Hour)
				}
				if !waitLog(ctx, time.Duration(delay)) {
					return
				}
			}
			continue
		}
		ld, end, err := d.prepareSource()
		if err == nil && ld.LogRecordCount() == 0 {
			ld, end, err = r.readDurableBatch(ctx, d)
			if errors.Is(err, errSourceChanged) {
				ld, end, err = d.transition("source_truncated_or_rewritten")
			}
		}
		if err == nil && ld.LogRecordCount() > 0 {
			err = d.stage(ld, end)
		}
		if err != nil {
			r.noteSourceIssue("durable_source_or_storage_blocked")
		}
		if err != nil || ld.LogRecordCount() == 0 {
			if !waitLog(ctx, 200*time.Millisecond) {
				return
			}
		}
	}
}

func openLog(path string) (*os.File, string, error) {
	f, err := openLogHandle(path)
	if err != nil {
		return nil, "", err
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, "", errors.New("audit logfile is not a regular readable file")
	}
	id, err := logfileIdentity(fi)
	if err != nil {
		f.Close()
		return nil, "", err
	}
	return f, id, nil
}
func (d *durableLog) findSavedFile() (*os.File, error) {
	f, id, err := openLog(d.cfg.LogPath)
	if err == nil {
		if id == d.state.Cursor.FileID {
			return f, nil
		}
		f.Close()
	}
	dir, err := os.Open(filepath.Dir(d.cfg.LogPath))
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.Readdirnames(129)
	if err != nil && err != io.EOF {
		return nil, err
	}
	prefix := filepath.Base(d.cfg.LogPath) + "."
	for _, name := range entries {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		f, id, err := openLog(filepath.Join(filepath.Dir(d.cfg.LogPath), name))
		if err == nil {
			if id == d.state.Cursor.FileID {
				return f, nil
			}
			f.Close()
		}
	}
	return nil, errors.New("audit saved logfile generation is unavailable within bounded rotation scan")
}
func anchorAt(f *os.File, offset int64) (string, error) {
	if offset == 0 {
		return "", nil
	}
	n := int64(256)
	if offset < n {
		n = offset
	}
	b := make([]byte, int(n))
	if _, err := f.ReadAt(b, offset-n); err != nil {
		return "", err
	}
	return digest(b), nil
}
func (d *durableLog) prepareSource() (plog.Logs, logCursor, error) {
	empty := plog.NewLogs()
	c := d.state.Cursor
	if d.file != nil {
		fi, err := d.file.Stat()
		if err != nil {
			d.file.Close()
			d.file = nil
		} else {
			id, _ := logfileIdentity(fi)
			if id != c.FileID {
				d.file.Close()
				d.file = nil
			}
		}
	}
	if c.FileID == "" {
		f, id, err := openLog(d.cfg.LogPath)
		if err != nil {
			return empty, c, err
		}
		s := d.state
		s.Cursor.FileID = id
		if err = d.save(s); err != nil {
			f.Close()
			return empty, c, err
		}
		d.file = f
		return empty, d.state.Cursor, nil
	}
	if d.file == nil {
		f, err := d.findSavedFile()
		if err != nil {
			return d.transition("source_missing")
		}
		d.file = f
	}
	fi, err := d.file.Stat()
	if err != nil {
		return empty, c, err
	}
	anchor, err := anchorAt(d.file, c.Offset)
	if fi.Size() < c.Offset || err != nil || anchor != c.Anchor {
		return d.transition("source_truncated_or_rewritten")
	}
	// Drain the retained old descriptor before transitioning to the new inode.
	if fi.Size() == c.Offset {
		current, id, err := openLog(d.cfg.LogPath)
		if err == nil {
			current.Close()
			if id != c.FileID {
				return d.transition("source_rotated")
			}
		}
	}
	return empty, c, nil
}

// numericSuccessor uses auditd's numeric rename convention, never timestamps or
// inode magnitude as a chronology. Ambiguous/incomplete inventory is explicit.
func (d *durableLog) numericSuccessor() (string, string, bool) {
	dir, err := os.Open(filepath.Dir(d.cfg.LogPath))
	if err != nil {
		return d.cfg.LogPath, "", true
	}
	defer dir.Close()
	names, err := dir.Readdirnames(129)
	if err != nil && err != io.EOF {
		return d.cfg.LogPath, "", true
	}
	if len(names) > 128 {
		return d.cfg.LogPath, "", true
	}
	prefix := filepath.Base(d.cfg.LogPath) + "."
	candidates := map[int]string{0: d.cfg.LogPath}
	ids := map[int]string{}
	current, id, e := openLog(d.cfg.LogPath)
	if e != nil {
		return d.cfg.LogPath, "", true
	}
	current.Close()
	ids[0] = id
	oldIndex := -1
	ambiguous := false
	for _, name := range names {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		suffix := strings.TrimPrefix(name, prefix)
		n, e := strconv.Atoi(suffix)
		if e != nil || n < 1 || strconv.Itoa(n) != suffix {
			ambiguous = true
			continue
		}
		path := filepath.Join(filepath.Dir(d.cfg.LogPath), name)
		f, id, e := openLog(path)
		if e != nil {
			ambiguous = true
			continue
		}
		f.Close()
		candidates[n] = path
		ids[n] = id
		if id == d.state.Cursor.FileID {
			if oldIndex != -1 {
				ambiguous = true
			}
			oldIndex = n
		}
	}
	if oldIndex < 1 {
		return d.cfg.LogPath, "", true
	}
	best := -1
	for n := range candidates {
		if n < oldIndex && n > best {
			best = n
		}
	}
	if n := best; n >= 0 {
		if path, ok := candidates[n]; ok {
			// Recheck both mappings after enumeration; renumbering invalidates
			// adjacency and must not be presented as a proven contiguous rotation.
			old, oldID, e := openLog(candidates[oldIndex])
			if e != nil {
				return path, "", true
			}
			old.Close()
			next, nextID, e := openLog(path)
			if e != nil {
				return path, "", true
			}
			next.Close()
			return path, ids[n], ambiguous || n != oldIndex-1 || oldID != d.state.Cursor.FileID || nextID != ids[n] || nextID == oldID
		}
	}
	return d.cfg.LogPath, "", true
}

func (d *durableLog) transition(reason string) (plog.Logs, logCursor, error) {
	c := d.state.Cursor
	ld := plog.NewLogs()
	path := d.cfg.LogPath
	expectedID := ""
	if reason == "source_rotated" {
		var gap bool
		path, expectedID, gap = d.numericSuccessor()
		if gap {
			reason = "source_rotation_gap"
		}
	}
	f, id, err := openLog(path)
	if err != nil {
		return ld, c, err
	}
	f.Close()
	if expectedID != "" && id != expectedID {
		return ld, c, errors.New("audit rotation changed during inventory; retrying without cursor advance")
	}
	end := logCursor{FileID: id, Generation: c.Generation + 1}
	lr := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	lr.SetTimestamp(pcommonNow())
	lr.Attributes().PutStr("event_class", "audit")
	lr.Attributes().PutStr("audit.source", "logfile")
	lr.Attributes().PutStr("audit.event", reason)
	// These are incidents with unknown missing-event count, never invented totals.
	d.identify(lr, c, c.Offset, "transition:"+reason+":"+id)
	return ld, end, nil
}
func (d *durableLog) identify(lr plog.LogRecord, c logCursor, start int64, suffix string) {
	a := lr.Attributes()
	a.PutStr("audit.source_id", d.state.SourceID)
	a.PutInt("audit.source_generation", int64(c.Generation))
	a.PutInt("audit.cursor_start", start)
	a.PutInt("audit.cursor_end", c.Offset)
	a.PutStr("fabric.record_id", digest([]byte(d.state.SourceID+":"+strconv.FormatUint(c.Generation, 10)+":"+c.FileID+":"+strconv.FormatInt(start, 10)+":"+suffix)))
}

type batchEvent struct {
	event    *auditEvent
	start    int64
	end      int64
	complete bool
}
type batchCounts struct{ input, invalid, oversized, filtered, incomplete, unmatched, discarded int64 }

// readBoundedLine never allocates an unbounded input line. Oversized lines become
// exact counted loss evidence; unterminated lines do not advance the cursor.
var errSourceChanged = errors.New("audit logfile changed during batch read")

type observedRange struct {
	start, end int64
	hash       string
}

func readBoundedLine(ctx context.Context, br *bufio.Reader, max int, observe func([]byte)) (line []byte, n int64, oversize bool, sum string, err error) {
	h := sha256.New()
	for {
		if ctx.Err() != nil {
			return nil, n, oversize, "", ctx.Err()
		}
		part, e := br.ReadSlice('\n')
		if int64(len(part))+n > int64(max) {
			part = part[:int64(max)-n]
			e = bufio.ErrBufferFull
		}
		n += int64(len(part))
		h.Write(part)
		observe(part)
		if !oversize {
			if n > int64(max) {
				oversize = true
				line = nil
			} else {
				line = append(line, part...)
			}
		}
		if e == bufio.ErrBufferFull && n >= int64(max) {
			return nil, n, true, hex.EncodeToString(h.Sum(nil)), io.ErrShortBuffer
		}
		if e != bufio.ErrBufferFull {
			return line, n, oversize, hex.EncodeToString(h.Sum(nil)), e
		}
	}
}
func (r *auditReceiver) readDurableBatch(ctx context.Context, d *durableLog) (plog.Logs, logCursor, error) {
	ld := plog.NewLogs()
	c := d.state.Cursor
	if d.file == nil {
		return ld, c, errors.New("audit logfile is unavailable")
	}
	if _, err := d.file.Seek(c.Offset, io.SeekStart); err != nil {
		return ld, c, err
	}
	br := bufio.NewReaderSize(d.file, 4096)
	events := make(map[string]*batchEvent)
	var order []*batchEvent
	counts := batchCounts{}
	start := c.Offset
	// Retain only the last 256 actually observed source bytes. The committed
	// anchor must never be minted from different bytes read after translation.
	tailN := int64(256)
	if start < tailN {
		tailN = start
	}
	tail := make([]byte, tailN)
	if tailN > 0 {
		if _, err := d.file.ReadAt(tail, start-tailN); err != nil {
			return ld, d.state.Cursor, errSourceChanged
		}
		if digest(tail) != c.Anchor {
			return ld, d.state.Cursor, errSourceChanged
		}
	}
	observe := func(part []byte) {
		if len(part) >= 256 {
			tail = append(tail[:0], part[len(part)-256:]...)
		} else {
			tail = append(tail, part...)
			if len(tail) > 256 {
				tail = append(tail[:0], tail[len(tail)-256:]...)
			}
		}
	}
	var observed []observedRange
	lastActivity := time.Now()
	for chunks := 0; chunks < r.cfg.MaxBatchRecords && c.Offset-start < int64(r.cfg.MaxBatchBytes); chunks++ {
		if ctx.Err() != nil {
			return ld, d.state.Cursor, ctx.Err()
		}
		// Never split a potentially valid <=max_record_bytes line merely because
		// prior records used the batch budget. Resume it in the next batch instead.
		if c.Offset > start && c.Offset-start+int64(r.cfg.MaxRecordBytes) > int64(r.cfg.MaxBatchBytes) {
			break
		}
		priorTail := append([]byte(nil), tail...)
		line, n, large, sum, err := readBoundedLine(ctx, br, r.cfg.MaxRecordBytes, observe)
		if err == io.EOF && c.Discarding && n > 0 {
			observed = append(observed, observedRange{c.Offset, c.Offset + n, sum})
			c.Offset += n
			counts.discarded += n
			break
		}
		if err == io.EOF {
			tail = priorTail
			// Rewind fragments consumed on EOF. Wait briefly for trailing records.
			if _, e := d.file.Seek(c.Offset, io.SeekStart); e != nil {
				return ld, d.state.Cursor, e
			}
			br.Reset(d.file)
			if time.Since(lastActivity) < r.cfg.AssemblyTimeout && (len(events) > 0 || n > 0) {
				if !waitLog(ctx, 20*time.Millisecond) {
					return ld, d.state.Cursor, ctx.Err()
				}
				continue
			}
			if n > 0 {
				nf, id, e := openLog(d.cfg.LogPath)
				if e == nil {
					nf.Close()
					if id != c.FileID {
						counts.input++
						counts.invalid++
						observe(line)
						observed = append(observed, observedRange{c.Offset, c.Offset + n, sum})
						c.Offset += n
					}
				}
			}
			break
		}
		if err != nil && err != io.ErrShortBuffer {
			return ld, d.state.Cursor, err
		}
		before := c.Offset
		observed = append(observed, observedRange{c.Offset, c.Offset + n, sum})
		c.Offset += n
		lastActivity = time.Now()
		if c.Discarding || large {
			if !c.Discarding {
				counts.input++
				counts.oversized++
			}
			counts.discarded += n
			c.Discarding = err == io.ErrShortBuffer
			// ReadSlice may have consumed bytes beyond the exact configured limit.
			// Rewind buffered lookahead to the persisted discard boundary.
			if _, e := d.file.Seek(c.Offset, io.SeekStart); e != nil {
				return ld, d.state.Cursor, e
			}
			br.Reset(d.file)
			continue
		}
		counts.input++
		rec := parseRecord(string(line))
		if rec == nil {
			counts.invalid++
			continue
		}
		key := fmt.Sprintf("%d:%d:%d", rec.sec, rec.msec, rec.serial)
		ev := events[key]
		if ev == nil {
			ev = &batchEvent{event: &auditEvent{serial: rec.serial, sec: rec.sec, msec: rec.msec}, start: before}
			events[key] = ev
			order = append(order, ev)
		}
		ev.end = c.Offset
		if rec.typ == recEOE {
			ev.complete = true
			delete(events, key)
		} else {
			ev.event.records = append(ev.event.records, rec)
		}
	}
	if c.Offset == start {
		return ld, c, nil
	}
	if d.beforeVerify != nil {
		d.beforeVerify()
	}
	// Revalidate what was actually read, not a fresh anchor alone: copytruncate
	// may rewrite an equal/longer inode between reading records and checkpoint.
	oldAnchor, err := anchorAt(d.file, start)
	if err != nil || oldAnchor != d.state.Cursor.Anchor {
		return plog.NewLogs(), d.state.Cursor, errSourceChanged
	}
	for _, span := range observed {
		if ctx.Err() != nil {
			return plog.NewLogs(), d.state.Cursor, ctx.Err()
		}
		h := sha256.New()
		_, err = io.Copy(h, io.NewSectionReader(d.file, span.start, span.end-span.start))
		if err != nil || hex.EncodeToString(h.Sum(nil)) != span.hash {
			return plog.NewLogs(), d.state.Cursor, errSourceChanged
		}
	}
	c.Anchor = digest(tail)
	fresh, err := anchorAt(d.file, c.Offset)
	if err != nil || fresh != c.Anchor {
		return plog.NewLogs(), d.state.Cursor, errSourceChanged
	}
	out := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords()
	for _, ev := range order {
		if !ev.complete {
			counts.incomplete++
		}
		lr, _, ok := r.translate(ev.event)
		if !ok {
			if ev.event.find(recSyscall) == nil {
				counts.unmatched++
			} else {
				counts.filtered++
			}
			continue
		}
		lr.Attributes().PutBool("audit.assembly_complete", ev.complete)
		end := c
		end.Offset = ev.end
		d.identify(lr, end, ev.start, fmt.Sprintf("event:%d:%d:%d", ev.event.sec, ev.event.msec, ev.event.serial))
		lr.CopyTo(out.AppendEmpty())
	}
	marker := out.AppendEmpty()
	marker.SetTimestamp(pcommonNow())
	a := marker.Attributes()
	a.PutStr("event_class", "audit")
	a.PutStr("audit.source", "logfile")
	a.PutStr("audit.event", "logfile_checkpoint")
	a.PutInt("audit.input_records", counts.input)
	a.PutInt("audit.invalid_records", counts.invalid)
	a.PutInt("audit.oversized_records", counts.oversized)
	a.PutInt("audit.filtered_events", counts.filtered)
	a.PutInt("audit.incomplete_events", counts.incomplete)
	a.PutInt("audit.unmatched_events", counts.unmatched)
	a.PutInt("audit.discarded_bytes", counts.discarded)
	d.identify(marker, c, start, "checkpoint:"+strconv.FormatInt(c.Offset, 10))
	return ld, c, nil
}
