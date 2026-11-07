// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package hostrecords

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func kinds(batches []*Batch) []string {
	out := make([]string, len(batches))
	for i, b := range batches {
		out[i] = b.kind
	}
	return out
}

func TestOpenStagesManifestZero(t *testing.T) {
	s := mustOpen(t, testConfig(t.TempDir()))
	defer crash(t, s)
	pending, _ := s.Pending()
	if got := kinds(pending); !slices.Equal(got, []string{kindManifest}) {
		t.Fatalf("pending %v, want manifest 0 only", got)
	}
	m := batchSpans(t, pending[0])[0].attrs
	if m["fabric.manifest.manifest_seq"] != int64(0) || m["fabric.manifest.after_source_sequence"] != int64(-1) ||
		m["fabric.manifest.unsealed_prior_epoch_count"] != int64(0) || m["fabric.source_id"] != s.SourceID() {
		t.Errorf("manifest 0: %v", m)
	}
	if !strings.HasPrefix(s.SourceID(), "s-") || len(s.SourceID()) != 34 || s.Epoch() == 0 || s.Epoch() >= 1<<63 {
		t.Errorf("source id %s, epoch %d", s.SourceID(), s.Epoch())
	}
}

func TestStagePositionsAndIDs(t *testing.T) {
	s := mustOpen(t, testConfig(t.TempDir()))
	defer crash(t, s)
	a, err := s.Stage([]Event{execEvent(10), execEvent(11)})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Stage([]Event{execEvent(12)})
	if err != nil {
		t.Fatal(err)
	}
	var sequences []int64
	ids := map[string]bool{}
	for _, span := range batchSpans(t, a, b) {
		sequences = append(sequences, span.attrs["fabric.source.sequence"].(int64))
		for _, k := range []string{"fabric.event_id", "fabric.attempt.uid"} {
			id := span.attrs[k].(string)
			if !uuid4.MatchString(id) || ids[id] {
				t.Errorf("%s %q is not a fresh uuid4", k, id)
			}
			ids[id] = true
		}
	}
	if !slices.Equal(sequences, []int64{0, 1, 2}) {
		t.Errorf("sequences %v", sequences)
	}
	if empty, err := s.Stage(nil); empty != nil || err != nil {
		t.Errorf("an empty stage gives (%v, %v)", empty, err)
	}
}

func TestStageRefusesWrongEventsWithoutAllocating(t *testing.T) {
	cfg := testConfig(t.TempDir())
	cfg.Classes = []string{"exec", "connect"}
	s := mustOpen(t, cfg)
	defer crash(t, s)
	bad := []Event{
		{},
		{TimeUnixNano: 1, Class: "file", Syscall: "openat", Result: "success", Pid: 1},  // class not enabled
		{TimeUnixNano: 1, Class: "exec", Syscall: "connect", Result: "success", Pid: 1}, // syscall of another class
		{TimeUnixNano: 1, Class: "exec", Syscall: "execve", Result: "ok", Pid: 1},
		{TimeUnixNano: 1, Class: "exec", Syscall: "execve", Result: "success", Pid: 0},
	}
	for i, e := range bad {
		if _, err := s.Stage([]Event{execEvent(5), e}); err == nil {
			t.Errorf("case %d staged", i)
		}
	}
	b, err := s.Stage([]Event{execEvent(5)})
	if err != nil {
		t.Fatal(err)
	}
	if b.first != 0 {
		t.Errorf("a refused batch allocated positions: first %d", b.first)
	}
	m := batchSpans(t, mustPendingManifest(t, s))[0].attrs
	if got := m["fabric.manifest.uncaptured_classes"]; !slicesEqualAny(got, []string{"sensor_file"}) {
		t.Errorf("uncaptured classes %v", got)
	}
}

func mustPendingManifest(t *testing.T, s *Source) *Batch {
	t.Helper()
	pending, _ := s.Pending()
	for _, b := range pending {
		if b.kind == kindManifest && b.epoch == s.Epoch() {
			return b
		}
	}
	t.Fatal("no manifest pending")
	return nil
}

func slicesEqualAny(got any, want []string) bool {
	values, ok := got.([]any)
	if !ok || len(values) != len(want) {
		return false
	}
	for i, v := range values {
		if v != want[i] {
			return false
		}
	}
	return true
}

func TestOptionalValuesKeyedOrOmitted(t *testing.T) {
	cfg := testConfig(t.TempDir())
	cfg.Digests = false
	s := mustOpen(t, cfg)
	defer crash(t, s)
	peer := netip.MustParseAddr("::ffff:10.0.4.7")
	e := Event{
		TimeUnixNano: 7, Class: "connect", Syscall: "connect", Result: "success", Errno: "EPERM", Pid: 3,
		NsPid: int64p(0), PeerFamily: "ipv9", Peer: peer, PeerPort: int64p(70000), Scope: "pod",
		ContainerID: "ABC", PodUID: "not-a-uuid", Incomplete: "most", PathSHA256: strings.Repeat("a", 64),
	}
	failed := Event{TimeUnixNano: 7, Class: "connect", Syscall: "connect", Result: "failed", Errno: "E2BIG", Pid: 3,
		ExeSHA256: "sha256:" + strings.Repeat("b", 64)}
	b, err := s.Stage([]Event{e, failed})
	if err != nil {
		t.Fatal(err)
	}
	spans := batchSpans(t, b)
	for _, k := range []string{
		"fabric.sensor.errno", "fabric.sensor.ns_pid", "fabric.sensor.peer_family", "fabric.sensor.peer_port",
		"fabric.sensor.scope", "fabric.execution.sandbox_id", "fabric.sensor.pod_id", "fabric.sensor.incomplete",
		"fabric.sensor.path_sha256",
	} {
		if _, ok := spans[0].attrs[k]; ok {
			t.Errorf("%s emitted for an invalid or unpermitted value", k)
		}
	}
	if spans[0].attrs["fabric.network.host_id"] != V2("hst", "10.0.4.7", []byte(testKey)) {
		t.Errorf("the mapped peer is keyed as its IPv4 text")
	}
	if spans[1].attrs["fabric.sensor.errno"] != "other" {
		t.Errorf("an unnamed errno of a failed result is other: %v", spans[1].attrs["fabric.sensor.errno"])
	}
	if _, ok := spans[1].attrs["fabric.sensor.exe_sha256"]; ok {
		t.Error("a digest without permission")
	}
	if spans[0].attrs["fabric.execution.host_id"] != V2("hst", "build-host-7", []byte(testKey)) {
		t.Error("the host id is the hst- v2 of the host label")
	}
}

func TestNoClearValueLeavesTheLibrary(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	cfg.SourceLabel, cfg.HostLabel = "canary-node-label-7781/ebpf", "canary-host-label-7781"
	s := mustOpen(t, cfg)
	container := strings.Repeat("c7", 32)
	e := execEvent(9)
	e.Class, e.Syscall, e.Peer = "connect", "connect", netip.MustParseAddr("10.77.81.9")
	e.ContainerID, e.PodUID = container, "77817781-7781-4781-8781-778177817781"
	b, err := s.Stage([]Event{e})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Close(true); err != nil {
		t.Fatal(err)
	}
	canaries := []string{"canary-node-label-7781", "canary-host-label-7781", "10.77.81.9", container,
		"77817781-7781-4781-8781-778177817781", testKey}
	all := slices.Clone(b.raw)
	pending, _ := s.Pending()
	for _, p := range pending {
		all = append(all, p.raw...)
	}
	err = filepath.WalkDir(cfg.StateDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		all = append(all, data...)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range canaries {
		if bytes.Contains(all, []byte(c)) {
			t.Errorf("clear value %q in the traces or the state directory", c)
		}
	}
}

func TestEpochRestartListsUnsealedPrior(t *testing.T) {
	cfg := testConfig(t.TempDir())
	first := mustOpen(t, cfg)
	if _, err := first.Stage([]Event{execEvent(1), execEvent(2), execEvent(3)}); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Manifest(); err != nil {
		t.Fatal(err)
	}
	crash(t, first)

	second := mustOpen(t, cfg)
	pending, _ := second.Pending()
	if got := kinds(pending); !slices.Equal(got, []string{kindManifest, kindRecords, kindManifest, kindHeartbeat, kindManifest}) {
		t.Fatalf("pending %v", got)
	}
	hb := batchSpans(t, pending[3])
	if len(hb) != 1 || hb[0].attrs["fabric.source.epoch"] != int64(first.Epoch()) ||
		hb[0].attrs["fabric.heartbeat.kind"] != "periodic" ||
		hb[0].attrs["fabric.heartbeat.last_sequence"] != int64(2) ||
		hb[0].attrs["fabric.capture.manifest_seq"] != int64(1) || hb[0].attrs["fabric.sensor.upstream_lost"] != int64(0) {
		t.Errorf("prior epoch heartbeat: %v", hb)
	}
	m := batchSpans(t, pending[4])[0].attrs
	if m["fabric.source.epoch"] != int64(second.Epoch()) || m["fabric.manifest.manifest_seq"] != int64(0) ||
		m["fabric.manifest.unsealed_prior_epoch_count"] != int64(1) ||
		!slicesEqualAny(m["fabric.manifest.unsealed_prior_epochs"], []string{strconv.FormatUint(first.Epoch(), 10)}) {
		t.Errorf("manifest 0 of the second epoch: %v", m)
	}
	if second.Epoch() == first.Epoch() {
		t.Error("a restart reused the epoch")
	}

	// Acknowledge everything and end with final: the next start lists none.
	final, err := second.Close(true)
	if err != nil {
		t.Fatal(err)
	}
	pending, _ = second.Pending()
	for _, b := range pending {
		if err := second.Acknowledge(b); err != nil {
			t.Fatal(err)
		}
	}
	if left, _ := second.Pending(); len(left) != 0 || final == nil {
		t.Fatalf("pending after acknowledging everything: %d", len(left))
	}
	third := mustOpen(t, cfg)
	defer crash(t, third)
	pending, _ = third.Pending()
	if got := kinds(pending); !slices.Equal(got, []string{kindManifest}) {
		t.Fatalf("after a final epoch, pending %v", got)
	}
	if batchSpans(t, pending[0])[0].attrs["fabric.manifest.unsealed_prior_epoch_count"] != int64(0) {
		t.Error("a final epoch was listed unsealed")
	}
}

func TestPriorHeartbeatUsesAcknowledgedHighWater(t *testing.T) {
	cfg := testConfig(t.TempDir())
	first := mustOpen(t, cfg)
	b, err := first.Stage([]Event{execEvent(1), execEvent(2)})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Acknowledge(b); err != nil {
		t.Fatal(err)
	}
	crash(t, first)
	second := mustOpen(t, cfg)
	defer crash(t, second)
	pending, _ := second.Pending()
	for _, p := range pending {
		if p.kind == kindHeartbeat {
			if got := batchSpans(t, p)[0].attrs["fabric.heartbeat.last_sequence"]; got != int64(1) {
				t.Errorf("the prior heartbeat's last sequence is %v, want 1 (acknowledged and removed)", got)
			}
			return
		}
	}
	t.Fatal("no prior heartbeat")
}

func TestReplayKeepsPositionsAndIDs(t *testing.T) {
	cfg := testConfig(t.TempDir())
	first := mustOpen(t, cfg)
	a, _ := first.Stage([]Event{execEvent(1), execEvent(2)})
	b, _ := first.Stage([]Event{execEvent(3)})
	before, _ := first.Pending()
	crash(t, first)

	second := mustOpen(t, cfg)
	defer crash(t, second)
	after, _ := second.Pending()
	if len(after) < len(before) {
		t.Fatalf("%d pending after restart, %d before", len(after), len(before))
	}
	for i := range before {
		if !bytes.Equal(before[i].raw, after[i].raw) || before[i].id != after[i].id || before[i].batchMeta != after[i].batchMeta {
			t.Errorf("batch %d changed in the replay", i)
		}
	}
	if !slices.Equal(eventIDs(t, []*Batch{a, b}), eventIDs(t, after[1:3])) {
		t.Error("the replay minted new event ids")
	}
	c, err := second.Stage([]Event{execEvent(4)})
	if err != nil {
		t.Fatal(err)
	}
	got := batchSpans(t, c)[0].attrs
	if got["fabric.source.sequence"] != int64(0) || got["fabric.source.epoch"] != int64(second.Epoch()) {
		t.Errorf("the new epoch starts at 0: %v", got)
	}
	// Acknowledging a replayed batch removes it for good.
	if err := second.Acknowledge(after[1]); err != nil {
		t.Fatal(err)
	}
	if err := second.Acknowledge(after[1]); err == nil {
		t.Error("a batch was acknowledged twice")
	}
}

func TestMarkersAreStagedAndReplayed(t *testing.T) {
	cfg := testConfig(t.TempDir())
	first := mustOpen(t, cfg)
	records, err := first.Stage([]Event{execEvent(1), execEvent(2), execEvent(3)})
	if err != nil {
		t.Fatal(err)
	}
	first.UpstreamLoss("ring_buffer_full", 4)
	heartbeat, err := first.Heartbeat()
	if err != nil {
		t.Fatal(err)
	}
	loss, err := first.Quarantine(records, 2)
	if err != nil {
		t.Fatal(err)
	}
	final, err := first.Close(true)
	if err != nil {
		t.Fatal(err)
	}
	staged, _ := first.Pending()
	if got := kinds(staged); !slices.Equal(got, []string{kindManifest, kindHeartbeat, kindLoss, kindFinal}) {
		t.Fatalf("staged %v", got)
	}
	if staged[1] != heartbeat || staged[2] != loss || staged[3] != final {
		t.Fatal("the returned batches are the pending ones")
	}
	lossAttrs := batchSpans(t, loss)[0].attrs
	if lossAttrs["fabric.loss.reason"] != "span_dropped" || lossAttrs["fabric.loss.first_sequence"] != int64(0) ||
		lossAttrs["fabric.loss.last_sequence"] != int64(2) || lossAttrs["fabric.loss.count"] != int64(3) {
		t.Errorf("loss marker %v", lossAttrs)
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, quarantineDir, batchName(records.id))); err != nil {
		t.Error("the quarantined batch is not kept sealed")
	}
	// A crash before any acknowledgement: every marker comes back with its
	// event id and manifest_seq.
	second := mustOpen(t, cfg)
	defer crash(t, second)
	replayed, _ := second.Pending()
	if !slices.Equal(eventIDs(t, staged), eventIDs(t, replayed[:4])) {
		t.Error("the markers' event ids changed in the replay")
	}
	for i, b := range staged {
		if replayed[i].manifestSeq != b.manifestSeq || !bytes.Equal(replayed[i].raw, b.raw) {
			t.Errorf("marker %d changed in the replay", i)
		}
	}
	for _, b := range replayed {
		if b.id == records.id {
			t.Error("a quarantined batch is pending again")
		}
	}
	// final was not acknowledged: the epoch is unsealed, so the restart
	// heartbeats it and lists it.
	m := batchSpans(t, replayed[len(replayed)-1])[0].attrs
	if m["fabric.manifest.unsealed_prior_epoch_count"] != int64(1) {
		t.Errorf("an unacknowledged final sealed the epoch: %v", m)
	}
	if _, err := second.Quarantine(replayed[0], 1); err == nil {
		t.Error("a marker batch was quarantined")
	}
}

func TestOneHeartbeatPerLossReason(t *testing.T) {
	s := mustOpen(t, testConfig(t.TempDir()))
	defer crash(t, s)
	if _, err := s.Stage([]Event{execEvent(1)}); err != nil {
		t.Fatal(err)
	}
	s.UpstreamLoss("scope_late", -1)
	s.UpstreamLoss("rate_limited", 2)
	s.UpstreamLoss("ring_buffer_full", 3)
	s.UpstreamLoss("rate_limited", 5)
	s.UpstreamLoss("not-a-reason", 1)
	s.UpstreamLoss("restart", 0)
	b, err := s.Heartbeat()
	if err != nil {
		t.Fatal(err)
	}
	spans := batchSpans(t, b)
	type hb struct {
		reason string
		lost   int64
	}
	var got []hb
	ids := map[string]bool{}
	for _, span := range spans {
		got = append(got, hb{span.attrs["fabric.sensor.upstream_loss_reason"].(string), span.attrs["fabric.sensor.upstream_lost"].(int64)})
		if span.attrs["fabric.heartbeat.last_sequence"] != int64(0) || span.attrs["fabric.heartbeat.kind"] != "periodic" {
			t.Errorf("heartbeat %v", span.attrs)
		}
		ids[span.attrs["fabric.event_id"].(string)] = true
	}
	want := []hb{{"ring_buffer_full", 3}, {"rate_limited", 7}, {"scope_late", -1}, {"unknown", 1}}
	if !slices.Equal(got, want) {
		t.Errorf("heartbeats %v, want %v", got, want)
	}
	if len(ids) != len(spans) {
		t.Error("two heartbeats share an event id")
	}
	quiet, err := s.Heartbeat()
	if err != nil {
		t.Fatal(err)
	}
	q := batchSpans(t, quiet)
	if len(q) != 1 || q[0].attrs["fabric.sensor.upstream_lost"] != int64(0) {
		t.Fatalf("a quiet interval: %v", q)
	}
	if _, ok := q[0].attrs["fabric.sensor.upstream_loss_reason"]; ok {
		t.Error("a quiet heartbeat carries a reason")
	}
}

func TestUpstreamLossUnknownStaysUnknown(t *testing.T) {
	s := mustOpen(t, testConfig(t.TempDir()))
	defer func() { _, _ = s.Close(false) }()
	s.UpstreamLoss("socket_overflow", 5)
	s.UpstreamLoss("socket_overflow", -1)
	s.UpstreamLoss("socket_overflow", 3)
	s.UpstreamLoss("backlog_limit", maxInt64)
	s.UpstreamLoss("backlog_limit", 10)
	s.UpstreamLoss("restart", -7)
	b, _ := s.Heartbeat()
	got := map[string]int64{}
	for _, span := range batchSpans(t, b) {
		got[span.attrs["fabric.sensor.upstream_loss_reason"].(string)] = span.attrs["fabric.sensor.upstream_lost"].(int64)
	}
	if got["socket_overflow"] != -1 || got["backlog_limit"] != maxInt64 || got["restart"] != -1 || len(got) != 3 {
		t.Errorf("accumulated %v", got)
	}
	// Close(true) reports loss still accrued in a heartbeat before final.
	s.UpstreamLoss("restart", -1)
	final, err := s.Close(true)
	if err != nil {
		t.Fatal(err)
	}
	pending, _ := s.Pending()
	n := len(pending)
	if pending[n-1] != final || pending[n-2].kind != kindHeartbeat ||
		batchSpans(t, pending[n-2])[0].attrs["fabric.sensor.upstream_lost"] != int64(-1) {
		t.Error("loss accrued before Close is not reported before final")
	}
	if _, ok := batchSpans(t, final)[0].attrs["fabric.sensor.upstream_lost"]; ok {
		t.Error("the final marker carries upstream keys")
	}
}

func TestKeyRotation(t *testing.T) {
	cfg := testConfig(t.TempDir())
	first := mustOpen(t, cfg)
	staged, err := first.Stage([]Event{execEvent(1)})
	if err != nil {
		t.Fatal(err)
	}
	oldSource := first.SourceID()
	crash(t, first)

	rotated := cfg
	rotated.IDKey = []byte("another-test-key-of-sixteen-plus")
	second := mustOpen(t, rotated)
	defer crash(t, second)
	if second.SourceID() == oldSource {
		t.Fatal("a new id key gives a new source id")
	}
	pending, _ := second.Pending()
	if got := kinds(pending); !slices.Equal(got, []string{kindManifest, kindRecords, kindHeartbeat, kindManifest}) {
		t.Fatalf("pending %v", got)
	}
	// The staged batches keep the ids they were staged with.
	if !bytes.Equal(pending[1].raw, staged.raw) || batchSpans(t, pending[1])[0].attrs["fabric.source_id"] != oldSource {
		t.Error("a staged batch changed under the new key")
	}
	hb := batchSpans(t, pending[2])[0].attrs
	if hb["fabric.source_id"] != oldSource || hb["fabric.heartbeat.last_sequence"] != int64(0) {
		t.Errorf("the prior epoch's heartbeat belongs to its own source: %v", hb)
	}
	m := batchSpans(t, pending[3])[0].attrs
	if m["fabric.source_id"] != second.SourceID() || m["fabric.manifest.key_id"] != keyID(rotated.IDKey) ||
		m["fabric.manifest.unsealed_prior_epoch_count"] != int64(0) {
		t.Errorf("manifest 0 under the new key: %v", m)
	}
	b, _ := second.Stage([]Event{execEvent(2)})
	if batchSpans(t, b)[0].attrs["fabric.execution.host_id"] != V2("hst", cfg.HostLabel, rotated.IDKey) {
		t.Error("new records are keyed with the new key")
	}
}

func TestCorruptStateRefusesStart(t *testing.T) {
	setup := func(t *testing.T) Config {
		cfg := testConfig(t.TempDir())
		s := mustOpen(t, cfg)
		if _, err := s.Stage([]Event{execEvent(1)}); err != nil {
			t.Fatal(err)
		}
		crash(t, s)
		return cfg
	}
	stagedFile := func(t *testing.T, cfg Config) string {
		entries, _ := os.ReadDir(filepath.Join(cfg.StateDir, stagingDir))
		return filepath.Join(cfg.StateDir, stagingDir, entries[len(entries)-1].Name())
	}
	flip := func(t *testing.T, path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data[len(data)-1] ^= 1
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := map[string]func(t *testing.T, cfg *Config){
		"a changed byte in epoch.state": func(t *testing.T, cfg *Config) { flip(t, filepath.Join(cfg.StateDir, epochFile)) },
		"a changed byte in a staged batch": func(t *testing.T, cfg *Config) {
			flip(t, stagedFile(t, *cfg))
		},
		"another state key": func(t *testing.T, cfg *Config) {
			cfg.StateKey = bytes.Repeat([]byte{9}, 32)
		},
		"a staged batch sealed as epoch state": func(t *testing.T, cfg *Config) {
			data, _ := os.ReadFile(filepath.Join(cfg.StateDir, epochFile))
			if err := os.WriteFile(stagedFile(t, *cfg), data, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"the Node queue magic": func(t *testing.T, cfg *Config) {
			path := filepath.Join(cfg.StateDir, epochFile)
			data, _ := os.ReadFile(path)
			data = append([]byte("FABRIC-NODE-QUEUE-1\n"), data[len(envelopeMagic):]...)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"an unknown file in staging": func(t *testing.T, cfg *Config) {
			if err := os.WriteFile(filepath.Join(cfg.StateDir, stagingDir, "notes.txt"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"a truncated epoch.state": func(t *testing.T, cfg *Config) {
			if err := os.WriteFile(filepath.Join(cfg.StateDir, epochFile), []byte(envelopeMagic), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := setup(t)
			corrupt(t, &cfg)
			s, err := Open(cfg)
			if err == nil {
				crash(t, s)
				t.Fatal("started on corrupt state")
			}
			if !errors.Is(err, errCorrupt) {
				t.Errorf("error %v", err)
			}
			// A refused start leaves the directory and label free.
			cfg2 := testConfig(t.TempDir())
			cfg2.SourceLabel = cfg.SourceLabel
			s2 := mustOpen(t, cfg2)
			crash(t, s2)
		})
	}
	t.Run("an unfinished staging file is not staged", func(t *testing.T) {
		cfg := setup(t)
		tmp := filepath.Join(cfg.StateDir, stagingDir, batchName(99)+tempSuffix)
		if err := os.WriteFile(tmp, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := mustOpen(t, cfg)
		defer crash(t, s)
		if _, err := os.Stat(tmp); !errors.Is(err, os.ErrNotExist) {
			t.Error("the unfinished file is still there")
		}
	})
}

func TestStateDirRules(t *testing.T) {
	t.Run("mode", func(t *testing.T) {
		cfg := testConfig(t.TempDir())
		if err := os.Mkdir(cfg.StateDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(cfg.StateDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(cfg); err == nil {
			t.Error("a 0755 state directory was accepted")
		}
	})
	t.Run("not a directory", func(t *testing.T) {
		cfg := testConfig(t.TempDir())
		if err := os.WriteFile(cfg.StateDir, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(cfg); err == nil {
			t.Error("a file was accepted as the state directory")
		}
	})
	t.Run("shared", func(t *testing.T) {
		cfg := testConfig(t.TempDir())
		s := mustOpen(t, cfg)
		defer crash(t, s)
		sameDir := cfg
		sameDir.SourceLabel = "build-host-7/auditd"
		if _, err := Open(sameDir); err == nil {
			t.Error("two sources share a state directory")
		}
		sameLabel := testConfig(t.TempDir())
		if _, err := Open(sameLabel); err == nil {
			t.Error("two open sources share a label")
		}
		// Another process holding the lock is refused too.
		other := testConfig(t.TempDir())
		other.SourceLabel = "other/ebpf"
		lock, err := prepareStateDir(other.StateDir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lock.Close() }()
		if _, err := Open(other); err == nil {
			t.Error("a locked state directory was opened")
		}
	})
	t.Run("another kind's state", func(t *testing.T) {
		cfg := testConfig(t.TempDir())
		crash(t, mustOpen(t, cfg))
		cfg.Kind = KindAuditd
		if _, err := Open(cfg); err == nil {
			t.Error("an auditd source opened an eBPF source's state")
		}
	})
}

func TestConfigRefusals(t *testing.T) {
	cases := map[string]func(*Config){
		"kind":                func(c *Config) { c.Kind = "host.etw" },
		"version":             func(c *Config) { c.Version = "" },
		"version form":        func(c *Config) { c.Version = "1.0 beta" },
		"tenant":              func(c *Config) { c.TenantID = "" },
		"source label":        func(c *Config) { c.SourceLabel = "" },
		"host label":          func(c *Config) { c.HostLabel = "" },
		"id key":              func(c *Config) { c.IDKey = nil },
		"short id key":        func(c *Config) { c.IDKey = []byte("fifteen-bytes!!") },
		"state key":           func(c *Config) { c.StateKey = make([]byte, 16) },
		"state dir":           func(c *Config) { c.StateDir = "" },
		"no classes":          func(c *Config) { c.Classes = nil },
		"an unknown class":    func(c *Config) { c.Classes = []string{"exec", "dns"} },
		"a repeated class":    func(c *Config) { c.Classes = []string{"exec", "exec"} },
		"label not UTF-8":     func(c *Config) { c.SourceLabel = "\xff" },
		"host label too long": func(c *Config) { c.HostLabel = strings.Repeat("h", 1025) },
	}
	for name, mutate := range cases {
		cfg := testConfig(t.TempDir())
		mutate(&cfg)
		s, err := Open(cfg)
		if err == nil {
			crash(t, s)
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), testKey) || strings.Contains(err.Error(), "build-host-7") {
			t.Errorf("%s: the error names a value", name)
		}
	}
}

func TestClosedSource(t *testing.T) {
	s := mustOpen(t, testConfig(t.TempDir()))
	if b, err := s.Close(false); b != nil || err != nil {
		t.Fatalf("Close(false) = %v, %v", b, err)
	}
	if _, err := s.Stage([]Event{execEvent(1)}); !errors.Is(err, ErrClosed) {
		t.Error("staged after Close")
	}
	if _, err := s.Heartbeat(); !errors.Is(err, ErrClosed) {
		t.Error("heartbeat after Close")
	}
	if _, err := s.Manifest(); !errors.Is(err, ErrClosed) {
		t.Error("manifest after Close")
	}
	if _, err := s.Close(true); !errors.Is(err, ErrClosed) {
		t.Error("closed twice")
	}
}

func TestAcknowledgeAfterCloseKeepsANewerEpoch(t *testing.T) {
	cfg := testConfig(t.TempDir())
	first := mustOpen(t, cfg)
	final, err := first.Close(true)
	if err != nil {
		t.Fatal(err)
	}
	second := mustOpen(t, cfg)
	defer crash(t, second)
	if err := first.Acknowledge(final); err != nil {
		t.Fatal(err)
	}
	st, ok, err := second.readState()
	if err != nil || !ok || st.Epoch != second.Epoch() || st.Final {
		t.Errorf("a late acknowledgement rewrote the newer epoch's state: %+v", st)
	}
}

func TestConcurrentStageAndHeartbeat(t *testing.T) {
	s := mustOpen(t, testConfig(t.TempDir()))
	defer crash(t, s)
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 10 {
				if _, err := s.Stage([]Event{execEvent(int64(100*w + i + 1))}); err != nil {
					t.Error(err)
				}
				s.UpstreamLoss("rate_limited", 1)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 10 {
			if _, err := s.Heartbeat(); err != nil {
				t.Error(err)
			}
		}
	}()
	wg.Wait()
	pending, _ := s.Pending()
	seen := map[int64]bool{}
	for _, b := range pending {
		if b.kind != kindRecords {
			continue
		}
		for _, span := range batchSpans(t, b) {
			seq := span.attrs["fabric.source.sequence"].(int64)
			if seen[seq] {
				t.Fatalf("position %d allocated twice", seq)
			}
			seen[seq] = true
		}
	}
	if len(seen) != 40 {
		t.Errorf("%d positions, want 40", len(seen))
	}
}

// TestDeclareClockUncertaintyNarrowsBack: after a step has settled the sensor
// declares the base again; the manifest is staged only on a change, and
// never below the default.
func TestDeclareClockUncertaintyNarrowsBack(t *testing.T) {
	s := mustOpen(t, testConfig(t.TempDir()))
	defer crash(t, s)
	if b, err := s.DeclareClockUncertainty(clockUncertaintyNs); b != nil || err != nil {
		t.Fatalf("an unchanged value staged (%v, %v)", b, err)
	}
	if b, err := s.DeclareClockUncertainty(1); b != nil || err != nil {
		t.Fatalf("a value below the default staged (%v, %v)", b, err)
	}
	wide := int64(3_002_019_859) // the 0.11.2 replay's widened value
	b, err := s.DeclareClockUncertainty(wide)
	if err != nil || b == nil {
		t.Fatalf("widen: (%v, %v)", b, err)
	}
	if got := batchSpans(t, b)[0].attrs["fabric.manifest.clock.uncertainty_ns"]; got != wide {
		t.Fatalf("widened manifest declares %v", got)
	}
	if b, err := s.DeclareClockUncertainty(wide); b != nil || err != nil {
		t.Fatalf("an unchanged value staged (%v, %v)", b, err)
	}
	b, err = s.DeclareClockUncertainty(0) // settled: back to the default
	if err != nil || b == nil {
		t.Fatalf("narrow: (%v, %v)", b, err)
	}
	m := batchSpans(t, b)[0].attrs
	if m["fabric.manifest.clock.uncertainty_ns"] != int64(clockUncertaintyNs) || m["fabric.manifest.manifest_seq"] != int64(2) {
		t.Errorf("narrowed manifest: %v", m)
	}
	if got := s.ClockUncertainty(); got != clockUncertaintyNs {
		t.Errorf("uncertainty %d, want %d", got, clockUncertaintyNs)
	}
}

func TestWidenClockUncertaintyStagesAWiderManifestOnly(t *testing.T) {
	s := mustOpen(t, testConfig(t.TempDir()))
	defer crash(t, s)
	if got := s.ClockUncertainty(); got != clockUncertaintyNs {
		t.Fatalf("initial uncertainty %d, want %d", got, clockUncertaintyNs)
	}
	if b, err := s.WidenClockUncertainty(clockUncertaintyNs - 1); b != nil || err != nil {
		t.Fatalf("a narrower value staged (%v, %v)", b, err)
	}
	step := int64(2_820_000_000) // the 0.11.1 acceptance run's 2.82 s step
	b, err := s.WidenClockUncertainty(step + clockUncertaintyNs)
	if err != nil || b == nil {
		t.Fatalf("widen: (%v, %v)", b, err)
	}
	m := batchSpans(t, b)[0].attrs
	if m["fabric.manifest.clock.uncertainty_ns"] != step+clockUncertaintyNs || m["fabric.manifest.manifest_seq"] != int64(1) {
		t.Errorf("widened manifest: %v", m)
	}
	if b, err := s.WidenClockUncertainty(step); b != nil || err != nil {
		t.Errorf("never narrowed: (%v, %v)", b, err)
	}
	if got := s.ClockUncertainty(); got != step+clockUncertaintyNs {
		t.Errorf("uncertainty %d", got)
	}
}
