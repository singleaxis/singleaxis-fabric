// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

const testIDKey = "fabric-test-id-key-not-a-secret"

// repoPath resolves a path from the repository root (the directory that
// holds contracts/).
func repoPath(t *testing.T, rel string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if info, err := os.Stat(filepath.Join(dir, "contracts")); err == nil && info.IsDir() {
			return filepath.Join(dir, rel)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found above the test directory")
		}
		dir = parent
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func writeKeyFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o400); err != nil {
		t.Fatal(err)
	}
	return path
}

func testStateKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xa0 + i)
	}
	return key
}

// productionConfig is a complete production configuration under dir.
func productionConfig(t *testing.T, parent string) *Config {
	t.Helper()
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(parent, "cfg")
	if err != nil {
		t.Fatal(err)
	}
	agentRoot := filepath.Join(dir, "cgroup", "fabric-agents.slice")
	if err := os.MkdirAll(agentRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	return &Config{
		Production:        true,
		Endpoint:          "node.example:4417",
		endpointSet:       true,
		TenantID:          "tenant-a",
		SourceLabel:       "build-host-7/ebpf",
		HostLabel:         "build-host-7",
		IDKeyFile:         writeKeyFile(t, dir, "id_key", []byte(testIDKey)),
		StateKeyFile:      writeKeyFile(t, dir, "state_key", testStateKey()),
		StateDir:          filepath.Join(dir, "state"),
		AgentCgroupRoots:  []string{agentRoot},
		Exec:              true,
		Connect:           true,
		Digests:           "omitted",
		HeartbeatInterval: defaultHeartbeat,
		CgroupRoot:        filepath.Join(dir, "cgroup"),
	}
}

// openTestSource opens the production source of cfg with the fixtures'
// capture point version.
func openTestSource(t *testing.T, cfg *Config) *hostrecords.Source {
	t.Helper()
	idKey, stateKey, err := readProductionKeys(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sc := sourceConfig(cfg, idKey, stateKey)
	sc.Version = "0.11.0"
	src, err := hostrecords.Open(sc)
	if err != nil {
		t.Fatalf("open source: %v", err)
	}
	return src
}

type span struct {
	name  string
	attrs map[string]any
}

func spansOf(td ptrace.Traces) []span {
	var out []span
	for i := 0; i < td.ResourceSpans().Len(); i++ {
		ss := td.ResourceSpans().At(i).ScopeSpans()
		for j := 0; j < ss.Len(); j++ {
			sp := ss.At(j).Spans()
			for k := 0; k < sp.Len(); k++ {
				out = append(out, span{name: sp.At(k).Name(), attrs: sp.At(k).Attributes().AsRaw()})
			}
		}
	}
	return out
}

func pendingSpans(t *testing.T, src recordSource) []span {
	t.Helper()
	batches, err := src.Pending()
	if err != nil {
		t.Fatal(err)
	}
	var out []span
	for _, b := range batches {
		out = append(out, spansOf(b.Traces())...)
	}
	return out
}

// fakeSender records sends and answers with the queued results.
type fakeSender struct {
	results []error
	sent    [][]span
}

func (f *fakeSender) sendBatch(_ context.Context, b *hostrecords.Batch) error {
	f.sent = append(f.sent, spansOf(b.Traces()))
	if len(f.results) == 0 {
		return nil
	}
	err := f.results[0]
	f.results = f.results[1:]
	return err
}

// --- configuration ----------------------------------------------------------

func TestProductionRefusesExactCgroupPath(t *testing.T) {
	cfg := productionConfig(t, t.TempDir())
	if err := cfg.Validate(); err != nil {
		t.Fatalf("complete production configuration refused: %v", err)
	}
	cfg.CgroupPath = cfg.AgentCgroupRoots[0]
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "EMIT_AGENT_CGROUP_ROOTS") {
		t.Fatalf("EMIT_CGROUP_PATH in production: %v; want a refusal naming EMIT_AGENT_CGROUP_ROOTS", err)
	}
	// Local mode keeps the exact path.
	local := &Config{Endpoint: "localhost:4317", CgroupPath: cfg.AgentCgroupRoots[0], Exec: true, SpoolDir: "/x", SpoolMaxBytes: 1}
	if err := local.Validate(); err != nil {
		t.Fatalf("local exact cgroup refused: %v", err)
	}
}

func TestProductionRefusesDedupeAndMissingKeys(t *testing.T) {
	dir := t.TempDir()
	for name, mutate := range map[string]func(*Config){
		"dedupe":            func(c *Config) { c.DedupeWindow = 1 },
		"tenant":            func(c *Config) { c.TenantID = "" },
		"source label":      func(c *Config) { c.SourceLabel = "" },
		"host label":        func(c *Config) { c.HostLabel = "" },
		"id key":            func(c *Config) { c.IDKeyFile = "" },
		"state key":         func(c *Config) { c.StateKeyFile = "" },
		"state dir":         func(c *Config) { c.StateDir = "" },
		"no scope":          func(c *Config) { c.AgentCgroupRoots = nil },
		"digests":           func(c *Config) { c.Digests = "always" },
		"heartbeat short":   func(c *Config) { c.HeartbeatInterval = 500_000_000 },
		"heartbeat long":    func(c *Config) { c.HeartbeatInterval = 61_000_000_000 },
		"missing root":      func(c *Config) { c.AgentCgroupRoots = []string{filepath.Join(dir, "absent")} },
		"relative root":     func(c *Config) { c.AgentCgroupRoots = []string{"fabric-agents.slice"} },
		"root in two lists": func(c *Config) { c.SandboxCgroupRoots = c.AgentCgroupRoots },
		"hierarchy root":    func(c *Config) { c.AgentCgroupRoots = []string{c.CgroupRoot} },
		"nine roots": func(c *Config) {
			for i := 0; i < 8; i++ {
				c.AgentCgroupRoots = append(c.AgentCgroupRoots, c.AgentCgroupRoots[0]+string(rune('a'+i)))
			}
		},
		"selector without node":   func(c *Config) { c.AgentPodSelector = "app=agent" },
		"set-based selector":      func(c *Config) { c.AgentPodSelector = "app in (agent)"; c.NodeName = "node-a" },
		"inequality selector":     func(c *Config) { c.AgentPodSelector = "app!=agent"; c.NodeName = "node-a" },
		"node without selector":   func(c *Config) { c.NodeName = "node-a" },
		"no endpoint":             func(c *Config) { c.Endpoint, c.endpointSet = "", false },
		"mistyped production":     func(c *Config) { c.loadErrs = []error{errors.New("EMIT_PRODUCTION must be true or false")} },
		"endpoint and its file":   func(c *Config) { c.EndpointFile = "/x" },
		"empty sandbox list item": func(c *Config) { c.loadErrs = []error{errors.New("EMIT_SANDBOX_CGROUP_ROOTS has an empty item")} },
	} {
		cfg := productionConfig(t, filepath.Join(dir, strings.ReplaceAll(name, " ", "-")))
		mutate(cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: production configuration accepted", name)
		}
	}
	ok := productionConfig(t, filepath.Join(dir, "selector"))
	ok.AgentCgroupRoots = nil
	ok.AgentPodSelector, ok.NodeName = "app.kubernetes.io/name=agent,tier=ai", "node-a"
	if err := ok.Validate(); err != nil {
		t.Fatalf("pod selector configuration refused: %v", err)
	}
	allHost := productionConfig(t, filepath.Join(dir, "all-host"))
	allHost.AgentCgroupRoots, allHost.AllHost = nil, true
	if err := allHost.Validate(); err != nil {
		t.Fatalf("explicit all-host production refused: %v", err)
	}

	// Key files are read with the library's rules; a key with a trailing
	// newline is refused, never trimmed.
	keys := productionConfig(t, filepath.Join(dir, "keys"))
	keys.IDKeyFile = writeKeyFile(t, filepath.Join(dir, "keys"), "id_key_nl", []byte(testIDKey+"\n"))
	if _, _, err := readProductionKeys(keys); err == nil {
		t.Fatal("an id key with a trailing newline was accepted")
	}
	keys = productionConfig(t, filepath.Join(dir, "keys2"))
	keys.StateKeyFile = writeKeyFile(t, filepath.Join(dir, "keys2"), "state_short", []byte("short"))
	if _, _, err := readProductionKeys(keys); err == nil {
		t.Fatal("a short state key was accepted")
	}
}

func TestEndpointFileExclusive(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o400); err != nil {
			t.Fatal(err)
		}
		return path
	}
	both := productionConfig(t, dir)
	both.EndpointFile = write("both", "node.example:4418\n")
	if err := both.Validate(); err == nil || !strings.Contains(err.Error(), "exclusive") {
		t.Fatalf("EMIT_ENDPOINT with EMIT_ENDPOINT_FILE: %v", err)
	}

	cfg := productionConfig(t, dir)
	cfg.Endpoint, cfg.endpointSet = "", false
	cfg.EndpointFile = write("endpoint", "fabric-node.fabric.svc:4418\n")
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.resolveEndpoint(); err != nil || cfg.Endpoint != "fabric-node.fabric.svc:4418" {
		t.Fatalf("endpoint from file = %q, %v", cfg.Endpoint, err)
	}
	for name, content := range map[string]string{
		"empty":      "",
		"two lines":  "a:1\nb:2\n",
		"no port":    "fabric-node\n",
		"bad port":   "fabric-node:70000\n",
		"spaces":     "fabric node:4418\n",
		"url":        "https://fabric-node:4418\n",
		"blank line": "\n",
	} {
		bad := productionConfig(t, dir)
		bad.Endpoint, bad.endpointSet = "", false
		bad.EndpointFile = write(strings.ReplaceAll(name, " ", "-"), content)
		if err := bad.resolveEndpoint(); err == nil {
			t.Errorf("%s endpoint file accepted as %q", name, bad.Endpoint)
		}
	}
	missing := productionConfig(t, dir)
	missing.Endpoint, missing.endpointSet = "", false
	missing.EndpointFile = filepath.Join(dir, "absent")
	if err := missing.resolveEndpoint(); err == nil {
		t.Fatal("a missing endpoint file was accepted")
	}
	// The file is an alternative in local mode too.
	local := &Config{EndpointFile: write("local", "127.0.0.1:4317"), CgroupPath: "/x", Exec: true, SpoolDir: "/x", SpoolMaxBytes: 1, Insecure: true}
	if err := local.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := local.resolveEndpoint(); err != nil || local.Endpoint != "127.0.0.1:4317" {
		t.Fatalf("local endpoint from file = %q, %v", local.Endpoint, err)
	}
	// Production refuses plaintext to a non-loopback endpoint.
	insecure := productionConfig(t, dir)
	insecure.Insecure = true
	if err := insecure.resolveEndpoint(); err == nil {
		t.Fatal("plaintext to a remote endpoint accepted in production")
	}
	insecure.Endpoint = "127.0.0.1:4417"
	if err := insecure.resolveEndpoint(); err != nil {
		t.Fatalf("plaintext to loopback refused: %v", err)
	}
}

func TestLoadConfigReadsProductionEnvironment(t *testing.T) {
	for k, v := range map[string]string{
		"EMIT_PRODUCTION":           "true",
		"EMIT_TENANT_ID":            "tenant-a",
		"EMIT_SOURCE_LABEL":         "node-a/ebpf",
		"EMIT_HOST_LABEL":           "node-a",
		"EMIT_ID_KEY_FILE":          "/run/secrets/id",
		"EMIT_STATE_KEY_FILE":       "/etc/fabric-host-emitter/state_key",
		"EMIT_STATE_DIR":            "/var/lib/fabric-host-emitter/state",
		"EMIT_AGENT_CGROUP_ROOTS":   "/sys/fs/cgroup/a.slice,/sys/fs/cgroup/b.slice",
		"EMIT_SANDBOX_CGROUP_ROOTS": "/sys/fs/cgroup/kubepods.slice",
		"EMIT_AGENT_POD_SELECTOR":   "app=agent",
		"EMIT_NODE_NAME":            "node-a",
		"EMIT_DIGESTS":              "permitted",
		"EMIT_HEARTBEAT_INTERVAL":   "5s",
		"EMIT_ENDPOINT_FILE":        "/etc/fabric-host-emitter/endpoint",
	} {
		t.Setenv(k, v)
	}
	t.Setenv("EMIT_ENDPOINT", "")
	cfg := loadConfig()
	if !cfg.Production || cfg.TenantID != "tenant-a" || cfg.SourceLabel != "node-a/ebpf" || cfg.HostLabel != "node-a" ||
		len(cfg.AgentCgroupRoots) != 2 || len(cfg.SandboxCgroupRoots) != 1 || cfg.AgentPodSelector != "app=agent" ||
		cfg.NodeName != "node-a" || cfg.Digests != "permitted" || cfg.HeartbeatInterval.String() != "5s" ||
		cfg.Endpoint != "" || cfg.EndpointFile == "" || len(cfg.loadErrs) != 0 {
		t.Fatalf("production environment not read: %+v", cfg)
	}
	t.Setenv("EMIT_PRODUCTION", "yes please")
	if cfg := loadConfig(); cfg.Validate() == nil {
		t.Fatal("a mistyped EMIT_PRODUCTION fell back to a default")
	}
	t.Setenv("EMIT_PRODUCTION", "false")
	t.Setenv("EMIT_ENDPOINT_FILE", "")
	if cfg := loadConfig(); cfg.Endpoint != "localhost:4317" {
		t.Fatalf("local default endpoint = %q", cfg.Endpoint)
	}
}

// --- translation ------------------------------------------------------------

// fixtureBatchSpans reads the spans a host-record fixture's first batch holds.
func fixtureBatchSpans(t *testing.T, name string) []ptrace.Span {
	t.Helper()
	var fx struct {
		Batches []json.RawMessage `json:"batches"`
	}
	readJSON(t, repoPath(t, filepath.Join("contracts/capture/v1/fixtures/host", name)), &fx)
	td, err := (&ptrace.JSONUnmarshaler{}).UnmarshalTraces(fx.Batches[0])
	if err != nil {
		t.Fatal(err)
	}
	var out []ptrace.Span
	ss := td.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
	for i := 0; i < ss.Len(); i++ {
		out = append(out, ss.At(i))
	}
	return out
}

// TestProductionTranslateGolden: kernel events through hostEvent and the
// library give the host-record fixtures' spans (the minted ids aside). The
// eBPF connect and openat tracepoints run at syscall entry, so their result
// is "unknown" where a fixture shows an observed outcome.
func TestProductionTranslateGolden(t *testing.T) {
	savedOffset, savedBoot := bootEpochOffsetNs, bootTimeS
	t.Cleanup(func() { bootEpochOffsetNs, bootTimeS = savedOffset, savedBoot })
	bootEpochOffsetNs = 0
	hex64 := strings.Repeat("3f", 32)
	cases := []struct {
		fixture string
		boot    *int64
		event   event
		// keys the eBPF sensor reports differently from the fixture
		differ map[string]any
	}{
		{"valid/record-exec-ebpf.json", i64(1791271080), event{Type: evExec, TsNs: 1791331201210600000, Pid: 4121, Ppid: 4100,
			NsPid: 41, NsPpid: 7, PidNS: 4026532481, StartBoottime: 60123217448, CgroupID: 9123, Scope: scopeAgent,
			Comm: "python3", Filename: "/usr/bin/python3", Argv: []byte("python3\x00-c\x00secret")}, nil},
		{"valid/record-exec-thread-spawned.json", i64(1791271080), event{Type: evExec, TsNs: 1791331201300200000, Pid: 4140, Ppid: 4100,
			NsPid: 44, NsPpid: 7, PidNS: 4026532481, StartBoottime: 60213000000, CgroupID: 9123, Scope: scopeAgent}, nil},
		{"valid/record-sandbox-scope.json", nil, event{Type: evExec, TsNs: 1791331201400000000, Pid: 4180, Ppid: 4170,
			NsPid: 1, NsPpid: 0, PidNS: 4026532612, StartBoottime: 60313000000, CgroupID: 10442, Scope: scopeSandbox,
			CgroupNamesRead: true, CgroupParentName: "kubepods-burstable-pod6a1d9c2e_4b7f_4e10_9a3c_2f5d8e7b1c04.slice",
			CgroupName: "cri-containerd-" + hex64 + ".scope"}, nil},
		{"valid/record-connect.json", nil, event{Type: evConnect, Pid: 4122, Ppid: 4121, NsPid: 42, NsPpid: 41, PidNS: 4026532481,
			CgroupID: 9123, Scope: scopeAgent, Family: 2, Port: 443, Addr: [16]byte{10, 0, 4, 7}}, map[string]any{"fabric.sensor.result": "unknown"}},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			want := fixtureBatchSpans(t, tc.fixture)[0]
			ev := tc.event
			if ev.TsNs == 0 {
				ev.TsNs = uint64(want.StartTimestamp())
			}
			bootTimeS = tc.boot
			cfg := productionConfig(t, t.TempDir())
			cfg.Digests = "omitted"
			src := openTestSource(t, cfg)
			defer src.Close(false)
			hev, ok := hostEvent(&ev)
			if !ok {
				t.Fatal("event not translated")
			}
			b, err := src.Stage([]hostrecords.Event{hev})
			if err != nil {
				t.Fatal(err)
			}
			got := b.Traces().ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
			if got.Name() != want.Name() || got.StartTimestamp() != want.StartTimestamp() || got.EndTimestamp() != want.EndTimestamp() {
				t.Fatalf("span %s %d..%d, want %s %d..%d", got.Name(), got.StartTimestamp(), got.EndTimestamp(),
					want.Name(), want.StartTimestamp(), want.EndTimestamp())
			}
			gotAttrs, wantAttrs := got.Attributes().AsRaw(), want.Attributes().AsRaw()
			for k, v := range tc.differ {
				wantAttrs[k] = v
			}
			// Minted per epoch and per staging, never translated.
			for _, k := range []string{"fabric.source.epoch", "fabric.source.sequence", "fabric.event_id", "fabric.attempt.uid"} {
				if _, ok := gotAttrs[k]; !ok {
					t.Errorf("record lacks %s", k)
				}
				delete(gotAttrs, k)
				delete(wantAttrs, k)
			}
			if g, w := mustJSON(t, gotAttrs), mustJSON(t, wantAttrs); g != w {
				t.Fatalf("attributes differ\n got %s\nwant %s", g, w)
			}
		})
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestKernfsNamesToSandboxIDs: the kernfs names of a sandbox-scope event's
// cgroup and its parent give the ids of sandbox-id-v1.json's cgroup forms.
func TestKernfsNamesToSandboxIDs(t *testing.T) {
	var vectors struct {
		Key     string `json:"key"`
		Cgroups []struct {
			Name        string            `json:"name"`
			LastTwo     string            `json:"last_two"`
			ContainerID *string           `json:"container_id"`
			PodUID      *string           `json:"pod_uid"`
			IDs         map[string]string `json:"ids"`
		} `json:"cgroups"`
	}
	readJSON(t, repoPath(t, "contracts/coverage/v1/fixtures/vectors/sandbox-id-v1.json"), &vectors)
	if len(vectors.Cgroups) == 0 {
		t.Fatal("no cgroup vectors")
	}
	key := []byte(vectors.Key)
	for _, v := range vectors.Cgroups {
		parent, leaf, ok := strings.Cut(v.LastTwo, "/")
		if !ok {
			parent, leaf = "", v.LastTwo
		}
		e := &event{Type: evExec, Pid: 10, Scope: scopeSandbox, CgroupNamesRead: true, CgroupParentName: parent, CgroupName: leaf}
		ev, translated := hostEvent(e)
		if !translated {
			t.Fatalf("%s: not translated", v.Name)
		}
		wantC, wantP := "", ""
		if v.ContainerID != nil {
			wantC = *v.ContainerID
		}
		if v.PodUID != nil {
			wantP = *v.PodUID
		}
		if ev.ContainerID != wantC || ev.PodUID != wantP {
			t.Errorf("%s: names %q/%q give container %q pod %q, want %q %q", v.Name, parent, leaf, ev.ContainerID, ev.PodUID, wantC, wantP)
		}
		if id := v.IDs["fabric.execution.sandbox_id"]; id != "" && hostrecords.V2("sbx", "container:"+ev.ContainerID, key) != id {
			t.Errorf("%s: keyed container id differs from the vector", v.Name)
		}
		if id := v.IDs["fabric.sensor.pod_id"]; id != "" && hostrecords.V2("sbx", "k8s-pod:"+ev.PodUID, key) != id {
			t.Errorf("%s: keyed pod id differs from the vector", v.Name)
		}
	}
}

// TestUnresolvableCgroupHasNoIDs: names that are not a container or pod,
// names the BPF program could not read, and agent-scope events carry no
// sandbox or pod id.
func TestUnresolvableCgroupHasNoIDs(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	for name, e := range map[string]*event{
		"docker service":    {Scope: scopeSandbox, CgroupNamesRead: true, CgroupParentName: "system.slice", CgroupName: "docker.service"},
		"names not read":    {Scope: scopeSandbox, CgroupName: "docker-" + hex64 + ".scope"},
		"empty leaf":        {Scope: scopeSandbox, CgroupNamesRead: true, CgroupParentName: "sandboxes"},
		"root cgroup":       {Scope: scopeSandbox, CgroupNamesRead: true},
		"truncated id":      {Scope: scopeSandbox, CgroupNamesRead: true, CgroupParentName: "docker", CgroupName: hex64[:63]},
		"agent scope":       {Scope: scopeAgent, CgroupNamesRead: true, CgroupParentName: "docker", CgroupName: hex64},
		"local mode scope":  {Scope: scopeNone, CgroupNamesRead: true, CgroupParentName: "docker", CgroupName: hex64},
		"three levels away": {Scope: scopeSandbox, CgroupNamesRead: true, CgroupParentName: "init.scope", CgroupName: "leaf"},
	} {
		e.Type, e.Pid = evExec, 10
		ev, ok := hostEvent(e)
		if !ok {
			t.Fatalf("%s: not translated", name)
		}
		if ev.ContainerID != "" || ev.PodUID != "" {
			t.Errorf("%s: ids %q %q, want none", name, ev.ContainerID, ev.PodUID)
		}
	}
}

func TestHostEventNeverCarriesClearValues(t *testing.T) {
	e := &event{Type: evExec, Pid: 7, Ppid: 1, Comm: "agent-tool", Filename: "/tmp/agent-tool",
		Argv: []byte("/tmp/agent-tool\x00--token\x00supersecret"), Scope: scopeAgent}
	ev, ok := hostEvent(e)
	if !ok || ev.ExeSHA256 != sha256String("/tmp/agent-tool") || ev.ArgvSHA256 == "" || ev.Incomplete != "" {
		t.Fatalf("exec translation: %+v", ev)
	}
	data := mustJSON(t, ev)
	for _, clear := range []string{"agent-tool", "supersecret"} {
		if strings.Contains(data, clear) {
			t.Fatalf("clear %q in the host event", clear)
		}
	}
	c, _ := hostEvent(&event{Type: evConnect, Pid: 7, Family: 10, Port: 8443, Addr: [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}})
	if c.PeerFamily != "ipv6" || c.Peer.String() != "2001:db8::1" || c.PeerPort == nil || *c.PeerPort != 8443 || c.Result != "unknown" {
		t.Fatalf("connect translation: %+v", c)
	}
	f, _ := hostEvent(&event{Type: evOpenat, Pid: 7, Filename: "/etc/secret", FilenameIncomplete: true})
	if f.Class != "file" || f.Incomplete != "path" || f.PathSHA256 != "" {
		t.Fatalf("incomplete openat translation: %+v", f)
	}
	if _, ok := hostEvent(&event{Type: evExec}); ok {
		t.Fatal("an event without a pid was translated")
	}
}

// --- staging, delivery and loss ---------------------------------------------

// TestEncryptedSpoolHasNoClearBytes: staged host records and markers are
// sealed; no file of the state directory holds a clear value.
func TestEncryptedSpoolHasNoClearBytes(t *testing.T) {
	dir := t.TempDir()
	cfg := productionConfig(t, dir)
	cfg.Digests = "permitted"
	src := openTestSource(t, cfg)
	prod := newProduction(src, &fakeSender{results: []error{errors.New("node down")}})
	container := strings.Repeat("c4", 32)
	events := []hostrecords.Event{}
	for _, e := range []*event{
		{Type: evConnect, Pid: 4122, Ppid: 4121, Family: 2, Port: 443, Addr: [16]byte{203, 0, 113, 77}, Scope: scopeAgent},
		{Type: evExec, Pid: 4180, Ppid: 4170, Scope: scopeSandbox, CgroupNamesRead: true, CgroupParentName: "sandboxes",
			CgroupName: "docker-" + container + ".scope", Filename: "/usr/bin/secret-tool", Argv: []byte("secret-tool\x00--password\x00hunter2")},
	} {
		ev, _ := hostEvent(e)
		events = append(events, ev)
	}
	if err := prod.stage(events); err != nil {
		t.Fatal(err)
	}
	prod.upstreamLoss(lossScopeLate, -1)
	if err := prod.heartbeat(); err != nil {
		t.Fatal(err)
	}
	if ok, err := prod.sendPending(context.Background()); ok || err != nil {
		t.Fatalf("send with the Node down: ok=%v err=%v", ok, err)
	}
	if err := prod.close(); err != nil {
		t.Fatal(err)
	}
	clear := []string{"203.0.113.77", container, "tenant-a", "build-host-7", "secret-tool", "hunter2",
		"fabric.sensor_event", "fabric.capture_heartbeat", "scope_late", testIDKey}
	files := 0
	err := filepath.Walk(cfg.StateDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(data) == 0 {
			return nil
		}
		files++
		for _, c := range clear {
			if bytes.Contains(data, []byte(c)) {
				t.Errorf("%s holds clear %q", filepath.Base(path), c)
			}
		}
		if !bytes.HasPrefix(data, []byte("FABRIC-HOST-RECORDS-1\n")) {
			t.Errorf("%s is not a sealed envelope", filepath.Base(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 4 {
		t.Fatalf("only %d state files; expected epoch state and staged batches", files)
	}
}

// TestPartialSuccessQuarantineIsSpanDropped: a records batch the Node
// accepts in part is never resent; its positions become a span_dropped loss
// marker that is sent next.
func TestPartialSuccessQuarantineIsSpanDropped(t *testing.T) {
	cfg := productionConfig(t, t.TempDir())
	src := openTestSource(t, cfg)
	defer src.Close(false)
	send := &fakeSender{}
	prod := newProduction(src, send)
	// Manifest 0 is pending from Open; deliver it first.
	if ok, err := prod.sendPending(context.Background()); !ok || err != nil {
		t.Fatalf("manifest 0: ok=%v err=%v", ok, err)
	}
	var events []hostrecords.Event
	for pid := uint32(100); pid < 103; pid++ {
		ev, _ := hostEvent(&event{Type: evExec, Pid: pid, Scope: scopeAgent})
		events = append(events, ev)
	}
	if err := prod.stage(events); err != nil {
		t.Fatal(err)
	}
	send.results = []error{&partialExportError{rejected: 2, total: 3}}
	if ok, err := prod.sendPending(context.Background()); !ok || err != nil {
		t.Fatalf("partial success: ok=%v err=%v", ok, err)
	}
	pending := pendingSpans(t, src)
	if len(pending) != 1 || pending[0].name != "fabric.capture_loss" {
		t.Fatalf("pending after the partial success = %+v; want only the loss marker", pending)
	}
	loss := pending[0].attrs
	if loss["fabric.loss.reason"] != "span_dropped" || loss["fabric.loss.count"] != int64(3) ||
		loss["fabric.loss.first_sequence"] != int64(0) || loss["fabric.loss.last_sequence"] != int64(2) {
		t.Fatalf("loss marker = %v", loss)
	}
	if ok, err := prod.sendPending(context.Background()); !ok || err != nil {
		t.Fatalf("loss marker send: ok=%v err=%v", ok, err)
	}
	if last := send.sent[len(send.sent)-1]; last[0].name != "fabric.capture_loss" {
		t.Fatalf("last send = %s", last[0].name)
	}
	if pending := pendingSpans(t, src); len(pending) != 0 {
		t.Fatalf("still pending: %d spans", len(pending))
	}
	if batches, rejected := prod.status(); batches != 1 || rejected != 2 {
		t.Fatalf("health partial batches=%d rejected=%d", batches, rejected)
	}
	// The quarantined batch is kept sealed, never deleted.
	if entries, _ := os.ReadDir(cfg.StateDir); len(entries) == 0 {
		t.Fatal("state directory empty")
	}
}

// TestRestartReplayNoIDChurn: batches staged but not acknowledged before a
// crash are sent after the restart with the same positions and ids.
func TestRestartReplayNoIDChurn(t *testing.T) {
	cfg := productionConfig(t, t.TempDir())
	src := openTestSource(t, cfg)
	down := &fakeSender{results: []error{errors.New("node down")}}
	prod := newProduction(src, down)
	ev, _ := hostEvent(&event{Type: evExec, Pid: 4121, Ppid: 4100, Scope: scopeAgent})
	if err := prod.stage([]hostrecords.Event{ev, ev}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := prod.sendPending(context.Background()); ok {
		t.Fatal("send succeeded with the Node down")
	}
	before := pendingSpans(t, src)
	// Crash: no final marker.
	if _, err := src.Close(false); err != nil {
		t.Fatal(err)
	}

	restarted := openTestSource(t, cfg)
	defer restarted.Close(false)
	send := &fakeSender{}
	prod = newProduction(restarted, send)
	for {
		ok, err := prod.sendPending(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if ok && !prod.hasPending() {
			break
		}
	}
	ids := func(spans []span) map[string]string {
		out := map[string]string{}
		for _, s := range spans {
			if s.name != "fabric.sensor_event" {
				continue
			}
			key := mustJSON(t, []any{s.attrs["fabric.source.epoch"], s.attrs["fabric.source.sequence"]})
			out[key] = mustJSON(t, []any{s.attrs["fabric.event_id"], s.attrs["fabric.attempt.uid"]})
		}
		return out
	}
	var sent []span
	for _, b := range send.sent {
		sent = append(sent, b...)
	}
	want, got := ids(before), ids(sent)
	if len(want) != 2 || mustJSON(t, want) != mustJSON(t, got) {
		t.Fatalf("replayed records changed identity\nbefore %v\n after %v", want, got)
	}
	// The new epoch's manifest 0 lists the unsealed prior epoch.
	found := false
	for _, s := range sent {
		if s.name == "fabric.capture_manifest" && s.attrs["fabric.source.epoch"] == int64(restarted.Epoch()) {
			found = strings.Contains(mustJSON(t, s.attrs), "unsealed")
		}
	}
	if !found {
		t.Fatal("manifest 0 of the restarted epoch does not list the unsealed prior epoch")
	}
}

// TestRingAndRateLossAreUpstreamLoss: ring-buffer and rate-limit drops are
// reported on the next heartbeat, one span per reason.
func TestRingAndRateLossAreUpstreamLoss(t *testing.T) {
	cfg := productionConfig(t, t.TempDir())
	src := openTestSource(t, cfg)
	defer src.Close(false)
	prod := newProduction(src, &fakeSender{})
	prod.upstreamLoss(lossRingBufferFull, 3)
	prod.upstreamLoss(lossRateLimited, 2)
	prod.upstreamLoss(lossRateLimited, 0)
	if err := prod.heartbeat(); err != nil {
		t.Fatal(err)
	}
	var heartbeats []map[string]any
	for _, s := range pendingSpans(t, src) {
		if s.name == "fabric.capture_heartbeat" {
			heartbeats = append(heartbeats, s.attrs)
		}
	}
	if len(heartbeats) != 2 ||
		heartbeats[0]["fabric.sensor.upstream_loss_reason"] != lossRingBufferFull || heartbeats[0]["fabric.sensor.upstream_lost"] != int64(3) ||
		heartbeats[1]["fabric.sensor.upstream_loss_reason"] != lossRateLimited || heartbeats[1]["fabric.sensor.upstream_lost"] != int64(2) {
		t.Fatalf("heartbeats = %v", heartbeats)
	}
}

func TestPrintSourceIDVector(t *testing.T) {
	var vectors struct {
		Cases []struct {
			Name     string  `json:"name"`
			File     string  `json:"file_base64"`
			Mode     string  `json:"mode"`
			Refused  *string `json:"refused"`
			SourceID string  `json:"source_id"`
		} `json:"cases"`
	}
	readJSON(t, repoPath(t, "contracts/capture/v1/fixtures/host/id-key-file-v1.json"), &vectors)
	dir := t.TempDir()
	checked := 0
	for i, c := range vectors.Cases {
		if c.Refused != nil || c.Mode != "0400" {
			continue
		}
		var key []byte
		if err := json.Unmarshal([]byte(`"`+c.File+`"`), &key); err != nil {
			t.Fatal(err)
		}
		path := writeKeyFile(t, dir, "key"+string(rune('a'+i)), key)
		got, err := printSourceID("node-a/ebpf", path)
		if err != nil || got != c.SourceID {
			t.Fatalf("%s: print-source-id = %q, %v; want %s", c.Name, got, err, c.SourceID)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no accepted id key vectors")
	}
	if _, err := printSourceID("", "/x"); err == nil {
		t.Fatal("print-source-id without a label accepted")
	}
}
