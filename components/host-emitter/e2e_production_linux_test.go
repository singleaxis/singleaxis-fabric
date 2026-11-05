// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

//go:build linux && e2e

// Privileged production-mode e2e (spec 056 §7.3.2 WP4-07c), run by
// `e2e-emitter.sh --production` in a privileged container with the host's
// pid namespace and a writable cgroup v2 hierarchy. Each test loads the real
// BPF programs with production scope roots and checks what the kernel
// reported against /proc.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const helperEnv = "FABRIC_E2E_HELPER"

func init() {
	// The ns-init helper must spawn its child from a thread other than the
	// thread-group leader: the main goroutine keeps the main thread.
	if os.Getenv(helperEnv) == "ns-init" {
		runtime.LockOSThread()
	}
}

func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "ns-init":
		os.Exit(nsInit())
	case "report":
		os.Exit(report())
	}
	os.Exit(m.Run())
}

// nsInit runs as pid 1 of a new pid and mount namespace: it mounts a /proc
// of that namespace and spawns the report child from a non-main thread.
func nsInit() int {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		fmt.Fprintln(os.Stderr, "make mounts private:", err)
		return 2
	}
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		fmt.Fprintln(os.Stderr, "mount proc:", err)
		return 2
	}
	done := make(chan int, 1)
	go func() {
		tid := unix.Gettid()
		cmd := exec.Command("/proc/self/exe", "-test.run=^$")
		cmd.Env = append(os.Environ(), helperEnv+"=report", "FABRIC_E2E_SPAWNER_TID="+strconv.Itoa(tid))
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "report child:", err)
			done <- 2
			return
		}
		done <- 0
	}()
	return <-done
}

// childReport is what the report child sees inside its namespace.
type childReport struct {
	Getppid     int    `json:"getppid"`
	StatusPPid  int    `json:"status_ppid"`
	StatusNSpid string `json:"status_nspid"`
	SpawnerTid  int    `json:"spawner_tid"`
	SpawnerPid  int    `json:"spawner_pid"`
}

func report() int {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		fmt.Fprintln(os.Stderr, "read status:", err)
		return 2
	}
	r := childReport{Getppid: os.Getppid(), SpawnerPid: os.Getppid()}
	r.SpawnerTid, _ = strconv.Atoi(os.Getenv("FABRIC_E2E_SPAWNER_TID"))
	for _, line := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "PPid:"); ok {
			r.StatusPPid, _ = strconv.Atoi(strings.TrimSpace(v))
		}
		if v, ok := strings.CutPrefix(line, "NSpid:"); ok {
			r.StatusNSpid = strings.TrimSpace(v)
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		return 2
	}
	// Stay alive until the test has read /proc from outside.
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	return 0
}

// --- harness ----------------------------------------------------------------

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// mkCgroup creates a cgroup v2 directory removed at the end of the test.
func mkCgroup(t *testing.T, path string) string {
	t.Helper()
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("create cgroup %s: %v", path, err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

// testBase is a fresh cgroup under the hierarchy root for one test.
func testBase(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("the production e2e needs root in a privileged container")
	}
	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &st); err != nil || st.Type != unix.CGROUP2_SUPER_MAGIC {
		t.Fatal("the production e2e needs a cgroup v2 hierarchy at /sys/fs/cgroup")
	}
	return mkCgroup(t, "/sys/fs/cgroup/fabric-e2e-"+randomHex(t, 4))
}

func cgroupID(t *testing.T, path string) uint64 {
	t.Helper()
	id, err := cgroupIDFromPath(path)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// loadProduction loads the BPF programs with the given static roots.
func loadProduction(t *testing.T, agent, sandbox []string) *bpfRuntime {
	t.Helper()
	cfg := &Config{Production: true, Exec: true, AgentCgroupRoots: agent, SandboxCgroupRoots: sandbox}
	rt, err := loadBPF(cfg)
	if err != nil {
		t.Fatalf("load BPF: %v", err)
	}
	t.Cleanup(rt.close)
	return rt
}

// collect reads events in the background into a channel.
func collect(t *testing.T, rt *bpfRuntime) <-chan *event {
	t.Helper()
	ch := make(chan *event, 1024)
	go func() {
		for {
			e, err := rt.next()
			if err != nil {
				return
			}
			ch <- e
		}
	}()
	return ch
}

// waitFor returns the first event that satisfies match, or fails.
func waitFor(t *testing.T, ch <-chan *event, what string, match func(*event) bool) *event {
	t.Helper()
	deadline := time.After(15 * time.Second)
	for {
		select {
		case e := <-ch:
			if match(e) {
				return e
			}
		case <-deadline:
			t.Fatalf("no event: %s", what)
		}
	}
}

// openCgroup opens a cgroup directory for CLONE_INTO_CGROUP.
func openCgroup(t *testing.T, path string) int {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

// runIn runs argv to completion in a cgroup.
func runIn(t *testing.T, cgroup string, argv ...string) {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: openCgroup(t, cgroup)}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run %v in %s: %v %s", argv, cgroup, err, out)
	}
}

func procStatusField(t *testing.T, pid uint32, field string) string {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, field+":"); ok {
			return strings.TrimSpace(v)
		}
	}
	t.Fatalf("/proc/%d/status has no %s", pid, field)
	return ""
}

// procStartTicks is /proc/<pid>/stat field 22 (starttime, clock ticks).
func procStartTicks(t *testing.T, pid uint32) uint64 {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatal(err)
	}
	// Field 2 (comm) may hold spaces; the fields after it start at ") ".
	rest := string(data[strings.LastIndexByte(string(data), ')')+2:])
	fields := strings.Fields(rest)
	v, err := strconv.ParseUint(fields[22-3], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// --- tests ------------------------------------------------------------------

// TestNamespacePidsMatchProc: a workload in its own pid namespace, its child
// spawned from a second thread. ns_pid equals NSpid, pid_ns the ns/pid
// inode, process_start_ns // 10^7 the stat starttime, and ns_ppid the
// child's own getppid() and the PPid of a /proc mounted inside the
// namespace; ppid is the parent's init-namespace tgid, not the thread's.
func TestNamespacePidsMatchProc(t *testing.T) {
	base := testBase(t)
	agent := mkCgroup(t, filepath.Join(base, "agent"))
	rt := loadProduction(t, []string{agent}, nil)
	events := collect(t, rt)
	agentID := cgroupID(t, agent)

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(), helperEnv+"=ns-init")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
		UseCgroupFD: true,
		CgroupFD:    openCgroup(t, agent),
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the namespace workload: %v", err)
	}
	t.Cleanup(func() {
		stdin.Close()
		_ = cmd.Wait()
	})
	var r childReport
	if err := json.NewDecoder(stdout).Decode(&r); err != nil {
		t.Fatalf("read the child's report: %v", err)
	}
	if r.SpawnerTid == r.SpawnerPid {
		t.Fatalf("the child was spawned from the thread-group leader (tid %d); the test needs a second thread", r.SpawnerTid)
	}
	nsInitPid := uint32(cmd.Process.Pid)
	var init, child *event
	deadline := time.After(15 * time.Second)
	for init == nil || child == nil {
		select {
		case e := <-events:
			if e.Type != evExec || e.CgroupID != agentID {
				continue
			}
			if e.Pid == nsInitPid {
				init = e
			} else if e.Ppid == nsInitPid {
				child = e
			}
		case <-deadline:
			t.Fatalf("missing exec events: namespace init %v, report child %v", init != nil, child != nil)
		}
	}
	if child.Scope != scopeAgent {
		t.Fatalf("scope = %d, want agent", child.Scope)
	}
	nspid := strings.Fields(procStatusField(t, child.Pid, "NSpid"))
	if len(nspid) < 2 || nspid[0] != strconv.Itoa(int(child.Pid)) {
		t.Fatalf("NSpid %v does not start with the event's init-namespace pid %d", nspid, child.Pid)
	}
	if nspid[len(nspid)-1] != strconv.Itoa(int(child.NsPid)) {
		t.Fatalf("ns_pid = %d, NSpid = %v", child.NsPid, nspid)
	}
	if r.StatusNSpid != strconv.Itoa(int(child.NsPid)) {
		t.Fatalf("ns_pid = %d, NSpid inside the namespace = %q", child.NsPid, r.StatusNSpid)
	}
	var st unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/pid", child.Pid), &st); err != nil {
		t.Fatal(err)
	}
	if uint64(child.PidNS) != st.Ino {
		t.Fatalf("pid_ns = %d, ns/pid inode = %d", child.PidNS, st.Ino)
	}
	if got, want := child.StartBoottime/10_000_000, procStartTicks(t, child.Pid); got != want {
		t.Fatalf("process_start_ns // 10^7 = %d, stat starttime = %d", got, want)
	}
	if int(child.NsPpid) != r.Getppid || int(child.NsPpid) != r.StatusPPid {
		t.Fatalf("ns_ppid = %d, getppid() = %d, PPid in the namespace = %d", child.NsPpid, r.Getppid, r.StatusPPid)
	}
	if want := procStatusField(t, child.Pid, "PPid"); strconv.Itoa(int(child.Ppid)) != want {
		t.Fatalf("ppid = %d, init-namespace PPid = %s", child.Ppid, want)
	}
	// The ns-init process itself is pid 1 of the namespace, and its parent is
	// outside it: ns_ppid 0.
	t.Logf("child pid %d ppid %d ns_pid %d ns_ppid %d pid_ns %d start_boottime %d; spawned from tid %d of pid %d",
		child.Pid, child.Ppid, child.NsPid, child.NsPpid, child.PidNS, child.StartBoottime, r.SpawnerTid, r.SpawnerPid)
	if init.NsPid != 1 || init.NsPpid != 0 || init.PidNS != child.PidNS {
		t.Fatalf("namespace init: ns_pid %d ns_ppid %d pid_ns %d", init.NsPid, init.NsPpid, init.PidNS)
	}
}

// TestAgentRootPodShape: an agent root shaped like a pod slice with two
// container scopes created at run time; both containers' events are scope
// agent, and a sibling outside the root is not emitted.
func TestAgentRootPodShape(t *testing.T) {
	base := testBase(t)
	uid := strings.ReplaceAll("6a1d9c2e-4b7f-4e10-9a3c-"+randomHex(t, 6), "-", "_")
	pod := mkCgroup(t, filepath.Join(base, "e2e-pod"+uid+".slice"))
	sibling := mkCgroup(t, filepath.Join(base, "sibling"))
	rt := loadProduction(t, []string{pod}, nil)
	events := collect(t, rt)

	var containers []string
	for i := 0; i < 2; i++ {
		containers = append(containers, mkCgroup(t, filepath.Join(pod, "cri-containerd-"+randomHex(t, 32)+".scope")))
	}
	siblingID := cgroupID(t, sibling)
	runIn(t, sibling, "/bin/true")
	want := map[uint64]bool{}
	for _, c := range containers {
		want[cgroupID(t, c)] = true
		runIn(t, c, "/bin/true")
	}
	deadline := time.After(15 * time.Second)
	for len(want) > 0 {
		select {
		case e := <-events:
			if e.CgroupID == siblingID {
				t.Fatal("an event outside the agent root was emitted")
			}
			if e.Type == evExec && want[e.CgroupID] {
				if e.Scope != scopeAgent {
					t.Fatalf("container event scope = %d, want agent", e.Scope)
				}
				delete(want, e.CgroupID)
			}
		case <-deadline:
			t.Fatalf("missing exec events for %d container cgroups", len(want))
		}
	}
	// Anything still queued must not be the sibling's.
	drain := time.After(500 * time.Millisecond)
	for {
		select {
		case e := <-events:
			if e.CgroupID == siblingID {
				t.Fatal("an event outside the agent root was emitted")
			}
		case <-drain:
			return
		}
	}
}

// TestSandboxRootScope: a short-lived container cgroup under a sandbox root,
// removed right after its exec and before user space reads the event, still
// carries its container id.
func TestSandboxRootScope(t *testing.T) {
	base := testBase(t)
	sandboxes := mkCgroup(t, filepath.Join(base, "sandboxes"))
	rt := loadProduction(t, nil, []string{sandboxes})
	id := randomHex(t, 32)
	container := filepath.Join(sandboxes, "docker-"+id+".scope")
	if err := os.Mkdir(container, 0o755); err != nil {
		t.Fatal(err)
	}
	cgID := cgroupID(t, container)
	cmd := exec.Command("/bin/true")
	fd, err := unix.Open(container, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	unix.Close(fd)
	// The container is gone before the ring buffer is read.
	removed := false
	for i := 0; i < 50 && !removed; i++ {
		removed = os.Remove(container) == nil
		if !removed {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !removed {
		t.Fatal("the container cgroup could not be removed")
	}
	if _, err := os.Stat(container); !os.IsNotExist(err) {
		t.Fatal("the container cgroup still exists")
	}
	events := collect(t, rt)
	e := waitFor(t, events, "the sandbox exec", func(e *event) bool {
		return e.Type == evExec && e.CgroupID == cgID
	})
	if e.Scope != scopeSandbox {
		t.Fatalf("scope = %d, want sandbox", e.Scope)
	}
	if !e.CgroupNamesRead || e.CgroupName != "docker-"+id+".scope" || e.CgroupParentName != "sandboxes" {
		t.Fatalf("kernfs names = %v %q %q", e.CgroupNamesRead, e.CgroupParentName, e.CgroupName)
	}
	ev, ok := hostEvent(e)
	if !ok || ev.ContainerID != id || ev.PodUID != "" || ev.Scope != "sandbox" {
		t.Fatalf("host event container %q pod %q scope %q", ev.ContainerID, ev.PodUID, ev.Scope)
	}
}
