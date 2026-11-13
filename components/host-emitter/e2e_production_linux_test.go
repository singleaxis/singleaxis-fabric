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
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/hostrecords"
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
	case "sensor-classes":
		os.Exit(sensorClassesHelper())
	case "held-connect":
		os.Exit(heldConnectHelper())
	case "refused-connect":
		os.Exit(refusedConnectHelper())
	case "seccomp-kill":
		os.Exit(seccompKillHelper())
	case "unmapped-path":
		os.Exit(unmappedPathHelper())
	case "plain-connect":
		os.Exit(plainConnectHelper())
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

// sensorClassesHelper (spec 057 OD-13, WP7-11) drops to nobody and makes
// one call of each kind the sensor pairs with its result, then exits 3. The
// paths and ports come from the environment.
func sensorClassesHelper() int {
	if err := syscall.Setgid(65534); err != nil {
		return 10
	}
	if err := syscall.Setuid(65534); err != nil {
		return 11
	}
	env := func(k string) string { return os.Getenv("FABRIC_E2E_" + k) }
	// openat: EACCES (root-only file), ENOENT, success (a watched file)
	if _, err := unix.Open(env("DENIED"), unix.O_RDONLY, 0); err != unix.EACCES {
		return 12
	}
	if _, err := unix.Open(env("MISSING"), unix.O_RDONLY, 0); err != unix.ENOENT {
		return 13
	}
	fd, err := unix.Open(env("WATCHED"), unix.O_RDONLY, 0)
	if err != nil {
		return 14
	}
	unix.Close(fd)
	// connect (blocking): ECONNREFUSED, then success
	for i, port := range []string{env("CLOSED_PORT"), env("OPEN_PORT")} {
		p, _ := strconv.Atoi(port)
		s, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if err != nil {
			return 15
		}
		err = unix.Connect(s, &unix.SockaddrInet4{Port: p, Addr: [4]byte{127, 0, 0, 1}})
		unix.Close(s)
		if (i == 0) != (err == unix.ECONNREFUSED) {
			return 16 + i
		}
	}
	// execve of a file without the execute bit: EACCES
	if err := unix.Exec(env("NOEXEC"), []string{"noexec"}, nil); err != unix.EACCES {
		return 18
	}
	return 3
}

// refusedConnectHelper connects once to 127.0.0.1:FABRIC_E2E_OPEN_PORT; the
// test's cgroup connect4 program refuses it, so connect fails with EPERM.
func refusedConnectHelper() int {
	p, _ := strconv.Atoi(os.Getenv("FABRIC_E2E_OPEN_PORT"))
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return 30
	}
	defer unix.Close(s)
	if err := unix.Connect(s, &unix.SockaddrInet4{Port: p, Addr: [4]byte{127, 0, 0, 1}}); err != unix.EPERM {
		return 31
	}
	return 4
}

// seccompKillHelper installs a seccomp filter that kills the process on
// getppid (SECCOMP_RET_KILL_PROCESS, the seccomp kill action) and calls it:
// the kernel ends the process with SIGSYS. It never dumps core.
func seccompKillHelper() int {
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return 40
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return 41
	}
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0}, // seccomp_data.nr
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: uint32(unix.SYS_GETPPID)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)), 0, 0); err != nil {
		return 42
	}
	_, _, _ = unix.RawSyscall(unix.SYS_GETPPID, 0, 0, 0)
	return 43 // not reached: the kernel killed the process
}

// unmappedPathHelper opens and execs FABRIC_E2E_DENIED through a path that
// sits in an untouched file-backed mapping (FABRIC_E2E_PATH_FILE holds the
// path and its NUL): the page has no page-table entry, so the sensor's read
// at sys_enter fails and only the kernel's own copy faults it in. Both calls
// fail with EACCES (the file is root-only and not executable).
func unmappedPathHelper() int {
	if err := syscall.Setgid(65534); err != nil {
		return 50
	}
	if err := syscall.Setuid(65534); err != nil {
		return 51
	}
	f, err := os.Open(os.Getenv("FABRIC_E2E_PATH_FILE"))
	if err != nil {
		return 52
	}
	defer f.Close()
	page, err := unix.Mmap(int(f.Fd()), 0, 4096, unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		return 53
	}
	path := uintptr(unsafe.Pointer(&page[0])) // the address only: the page is never touched here
	cwd := int64(unix.AT_FDCWD)
	atFDCWD := uintptr(cwd)
	_, _, e := unix.Syscall6(unix.SYS_OPENAT, atFDCWD, path, unix.O_RDONLY, 0, 0, 0)
	if e != unix.EACCES {
		return 54
	}
	argv := []*byte{nil}
	_, _, e = unix.Syscall(unix.SYS_EXECVE, path, uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&argv[0])))
	if e != unix.EACCES {
		return 55
	}
	return 5
}

// plainConnectHelper connects once to 127.0.0.1:FABRIC_E2E_OPEN_PORT.
func plainConnectHelper() int {
	p, _ := strconv.Atoi(os.Getenv("FABRIC_E2E_OPEN_PORT"))
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return 60
	}
	defer unix.Close(s)
	if err := unix.Connect(s, &unix.SockaddrInet4{Port: p, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		return 61
	}
	return 0
}

// heldConnectHelper connects twice to a listener that accepts nothing and
// has a backlog of 0: the second connect blocks in the kernel until killed,
// so the sensor still holds it for its sys_exit when the test stops.
func heldConnectHelper() int {
	p, _ := strconv.Atoi(os.Getenv("FABRIC_E2E_OPEN_PORT"))
	for i := 0; i < 8; i++ {
		s, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if err != nil {
			return 20
		}
		_ = unix.Connect(s, &unix.SockaddrInet4{Port: p, Addr: [4]byte{127, 0, 0, 1}})
	}
	return 21
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

// loadSensorClasses loads the BPF programs with spec 057 OD-13's syscall
// results and process exits on, file access on, under one agent root.
func loadSensorClasses(t *testing.T, agent string) *bpfRuntime {
	t.Helper()
	cfg := &Config{Production: true, Exec: true, Connect: true, FileAccess: true,
		SyscallResults: true, ProcessExit: true, AgentCgroupRoots: []string{agent}}
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
	ev, ok := hostEvent(e, nil)
	if !ok || ev.ContainerID != id || ev.PodUID != "" || ev.Scope != "sandbox" {
		t.Fatalf("host event container %q pod %q scope %q", ev.ContainerID, ev.PodUID, ev.Scope)
	}
}

// TestSyscallResultsAndExits (spec 057 OD-13, WP7-11, kernel matrix): each
// paired syscall is emitted once with its result and errno; a failed exec is
// seen; a process exit carries its exit code or signal; a watched open is
// labelled in user space and an unwatched one is not; nothing is lost.
func TestSyscallResultsAndExits(t *testing.T) {
	base := testBase(t)
	agent := mkCgroup(t, filepath.Join(base, "agent"))
	rt := loadSensorClasses(t, agent)
	events := collect(t, rt)

	dir := filepath.Join("/tmp", "fabric-e2e-"+randomHex(t, 4))
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	write := func(name string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	denied, watched, noexec := write("denied", 0o600), write("acl.json", 0o644), write("noexec", 0o644)
	missing := filepath.Join(dir, "missing")
	open, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closed.Addr().(*net.TCPAddr).Port
	closed.Close()

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(), helperEnv+"=sensor-classes",
		"FABRIC_E2E_DENIED="+denied, "FABRIC_E2E_MISSING="+missing, "FABRIC_E2E_WATCHED="+watched,
		"FABRIC_E2E_NOEXEC="+noexec, "FABRIC_E2E_CLOSED_PORT="+strconv.Itoa(closedPort),
		"FABRIC_E2E_OPEN_PORT="+strconv.Itoa(open.Addr().(*net.TCPAddr).Port))
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: openCgroup(t, agent)}
	err = cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 {
		t.Fatalf("the helper did not make every call as expected: %v", err)
	}
	pid := uint32(cmd.Process.Pid)

	watch, err := hostrecords.NewWatchTable([]hostrecords.WatchedPath{{Path: watched, Match: "exact", Label: "agent-acl", Class: "permission_config"}})
	if err != nil {
		t.Fatal(err)
	}
	type seen struct{ result, errno string }
	opens := map[string][]seen{}
	var connects []seen
	var execs []seen
	var exit *event
	var watchedLabel string
	var trace []string // every event of the helper, logged when an assertion fails
	deadline := time.After(15 * time.Second)
	quiet := time.NewTimer(time.Hour)
	for exit == nil || quiet != nil {
		var tick <-chan time.Time
		if exit != nil {
			tick = quiet.C
		}
		select {
		case e := <-events:
			if e.Pid != pid {
				continue
			}
			trace = append(trace, fmt.Sprintf("type=%d result=%d errno=%d incomplete=%v name=%q",
				e.Type, e.Result, e.Errno, e.FilenameIncomplete, e.Filename))
			ev, ok := hostEvent(e, watch)
			if !ok {
				t.Fatalf("untranslatable event %+v", e)
			}
			switch e.Type {
			case evOpenat:
				for _, p := range []string{denied, missing, watched} {
					if e.Filename == p {
						opens[p] = append(opens[p], seen{ev.Result, ev.Errno})
						if ev.Watch != nil {
							watchedLabel = p + "=" + ev.Watch.Label
						}
					}
				}
			case evConnect:
				if e.Family == 2 && (e.Port == uint32(closedPort) || e.Port == uint32(open.Addr().(*net.TCPAddr).Port)) {
					connects = append(connects, seen{ev.Result, ev.Errno})
				}
			case evExec:
				if e.Filename == noexec || ev.Result == "success" {
					execs = append(execs, seen{ev.Result, ev.Errno})
				}
			case evExit:
				exit = e
				quiet.Reset(500 * time.Millisecond)
			}
		case <-tick:
			quiet = nil
		case <-deadline:
			t.Fatalf("no exit event for pid %d (opens %v connects %v execs %v)", pid, opens, connects, execs)
		}
	}
	want := map[string][]seen{denied: {{"failed", "EACCES"}}, missing: {{"failed", "ENOENT"}}, watched: {{"success", ""}}}
	defer func() {
		if t.Failed() {
			t.Logf("kernel %s; the helper's events:\n%s", kernelRelease(), strings.Join(trace, "\n"))
		}
	}()
	if !reflect.DeepEqual(opens, want) {
		t.Errorf("opens %v, want %v", opens, want)
	}
	if !reflect.DeepEqual(connects, []seen{{"failed", "ECONNREFUSED"}, {"success", ""}}) {
		t.Errorf("connects %v", connects)
	}
	// The helper's own successful exec (sched_process_exec), then the refused one.
	if !reflect.DeepEqual(execs, []seen{{"success", ""}, {"failed", "EACCES"}}) {
		t.Errorf("execs %v", execs)
	}
	if exit.ExitCode != 3 || exit.ExitSignal != 0 {
		t.Errorf("exit code %d signal %d, want 3 and 0", exit.ExitCode, exit.ExitSignal)
	}
	if watchedLabel != watched+"=agent-acl" {
		t.Errorf("watched label %q", watchedLabel)
	}
	if lost, err := rt.lossCount(); err != nil || lost != 0 {
		t.Errorf("ring loss %d (%v): loss accounting must stay zero for this load", lost, err)
	}

	// A process killed by a signal: the signal, no exit code.
	sleeper := exec.Command("/bin/sleep", "30")
	sleeper.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: openCgroup(t, agent)}
	if err := sleeper.Start(); err != nil {
		t.Fatal(err)
	}
	_ = sleeper.Process.Kill()
	_ = sleeper.Wait()
	killed := waitFor(t, events, "the killed process's exit", func(e *event) bool {
		return e.Type == evExit && e.Pid == uint32(sleeper.Process.Pid)
	})
	if killed.ExitSignal != 9 {
		t.Errorf("killed: signal %d exit code %d, want signal 9", killed.ExitSignal, killed.ExitCode)
	}
}

// TestHeldSyscallEmittedAtStop: a connect still blocked in the kernel when the
// emitter stops is emitted by the drain, result unknown, so a held event is
// never lost.
func TestHeldSyscallEmittedAtStop(t *testing.T) {
	base := testBase(t)
	agent := mkCgroup(t, filepath.Join(base, "agent"))
	rt := loadSensorClasses(t, agent)
	// A listener with a backlog of 0 that never accepts: once its accept
	// queue is full, the kernel drops the next SYN and that connect blocks.
	ln, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(ln)
	if err := unix.Bind(ln, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(ln, 0); err != nil {
		t.Fatal(err)
	}
	sa, err := unix.Getsockname(ln)
	if err != nil {
		t.Fatal(err)
	}
	port := sa.(*unix.SockaddrInet4).Port
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(), helperEnv+"=held-connect",
		"FABRIC_E2E_OPEN_PORT="+strconv.Itoa(port))
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: openCgroup(t, agent)}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	pid := uint32(cmd.Process.Pid)
	// Read until the helper's connects stop completing: the next one is held.
	completed := 0
	idle := time.After(3 * time.Second)
read:
	for {
		select {
		case <-idle:
			break read
		default:
		}
		e, err := rt.nextWithin(200 * time.Millisecond)
		if err != nil {
			continue
		}
		if e.Pid == pid && e.Type == evConnect {
			completed++
		}
	}
	if err := rt.stop(); err != nil {
		t.Fatal(err)
	}
	var held []*event
	for {
		// a deadline, so a drain that never ends fails instead of hanging
		e, err := rt.nextWithin(5 * time.Second)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal("the stop drain never returned ErrFlushed")
		}
		if err != nil {
			break
		}
		if e.Pid == pid && e.Type == evConnect {
			held = append(held, e)
		}
	}
	if len(held) != 1 || held[0].Result != resultUnknown {
		t.Fatalf("after %d completed connects, the stop drain gave %d held connects (want 1, result unknown)", completed, len(held))
	}
}

// nextWithin is next with a read deadline (the held-event test reads until
// the helper's connects stop completing).
func (rt *bpfRuntime) nextWithin(d time.Duration) (*event, error) {
	rt.reader.SetDeadline(time.Now().Add(d))
	defer rt.reader.SetDeadline(time.Time{})
	return rt.next()
}

// TestKernelRefusals (spec 057 WP7-11 and WP7-12, kernel matrix): the two
// refusals of the closed set no file permission can produce. A connect that a
// cgroup connect4 program refuses (as a network policy does) is emitted
// failed with EPERM; a process the seccomp kill action ends is emitted as an
// exit with signal 31 (SIGSYS) and no exit code. Both are what the kernel
// reported; the emitter decides nothing.
func TestKernelRefusals(t *testing.T) {
	base := testBase(t)
	agent := mkCgroup(t, filepath.Join(base, "agent"))
	refusing := mkCgroup(t, filepath.Join(agent, "refusing"))
	rt := loadSensorClasses(t, agent)
	events := collect(t, rt)

	// The refusing control, test-only: return 0 from a connect4 hook (EPERM).
	deny, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.CGroupSockAddr,
		AttachType: ebpf.AttachCGroupInet4Connect,
		License:    "Apache-2.0",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		t.Fatalf("load the test's connect4 program: %v", err)
	}
	t.Cleanup(func() { deny.Close() })
	l, err := link.AttachCgroup(link.CgroupOptions{Path: refusing, Attach: ebpf.AttachCGroupInet4Connect, Program: deny})
	if err != nil {
		t.Fatalf("attach the test's connect4 program: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	open, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	port := open.Addr().(*net.TCPAddr).Port
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := func(name, cgroup string) *exec.Cmd {
		cmd := exec.Command(exe, "-test.run=^$")
		cmd.Env = append(os.Environ(), helperEnv+"="+name, "FABRIC_E2E_OPEN_PORT="+strconv.Itoa(port))
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: openCgroup(t, cgroup)}
		return cmd
	}

	refused := helper("refused-connect", refusing)
	err = refused.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 4 {
		t.Fatalf("the refused-connect helper did not see EPERM: %v", err)
	}
	connect := waitFor(t, events, "the refused connect", func(e *event) bool {
		return e.Type == evConnect && e.Pid == uint32(refused.Process.Pid) && e.Port == uint32(port)
	})
	if ev, ok := hostEvent(connect, nil); !ok || ev.Result != "failed" || ev.Errno != "EPERM" {
		t.Errorf("refused connect: result %q errno %q, want failed EPERM", ev.Result, ev.Errno)
	}

	killed := helper("seccomp-kill", agent)
	err = killed.Run()
	if !errors.As(err, &exitErr) {
		t.Fatalf("the seccomp-kill helper was not killed: %v", err)
	}
	if ws, ok := exitErr.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGSYS {
		t.Fatalf("the seccomp-kill helper ended with %v, want SIGSYS", err)
	}
	exit := waitFor(t, events, "the seccomp-killed exit", func(e *event) bool {
		return e.Type == evExit && e.Pid == uint32(killed.Process.Pid)
	})
	ev, ok := hostEvent(exit, nil)
	if !ok || ev.Class != "exit" || ev.Signal == nil || *ev.Signal != 31 || ev.ExitCode != nil {
		t.Errorf("seccomp kill: %+v, want class exit, signal 31, no exit code", ev)
	}
	if lost, err := rt.lossCount(); err != nil || lost != 0 {
		t.Errorf("ring loss %d (%v): loss accounting must stay zero for this load", lost, err)
	}
}

// TestFileAccessWithoutResults (kernel matrix): with syscall results off,
// an openat and a connect in the agent root are each emitted once at
// sys_enter, result unknown. On Ubuntu's 7.0 kernel the per-syscall openat
// tracepoint never ran an attached BPF program, so file access was silently
// empty; the raw syscall dispatch sees it on every kernel.
func TestFileAccessWithoutResults(t *testing.T) {
	base := testBase(t)
	agent := mkCgroup(t, filepath.Join(base, "agent"))
	cfg := &Config{Production: true, Exec: true, Connect: true, FileAccess: true, AgentCgroupRoots: []string{agent}}
	rt, err := loadBPF(cfg)
	if err != nil {
		t.Fatalf("load BPF: %v", err)
	}
	t.Cleanup(rt.close)
	events := collect(t, rt)

	marker := filepath.Join("/tmp", "fabric-e2e-"+randomHex(t, 4))
	if err := os.WriteFile(marker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(marker) })
	open, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	port := open.Addr().(*net.TCPAddr).Port
	runIn(t, agent, "/bin/cat", marker)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(), helperEnv+"=plain-connect", "FABRIC_E2E_OPEN_PORT="+strconv.Itoa(port))
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: openCgroup(t, agent)}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the plain-connect helper: %v %s", err, out)
	}
	defer func() {
		if t.Failed() {
			t.Logf("kernel %s", kernelRelease())
		}
	}()
	opened := waitFor(t, events, "the openat of the marker", func(e *event) bool {
		return e.Type == evOpenat && e.Filename == marker
	})
	if opened.Result != resultUnknown || opened.FilenameIncomplete {
		t.Errorf("openat: result %d incomplete %v, want unknown and complete", opened.Result, opened.FilenameIncomplete)
	}
	connect := waitFor(t, events, "the connect", func(e *event) bool {
		return e.Type == evConnect && e.Pid == uint32(cmd.Process.Pid) && e.Port == uint32(port)
	})
	if connect.Result != resultUnknown {
		t.Errorf("connect: result %d, want unknown", connect.Result)
	}
	if lost, err := rt.lossCount(); err != nil || lost != 0 {
		t.Errorf("ring loss %d (%v): loss accounting must stay zero for this load", lost, err)
	}
}

// kernelRelease is uname -r, for failure messages of the kernel matrix.
func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "unknown"
	}
	return unix.ByteSliceToString(u.Release[:])
}

// TestPathReadRetriedAtExit (spec 057 WP7-11): a held openat or execve whose
// path the sensor could not read at sys_enter (the page was not resident)
// is read again at sys_exit, after the kernel copied it, so the record still
// names the path (its digest and watched label) with the result and errno.
func TestPathReadRetriedAtExit(t *testing.T) {
	base := testBase(t)
	agent := mkCgroup(t, filepath.Join(base, "agent"))
	rt := loadSensorClasses(t, agent)
	events := collect(t, rt)

	dir := filepath.Join("/tmp", "fabric-e2e-"+randomHex(t, 4))
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	denied := filepath.Join(dir, "denied")
	if err := os.WriteFile(denied, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	pathFile := filepath.Join(dir, "path")
	if err := os.WriteFile(pathFile, append([]byte(denied), 0), 0o644); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(), helperEnv+"=unmapped-path", "FABRIC_E2E_PATH_FILE="+pathFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: openCgroup(t, agent)}
	err = cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 5 {
		t.Fatalf("the unmapped-path helper did not make both calls as expected: %v", err)
	}
	pid := uint32(cmd.Process.Pid)
	for _, typ := range []uint32{evOpenat, evExec} {
		e := waitFor(t, events, fmt.Sprintf("the refused call of type %d", typ), func(e *event) bool {
			return e.Pid == pid && e.Type == typ && e.Result == resultFailed && e.Errno == 13 // not the Go runtime's own opens
		})
		if e.Filename != denied || e.FilenameIncomplete {
			t.Errorf("type %d: name %q incomplete %v, want %q and complete",
				typ, e.Filename, e.FilenameIncomplete, denied)
		}
	}
}
