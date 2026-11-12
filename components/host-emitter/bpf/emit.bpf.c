// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// emit.bpf.c — passive host-observation tracepoints for the Fabric host
// emitter (spec 031). Read-only by construction: no LSM hooks, no packet
// interception, no enforcement. Events flow over a ringbuf to userspace,
// which translates them to the shared event_class=audit schema (local mode)
// or to host records (production mode, spec 053 §6.2.9, spec 056 §7.3.3 (c))
// and OTLP-exports them to the Fabric Node.
//
// Syscall results (spec 057 OD-13, WP7-11; cfg[CFG_RESULTS]): a connect,
// openat or execve is held in a per-thread pending map at sys_enter and
// emitted once, at its sys_exit, with the return value. Nothing waits: the
// syscall runs exactly as without the sensor. Every held event is emitted
// exactly once; when the map is full, a stale entry is found or the thread
// exits mid-call, the event goes out with result unknown, as without
// results. The only loss stays the ring-buffer reservation counter.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EV_EXEC 1
#define EV_CONNECT 2
#define EV_OPENAT 3
#define EV_EXIT 4

// Result of the paired syscall (spec 057 OD-13).
#define RES_UNKNOWN 0
#define RES_SUCCESS 1
#define RES_FAILED 2

// errno values (asm-generic, the same on x86 and arm64).
#define EINTR 4
#define EALREADY 114
#define EINPROGRESS 115

// include/linux/sched/signal.h
#define SIGNAL_GROUP_EXIT 0x00000004

#define AF_INET 2
#define AF_INET6 10

// Event scope (production mode, spec 056 §4.3): which configured cgroup root
// admitted the event. Local mode leaves it SCOPE_NONE.
#define SCOPE_NONE 0
#define SCOPE_AGENT 1
#define SCOPE_SANDBOX 2

// pid_namespace levels are bounded by MAX_PID_NS_LEVEL (32) in the kernel.
#define MAX_PID_LEVEL 32
// Ancestor levels walked for the root-based scope (056 §7.3.3 (c)).
#define MAX_CGROUP_LEVEL 32
#define CG_NAME_LEN 128

// Field order and sizes are mirrored by rawEvent in bpf.go; every member is
// naturally aligned and the struct has no implicit padding.
struct event {
    __u64 cgroup_id;
    __u64 ts_ns;
    // The thread-group leader's task_struct.start_boottime (CLOCK_BOOTTIME
    // ns, unrounded): the field /proc/<pid>/stat field 22 is computed from.
    __u64 start_boottime;
    __u32 pid;
    __u32 ppid;
    // The process in its own pid namespace, the parent's thread-group id in
    // that namespace (0 when the parent is outside it) and the namespace's
    // inode (053 §6.2.3 revisions 3 and 4).
    __u32 ns_pid;
    __u32 ns_ppid;
    __u32 pid_ns;
    __u32 scope;
    __u32 type;
    __u32 family;
    __u32 port;
    __u8  addr[16];
    __u32 argv_len;
    __u32 argv_incomplete;
    __u32 filename_incomplete;
    // Set when cg_name and cg_parent hold the kernfs names of the event's
    // cgroup and its parent (sandbox-scope events only).
    __u32 cg_names;
    // Spec 057 OD-13: the paired syscall's result (RES_*) and, when failed,
    // its positive errno; a process exit's wait status split into exit code
    // and terminating signal (exit_signal 0: a normal exit).
    __u32 result;
    __s32 err;
    __s32 exit_code;
    __u32 exit_signal;
    __u32 reserved;
    // The user address of a held openat or execve path (never sent: cleared
    // before emission). When the read at sys_enter failed (the page was not
    // resident, and a BPF read cannot fault it in), sys_exit reads it again
    // after the kernel itself has copied the path.
    __u64 uptr;
    char  comm[16];
    char  filename[240];
    __u8  argv[384];
    char  cg_name[CG_NAME_LEN];
    char  cg_parent[CG_NAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Count ring-buffer reservation failures per CPU. These are outside the
// userspace spool and must be reported as capture loss, not inferred away.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} losses SEC(".maps");

static __always_inline void note_ring_loss(void) {
    __u32 k = 0;
    __u64 *n = bpf_map_lookup_elem(&losses, &k);
    if (n)
        (*n)++;
}

// cfg[0] = target cgroup id in local mode; 0 means unfiltered (all_host
// opt-in). cfg[1] = 1 selects production mode (root-based scope). cfg[2] is
// the production scope of an event under no root: SCOPE_AGENT with
// EMIT_ALL_HOST, else SCOPE_NONE (not emitted). cfg[3] = 1 holds connect,
// openat and execve for their sys_exit (EMIT_SYSCALL_RESULTS); cfg[4] = 1
// emits process exits (EMIT_EXIT).
#define CFG_LOCAL_CGROUP 0
#define CFG_MODE 1
#define CFG_DEFAULT_SCOPE 2
#define CFG_RESULTS 3
#define CFG_EXIT 4
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u64);
} cfg SEC(".maps");

// Production scope roots: cgroup id -> SCOPE_AGENT or SCOPE_SANDBOX. Static
// agent and sandbox roots and the pod roots installed by user space.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u32);
} roots SEC(".maps");

static __always_inline __u64 cfg_get(__u32 k) {
    __u64 *v = bpf_map_lookup_elem(&cfg, &k);
    return v ? *v : 0;
}

// Events held between sys_enter and sys_exit, by pid_tgid (one syscall per
// thread at a time). Preallocated: an insert never allocates.
#define PENDING_MAX 4096
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PENDING_MAX);
    __type(key, __u64);
    __type(value, struct event);
} pending SEC(".maps");

// A zeroed event, the source of a pending insert. Never written, so programs
// that share a CPU cannot disturb each other through it.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} zero_event SEC(".maps");

// emit_copy sends a held event to the ring buffer (a reservation failure is
// the same counted loss as for an event emitted at once).
static __always_inline void emit_copy(struct event *e) {
    e->uptr = 0;
    if (bpf_ringbuf_output(&events, e, sizeof(*e), 0) != 0)
        note_ring_loss();
}

// flush_pending emits the event a thread still holds, result unknown, and
// forgets it: its sys_exit was never seen (a stale entry, a thread exit).
static __always_inline void flush_pending(__u64 key) {
    struct event *old = bpf_map_lookup_elem(&pending, &key);
    if (!old)
        return;
    old->result = RES_UNKNOWN;
    emit_copy(old);
    bpf_map_delete_elem(&pending, &key);
}

// scope_of walks the current task's cgroup ancestors from level 1 down to
// its own level; the deepest configured root that contains the cgroup wins.
static __always_inline __u32 scope_of(void) {
    __u32 scope = SCOPE_NONE;
    for (int level = 1; level <= MAX_CGROUP_LEVEL; level++) {
        __u64 id = bpf_get_current_ancestor_cgroup_id(level);
        if (id == 0)
            break;
        __u32 *s = bpf_map_lookup_elem(&roots, &id);
        if (s)
            scope = *s;
    }
    return scope;
}

// admit decides whether an event is emitted and with which scope. Local mode
// keeps the exact-cgroup filter unchanged.
static __always_inline int admit(__u64 cg, __u32 *scope) {
    *scope = SCOPE_NONE;
    if (cfg_get(CFG_MODE) == 0) {
        __u64 target = cfg_get(CFG_LOCAL_CGROUP);
        return target == 0 || target == cg;
    }
    __u32 s = scope_of();
    if (s == SCOPE_NONE)
        s = (__u32)cfg_get(CFG_DEFAULT_SCOPE);
    *scope = s;
    return s != SCOPE_NONE;
}

// Linux 6.15 renamed kernfs_node.parent to __parent; CO-RE picks whichever
// the running kernel has.
struct kernfs_node___new {
    struct kernfs_node *__parent;
} __attribute__((preserve_access_index));

static __always_inline struct kernfs_node *kn_parent(struct kernfs_node *kn) {
    if (bpf_core_field_exists(kn->parent))
        return BPF_CORE_READ(kn, parent);
    struct kernfs_node___new *n = (void *)kn;
    return BPF_CORE_READ(n, __parent);
}

// fill_names reads the kernfs names of the task's default-hierarchy cgroup
// and its parent at event time, so a container whose cgroup is removed
// before user space reads the event keeps its ids (056 §4.3 H5).
static __always_inline void fill_names(struct event *e, struct task_struct *task) {
    struct kernfs_node *kn = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn);
    if (!kn)
        return;
    const char *name = BPF_CORE_READ(kn, name);
    if (!name || bpf_probe_read_kernel_str(&e->cg_name, sizeof(e->cg_name), name) <= 0)
        return;
    struct kernfs_node *parent = kn_parent(kn);
    if (parent) {
        const char *pname = BPF_CORE_READ(parent, name);
        if (pname && bpf_probe_read_kernel_str(&e->cg_parent, sizeof(e->cg_parent), pname) <= 0)
            e->cg_parent[0] = 0;
    }
    e->cg_names = 1;
}

// fill_task records both pid numberings of the thread-group leader. pid and
// ppid are init-namespace tgids. ns_pid is numbers[level].nr of the leader's
// thread_pid at its own level; ns_ppid is the real parent's thread-group id
// at that level when the parent is in the same namespace, else 0 (what
// getppid() returns there). The spawning thread's own id is never used.
static __always_inline void fill_task(struct event *e, struct task_struct *task) {
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    struct task_struct *parent = BPF_CORE_READ(leader, real_parent);
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(parent, tgid);
    e->start_boottime = BPF_CORE_READ(leader, start_boottime);
    struct pid *p = BPF_CORE_READ(leader, thread_pid);
    if (!p)
        return;
    unsigned int level = BPF_CORE_READ(p, level);
    if (level > MAX_PID_LEVEL)
        return;
    struct pid_namespace *ns = BPF_CORE_READ(p, numbers[level].ns);
    e->ns_pid = BPF_CORE_READ(p, numbers[level].nr);
    e->pid_ns = BPF_CORE_READ(ns, ns.inum);
    struct task_struct *pleader = BPF_CORE_READ(parent, group_leader);
    struct pid *pp = BPF_CORE_READ(pleader, thread_pid);
    if (!pp)
        return;
    unsigned int plevel = BPF_CORE_READ(pp, level);
    if (plevel < level || plevel > MAX_PID_LEVEL)
        return;
    if (BPF_CORE_READ(pp, numbers[level].ns) == ns)
        e->ns_ppid = BPF_CORE_READ(pp, numbers[level].nr);
}

// fill writes the common part of a zeroed event.
static __always_inline void fill(struct event *e, __u32 type, __u64 cg, __u32 scope) {
    struct task_struct *task = (void *)bpf_get_current_task();
    e->type = type;
    e->cgroup_id = cg;
    e->scope = scope;
    e->ts_ns = bpf_ktime_get_ns();
    fill_task(e, task);
    if (scope == SCOPE_SANDBOX)
        fill_names(e, task);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// reserve reserves a zeroed ring-buffer event, counting a failure as loss.
static __always_inline struct event *reserve(void) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        note_ring_loss();
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    return e;
}

// begin reserves and fills the common part of an event, or returns NULL when
// the event is out of scope or the ring buffer is full.
static __always_inline struct event *begin(__u32 type) {
    __u64 cg = bpf_get_current_cgroup_id();
    __u32 scope;
    if (!admit(cg, &scope))
        return 0;
    struct event *e = reserve();
    if (e)
        fill(e, type, cg, scope);
    return e;
}

// struct held is where an enter program writes its event: the pending map
// entry of this thread (held = 1; sent at sys_exit) or, with results off or
// the map full, a ring-buffer reservation (held = 0; sent by finish).
struct held {
    struct event *e;
    int held;
};

// hold returns the thread's new pending entry when results are on, else a
// ring-buffer event as begin does. A stale entry of the thread (its sys_exit
// was never seen) is emitted first, result unknown.
static __always_inline struct held hold(__u32 type) {
    struct held h = {0, 0};
    __u64 cg = bpf_get_current_cgroup_id();
    __u32 scope;
    if (!admit(cg, &scope))
        return h;
    if (cfg_get(CFG_RESULTS)) {
        __u64 key = bpf_get_current_pid_tgid();
        __u32 zk = 0;
        struct event *zero = bpf_map_lookup_elem(&zero_event, &zk);
        flush_pending(key);
        if (zero && bpf_map_update_elem(&pending, &key, zero, BPF_NOEXIST) == 0) {
            struct event *e = bpf_map_lookup_elem(&pending, &key);
            if (e) {
                fill(e, type, cg, scope);
                h.e = e;
                h.held = 1;
                return h;
            }
        }
        // The map is full: emit at once, result unknown (no event is lost).
    }
    h.e = reserve();
    if (h.e)
        fill(h.e, type, cg, scope);
    return h;
}

// finish submits a ring-buffer event; a held one waits for its sys_exit.
static __always_inline void finish(struct held h) {
    if (!h.held)
        bpf_ringbuf_submit(h.e, 0);
}

// complete emits the thread's pending event of the given type with the
// syscall's return value and forgets it. Another type's entry is left alone.
static __always_inline void complete(__u32 type, long ret) {
    __u64 key = bpf_get_current_pid_tgid();
    struct event *e = bpf_map_lookup_elem(&pending, &key);
    if (!e || e->type != type)
        return;
    if (e->filename_incomplete && e->uptr) {
        // The sys_enter read failed; the kernel has read the path by now.
        long n = bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (const void *)e->uptr);
        if (n > 0 && n < sizeof(e->filename))
            e->filename_incomplete = 0;
    }
    if (ret >= 0) {
        e->result = RES_SUCCESS;
    } else if (type == EV_CONNECT && (ret == -EINPROGRESS || ret == -EINTR || ret == -EALREADY)) {
        // A non-blocking or interrupted connect goes on after the call returns:
        // its outcome is not this return value.
        e->result = RES_UNKNOWN;
    } else {
        e->result = RES_FAILED;
        e->err = (__s32)-ret;
    }
    emit_copy(e);
    bpf_map_delete_elem(&pending, &key);
}

// forget_exec drops a held execve of key: this exec succeeded, and
// sched_process_exec records it (with argv and the image actually run).
static __always_inline void forget_exec(__u64 key) {
    struct event *e = bpf_map_lookup_elem(&pending, &key);
    if (e && e->type == EV_EXEC)
        bpf_map_delete_elem(&pending, &key);
}

SEC("tracepoint/sched/sched_process_exec")
int tp_exec(struct trace_event_raw_sched_process_exec *ctx) {
    if (cfg_get(CFG_RESULTS)) {
        // A non-leader thread that exec'd took the leader's id: its held
        // execve is under the id it had (old_pid).
        __u64 tgid = bpf_get_current_pid_tgid() >> 32;
        forget_exec((tgid << 32) | (__u32)ctx->old_pid);
        forget_exec(bpf_get_current_pid_tgid());
    }
    struct event *e = begin(EV_EXEC);
    if (!e)
        return 0;
    e->result = RES_SUCCESS;
    // filename sits behind the tracepoint's __data_loc (low 16 bits = offset)
    __u32 off = ctx->__data_loc_filename & 0xFFFF;
    __u32 source_len = ctx->__data_loc_filename >> 16;
    long path_read = bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + off);
    if (path_read <= 0 || source_len >= sizeof(e->filename) || path_read >= sizeof(e->filename))
        e->filename_incomplete = 1;
    // argv: mm->arg_start..arg_end — raw bytes go to userspace, which emits
    // only their SHA-256 (collection-side scrub).
    struct task_struct *task = (void *)bpf_get_current_task();
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (mm) {
        __u64 astart = BPF_CORE_READ(mm, arg_start);
        __u64 aend = BPF_CORE_READ(mm, arg_end);
        if (aend > astart) {
            __u64 size = aend - astart;
            if (size > sizeof(e->argv)) {
                e->argv_incomplete = 1;
            } else {
                e->argv_len = (__u32)size;
                if (bpf_probe_read(&e->argv, e->argv_len, (const void *)astart) < 0) {
                    e->argv_len = 0;
                    e->argv_incomplete = 1;
                }
            }
        }
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tp_connect(struct trace_event_raw_sys_enter *ctx) {
    struct sockaddr *uservaddr = (struct sockaddr *)ctx->args[1];
    __u16 fam = 0;
    bpf_probe_read(&fam, sizeof(fam), uservaddr);
    if (fam != AF_INET && fam != AF_INET6)
        return 0;
    struct held h = hold(EV_CONNECT);
    struct event *e = h.e;
    if (!e)
        return 0;
    e->family = fam;
    if (fam == AF_INET) {
        struct sockaddr_in sa4;
        bpf_probe_read(&sa4, sizeof(sa4), uservaddr);
        e->port = __builtin_bswap16(sa4.sin_port);
        __builtin_memcpy(&e->addr, &sa4.sin_addr, 4);
    } else {
        struct sockaddr_in6 sa6;
        bpf_probe_read(&sa6, sizeof(sa6), uservaddr);
        e->port = __builtin_bswap16(sa6.sin6_port);
        __builtin_memcpy(&e->addr, &sa6.sin6_addr, 16);
    }
    finish(h);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int tp_connect_exit(struct trace_event_raw_sys_exit *ctx) {
    complete(EV_CONNECT, ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx) {
    struct held h = hold(EV_OPENAT);
    struct event *e = h.e;
    if (!e)
        return 0;
    const char *fname = (const char *)ctx->args[1];
    long path_read = bpf_probe_read_str(&e->filename, sizeof(e->filename), fname);
    if (path_read <= 0 || path_read >= sizeof(e->filename))
        e->filename_incomplete = 1;
    if (h.held && path_read <= 0)
        e->uptr = (__u64)fname;
    finish(h);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tp_openat_exit(struct trace_event_raw_sys_exit *ctx) {
    complete(EV_OPENAT, ctx->ret);
    return 0;
}

// execve is held at sys_enter only to see a failed exec (spec 057 OD-13):
// a successful one is recorded by sched_process_exec, which forgets this.
// argv is not read here, so a failed exec carries no argv digest.
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve_enter(struct trace_event_raw_sys_enter *ctx) {
    if (!cfg_get(CFG_RESULTS))
        return 0;
    struct held h = hold(EV_EXEC);
    struct event *e = h.e;
    if (!e)
        return 0;
    if (!h.held) {
        // The map is full: a failed exec cannot be paired, and a successful
        // one is recorded by sched_process_exec anyway.
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    const char *fname = (const char *)ctx->args[0];
    long path_read = bpf_probe_read_user_str(&e->filename, sizeof(e->filename), fname);
    if (path_read <= 0 || path_read >= sizeof(e->filename))
        e->filename_incomplete = 1;
    if (path_read <= 0)
        e->uptr = (__u64)fname;
    e->argv_incomplete = 1;
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tp_execve_exit(struct trace_event_raw_sys_exit *ctx) {
    if (ctx->ret == 0) {
        forget_exec(bpf_get_current_pid_tgid());
        return 0;
    }
    complete(EV_EXEC, ctx->ret);
    return 0;
}

// sched_process_exit fires for every exiting thread. It emits what the
// thread still holds (result unknown) and, with process exits on, one exit
// event when the thread group's last thread exits: the status wait() reports
// (the group exit code after exit_group or a fatal signal, else the leader's).
SEC("tracepoint/sched/sched_process_exit")
int tp_proc_exit(struct trace_event_raw_sched_process_template *ctx) {
    flush_pending(bpf_get_current_pid_tgid());
    if (!cfg_get(CFG_EXIT))
        return 0;
    struct task_struct *task = (void *)bpf_get_current_task();
    if (BPF_CORE_READ(task, signal, live.counter) != 0)
        return 0; // another thread of the group still runs
    int status;
    if (BPF_CORE_READ(task, signal, flags) & SIGNAL_GROUP_EXIT)
        status = BPF_CORE_READ(task, signal, group_exit_code);
    else
        status = BPF_CORE_READ(task, group_leader, exit_code);
    struct event *e = begin(EV_EXIT);
    if (!e)
        return 0;
    if (status & 0x7f) {
        e->exit_signal = status & 0x7f;
    } else {
        e->exit_code = (status >> 8) & 0xff;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}
