// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// emit.bpf.c — passive host-observation tracepoints for the Fabric host
// emitter (spec 031). Read-only by construction: no LSM hooks, no packet
// interception, no enforcement. Events flow over a ringbuf to userspace,
// which translates them to the shared event_class=audit schema (local mode)
// or to host records (production mode, spec 053 §6.2.9, spec 056 §7.3.3 (c))
// and OTLP-exports them to the Fabric Node.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EV_EXEC 1
#define EV_CONNECT 2
#define EV_OPENAT 3

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
    __u32 reserved;
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
// EMIT_ALL_HOST, else SCOPE_NONE (not emitted).
#define CFG_LOCAL_CGROUP 0
#define CFG_MODE 1
#define CFG_DEFAULT_SCOPE 2
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
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

// begin reserves and fills the common part of an event, or returns NULL when
// the event is out of scope or the ring buffer is full.
static __always_inline struct event *begin(__u32 type) {
    __u64 cg = bpf_get_current_cgroup_id();
    __u32 scope;
    if (!admit(cg, &scope))
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        note_ring_loss();
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    struct task_struct *task = (void *)bpf_get_current_task();
    e->type = type;
    e->cgroup_id = cg;
    e->scope = scope;
    e->ts_ns = bpf_ktime_get_ns();
    fill_task(e, task);
    if (scope == SCOPE_SANDBOX)
        fill_names(e, task);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return e;
}

SEC("tracepoint/sched/sched_process_exec")
int tp_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct event *e = begin(EV_EXEC);
    if (!e)
        return 0;
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
    struct event *e = begin(EV_CONNECT);
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
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = begin(EV_OPENAT);
    if (!e)
        return 0;
    const char *fname = (const char *)ctx->args[1];
    long path_read = bpf_probe_read_str(&e->filename, sizeof(e->filename), fname);
    if (path_read <= 0 || path_read >= sizeof(e->filename))
        e->filename_incomplete = 1;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
