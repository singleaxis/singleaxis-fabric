// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// emit.bpf.c — passive host-observation tracepoints for the Fabric host
// emitter (spec 031). Read-only by construction: no LSM hooks, no packet
// interception, no enforcement. Events flow over a ringbuf to userspace,
// which translates them to the shared event_class=audit schema and
// OTLP-exports them to the Fabric Node.

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

struct event {
    __u64 cgroup_id;
    __u64 ts_ns;
    __u32 pid;
    __u32 ppid;
    __u32 type;
    __u32 family;
    __u32 port;
    __u8  addr[16];
    __u32 argv_len;
    __u32 argv_incomplete;
    __u32 filename_incomplete;
    char  comm[16];
    char  filename[240];
    __u8  argv[384];
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

// cfg[0] = target cgroup id; 0 means unfiltered (all_host opt-in).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} cfg SEC(".maps");

static __always_inline int want(__u64 cg) {
    __u32 k = 0;
    __u64 *t = bpf_map_lookup_elem(&cfg, &k);
    return !t || *t == 0 || *t == cg;
}

static __always_inline __u32 task_ppid(void) {
    struct task_struct *task = (void *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    return BPF_CORE_READ(parent, tgid);
}

SEC("tracepoint/sched/sched_process_exec")
int tp_exec(struct trace_event_raw_sched_process_exec *ctx) {
    __u64 cg = bpf_get_current_cgroup_id();
    if (!want(cg))
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        note_ring_loss();
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->type = EV_EXEC;
    e->cgroup_id = cg;
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = task_ppid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
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
    __u64 cg = bpf_get_current_cgroup_id();
    if (!want(cg))
        return 0;
    struct sockaddr *uservaddr = (struct sockaddr *)ctx->args[1];
    __u16 fam = 0;
    bpf_probe_read(&fam, sizeof(fam), uservaddr);
    if (fam != AF_INET && fam != AF_INET6)
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        note_ring_loss();
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->type = EV_CONNECT;
    e->cgroup_id = cg;
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = task_ppid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
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
    __u64 cg = bpf_get_current_cgroup_id();
    if (!want(cg))
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        note_ring_loss();
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->type = EV_OPENAT;
    e->cgroup_id = cg;
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = task_ppid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    const char *fname = (const char *)ctx->args[1];
    long path_read = bpf_probe_read_str(&e->filename, sizeof(e->filename), fname);
    if (path_read <= 0 || path_read >= sizeof(e->filename))
        e->filename_incomplete = 1;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
