// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Kestrel eBPF Event Collection
 *
 * This eBPF program captures system events for security detection.
 * Initial focus: process execution events (execve)
 *
 * Uses Aya framework for cross-kernel compatibility (CO-RE).
 */

#ifndef __KERNEL__
#define __KERNEL__
#endif

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Basic type definitions */
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;

#ifndef __VMLINUX_H__
/* Minimal type definitions if vmlinux.h is not available */
struct task_struct {
    int __state;
    unsigned int flags;
    int prio;
    /* ... minimal fields needed ... */
    int pid;
    int tgid;
    struct task_struct *real_parent;
    struct cred *real_cred;
    u64 start_time;
    char comm[16];
};

struct cred {
    uid_t uid;
    gid_t gid;
};

struct trace_event_raw_sys_enter {
    short unsigned int type;
    unsigned char flags;
    short unsigned int preempt_count;
    int pid;
    unsigned long id;
    long args[6];
};
#endif

#define MAX_PATH_LEN 256
#define MAX_ARGS_LEN 512
#define TASK_COMM_LEN 16

/* Event structure shared with userspace */
struct execve_event {
    u64 ts_mono_ns;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u32 entity_key;
    char comm[TASK_COMM_LEN];
    char pathname[MAX_PATH_LEN];
    char args[MAX_ARGS_LEN];
} __attribute__((packed));

/* Ring buffer for sending events to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} rb SEC(".maps");

/* Get monotonic timestamp */
static __always_inline u64 get_mono_time(void)
{
    return bpf_ktime_get_ns();
}

/* Generate entity key for process correlation */
static __always_inline u32 get_entity_key(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 start_time;
    u32 pid;

    /* Read start_time - may need BPF_CORE_READ with CO-RE */
    __builtin_memset(&start_time, 0, sizeof(start_time));
    bpf_probe_read_kernel(&start_time, sizeof(start_time), &task->start_time);

    pid = bpf_get_current_pid_tgid() >> 32;

    /* Combine pid and start_time for uniqueness */
    return pid ^ (u32)(start_time >> 32);
}

/* Tracepoint for sys_enter_execve */
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(void *ctx)
{
    struct task_struct *task;
    struct execve_event *e;
    const char *filename_ptr;
    const char **args_p;
    u32 pid;
    int i, args_len;
    const char *arg;

    /* Get current task */
    task = (struct task_struct *)bpf_get_current_task();

    /* Reserve space in ring buffer */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;  /* Buffer full, skip */

    /* Get timestamp */
    e->ts_mono_ns = get_mono_time();

    /* Read process information */
    pid = bpf_get_current_pid_tgid() >> 32;
    e->pid = pid;

    /* Read parent PID */
    bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid), &task->real_parent->tgid);

    /* Read user/group IDs */
    bpf_probe_read_kernel(&e->uid, sizeof(e->uid), &task->real_cred->uid);
    bpf_probe_read_kernel(&e->gid, sizeof(e->gid), &task->real_cred->gid);

    /* Generate entity key */
    e->entity_key = get_entity_key();

    /* Read process name (comm) */
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    /* Read executable pathname */
    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr), &((void **)ctx)[0]);
    bpf_probe_read_user_str(e->pathname, sizeof(e->pathname), filename_ptr);

    /* Read command line arguments */
    args_p = (const char **)((void **)ctx + 1);
    args_len = 0;

    for (i = 0; i < 32; i++) {
        bpf_probe_read_kernel(&arg, sizeof(arg), &args_p[i]);
        if (!arg)
            break;

        if (args_len >= MAX_ARGS_LEN - 1)
            break;

        long len = bpf_probe_read_user_str(&e->args[args_len],
                                            MAX_ARGS_LEN - args_len,
                                            arg);
        if (len <= 0)
            break;

        args_len += len;
    }

    /* Submit event to ring buffer */
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
