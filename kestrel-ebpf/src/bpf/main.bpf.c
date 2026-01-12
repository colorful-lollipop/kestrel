// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Kestrel eBPF Event Collection and Enforcement
 *
 * This eBPF program captures system events and provides enforcement hooks.
 * Features:
 * - Event collection via tracepoints
 * - LSM hooks for real-time blocking
 *
 * Uses Aya framework for cross-kernel compatibility (CO-RE).
 */

#ifndef __KERNEL__
#define __KERNEL__
#endif

#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/types.h>

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

struct linux_binprm {
    const char *filename;
    int interp_flags;
};

struct file {
    const char *f_path;
};

struct inode {
    u64 i_ino;
};

struct trace_event_raw_sys_enter {
    short unsigned int type;
    unsigned char flags;
    short unsigned int preempt_count;
    int pid;
    unsigned long id;
    long args[6];
};

struct sockaddr {
    __u16 sa_family;
    char sa_data[14];
};
#endif

#define MAX_PATH_LEN 256
#define MAX_ARGS_LEN 512
#define TASK_COMM_LEN 16
#define MAX_BLOCKED_PIDS 1024

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

/* Enforcement decision from userspace */
struct enforcement_decision {
    u32 pid;             /* Target PID */
    u32 action;          /* 0=allow, 1=block, 2=kill */
    u64 ttl_ns;          /* Time-to-live for this decision */
    u64 timestamp_ns;    /* When this decision was made */
} __attribute__((packed));

/* Ring buffer for sending events to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} rb SEC(".maps");

/* Hash map for enforcement decisions (userspace -> kernel) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BLOCKED_PIDS);
    __type(key, u32);
    __type(value, struct enforcement_decision);
} enforcement_map SEC(".maps");

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

    /* Read start_time */
    __builtin_memset(&start_time, 0, sizeof(start_time));
    bpf_probe_read_kernel(&start_time, sizeof(start_time), &task->start_time);

    pid = bpf_get_current_pid_tgid() >> 32;

    /* Combine pid and start_time for uniqueness */
    return pid ^ (u32)(start_time >> 32);
}

/* Check if action should be enforced for current PID */
static __always_inline int check_enforcement(u32 pid)
{
    struct enforcement_decision *decision;
    u64 now = get_mono_time();

    decision = bpf_map_lookup_elem(&enforcement_map, &pid);
    if (!decision)
        return 0; /* No decision = allow */

    /* Check if decision expired */
    if (decision->ttl_ns > 0 && (now - decision->timestamp_ns) > decision->ttl_ns) {
        bpf_map_delete_elem(&enforcement_map, &pid);
        return 0; /* Expired = allow */
    }

    return decision->action; /* 0=allow, 1=block, 2=kill */
}

/* ============================================================================
 * LSM HOOKS - Real-time Enforcement Points
 * ============================================================================ */

/* LSM hook: bprm_check_security - Called before process execution
 * Return 0 to allow, negative to deny
 */
SEC("lsm/bprm_check_security")
int lsm_bprm_check_security(struct bpf_lsm_ctx *ctx)
{
    struct linux_binprm *bprm = (struct linux_binprm *)ctx;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int action = check_enforcement(pid);

    if (action == 1) {
        /* Block this execution */
        bpf_printk("Kestrel: Blocking exec of PID %d\n", pid);
        return -EPERM;
    }

    return 0; /* Allow */
}

/* LSM hook: file_open - Called before file open
 * Return 0 to allow, negative to deny
 */
SEC("lsm/file_open")
int lsm_file_open(struct bpf_lsm_ctx *ctx, struct file *file)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int action = check_enforcement(pid);

    if (action == 1) {
        /* Block file operations for this PID */
        bpf_printk("Kestrel: Blocking file open for PID %d\n", pid);
        return -EPERM;
    }

    return 0; /* Allow */
}

/* LSM hook: inode_permission - Called before file permission check
 * Return 0 to allow, negative to deny
 */
SEC("lsm/inode_permission")
int lsm_inode_permission(struct bpf_lsm_ctx *ctx, struct inode *inode, int mask)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int action = check_enforcement(pid);

    if (action == 1) {
        /* Block file access for this PID */
        bpf_printk("Kestrel: Blocking inode permission for PID %d\n", pid);
        return -EPERM;
    }

    return 0; /* Allow */
}

/* LSM hook: socket_connect - Called before socket connection
 * Return 0 to allow, negative to deny
 */
SEC("lsm/socket_connect")
int lsm_socket_connect(struct bpf_lsm_ctx *ctx, struct sockaddr *addr, int addr_len)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int action = check_enforcement(pid);

    if (action == 1) {
        /* Block network connections for this PID */
        bpf_printk("Kestrel: Blocking socket connect for PID %d\n", pid);
        return -EPERM;
    }

    return 0; /* Allow */
}

/* ============================================================================
 * TRACEPOINTS - Event Collection
 * ============================================================================ */

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
