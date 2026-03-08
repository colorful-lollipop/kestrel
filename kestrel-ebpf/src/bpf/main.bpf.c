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
typedef __u16 sa_family_t;

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

struct inode {
    u64 i_ino;
};

struct qstr {
    union {
        struct {
            u32 hash;
            u32 len;
        };
        u64 hash_len;
    };
    const unsigned char *name;
};

struct dentry {
    struct qstr d_name;
    struct inode *d_inode;
    struct dentry *d_parent;
};

struct path {
    void *mnt;
    struct dentry *dentry;
};

struct file {
    struct path f_path;
};

struct trace_event_raw_sys_enter {
    short unsigned int type;
    unsigned char flags;
    short unsigned int preempt_count;
    int pid;
    unsigned long id;
    long args[6];
};

struct bpf_lsm_ctx;

struct sockaddr {
    __u16 sa_family;
    char sa_data[14];
};

struct sockaddr_in {
    sa_family_t sin_family;
    __u16 sin_port;
    __u32 sin_addr;
};

struct in6_addr {
    __u8 s6_addr[16];
};

struct sockaddr_in6 {
    sa_family_t sin6_family;
    __u16 sin6_port;
    __u32 sin6_flowinfo;
    struct in6_addr sin6_addr;
    __u32 sin6_scope_id;
};

#endif

#define MAX_PATH_LEN 256
#define MAX_ARGS_LEN 512
#define TASK_COMM_LEN 16
#define MAX_BLOCKED_PIDS 1024

#define EVENT_PROCESS 1
#define EVENT_FILE 3
#define EVENT_NETWORK 6

#define PROCESS_OP_EXEC 1
#define PROCESS_OP_EXIT 2
#define FILE_OP_OPEN 1
#define NETWORK_OP_CONNECT 1

/* Event structure shared with userspace */
struct live_event {
    u32 event_type;
    u32 event_size;
    u64 ts_mono_ns;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u32 entity_key;
    u32 subtype;
    u32 aux_u32_1;
    u32 aux_u32_2;
    u64 aux_u64_1;
    char comm[TASK_COMM_LEN];
    char primary[MAX_PATH_LEN];
    char secondary[MAX_PATH_LEN];
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
static __always_inline void fill_common_event(struct live_event *e)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->ts_mono_ns = get_mono_time();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid), &task->real_parent->tgid);
    bpf_probe_read_kernel(&e->uid, sizeof(e->uid), &task->real_cred->uid);
    bpf_probe_read_kernel(&e->gid, sizeof(e->gid), &task->real_cred->gid);
    e->entity_key = get_entity_key();
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    __builtin_memset(e->primary, 0, sizeof(e->primary));
    __builtin_memset(e->secondary, 0, sizeof(e->secondary));
    e->aux_u32_1 = 0;
    e->aux_u32_2 = 0;
    e->aux_u64_1 = 0;
}

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
    (void)ctx;
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
    struct live_event *e;
    struct dentry *dentry = 0;
    struct dentry *parent = 0;
    struct inode *inode = 0;
    const unsigned char *name_ptr = 0;
    const unsigned char *parent_name_ptr = 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        __builtin_memset(e, 0, sizeof(*e));
        e->event_type = EVENT_FILE;
        e->event_size = sizeof(*e);
        e->subtype = FILE_OP_OPEN;
        fill_common_event(e);

        if (file) {
            bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry);
            if (dentry) {
                bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), &dentry->d_name.name);
                if (name_ptr)
                    bpf_probe_read_kernel_str(e->primary, sizeof(e->primary), name_ptr);

                bpf_probe_read_kernel(&parent, sizeof(parent), &dentry->d_parent);
                if (parent) {
                    bpf_probe_read_kernel(&parent_name_ptr, sizeof(parent_name_ptr), &parent->d_name.name);
                    if (parent_name_ptr)
                        bpf_probe_read_kernel_str(e->secondary, sizeof(e->secondary), parent_name_ptr);
                }

                bpf_probe_read_kernel(&inode, sizeof(inode), &dentry->d_inode);
                if (inode)
                    bpf_probe_read_kernel(&e->aux_u64_1, sizeof(e->aux_u64_1), &inode->i_ino);
            }
        }

        bpf_ringbuf_submit(e, 0);
    }

    if (action == 1) {
        bpf_printk("Kestrel: Blocking file open for PID %d\n", pid);
        return -EPERM;
    }

    return 0;
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
    sa_family_t family = 0;
    struct live_event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        __builtin_memset(e, 0, sizeof(*e));
        e->event_type = EVENT_NETWORK;
        e->event_size = sizeof(*e);
        e->subtype = NETWORK_OP_CONNECT;
        fill_common_event(e);

        if (addr) {
            bpf_probe_read_kernel(&family, sizeof(family), &addr->sa_family);
            e->aux_u32_1 = (u32)family << 16;

            if (family == 2 && addr_len >= sizeof(struct sockaddr_in)) {
                struct sockaddr_in addr_in = {};
                bpf_probe_read_kernel(&addr_in, sizeof(addr_in), addr);
                e->aux_u32_1 = ((u32)family << 16) | ((__u16)__builtin_bswap16(addr_in.sin_port));
                e->aux_u32_2 = addr_in.sin_addr;
            }
        }

        bpf_ringbuf_submit(e, 0);
    }

    if (action == 1) {
        bpf_printk("Kestrel: Blocking socket connect for PID %d\n", pid);
        return -EPERM;
    }

    return 0;
}

/* ============================================================================
 * TRACEPOINTS - Event Collection
 * ============================================================================ */

/* Tracepoint for sys_enter_execve */
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(void *ctx)
{
    struct live_event *e;
    const char *filename_ptr;
    const char **args_p;
    int i, args_len;
    const char *arg;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->event_type = EVENT_PROCESS;
    e->event_size = sizeof(*e);
    e->subtype = PROCESS_OP_EXEC;
    fill_common_event(e);

    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr), &((void **)ctx)[0]);
    bpf_probe_read_user_str(e->primary, sizeof(e->primary), filename_ptr);

    args_p = (const char **)((void **)ctx + 1);
    args_len = 0;

    for (i = 0; i < 32; i++) {
        bpf_probe_read_kernel(&arg, sizeof(arg), &args_p[i]);
        if (!arg)
            break;
        if (args_len >= MAX_PATH_LEN - 1)
            break;

        long len = bpf_probe_read_user_str(&e->secondary[args_len],
                                            MAX_PATH_LEN - args_len,
                                            arg);
        if (len <= 0)
            break;
        args_len += len;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
