// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/stat.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/types.h>

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef unsigned long ulong;
typedef __kernel_uid32_t uid_t;
typedef __kernel_gid32_t gid_t;
typedef __kernel_mode_t umode_t;
typedef __kernel_pid_t pid_t;
typedef u16 sa_family_t;

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
    const char *pathname;
    int interp_flags;
    unsigned long p;
};

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
};

struct vfsmount {
    struct dentry *mnt_root;
    struct super_block *mnt_sb;
};

struct super_block {
    unsigned long s_blocksize;
    unsigned char s_blocksize_bits;
};

struct dentry {
    const char *d_name;
    struct inode *d_inode;
    struct dentry *d_parent;
};

struct inode {
    u64 i_ino;
    umode_t i_mode;
    uid_t i_uid;
    gid_t i_gid;
    unsigned long i_size;
};

struct socket {
    struct sock *sk;
    void *file;
    short type;
};

struct sock {
    sa_family_t sk_family;
    __be32 sk_rcv_saddr;
    __be32 sk_daddr;
    __be16 sk_num;
    __be16 sk_dport;
};

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};

struct sockaddr_in {
    sa_family_t sin_family;
    __be16 sin_port;
    __be32 sin_addr;
};

struct in6_addr {
    u8 s6_addr[16];
};

struct sockaddr_in6 {
    sa_family_t sin6_family;
    __be16 sin6_port;
    __u32 sin6_flowinfo;
    struct in6_addr sin6_addr;
    __u32 sin6_scope_id;
};

#define MAX_PATH_LEN 256
#define TASK_COMM_LEN 16
#define MAX_BLOCKED_PIDS 1024
#define MAX_BLOCKING_RULES 1024

#define ACTION_ALLOW 0
#define ACTION_BLOCK 1
#define ACTION_KILL 2

struct blocking_key {
    u64 entity_type;
    u64 entity_value;
} __attribute__((packed));

struct blocking_rule {
    u64 entity_key;
    u64 action;
    u64 ttl_ns;
    u64 timestamp_ns;
    u64 rule_id;
} __attribute__((packed));

struct enforcement_event {
    u64 ts_mono_ns;
    u32 pid;
    u32 hook_type;
    u32 action;
    u32 result;
    u64 entity_key;
    char details[128];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct blocking_key);
    __type(value, struct blocking_rule);
    __uint(max_entries, MAX_BLOCKING_RULES);
} blocking_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, MAX_BLOCKED_PIDS);
} pid_blocking_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} enforcement_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 1024);
} path_blocking_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 1024);
} network_blocking_map SEC(".maps");

static __always_inline u64 get_mono_time(void)
{
    return bpf_ktime_get_ns();
}

static __always_inline u32 get_current_pid(void)
{
    return bpf_get_current_pid_tgid() >> 32;
}

static __always_inline u64 get_task_start_time(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 start_time = 0;
    bpf_probe_read_kernel(&start_time, sizeof(start_time), &task->start_time);
    return start_time;
}

static __always_inline u64 generate_entity_key(u32 pid, u64 extra)
{
    u64 start_time = get_task_start_time();
    return ((u64)pid << 32) ^ (start_time >> 32) ^ extra;
}

static __always_inline int check_blocking_rules(u64 entity_key)
{
    struct blocking_rule *rule = bpf_map_lookup_elem(&blocking_rules, &entity_key);
    if (!rule)
        return ACTION_ALLOW;

    if (rule->ttl_ns > 0) {
        u64 now = get_mono_time();
        if ((now - rule->timestamp_ns) > rule->ttl_ns) {
            bpf_map_delete_elem(&blocking_rules, &entity_key);
            return ACTION_ALLOW;
        }
    }
    return (int)rule->action;
}

static __always_inline int check_pid_blocked(u32 pid)
{
    u64 *value = bpf_map_lookup_elem(&pid_blocking_map, &pid);
    return (value && *value == 1) ? ACTION_BLOCK : ACTION_ALLOW;
}

static __always_inline int check_path_blocked(u64 path_hash)
{
    u64 *value = bpf_map_lookup_elem(&path_blocking_map, &path_hash);
    return (value && *value == 1) ? ACTION_BLOCK : ACTION_ALLOW;
}

static __always_inline int check_network_blocked(u64 addr_hash)
{
    u64 *value = bpf_map_lookup_elem(&network_blocking_map, &addr_hash);
    return (value && *value == 1) ? ACTION_BLOCK : ACTION_ALLOW;
}

static __always_inline void send_enforcement_event(
    u32 pid, u32 hook_type, u32 action, u32 result, u64 entity_key, const char *details)
{
    struct enforcement_event *event = bpf_ringbuf_reserve(&enforcement_events, sizeof(*event), 0);
    if (!event)
        return;

    event->ts_mono_ns = get_mono_time();
    event->pid = pid;
    event->hook_type = hook_type;
    event->action = action;
    event->result = result;
    event->entity_key = entity_key;
    __builtin_memset(event->details, 0, sizeof(event->details));
    if (details)
        __builtin_memcpy(event->details, details, 127);

    bpf_ringbuf_submit(event, 0);
}

#define HOOK_BPRM_CHECK_SECURITY 1
#define HOOK_FILE_OPEN 2
#define HOOK_INODE_PERMISSION 3
#define HOOK_SOCKET_CONNECT 4
#define HOOK_MMAP_FILE 5

SEC("lsm/bprm_check_security")
int lsm_bprm_check_security(struct linux_binprm *bprm)
{
    u32 pid = get_current_pid();
    u64 entity_key = generate_entity_key(pid, 0);
    int action;
    const char *filename = NULL;

    bpf_probe_read_kernel(&filename, sizeof(filename), &bprm->filename);
    action = check_blocking_rules(entity_key);
    if (action == ACTION_ALLOW)
        action = check_pid_blocked(pid);

    if (action == ACTION_BLOCK) {
        bpf_printk("Kestrel: Blocking exec for PID %d\n", pid);
        send_enforcement_event(pid, HOOK_BPRM_CHECK_SECURITY, ACTION_BLOCK, -EPERM, entity_key, filename);
        return -EPERM;
    }
    if (action == ACTION_KILL) {
        bpf_printk("Kestrel: Kill signal for PID %d\n", pid);
        send_enforcement_event(pid, HOOK_BPRM_CHECK_SECURITY, ACTION_KILL, -EPERM, entity_key, filename);
        return -EPERM;
    }
    send_enforcement_event(pid, HOOK_BPRM_CHECK_SECURITY, ACTION_ALLOW, 0, entity_key, filename);
    return 0;
}

SEC("lsm/file_open")
int lsm_file_open(const void *file)
{
    u32 pid = get_current_pid();
    u64 entity_key = generate_entity_key(pid, 0);
    int action;

    bpf_printk("Kestrel: file_open called for PID %d\n", pid);
    action = check_blocking_rules(entity_key);
    if (action == ACTION_ALLOW)
        action = check_pid_blocked(pid);

    if (action == ACTION_BLOCK) {
        bpf_printk("Kestrel: Blocking file open for PID %d\n", pid);
        send_enforcement_event(pid, HOOK_FILE_OPEN, ACTION_BLOCK, -EPERM, entity_key, NULL);
        return -EPERM;
    }
    send_enforcement_event(pid, HOOK_FILE_OPEN, ACTION_ALLOW, 0, entity_key, NULL);
    return 0;
}

SEC("lsm/inode_permission")
int lsm_inode_permission(struct inode *inode, int mask)
{
    u32 pid = get_current_pid();
    u64 entity_key = generate_entity_key(pid, 0);
    int action;

    action = check_blocking_rules(entity_key);
    if (action == ACTION_ALLOW)
        action = check_pid_blocked(pid);

    if (action == ACTION_BLOCK) {
        bpf_printk("Kestrel: Blocking inode permission for PID %d\n", pid);
        send_enforcement_event(pid, HOOK_INODE_PERMISSION, ACTION_BLOCK, -EACCES, entity_key, NULL);
        return -EACCES;
    }
    return 0;
}

SEC("lsm/socket_connect")
int lsm_socket_connect(struct socket *sock, struct sockaddr *addr, int addr_len)
{
    u32 pid = get_current_pid();
    u64 entity_key = generate_entity_key(pid, 0);
    int action;
    u64 addr_hash = 0;
    sa_family_t family = 0;

    if (addr && addr_len >= 2)
        bpf_probe_read_kernel(&family, sizeof(family), &addr->sa_family);

    if (family == 2 && addr_len >= 8) {
        struct sockaddr_in addr_in;
        bpf_probe_read_kernel(&addr_in, sizeof(addr_in), addr);
        int i;
        for (i = 0; i < 4 && i < addr_len - 4; i++) {
            u8 byte = ((u8 *)&addr_in.sin_addr)[i];
            addr_hash = addr_hash * 31 + byte;
        }
        addr_hash = (addr_hash << 16) ^ (u64)addr_in.sin_port;
    } else if (family == 10 && addr_len >= 24) {
        struct sockaddr_in6 addr_in6;
        bpf_probe_read_kernel(&addr_in6, sizeof(addr_in6), addr);
        int i;
        for (i = 0; i < 16 && i < addr_len - 8; i++) {
            addr_hash = addr_hash * 31 + addr_in6.sin6_addr.s6_addr[i];
        }
        addr_hash = (addr_hash << 16) ^ (u64)addr_in6.sin6_port;
    }

    entity_key = generate_entity_key(pid, addr_hash);
    action = check_blocking_rules(entity_key);
    if (action == ACTION_ALLOW)
        action = check_pid_blocked(pid);
    if (action == ACTION_ALLOW)
        action = check_network_blocked(addr_hash);

    if (action == ACTION_BLOCK) {
        bpf_printk("Kestrel: Blocking socket connect for PID %d\n", pid);
        send_enforcement_event(pid, HOOK_SOCKET_CONNECT, ACTION_BLOCK, -ECONNREFUSED, entity_key, NULL);
        return -ECONNREFUSED;
    }
    send_enforcement_event(pid, HOOK_SOCKET_CONNECT, ACTION_ALLOW, 0, entity_key, NULL);
    return 0;
}

SEC("lsm/mmap_file")
int lsm_mmap_file(void *file, unsigned long reqprot)
{
    u32 pid = get_current_pid();
    u64 entity_key = generate_entity_key(pid, 0);
    int action;

    if (!(reqprot & 0x4))
        return 0;

    action = check_blocking_rules(entity_key);
    if (action == ACTION_ALLOW)
        action = check_pid_blocked(pid);

    if (action == ACTION_BLOCK) {
        bpf_printk("Kestrel: Blocking mmap with exec for PID %d\n", pid);
        send_enforcement_event(pid, HOOK_MMAP_FILE, ACTION_BLOCK, -EPERM, entity_key, NULL);
        return -EPERM;
    }
    send_enforcement_event(pid, HOOK_MMAP_FILE, ACTION_ALLOW, 0, entity_key, NULL);
    return 0;
}

SEC("lsm/inode_unlink")
int lsm_inode_unlink(void *dir, void *victim)
{
    u32 pid = get_current_pid();
    u64 entity_key = generate_entity_key(pid, 0);
    int action = check_blocking_rules(entity_key);

    if (action == ACTION_ALLOW)
        action = check_pid_blocked(pid);

    if (action == ACTION_BLOCK) {
        bpf_printk("Kestrel: Blocking inode unlink for PID %d\n", pid);
        send_enforcement_event(pid, 7, ACTION_BLOCK, -EPERM, entity_key, NULL);
        return -EPERM;
    }
    return 0;
}

SEC("lsm/bpf")
int lsm_bpf(int cmd, void *attr)
{
    u32 pid = get_current_pid();
    u64 entity_key = generate_entity_key(pid, (u64)cmd);
    int action = check_blocking_rules(entity_key);

    if (action == ACTION_ALLOW)
        action = check_pid_blocked(pid);

    if (action == ACTION_BLOCK) {
        bpf_printk("Kestrel: Blocking bpf syscall %d for PID %d\n", cmd, pid);
        send_enforcement_event(pid, 10, ACTION_BLOCK, -EPERM, entity_key, NULL);
        return -EPERM;
    }
    return 0;
}

SEC("lsm/perf_event_open")
int lsm_perf_event_open(void *attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
    u32 current_pid = get_current_pid();
    u64 entity_key = generate_entity_key(current_pid, (u64)pid);
    int action = check_blocking_rules(entity_key);

    if (action == ACTION_ALLOW)
        action = check_pid_blocked(current_pid);

    if (action == ACTION_BLOCK) {
        bpf_printk("Kestrel: Blocking perf_event_open for PID %d\n", current_pid);
        send_enforcement_event(current_pid, 11, ACTION_BLOCK, -EPERM, entity_key, NULL);
        return -EPERM;
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
