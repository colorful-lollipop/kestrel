/* Minimal vmlinux.h for Aya eBPF programs
 * This provides the necessary kernel type definitions
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#include <types.h>

/* Task structure definitions */
struct task_struct {
    int pid;
    int tgid;
    struct task_struct *real_parent;
    struct cred *real_cred;
    u64 start_time;
    char comm[16];
};

/* Cred structure */
struct cred {
    uid_t uid;
    gid_t gid;
};

/* Tracepoint structure for sys_enter_execve */
struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    unsigned long id;
    long args[6];
};

struct trace_entry {
    short unsigned int type;
    unsigned char flags;
    short unsigned int preempt_count;
    int pid;
};

/* Basic types */
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8 s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

#endif /* __VMLINUX_H__ */
