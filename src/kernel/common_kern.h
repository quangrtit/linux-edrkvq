#ifndef __COMMON_KERN_H
#define __COMMON_KERN_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>      // eBPF helper macro
#include <bpf/bpf_tracing.h>      

#define LOG_MSG_MAX_LEN 128
#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 128
#define MAX_POLICY_ENTRIES 64
#define NAME_MAX 255
#define EPERM 1


#define MAY_EXEC    0x00000001  
#define MAY_WRITE   0x00000002  
#define MAY_READ    0x00000004  
#define MAY_APPEND  0x00000008  
#define MAY_ACCESS  0x00000010  
#define ENOENT       2    // No such file or directory
#define EACCES      13    // Permission denied
#define O_TRUNC 0x00000200
#define ATTR_MODE (1 << 1)
#define ATTR_UID  (1 << 2)

#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define PROT_EXEC   0x4
#define PROT_SEM    0x8
#define PROT_NONE   0x0

#define MAP_ANONYMOUS 0x20
#define MAP_PRIVATE   0x02
#define MAP_SHARED    0x01
#define S_ISLNK(m) (((m) & 0170000) == 0120000)

#define EPERM 1
#define AF_INET 2
#define ECONNREFUSED 111

enum log_level {
    INFO,
    WARNING,
    ERROR,
    BLOCKED_ACTION
};

struct log_debug {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u32 level; // Corresponds to enum log_level
    char comm[TASK_COMM_LEN];
    char msg[LOG_MSG_MAX_LEN];
};

// typedef char file_policy_key_t[MAX_PATH_LEN];
typedef __u64 file_policy_key_t;
struct file_policy_value {
    char path[MAX_PATH_LEN];
    __s64 inode;
    __s64 inode_symlink;
    __u8 block_read;
    __u8 block_write;
    __u8 block_truncate_create;
    __u8 block_unlink;
    __u8 block_rename;
    __u8 block_move;
    __u8 block_chmod;
    __u8 block_symlink_create;
    __u8 block_hardlink_create;
};

typedef __u32 process_policy_key_t;
struct process_policy_value {
    __u32 pid; 
    char path[MAX_PATH_LEN];
    __u64 inode;
    __u8 block_termination;
    __u8 block_injection;
    __u8 block_prlimit;
    __u8 block_setnice;
    __u8 block_setioprio;
};

// ===================== MAP DEFINITIONS =====================
// self-defense
// map debug event 
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} debug_events SEC(".maps");

// map whilelist pid
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, __u32);   // PID
    __type(value, __u8);  // flag = 1
} whitelist_pid_map SEC(".maps");

// map file protection
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(file_policy_key_t));
    __uint(value_size, sizeof(struct file_policy_value));
    __uint(max_entries, MAX_POLICY_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} file_protection_policy SEC(".maps");

// map process protection
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(process_policy_key_t));
    __uint(value_size, sizeof(struct process_policy_value));
    __uint(max_entries, MAX_POLICY_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} process_protection_policy SEC(".maps");

static __always_inline void send_debug_log(__u32 level, const char *msg) {
    struct log_debug *log_entry;
    log_entry = bpf_ringbuf_reserve(&debug_events, sizeof(*log_entry), 0);
    if (!log_entry) {
        return;
    }
    log_entry->timestamp_ns = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    log_entry->pid = pid_tgid >> 32;
    __u64 uid_gid = bpf_get_current_uid_gid();
    log_entry->uid = uid_gid & 0xFFFFFFFF;
    log_entry->level = level;
    bpf_get_current_comm(&log_entry->comm, sizeof(log_entry->comm));
    bpf_probe_read_kernel_str(&log_entry->msg, sizeof(log_entry->msg), msg);

    bpf_ringbuf_submit(log_entry, 0);
}

// ioc_block
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // IPv4 in network byte order
    __type(value, __u8);   // flag (1 = blocked)
} blocked_ips SEC(".maps");


#endif // __COMMON_KERN_H
