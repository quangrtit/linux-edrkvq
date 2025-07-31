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

typedef char file_policy_key_t[MAX_PATH_LEN];

struct file_policy_value {
    char path[128];
    __u8 block_read;
    __u8 block_write;
    __u8 block_truncate_create;
    __u8 block_unlink;
    __u8 block_rename;
    __u8 block_chmod;
    __u8 block_symlink_create;
    __u8 block_hardlink_create;
};

#endif // __COMMON_KERN_H
