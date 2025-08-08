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
    __u8 block_read;
    __u8 block_write;
    __u8 block_truncate_create;
    __u8 block_unlink;
    __u8 block_rename;
    __u8 block_move;
    __u8 block_chmod;
    __u8 block_symlink_create;
    __u8 block_hardlink_create;
    __u8 block_dpexe;
};

typedef __u32 process_policy_key_t;
struct process_policy_value {
    __u32 pid; 
    char path[MAX_PATH_LEN];
    __u64 inode;
    __u8 block_termination;
    __u8 block_injection;
};
#endif // __COMMON_KERN_H
