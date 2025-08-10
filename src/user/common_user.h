#ifndef __COMMON_USER_H
#define __COMMON_USER_H

#include <stdbool.h>
#include <stdint.h>  
#include <linux/types.h> 
#define LOG_MSG_MAX_LEN 128
#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 128
#define MAX_POLICY_ENTRIES 64
#define NAME_MAX 255
#define EPERM     1
#define __u64 long long unsigned int
#define LOCK_PATH "/var/run/sentinel.lock"
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
    __u32 level;
    char comm[TASK_COMM_LEN];
    char msg[LOG_MSG_MAX_LEN];
};

// typedef char file_policy_key_t[MAX_PATH_LEN];

typedef long long unsigned int file_policy_key_t;
struct file_policy_value {
    char path[MAX_PATH_LEN];
    bool block_read;
    bool block_write;
    bool block_truncate_create;
    bool block_unlink;
    bool block_rename;
    bool block_move;
    bool block_chmod;
    bool block_symlink_create;
    bool block_hardlink_create;
};

typedef __u32 process_policy_key_t;
struct process_policy_value {
    __u32 pid; 
    char path[MAX_PATH_LEN];
    __u64 inode;
    __u8 block_termination;
    __u8 block_injection;
};
#endif // __COMMON_USER_H
