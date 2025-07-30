#ifndef __COMMON_USER_H
#define __COMMON_USER_H

#include <stdbool.h>
#include <stdint.h>   // cho uint32_t, uint64_t
#include <linux/types.h>  // hoặc <sys/types.h> nếu dùng kiểu __u32, __u64
#define LOG_MSG_MAX_LEN 128
#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256
#define MAX_POLICY_ENTRIES 256
#define NAME_MAX 255
#define EPERM     1

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

typedef char file_policy_key_t[MAX_PATH_LEN];

struct file_policy_value {
    char* path;
    bool block_read;
    bool block_write;
    bool block_truncate_create;
    bool block_unlink;
    bool block_rename;
    bool block_chmod;
    bool block_symlink_create;
    bool block_hardlink_create;
};

#endif // __COMMON_USER_H
