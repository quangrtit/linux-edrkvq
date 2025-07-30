#ifndef __COMMON_H
#define __COMMON_H
#include <linux/errno.h>    
#include <linux/limits.h>   
#include <stdint.h>    
#include <stdbool.h>    
#include <linux/types.h>
#define LOG_MSG_MAX_LEN 128
#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256
#define MAX_POLICY_ENTRIES 256
// Debug log
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

// Files protection 
typedef char file_policy_key_t[MAX_PATH_LEN]; 
struct file_policy_value {
    char* path;
    bool block_read;                 // open/read
    bool block_write;                // open with write + write()
    bool block_truncate_create;      // open with O_TRUNC | O_CREAT (overwrite)
    bool block_unlink;               // unlink/delete
    bool block_rename;               // rename
    bool block_chmod;                // chmod/fchmod
    bool block_symlink_create;       // symlink to this file
    bool block_hardlink_create;      // hardlink to this file
};
#endif // __COMMON_H
