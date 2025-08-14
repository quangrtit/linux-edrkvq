#ifndef __COMMON_USER_H
#define __COMMON_USER_H

#include <stdbool.h>
#include <stdint.h>  
#include <linux/types.h> 
#include <thread>
#include <atomic>
#include <mutex>
#include <map>
#include <unordered_map>
#include <string>
#include <sys/fanotify.h>
#include <poll.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <signal.h>
#include <openssl/sha.h>
#include <cstdio>
#include <memory>
#include <cstdlib>
#include <chrono>
#include <openssl/evp.h>
#define LOG_MSG_MAX_LEN 128
#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 128
#define MAX_POLICY_ENTRIES 64
#define NAME_MAX 255
#define EPERM     1
#define __u64 long long unsigned int
#define __s64 int64_t
#define KERNEL_MINORBITS 20
#define KERNEL_MKDEV(major, minor) ((__u64)(major) << KERNEL_MINORBITS | (minor))
#define LOCK_PATH "/var/run/sentinel.lock"
#define PORT 8080
#define BUFFER_SIZE 1024
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


typedef long long unsigned int file_policy_key_t;
struct file_policy_value {
    char path[MAX_PATH_LEN];
    __s64 inode;
    __s64 inode_symlink;
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
    __u8 block_prlimit;
    __u8 block_setnice;
    __u8 block_setioprio;
};
struct FileCloser {
    void operator()(FILE* fp) const {
        if (fp) {
            fclose(fp);
        }
    }
};

// IOC type
enum ioc_event_type {
    IOC_EVT_EXEC_FILE = 1,   // Execute file
    IOC_EVT_CONNECT_IP,      // IP Connection
    IOC_EVT_CMD_CONTROL,     // Receive control command
};

// Payload for IOC_EXEC_FILE
struct exec_payload {
    char file_path[MAX_PATH_LEN];  
    __u64 inode_id;       
};

// Payload for IOC_CONNECT_IP
struct net_payload {
    __u32 saddr;          
    __u32 daddr;          
    __u16 sport;         
    __u16 dport;          
};

// Payload for IOC_CMD_CONTROL
struct cmd_payload {
    char cmd[NAME_MAX];        
};

// Event sent from kernel to user
struct ioc_event {
    __u64 timestamp_ns;       // Time of occurrence
    __u32 pid;                // PID of the process
    __u32 tgid;               // TGID (parent pid)
    __u32 ppid;               // parent PID
    __u32 uid;                // UID of the user running the process
    __u32 gid;                // GID

    enum ioc_event_type type; // Blocked IOC Type

    union {
        struct {
            char file_path[MAX_PATH_LEN]; // Executable file path
            __u64 inode_id;      // file inode (dev<<32 | ino)
        } exec;

        struct {
            __u32 saddr;         // Source IP (IPv4)
            __u32 daddr;         // Destination IP (IPv4)
            __u16 sport;         // Source port
            __u16 dport;         // Destination Port
        } net;

        struct {
            char cmd[NAME_MAX];       // C2 command or data
        } cmdctl;

    };
};

#endif // __COMMON_USER_H
