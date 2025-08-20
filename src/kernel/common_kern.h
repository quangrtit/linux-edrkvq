#ifndef __COMMON_KERN_H
#define __COMMON_KERN_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>      // eBPF helper macro
#include <bpf/bpf_tracing.h>      

#define LOG_MSG_MAX_LEN 128
#define TASK_COMM_LEN 32
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
#define AF_INET6 23 
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

// IOC type
enum ioc_event_type {
    IOC_EVT_EXEC_FILE = 1,   // Execute file
    IOC_EVT_CONNECT_IP,      // IP Connection
    IOC_EVT_CMD_CONTROL,     // Receive control command
    IOC_EVT_MOUNT_EVENT,
};
// Payload for IOC_EXEC_FILE
struct exec_payload {
    char file_path[MAX_PATH_LEN];  
    __u64 inode_id;       
};
// Event Mountpoint 
enum mount_type{
    MOUNT_ADD,
    MOUNT_REMOVE
};
struct mount_payload {
    enum mount_type action;                  // MOUNT_ADD, MOUNT_REMOVE
    char dev_name[MAX_PATH_LEN];           // device (/dev/sda1)
    char fs_type[TASK_COMM_LEN];            // ext4, vfat...
    char mnt_point[MAX_PATH_LEN];         // mountpoint path
};
// Payload for IOC_CONNECT_IP
struct net_payload {
    __u8  family;       // AF_INET / AF_INET6
    __u32 daddr_v4;     // IPv4 dest
    __u8  daddr_v6[16]; // IPv6 dest
    __u16 dport;        // dest port

    __u32 pid;          // process created connection
    __u32 protocol;     // TCP/UDP
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
        struct exec_payload exec;
        struct mount_payload mnt;
        
        struct net_payload net;
        struct cmd_payload cmd;
    };
};


#endif // __COMMON_KERN_H
