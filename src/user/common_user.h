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
#include <cstring>
#include <vector>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <bpf/libbpf.h>
#include <algorithm>
#include <libgen.h>
#include <future>
#include <cJSON.h>
#include <optional>
#include <cmath>
#include <elf.h>
#define LOG_MSG_MAX_LEN 128
#define TASK_COMM_LEN 32
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
#define MAX_IFACES 16
#define LIMIT_IP_STORE 50000
#define LIMIT_FILE_SIZE ((__u64)50 * 1024 * 1024)
#define TIME_OUT_CHECK_FILE_MS 500 // 500ms
#define SERVER_IP "192.168.159.128"
#define SERVER_PORT "8443"
#define BASE_POLICY_DIR "/var/lib/SentinelEDR"


#if !defined(DEFAULT_POLICY_FILE_PATH) 
#define DEFAULT_POLICY_FILE_PATH BASE_POLICY_DIR "/self_defense_policy.json"
#define IOC_DB_PATH BASE_POLICY_DIR "/IOC_DB"
#else 
#define IOC_DB_PATH "IOC_DB"
#endif


// build db
// #define IOC_DB_PATH "/home/ubuntu/lib/vdt-ajiant-edr/configs/IOC_DB"
#define IOC_HASH_FILE_PATH "/home/ubuntu/lib/vdt-ajiant-edr/tools/IOC_DB/ioc_file_hash"
#define IOC_IP_PATH "/home/ubuntu/lib/vdt-ajiant-edr/tools/IOC_DB/ioc_ip"

#define FILE_TEST_BLOCK_EXE "main_test_block_exe"

#define PATH_LOG_ERROR "/home/ubuntu/lib/vdt-ajiant-edr/build/log.txt" 

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

#define FILELESS_PROFILE_KEY 0
enum fileless_lock_policy_value {
    FILELESS_ALLOW,
    FILELESS_RESTRICTED,
    FILELESS_BASELINE
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
    IOC_EVT_MOUNT_EVENT,
};

// Payload for IOC_EXEC_FILE
struct exec_payload {
    char file_path[MAX_PATH_LEN];  
    __u64 inode_id;       
};
// Event Mountpoint 
enum mount_type {
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
struct ip_key {
    __u8 family;       // AF_INET / AF_INET6
    union {
        __u32  ipv4;
        __u8   ipv6[16];
    };
};
enum ip_status {
    ALLOW = 0,
    DENY = 1
};
struct net_payload {
    enum ip_status status;
    __u8  family;       // AF_INET / AF_INET6
    __u32 daddr_v4;     // IPv4 dest
    __u8  daddr_v6[16]; // IPv6 dest
    __u16 dport;        // dest port
    __u32 protocol;     // TCP/UDP
};


struct ip_lpm_key {
    __u32 prefixlen;   // bit length: 32 cho IPv4, 128 cho IPv6
    __u8  data[16];    // IPv4 dùng 4 byte đầu, IPv6 dùng đủ 16 byte
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


struct MountInfo {
    std::string dev_name;          
    std::string fs_type; 
    MountInfo(){}
    MountInfo(std::string dev_name_in, std::string fs_type_in) {dev_name = dev_name_in; fs_type = fs_type_in;}
};

class ExecutableIOCBlocker;

struct CallbackContext {
    ExecutableIOCBlocker *exe_ioc_blocker;
};


// json format for ioc server send to client

#endif // __COMMON_USER_H
