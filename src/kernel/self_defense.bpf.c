#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h> 
#include "common_kern.h"


char LICENSE[] SEC("license") = "GPL";

// map debug event 
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} debug_events SEC(".maps");

// map file protection
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(file_policy_key_t));
    __uint(value_size, sizeof(struct file_policy_value));
    __uint(max_entries, MAX_POLICY_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} file_protection_policy SEC(".maps");

static __always_inline void send_debug_log(__u32 level, const char *msg) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    if(bpf_strncmp(comm, sizeof(comm) - 1, "rm") != 0)
    {
        return;
    }
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


// search policy
static __always_inline struct file_policy_value *lookup_file_policy(const char *filename) {
    file_policy_key_t key;
    __builtin_memset(&key, 0, sizeof(key));
    bpf_probe_read_kernel_str(&key, sizeof(key), filename);
    return bpf_map_lookup_elem(&file_protection_policy, &key);
}

SEC("lsm/inode_unlink")
int BPF_PROG(protect_delete_secret_file, struct inode *dir, struct dentry *dentry, int ret) {

    // send_debug_log(INFO, "[inode_unlink] entered");

    if (ret != 0) {
        send_debug_log(INFO, "[inode_unlink] returned early due to existing denial");
        return ret;
    }

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (uid_gid & 0xFFFFFFFF);

    // if (uid == 0) {
    //     send_debug_log(INFO, "[inode_unlink] Admin user detected, allowing unlink");
    //     return 0;
    // }

    char dentry_name_buf[NAME_MAX];
    const unsigned char *dentry_name_ptr = BPF_CORE_READ(dentry, d_name.name);
    bpf_core_read_str(&dentry_name_buf, sizeof(dentry_name_buf), dentry_name_ptr);
    struct file_policy_value *policy = lookup_file_policy(dentry_name_buf);
    // send_debug_log(INFO, dentry_name_buf);
    // send_debug_log(INFO, policy->path);
    if (policy && policy->block_unlink) {
        send_debug_log(BLOCKED_ACTION, "[inode_unlink] Blocked unlink due to policy");
        return -EPERM;
    }

    // send_debug_log(INFO, "[inode_unlink] Non-secret file unlink by non-root user, allowing");
    return 0;
}

// SEC("lsm/path_unlink")
// int BPF_PROG(protect_secret_file_0, const struct path *dir, struct dentry *dentry, int ret) {
//     send_debug_log(INFO, "[path_unlink] entered");

//     if (ret != 0) {
//         send_debug_log(INFO, "[path_unlink] returned early due to existing denial");
//         return ret;
//     }

//     __u64 uid_gid = bpf_get_current_uid_gid();
//     __u32 uid = (uid_gid & 0xFFFFFFFF);

//     if (uid == 0) {
//         send_debug_log(INFO, "[path_unlink] Admin user detected, allowing unlink");
//         return 0;
//     }

//     char dentry_name_buf[NAME_MAX];
//     const unsigned char *dentry_name_ptr = BPF_CORE_READ(dentry, d_name.name);
//     bpf_core_read_str(&dentry_name_buf, sizeof(dentry_name_buf), dentry_name_ptr);

//     if (bpf_strncmp(dentry_name_buf, sizeof(SECRET_FILE_NAME) - 1, SECRET_FILE_NAME) == 0) {
//         send_debug_log(BLOCKED_ACTION, "[path_unlink] Blocked non-root unlink of secret file");
//         return -EPERM;
//     }

//     send_debug_log(INFO, "[path_unlink] Non-secret file unlink by non-root user, allowing");
//     return 0;
// }

SEC("lsm/file_permission")
int BPF_PROG(protect_read_write_secret_file, struct file *file, int mask) {
    if (mask & MAY_WRITE)
    {
        bpf_printk("Write access denined\n");
        return -EACCES;
    }
    // for read 
    if (mask & MAY_READ) {
        bpf_printk("Read access denied\n");
        return -EACCES;
    }
    return 0;
}



