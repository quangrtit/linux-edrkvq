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

// static function

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


// search policy of file
static __always_inline struct file_policy_value *lookup_file_policy(struct dentry *dentry) {
    struct file_policy_value *policy = NULL;

    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode)
        return NULL;
    __u64 ino = BPF_CORE_READ(inode, i_ino);
    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (!sb)
        return NULL;
    dev_t dev = BPF_CORE_READ(sb, s_dev);
    __u64 key = ((__u64)dev << 32) | (__u64)ino;
    policy = bpf_map_lookup_elem(&file_protection_policy, &key);
    // bpf_printk("dev=0x%x", dev);
    // bpf_printk("ino=0x%lx", ino);
    // bpf_printk("key=0x%llx", key);
    return policy;
}

// search policy of process 
static __always_inline struct process_policy_value *lookup_process_policy(__u32 pid) {
    return bpf_map_lookup_elem(&process_protection_policy, &pid);
}

// all protection of files
SEC("lsm/inode_unlink")
int BPF_PROG(protect_delete_secret_file, struct inode *dir, struct dentry *dentry, int ret) {
    if (ret != 0) {
        send_debug_log(INFO, "[inode_unlink] returned early due to existing denial");
        return ret;
    }
    
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *flag = bpf_map_lookup_elem(&whitelist_pid_map, &pid);
    if (flag && *flag == 1) {
        return 0;  
    }
    // if (uid == 0) {
    //     send_debug_log(INFO, "[inode_unlink] Admin user detected, allowing unlink");
    //     return 0;
    // }
    // char dentry_name_buf[NAME_MAX];
    // const unsigned char *dentry_name_ptr = BPF_CORE_READ(dentry, d_name.name);
    // bpf_core_read_str(&dentry_name_buf, sizeof(dentry_name_buf), dentry_name_ptr);
    // bpf_printk("INFO, [kernel space inode_unlink] Blocked unlink due to policy, %s", dentry_name_buf);
    if (!dentry) {
        return 0;
    }
    struct file_policy_value *policy = lookup_file_policy(dentry);
    // struct inode *target_inode;
    // BPF_CORE_READ_INTO(&target_inode, dentry, d_inode);
    // umode_t mode;
    // BPF_CORE_READ_INTO(&mode, target_inode, i_mode);
    // if (S_ISLNK(mode)) {
    //     char dentry_name_buf[NAME_MAX];
    //     const unsigned char *dentry_name_ptr = BPF_CORE_READ(dentry, d_name.name);
    //     bpf_core_read_str(&dentry_name_buf, sizeof(dentry_name_buf), dentry_name_ptr);
    //     bpf_printk("INFO, [kernel space inode_unlink] Blocked unlink due to policy yes yes 11111, %s", dentry_name_buf);
    //     if(policy) {
    //         bpf_printk("YES YES YES ");
    //     }
    //     else {
    //         bpf_printk("NO NO NO");
    //     }
    // }
    if (policy && policy->block_unlink) {
        bpf_printk("BLOCK_ACTION, [kernel space inode_unlink] Blocked unlink due to policy");
        send_debug_log(BLOCKED_ACTION, "[kernel space inode_unlink] Blocked unlink due to policy");
        return -EPERM;
    }
    return 0;
}

SEC("lsm/path_unlink")
int BPF_PROG(protect_secret_file_0, const struct path *dir, struct dentry *dentry, int ret) {
    if (ret != 0) {
        send_debug_log(INFO, "[kernel space path_unlink] returned early due to existing denial");
        return ret;
    }
    // bpf_printk("INFO, [kernel space path_unlink] Blocked unlink due to policy");
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *flag = bpf_map_lookup_elem(&whitelist_pid_map, &pid);
    if (flag && *flag == 1) {
        return 0;  
    }
    // if (uid == 0) {
    //     send_debug_log(INFO, "[path_unlink] Admin user detected, allowing unlink");
    //     return 0;
    // }

    // char dentry_name_buf[NAME_MAX];
    // const unsigned char *dentry_name_ptr = BPF_CORE_READ(dentry, d_name.name);
    // bpf_core_read_str(&dentry_name_buf, sizeof(dentry_name_buf), dentry_name_ptr);
    if (!dentry) {
        return 0;
    }
    struct file_policy_value *policy = lookup_file_policy(dentry);
    if (policy && policy->block_unlink) {
        bpf_printk("BLOCK_ACTION, [kernel space path_unlink] Blocked unlink due to policy");
        send_debug_log(BLOCKED_ACTION, "[kernel space path_unlink] Blocked unlink due to policy");
        return -EPERM;
    }

    return 0;
}

// for write and read file 
SEC("lsm/file_permission")
int BPF_PROG(protect_read_write_secret_file, struct file *file, int mask) {
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    // char filename[MAX_PATH_LEN] = {};
    // bpf_core_read_str(&filename, sizeof(filename), file->f_path.dentry->d_name.name);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *flag = bpf_map_lookup_elem(&whitelist_pid_map, &pid);
    bpf_printk("this is pid: %d\n", pid);
    if (flag && *flag == 1) {
        return 0;  
    }
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry) {
        return 0;
    }
    struct file_policy_value *policy = lookup_file_policy(dentry);
    
    // for write
    if ((mask & MAY_WRITE) && policy && policy->block_write) {
        bpf_printk("BLOCK_ACTION, [kernel space file_permission] Write access denied");
        send_debug_log(BLOCKED_ACTION, "[kernel space file_permission] Write access denied");
        return -EACCES;
    }
    // for read 
    if (mask & MAY_READ && policy && policy->block_read) {
        bpf_printk("BLOCK_ACTION, [kernel space file_permission] Read access denied");
        send_debug_log(BLOCKED_ACTION, "[kernel space file_permission] Read access denied");
        return -EACCES;
    }
    return 0;
}

// for move and rename file 
SEC("lsm/inode_rename")
int BPF_PROG(protect_rename_move_file,
             struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry,
             unsigned int flags)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *flag = bpf_map_lookup_elem(&whitelist_pid_map, &pid);
    if (flag && *flag == 1) {
        return 0;  
    }
    // char old_name[MAX_PATH_LEN];
    // bpf_core_read_str(old_name, sizeof(old_name), old_dentry->d_name.name);
    if (!old_dentry) {
        return 0;
    }
    struct file_policy_value *policy = lookup_file_policy(old_dentry);
    
    if (policy && (policy->block_rename || policy->block_move)) {
        bpf_printk("BLOCK_ACTION, [kernel space inode_rename] move or rename access denined");
        send_debug_log(BLOCKED_ACTION, "[kernel space inode_rename] move or rename access denined");
        return -EPERM;
    }

    return 0;
}

// : > test_file_vcs1.txt : override file by O_TRUNC when file open
SEC("lsm/file_open")
int BPF_PROG(block_trunc_file, struct file *file) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *flag = bpf_map_lookup_elem(&whitelist_pid_map, &pid);
    if (flag && *flag == 1) {
        return 0;  
    }
    // char filename[MAX_PATH_LEN] = {};
    // bpf_core_read_str(&filename, sizeof(filename), file->f_path.dentry->d_name.name);
    // send_debug_log(WARNING, filename);
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry) {
        return 0;
    }
    struct file_policy_value *policy = lookup_file_policy(dentry);
    if ((file->f_flags & O_TRUNC) && policy && policy->block_truncate_create) {
        bpf_printk("BLOCK_ACTION, [kernel space file_open] override file by O_TRUNC access denined");
        send_debug_log(BLOCKED_ACTION, "[kernel space file_open] override file by O_TRUNC access denined");
        return -EPERM;
    }
    return 0;
}

//inode_permission 
// set attribute 
SEC("lsm/inode_setattr")
int BPF_PROG(block_inode_setattr, struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr) {

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *flag = bpf_map_lookup_elem(&whitelist_pid_map, &pid);
    if (flag && *flag == 1) {
        return 0;  
    }

    if(!dentry) {
        return 0;
    }
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    struct file_policy_value *policy = lookup_file_policy(dentry);
    if (!policy || !inode) {
        return 0; 
    }
    // send_debug_log(INFO, "[kernel space inode_setattr] this is");
    __u32 ia_valid = BPF_CORE_READ(attr, ia_valid);
    if(!(ia_valid & ATTR_MODE)) {
        return 0;
    }
    if (policy->block_chmod) {
        umode_t old_mode = BPF_CORE_READ(inode, i_mode) & 0777;
        // umode_t new_mode = attr->ia_mode & 0777;
        umode_t new_mode = BPF_CORE_READ(attr, ia_mode) & 0777;
        if (old_mode != new_mode) {
            bpf_printk("BLOCK_ACTION, [kernel space inode_setattr] Block chmod attempt");
            send_debug_log(BLOCKED_ACTION, "[kernel space inode_setattr] Block chmod attempt");
            return -EPERM;
        }
        else {
            send_debug_log(WARNING, "[kernel space inode_setattr] chmod attempt");
        }
    }
    return 0;
}

SEC("lsm/path_chmod")
int BPF_PROG(block_path_chmod, struct path *path, umode_t mode) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *flag = bpf_map_lookup_elem(&whitelist_pid_map, &pid);
    if (flag && *flag == 1) {
        return 0;  
    }
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    if (!dentry) {
        return 0;
    }

    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    struct file_policy_value *policy = lookup_file_policy(dentry);
    if (!policy || !inode) {
        return 0;
    }

    umode_t old_mode = BPF_CORE_READ(inode, i_mode) & 0777;
    umode_t new_mode = mode & 0777;

    if (old_mode != new_mode && policy->block_chmod) {
        bpf_printk("BLOCK_ACTION, [kernel space path_chmod] Block chmod attempt");
        send_debug_log(BLOCKED_ACTION, "[kernel space path_chmod] Block chmod attempt");
        return -EPERM;
    } 
    else {
        send_debug_log(WARNING, "[kernel space path_chmod] chmod attempt");
    }

    return 0;
}
// block write file by mmap
SEC("lsm/mmap_file")
int BPF_PROG(block_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *flag = bpf_map_lookup_elem(&whitelist_pid_map, &pid);
    if (flag && *flag == 1) {
        return 0;  
    }
    if (!(prot & PROT_WRITE)) {
        return 0;
    }
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry) {
        return 0;
    }
    // char filename[NAME_MAX];
    // const unsigned char *dentry_name_ptr = BPF_CORE_READ(dentry, d_name.name);
    // bpf_core_read_str(&filename, sizeof(filename), dentry_name_ptr);
    // send_debug_log(BLOCKED_ACTION, filename);

    struct file_policy_value *policy = lookup_file_policy(dentry);
    if (policy && policy->block_write) {
        bpf_printk("BLOCK_ACTION, [kernel space mmap_file] Blocked mmap(PROT_WRITE) on protected file");
        send_debug_log(BLOCKED_ACTION, "[kernel space mmap_file] Blocked mmap(PROT_WRITE) on protected file");
        return -EACCES;
    }

    return 0;
}

// SEC("lsm/file_mprotect")
// int BPF_PROG(block_file_mprotect, struct vm_area_struct *vma, unsigned long prot) {

//     if (!(prot & PROT_WRITE)) {
//         return 0;
//     }
//     struct dentry *dentry = file->f_path.dentry;
//     struct file_policy_value *policy = lookup_file_policy(dentry);
//     if (policy && policy->block_write) {
//         send_debug_log(INFO, "Blocked mmap(PROT_WRITE) on protected file");
//         return -EACCES;
//     }
//     return 0;
// }

// inode_permission
// all protect processes
// block kill process
SEC("lsm/task_kill")
int BPF_PROG(task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred)
{
    
    char* comm = BPF_CORE_READ(p, comm);
    // if(bpf_strncmp(comm, sizeof(comm), "edr_main") == 0) {
    //     send_debug_log(INFO, comm);
    // }
    __u32 pid = BPF_CORE_READ(p, pid);
    __u32 tgid = BPF_CORE_READ(p, tgid);
    __u8 *flag = bpf_map_lookup_elem(&whitelist_pid_map, &pid);

    // if (flag && *flag == 1) {
    //     return 0;  
    // }
    bpf_printk("have all pid %d %d\n", pid, tgid);
    struct process_policy_value *policy = lookup_process_policy(pid);
    if (!policy) {
        policy = lookup_process_policy(tgid);
    }
    if (policy && policy->block_termination) {
        bpf_printk("BLOCK_ACTION, [kernel space task_kill] Blocked termination");
        send_debug_log(BLOCKED_ACTION, "[kernel space task_kill] Blocked termination");
        return -EPERM;
    }
    return 0;
}
//  block debug memory 
SEC("lsm/ptrace_access_check")
int BPF_PROG(block_ptrace, struct task_struct *child, unsigned int mode)
{
    __u32 pid = BPF_CORE_READ(child, pid);
    // __u8 *flag = bpf_map_lookup_elem(&whitelist_pid_map, &pid);
    // if (flag && *flag == 1) {
    //     return 0;  
    // }
    // __u32 tracer_pid = bpf_get_current_pid_tgid() >> 32;
    // if(tracer_pid == pid) {
    //     return 0;
    // }
    struct process_policy_value *policy = lookup_process_policy(pid);
    if (policy && policy->block_injection) {
        send_debug_log(BLOCKED_ACTION, "[kernel space ptrace_access_check] Blocked injection shellcode by ptrace");
        return -EPERM;  
    }

    return 0;  
}
// block limit resource 
// hook task_prlimit
SEC("lsm/task_setrlimit")
int BPF_PROG(lsm_task_setrlimit, struct task_struct *p, unsigned int resource,
             struct rlimit *new_rlim)
{
    __u32 target_pid = bpf_get_current_pid_tgid() >> 32;
    __u32 target_pid_real = (__u32)BPF_CORE_READ(p, pid);
    if (target_pid == target_pid_real) {
        return 0;
    }
    struct process_policy_value * policy = lookup_process_policy(target_pid_real);
    if (policy && policy->block_prlimit) {
        send_debug_log(BLOCKED_ACTION, "[kernel space ptrace_access_check] Blocked limit memory");
        return -EPERM;
    }
    return 0;
}
// SEC("kprobe/__x64_sys_prlimit64")
// int BPF_PROG(kp_prlimit_enter)
// {
//     send_debug_log(BLOCKED_ACTION, "[kernel space ptrace_access_check] Blocked limit memory1");
//     /* x86_64 syscall args: (pid_t pid, int resource, const struct rlimit *new_limit, struct rlimit *old_limit) */
//     long arg0 = (long)PT_REGS_PARM1((struct pt_regs *)ctx); /* pid (may be 0 -> current) */
//     __s32 pid_arg = (__s32)arg0;
//     bpf_printk("raw=%ld pid_arg=%d", arg0, pid_arg);
//     __u32 caller_tgid = (bpf_get_current_pid_tgid() >> 32);
//     __u32 target_tgid;

//     if (pid_arg == 0) {
//         target_tgid = caller_tgid;
//     } else if (pid_arg < 0) {
//         // Negative pid not expected for prlimit; treat as no-op
//         send_debug_log(BLOCKED_ACTION, "[kernel space ptrace_access_check] Blocked limit memory2");
//         return 0;
//     } else {
//         target_tgid = ( __u32 ) pid_arg;
//     }
//     bpf_printk("this is pid process 1 %d", target_tgid);
//     struct process_policy_value *policy = lookup_process_policy(target_tgid);
//     if(!(policy && policy->block_prlimit)) {
//         send_debug_log(BLOCKED_ACTION, "[kernel space ptrace_access_check] Blocked limit memory3");
//         return 0;
//     }
//     if (caller_tgid == target_tgid) {
//         send_debug_log(BLOCKED_ACTION, "[kernel space ptrace_access_check] Blocked limit memory4");
//         return 0;
//     }
//     send_debug_log(BLOCKED_ACTION, "[kernel space ptrace_access_check] Blocked limit memory");
//     // Deny the syscall: require kernel helper bpf_override_return
//     // return value is errno-like negative; use -EPERM
//     bpf_override_return((struct pt_regs *)ctx, -EPERM);
//     return 0;
// }
// Hook task_setnice
SEC("lsm/task_setnice")
int BPF_PROG(block_task_setnice, struct task_struct *p, int nice)
{
    __u32 target_pid = BPF_CORE_READ(p, pid);
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;
    if (caller_pid == target_pid) {
        return 0;
    }
    struct process_policy_value *policy = lookup_process_policy(target_pid);
    if (policy && policy->block_setnice) {
        send_debug_log(BLOCKED_ACTION, "[kernel space ptrace_access_check] Blocked limit CPU");
        return -EPERM;
    }
    return 0;
}

// Hook task_setioprio
SEC("lsm/task_setioprio")
int BPF_PROG(block_task_setioprio, struct task_struct *p, int ioprio)
{
    __u32 target_pid = BPF_CORE_READ(p, pid);
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;
    if (caller_pid == target_pid) {
        return 0;
    }
    struct process_policy_value *policy = lookup_process_policy(target_pid);
    if (policy && policy->block_setioprio) {
        send_debug_log(BLOCKED_ACTION, "[kernel space ptrace_access_check] Blocked limit IO");
        return -EPERM;
    }
    return 0;
}
/*
    LSM_HOOK(int, 0, task_setpgid, struct task_struct *p, pid_t pgid)
    LSM_HOOK(int, 0, task_getpgid, struct task_struct *p)
    LSM_HOOK(int, 0, task_getsid, struct task_struct *p)
*/
//SEC("lsm/inode_permission")
// // bprm_creds_for_exec
// SEC("lsm/bprm_creds_for_exec")
// int BPF_PROG(block_ldpreload, struct linux_binprm *bprm) {
    
//     return 0;
// }
