#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h> 
#include <sys/stat.h>
#include "common_user.h"
#include "policy_manager.h"
#include "cJSON.h"
#include <sys/sysmacros.h>


const char *get_policy_path() {
    const char *env = getenv("SENTINEL_POLICY_FILE");
    return env ? env : DEFAULT_POLICY_FILE_PATH;
}


static int update_policy_map(struct self_defense_bpf *skel, __u64 key, const struct file_policy_value *value) {
    int err = bpf_map__update_elem(skel->maps.file_protection_policy, &key, sizeof(key), (void *)value, sizeof(*value), BPF_ANY);
    return err;
}

int apply_file_policy(struct self_defense_bpf *skel, const char *path, struct file_policy_value *value, const char *json_filepath) {
    if(value->inode == -1) {
        struct stat st_stat;
        struct stat st_lstat;
        int err_stat = 0, err_lstat = 0;
        __u64 key_stat = 0, key_lstat = 0;
        unsigned int user_major, user_minor;
        __u64 kernel_compatible_dev;

        if (stat(path, &st_stat) != 0) {
            fprintf(stderr, "[user space policy_manager.cpp] Failed to stat file '%s': %s\n", path, strerror(errno));
            return -1;
        }

        user_major = major(st_stat.st_dev);
        user_minor = minor(st_stat.st_dev);
        kernel_compatible_dev = KERNEL_MKDEV(user_major, user_minor);
        key_stat = (kernel_compatible_dev << 32) | (__u64)st_stat.st_ino;
        value->inode = key_stat;
        err_stat = update_policy_map(skel, key_stat, value);
        if (err_stat) {
            fprintf(stderr, "[user space policy_manager.cpp] Failed to update file policy for target '%s' (key=0x%llx): %s\n",
                    path, (unsigned long long)key_stat, strerror(errno));
        } else {
            // printf("[user space policy_manager.cpp] Applied file policy (target) for '%s'. Key=0x%llx\n",
            //        path, (unsigned long long)key_stat);
        }

        if (lstat(path, &st_lstat) != 0) {
            fprintf(stderr, "[user space policy_manager.cpp] lstat failed for '%s': %s\n", path, strerror(errno));
        } else {
            unsigned int link_major = major(st_lstat.st_dev);
            unsigned int link_minor = minor(st_lstat.st_dev);
            __u64 kernel_dev_link = KERNEL_MKDEV(link_major, link_minor);
            key_lstat = (kernel_dev_link << 32) | (__u64)st_lstat.st_ino;

            if (key_lstat == key_stat) {
                // printf("[user space policy_manager.cpp] Target and link resolved to same key for '%s' (0x%llx).\n",
                //        path, (unsigned long long)key_stat);
                err_lstat = 0; /* nothing to do */
            } else {
                value->inode_symlink = key_lstat;
                err_lstat = update_policy_map(skel, key_lstat, value);
                if (err_lstat) {
                    fprintf(stderr, "[user space policy_manager.cpp] Failed to update file policy for link '%s' (key=0x%llx): %s\n",
                            path, (unsigned long long)key_lstat, strerror(errno));
                } else {
                    // printf("[user space policy_manager.cpp] Applied file policy (link) for '%s'. Key=0x%llx\n",
                    //        path, (unsigned long long)key_lstat);
                }
            }
        }

        printf("[user space policy_manager.cpp] User space debug for '%s': stat_dev=0x%llx stat_ino=0x%llx, lstat_dev=0x%llx lstat_ino=0x%llx\n",
            path,
            (unsigned long long)st_stat.st_dev, (unsigned long long)st_stat.st_ino,
            (unsigned long long)st_lstat.st_dev, (unsigned long long)st_lstat.st_ino);
        // update new inode for policy

        if (err_stat == 0 || err_lstat == 0) {
            return 0;
        }

        return -1;
    }
    else {
        int err_stat = 0, err_lstat = 0;
        __u64 key_stat = value->inode, key_lstat = value->inode_symlink;
        err_stat = update_policy_map(skel, key_stat, value);
        err_lstat = update_policy_map(skel, key_lstat, value);
        if (err_stat == 0 || err_lstat == 0) {
            return 0;
        }
        
        return -1;
    }
}

int apply_process_policy(struct self_defense_bpf *skel, __u32 pid, const struct process_policy_value *value)
{
    // temporarily protects only the current process itself
    pid = (__u32)getpid(); 
    int err = bpf_map__update_elem(skel->maps.process_protection_policy, &pid, sizeof(pid), (void *)value, sizeof(*value), BPF_ANY);
    if (err) {
        fprintf(stderr, "[user space policy_manager.cpp] Failed to apply process policy for PID %u: %s\n", pid, strerror(errno));
        return err;
    }

    printf("[user space policy_manager.cpp] Applied process policy for PID %u (block_termination=%d, block_injection=%d)\n",
           pid, value->block_termination, value->block_injection);
    return 0;
}

int load_and_apply_policies(struct self_defense_bpf *skel, const char *json_filepath) {
    FILE *fp = fopen(json_filepath, "r");
    if (fp == NULL) {
        fprintf(stderr, "[user space policy_manager.cpp] Error: Could not open policy file '%s': %s\n", json_filepath, strerror(errno));
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *json_string = (char*)malloc(fsize + 1);
    fread(json_string, 1, fsize, fp);
    fclose(fp);
    json_string[fsize] = '\0';

    cJSON *root = cJSON_Parse(json_string);
    if (root == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "[user space policy_manager.cpp] Error parsing JSON: %s\n", error_ptr);
        }
        free(json_string);
        return -1;
    }
    // rules for files
    cJSON *file_rules = cJSON_GetObjectItemCaseSensitive(root, "file_protection_rules");
    if (cJSON_IsArray(file_rules)) {
        
        cJSON *rule_item = NULL;
        cJSON_ArrayForEach(rule_item, file_rules) {
            cJSON *path_json = cJSON_GetObjectItemCaseSensitive(rule_item, "path");
            if (!cJSON_IsString(path_json) || (path_json->valuestring == NULL)) {
                fprintf(stderr, "[user space policy_manager.cpp] Warning: 'path' not found or not a string in a file rule. Skipping.\n");
                continue;
            }
            const char *path = path_json->valuestring;

            struct file_policy_value policy = {0};
            cJSON *dentry_json = cJSON_GetObjectItemCaseSensitive(rule_item, "path");
            if (cJSON_IsString(dentry_json) && dentry_json->valuestring != NULL) {
                memset(&policy.path, 0, sizeof(policy.path));
                strncpy(policy.path, dentry_json->valuestring, sizeof(policy.path) - 1);
                policy.path[sizeof(policy.path) - 1] = '\0';  
            }
            policy.block_read = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rule_item, "block_read"));
            policy.block_write = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rule_item, "block_write"));
            policy.block_truncate_create = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rule_item, "block_truncate_create"));
            policy.block_unlink = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rule_item, "block_unlink"));
            policy.block_rename = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rule_item, "block_rename"));
            policy.block_move = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rule_item, "block_move"));
            policy.block_chmod = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rule_item, "block_chmod"));
            policy.block_symlink_create = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rule_item, "block_symlink_create"));
            policy.block_hardlink_create = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rule_item, "block_hardlink_create"));
            cJSON *inode_item = cJSON_GetObjectItemCaseSensitive(rule_item, "inode");
            if (cJSON_IsString(inode_item) && inode_item->valuestring) {
                policy.inode = strtoll(inode_item->valuestring, NULL, 10);
            } else if (cJSON_IsNumber(inode_item)) {
                policy.inode = (__s64)inode_item->valuedouble;
            }

            cJSON *inode_symlink_item = cJSON_GetObjectItemCaseSensitive(rule_item, "inode_symlink");
            if (cJSON_IsString(inode_symlink_item) && inode_symlink_item->valuestring) {
                policy.inode_symlink = strtoll(inode_symlink_item->valuestring, NULL, 10);
            } else if (cJSON_IsNumber(inode_symlink_item)) {
                policy.inode_symlink = (__s64)inode_symlink_item->valuedouble;
            }

            apply_file_policy(skel, policy.path, &policy, json_filepath);

            printf("begin inode: %lld\n", (long long)policy.inode);
            printf("begin inode_symlink: %lld\n", (long long)policy.inode_symlink);

            char buf[32];
            snprintf(buf, sizeof(buf), "%lld", (long long)policy.inode);
            cJSON_ReplaceItemInObject(rule_item, "inode", cJSON_CreateString(buf));

            snprintf(buf, sizeof(buf), "%lld", (long long)policy.inode_symlink);
            cJSON_ReplaceItemInObject(rule_item, "inode_symlink", cJSON_CreateString(buf));
        }
    }

    // rules for processes 
    cJSON *process_rules = cJSON_GetObjectItemCaseSensitive(root, "process_protection_rules");
    if (cJSON_IsArray(process_rules)) {
        
        cJSON *rule_item = NULL;
        cJSON_ArrayForEach(rule_item, process_rules) {
            struct process_policy_value policy = {0};

            cJSON *pid_json = cJSON_GetObjectItemCaseSensitive(rule_item, "pid");
            if (!cJSON_IsNumber(pid_json)) {
                fprintf(stderr, "[user space policy_manager.cpp] Warning: 'pid' not found or not a number in process rule. Skipping.\n");
                continue;
            }
            policy.pid = (__u32)pid_json->valueint;

            cJSON *dentry_json_process = cJSON_GetObjectItemCaseSensitive(rule_item, "path");
            if (cJSON_IsString(dentry_json_process) && dentry_json_process->valuestring != NULL) {
                memset(&policy.path, 0, sizeof(policy.path));
                strncpy(policy.path, dentry_json_process->valuestring, sizeof(policy.path) - 1);
                policy.path[sizeof(policy.path) - 1] = '\0';  
            }
            // get inode elf
            struct stat st;
            if (stat(policy.path, &st) != 0) {
                fprintf(stderr, "[user space policy_manager.cpp] Failed to stat file '%s': %s\n", policy.path, strerror(errno));
                return -1;
            }
            unsigned int user_major = major(st.st_dev);
            unsigned int user_minor = minor(st.st_dev);
            __u64 kernel_compatible_dev = KERNEL_MKDEV(user_major, user_minor);
            __u64 key = (kernel_compatible_dev << 32) | (__u64)st.st_ino;
            policy.inode = key;
            policy.block_termination = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rule_item, "block_termination"));
            policy.block_injection = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rule_item, "block_injection"));
            policy.block_prlimit = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rule_item, "block_prlimit"));
            policy.block_setnice = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rule_item, "block_setnice"));
            policy.block_setioprio = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rule_item, "block_setioprio"));
            apply_process_policy(skel, policy.pid, &policy);
        }
    }
    // whitelist pid 
    __u32 pid = getpid();  
    __u8 flag = 1;
    int err = bpf_map__update_elem(skel->maps.whitelist_pid_map, &pid, sizeof(pid), &flag, sizeof(flag), BPF_ANY);
    if (err) {
        perror("Failed to add PID to whitelist");
    }

    // FILE *fx = fopen("/home/quang/myLib/vcs-ajiant-edr/test_environment/attack_test/test_file_vcs1.txt", "w");
    // if(!fx) {
    //     perror("fuck ???? \n");
    // }
    char *updated_json = cJSON_Print(root);
    fp = fopen(json_filepath, "w");
    if (!fp) {
        perror("fopen write 1 1 1 1 1");
        cJSON_Delete(root);
        free(json_string);
        free(updated_json);
        return 1;
    }
    fwrite(updated_json, 1, strlen(updated_json), fp);
    fclose(fp);

    free(updated_json);
    cJSON_Delete(root);
    free(json_string);
    return 0;
}





