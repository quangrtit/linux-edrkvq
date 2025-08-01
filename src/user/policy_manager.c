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

#define KERNEL_MINORBITS 20
#define KERNEL_MKDEV(major, minor) ((__u64)(major) << KERNEL_MINORBITS | (minor))

const char *get_policy_path() {
    const char *env = getenv("SENTINEL_POLICY_FILE");
    return env ? env : DEFAULT_POLICY_FILE_PATH;
}

int apply_file_policy(struct self_defense_bpf *skel, const char *path, const struct file_policy_value *value) {
    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "[user space policy_manager.c] Failed to stat file '%s': %s\n", path, strerror(errno));
        return -1;
    }

    unsigned int user_major = major(st.st_dev);
    unsigned int user_minor = minor(st.st_dev);

    __u64 kernel_compatible_dev = KERNEL_MKDEV(user_major, user_minor);

    __u64 key = (kernel_compatible_dev << 32) | (__u64)st.st_ino;

    int err = bpf_map__update_elem(skel->maps.file_protection_policy, &key, sizeof(key), (void *)value, sizeof(*value), BPF_ANY);
    if (err) {
        fprintf(stderr, "[user space policy_manager.c] Failed to update file policy for '%s': %s\n", path, strerror(errno));
        return err;
    }

    printf("[user space policy_manager.c] Applied file policy for '%s' (user_dev=0x%llx, user_ino=0x%llx, kernel_compatible_dev=0x%llx). Final Key=0x%llx\n",
           path, (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
           (unsigned long long)kernel_compatible_dev, (unsigned long long)key);
    printf("[user space policy_manager.c] User space debug: major=%u, minor=%u\n", user_major, user_minor);
    return 0;
}


int load_and_apply_policies(struct self_defense_bpf *skel, const char *json_filepath) {
    FILE *fp = fopen(json_filepath, "r");
    if (fp == NULL) {
        fprintf(stderr, "[user space policy_manager.c] Error: Could not open policy file '%s': %s\n", json_filepath, strerror(errno));
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *json_string = malloc(fsize + 1);
    fread(json_string, 1, fsize, fp);
    fclose(fp);
    json_string[fsize] = '\0';

    cJSON *root = cJSON_Parse(json_string);
    if (root == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "[user space policy_manager.c] Error parsing JSON: %s\n", error_ptr);
        }
        free(json_string);
        return -1;
    }
    cJSON *file_rules = cJSON_GetObjectItemCaseSensitive(root, "file_protection_rules");
    if (cJSON_IsArray(file_rules)) {
        
        cJSON *rule_item = NULL;
        cJSON_ArrayForEach(rule_item, file_rules) {
            cJSON *path_json = cJSON_GetObjectItemCaseSensitive(rule_item, "path");
            if (!cJSON_IsString(path_json) || (path_json->valuestring == NULL)) {
                fprintf(stderr, "[user space policy_manager.c] Warning: 'path' not found or not a string in a file rule. Skipping.\n");
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
            
            // printf("[user space policy_manager.c] 11 1111111 1 %s\n", policy.path);
            apply_file_policy(skel, policy.path, &policy);
        }
    }
    cJSON_Delete(root);
    free(json_string);
    return 0;
}





