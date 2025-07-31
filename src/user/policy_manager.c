#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h> 
#include "common_user.h"
#include "policy_manager.h"
#include "cJSON.h"



const char *get_policy_path() {
    const char *env = getenv("SENTINEL_POLICY_FILE");
    return env ? env : DEFAULT_POLICY_FILE_PATH;
}

int apply_file_policy(struct self_defense_bpf *skel, const char *path, const struct file_policy_value *value) {
    file_policy_key_t key;
    memset(&key, 0, sizeof(key));
    strncpy(key, path, sizeof(key) - 1);
    key[sizeof(key) - 1] = '\0';
    printf("debug 1: %s\n", key);
    int err = bpf_map__update_elem(skel->maps.file_protection_policy, &key, sizeof(key), (void *)value, sizeof(*value), BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update file policy for '%s': %s\n", path, strerror(errno));
        return err;
    }
    printf("[Policy Manager] Applied file policy for '%s'.\n", path);
    return 0;
}

int load_and_apply_policies(struct self_defense_bpf *skel, const char *json_filepath) {
    FILE *fp = fopen(json_filepath, "r");
    if (fp == NULL) {
        fprintf(stderr, "[Policy Manager] Error: Could not open policy file '%s': %s\n", json_filepath, strerror(errno));
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
            fprintf(stderr, "[Policy Manager] Error parsing JSON: %s\n", error_ptr);
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
                fprintf(stderr, "[Policy Manager] Warning: 'path' not found or not a string in a file rule. Skipping.\n");
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
            policy.block_chmod = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rule_item, "block_chmod"));
            policy.block_symlink_create = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rule_item, "block_symlink_create"));
            policy.block_hardlink_create = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rule_item, "block_hardlink_create"));
            printf("\n[userspace debug] 11 1111111 1 %s\n", policy.path);
            apply_file_policy(skel, policy.path, &policy);
        }
    }

    cJSON_Delete(root);
    free(json_string);
    return 0;
}





