#ifndef __POLICY_MANAGER_H
#define __POLICY_MANAGER_H

#include <cJSON.h>
#include "self_defense.skel.h"   
#include <stdlib.h> 
#ifndef DEFAULT_POLICY_FILE_PATH
#define DEFAULT_POLICY_FILE_PATH "/etc/SentinelEDR/self_defense_policy.json"
#endif

const char *get_policy_path();

int apply_file_policy(struct self_defense_bpf *skel, const char *path, const struct file_policy_value *value);

int apply_process_policy(struct self_defense_bpf *skel, __u32 pid, const struct process_policy_value *value);

int load_and_apply_policies(struct self_defense_bpf *skel, const char *json_filepath);



#endif // __POLICY_MANAGER_H