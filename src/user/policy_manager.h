#ifndef __POLICY_MANAGER_H
#define __POLICY_MANAGER_H

#include <stdbool.h>
#include <linux/errno.h>    
#include <linux/limits.h>   
#include <cJSON.h>

#include "self_defense.skel.h"   

int load_and_apply_policies(struct self_defense_bpf *skel, const char *json_filepath);

int apply_file_policy(struct self_defense_bpf *skel, const char *path, const struct file_policy_value *value);

// int apply_process_policy(struct self_defense_bpf *skel, __u32 pid, const struct process_policy_value *value);



#endif // __POLICY_MANAGER_H