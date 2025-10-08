#ifndef __POLICY_MANAGER_H
#define __POLICY_MANAGER_H

#include <cJSON.h>
#include "self_defense.skel.h" 
#include "ioc_block.skel.h"
#include "common_user.h"  
#include <stdlib.h> 


const char *get_policy_path();

int apply_file_policy(struct self_defense_bpf *skel, const char *path, struct file_policy_value *value, const char *json_filepath);

int apply_process_policy(struct self_defense_bpf *skel, __u32 pid, const struct process_policy_value *value);

int apply_fileless_lock_policy(struct ioc_block_bpf *skel, const uint32_t value);

int apply_disable_module_autoload_policy(struct self_defense_bpf *skel, const uint32_t value);

int apply_whitelists_process_policy(struct self_defense *skel, struct whitelists_process_policy_value* value);

int load_and_apply_policies(struct self_defense_bpf *skel_self, struct ioc_block_bpf* skel_ioc, const char *json_filepath);



#endif // __POLICY_MANAGER_H