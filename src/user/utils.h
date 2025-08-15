#ifndef __UTILS_H
#define __UTILS_H


#include "self_defense.skel.h" 
#include "common_user.h"  

char* get_local_ip();

int acquire_lock_and_write_pid(const char *path, int *out_fd);

__u64 get_inode_key(const char* path);

std::string calculate_sha256_fast(const char* file_path);

bool is_elf_fd(int fd);
bool is_executable_fd(int fd);
// const char *get_ioc_db_path();
#endif // __UTILS_H