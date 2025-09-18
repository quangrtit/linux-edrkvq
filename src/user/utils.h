#ifndef __UTILS_H
#define __UTILS_H


#include "self_defense.skel.h" 
#include "ioc_block.skel.h"
#include "common_user.h"  
#include <lmdb.h>
#include "ioc_database.h"

char* get_local_ip();

int acquire_lock_and_write_pid(const char *path, int *out_fd);

__u64 get_inode_key(const char* path);

std::string calculate_sha256_fast(const char* file_path);

bool is_elf_fd(int fd);
bool is_executable_fd(int fd);

bool load_ioc_ip_into_kernel_map(struct ioc_block_bpf *skel, IOCDatabase &ioc_db);

int has_default_route4(const char *ifname);

int has_default_route6(const char *ifname);

std::vector<unsigned int> get_all_default_ifindexes();

std::string get_binary_dir();

__u64 get_file_size(const char *filename);

#endif // __UTILS_H