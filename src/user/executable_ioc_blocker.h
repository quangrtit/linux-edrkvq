#ifndef __EXECUTABLE_IOC_BLOCKER_H
#define __EXECUTABLE_IOC_BLOCKER_H

#include "common_user.h"
#include "utils.h"
#include "ioc_database.h"

class ExecutableIOCBlocker {
public:
    ExecutableIOCBlocker(volatile sig_atomic_t* external_exit, IOCDatabase &db);
    ~ExecutableIOCBlocker();

    void add_policy(const std::string &path); 
    void add_policy(const __u64 &inode);
    bool start();   
    void stop();    

    bool check_exe_malicious(const char* real_path, IOCDatabase& ioc_db);
    void enumerate_mounts_and_mark();
    bool add_mount(const std::string &path, const MountInfo& mount_info);
    bool remove_mount(const std::string &path);
private:
    void loop();    

    int fan_fd;
    volatile sig_atomic_t* exiting; 
    std::mutex cache_inode_policy_map_mutex;
    std::unordered_map<__u64,bool> cache_inode_policy_map; // cache inode exe file 
    std::thread worker_thread;

    IOCDatabase &ioc_db;
    std::unordered_map<std::string, MountInfo> mount_cache;
};

#endif // __EXECUTABLE_IOC_BLOCKER_H