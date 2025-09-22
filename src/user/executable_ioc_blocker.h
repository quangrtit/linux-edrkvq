#ifndef __EXECUTABLE_IOC_BLOCKER_H
#define __EXECUTABLE_IOC_BLOCKER_H

#include "common_user.h"
#include "utils.h"
#include "ioc_database.h"

class ExecutableIOCBlocker {
public:
    ExecutableIOCBlocker(volatile sig_atomic_t* external_exit, IOCDatabase &db);
    ~ExecutableIOCBlocker();

    // void add_policy(const std::string &path); 
    void add_policy(const __u64 &inode, __u64 ctime_sec, __u64 ctime_nsec);
    void remove_policy(const __u64 &inode);
    bool start();   
    void stop();    

    bool check_exe_malicious(const char* real_path, IOCDatabase& ioc_db);
    void enumerate_mounts_and_mark();
    bool add_mount(const std::string &path, const MountInfo& mount_info);
    bool remove_mount(const std::string &path);
    // std::ofstream file_log;
private:
    void loop(); 
    bool check_with_timeout(const char* real_path, IOCDatabase& db, int timeout_ms);   
    int fan_fd;
    volatile sig_atomic_t* exiting; 
    std::mutex cache_inode_policy_map_mutex;
    std::unordered_map<__u64,std::pair<__u64,__u64>> cache_inode_policy_map; // cache inode exe file malicious

    std::mutex cache_inode_policy_map_not_malicious_mutex;
    std::unordered_map<__u64,std::pair<__u64,__u64>> cache_inode_policy_map_not_malicious; // cache inode exe file not malicious
    std::thread worker_thread;

    IOCDatabase &ioc_db;
    std::unordered_map<std::string, MountInfo> mount_cache;
};

#endif // __EXECUTABLE_IOC_BLOCKER_H