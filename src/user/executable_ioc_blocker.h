#ifndef __EXECUTABLE_IOC_BLOCKER_H
#define __EXECUTABLE_IOC_BLOCKER_H

#include "common_user.h"
#include "utils.h"

class ExecutableIOCBlocker {
public:
    ExecutableIOCBlocker(volatile sig_atomic_t* external_exit);
    ~ExecutableIOCBlocker();

    void add_policy(const std::string &path); 
    bool start();   
    void stop();    

    // bool check_exe_malicious();
private:
    void loop();    

    int fan_fd;
    volatile sig_atomic_t* exiting; 
    std::mutex inode_policy_map_mutex;
    std::unordered_map<__u64,bool> inode_policy_map; // cache inode exe file 
    std::thread worker_thread;
};

#endif // __EXECUTABLE_IOC_BLOCKER_H