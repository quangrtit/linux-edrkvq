#include "executable_ioc_blocker.h"
#include "ioc_database.h"


ExecutableIOCBlocker::ExecutableIOCBlocker(volatile sig_atomic_t* external_exit, IOCDatabase &db)
    : fan_fd(-1), exiting(external_exit), ioc_db(db) {}

ExecutableIOCBlocker::~ExecutableIOCBlocker() {
    stop();
}

void ExecutableIOCBlocker::add_policy(const std::string &path) {
    __u64 key = get_inode_key(path.c_str());
    if (key != 0) {
        {
            std::lock_guard<std::mutex> lock(cache_inode_policy_map_mutex);
            cache_inode_policy_map[key] = true;
        }
        
    }
}
void ExecutableIOCBlocker::add_policy(const __u64 &inode) {
    if (inode != 0) {
        {
            std::lock_guard<std::mutex> lock(cache_inode_policy_map_mutex);
            cache_inode_policy_map[inode] = true;
        }
        
    }
}
bool ExecutableIOCBlocker::start() {
    if (fan_fd >= 0) return false; // already started
    fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE);
    if (fan_fd < 0) return false;

    if (fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN_EXEC_PERM, AT_FDCWD, "/") < 0) {
        close(fan_fd);
        fan_fd = -1;
        return false;
    }

    worker_thread = std::thread(&ExecutableIOCBlocker::loop, this);
    return true;
}

void ExecutableIOCBlocker::stop() {
    if (worker_thread.joinable()) worker_thread.join();
    if (fan_fd >= 0) {
        close(fan_fd);
        fan_fd = -1;
    }
}
bool ExecutableIOCBlocker::check_exe_malicious(const char* real_path, IOCDatabase& ioc_db) {
    auto start = std::chrono::high_resolution_clock::now();
    bool malicious;
    __u64 file_key = get_inode_key(real_path);
    {
        std::lock_guard<std::mutex> lock(cache_inode_policy_map_mutex);
        malicious = cache_inode_policy_map.count(file_key) > 0;
    }
    if(!malicious) {
        
        std::string hash_check = calculate_sha256_fast(real_path);   
        // check malicious
        IOCMeta result;
        printf("start hash: %s......\n", real_path);
        malicious = ioc_db.get_file_hash(hash_check, result); // memory load ????
        if(malicious) { // cache malicious
            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double, std::milli> elapsed = end - start;        
            printf("malicious file: %s and time to hash file: %.3f ms\n", real_path, elapsed.count());
            add_policy(file_key);
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;
    printf("Time to hash file %s : %.3f ms\n", real_path, elapsed.count());
    return malicious;
}
// static bool is_system_critical_file(const char* path) {
//     static const char* critical_paths[] = {
//         "/usr/bin/systemd",
//         "/usr/lib/systemd/",
//         "/sbin/init",
//         "/usr/bin/dbus-daemon",
//         "/usr/bin/gnome-shell",
//         "/usr/bin/Xorg",
//         nullptr
//     };
    
//     for (int i = 0; critical_paths[i] != nullptr; i++) {
//         if (strncmp(path, critical_paths[i], strlen(critical_paths[i])) == 0) {
//             return true;
//         }
//     }
    
//     return false;
// }
void ExecutableIOCBlocker::loop() {
    struct pollfd fds[1];
    fds[0].fd = fan_fd;
    fds[0].events = POLLIN;
    const int POLL_TIMEOUT_MS = 50;    
    const size_t BUF_SIZE = 8192;  
    char buffer[BUF_SIZE];

    while (*exiting == 0) {
        int ret = poll(fds, 1, POLL_TIMEOUT_MS);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        if (ret == 0) continue; 

        ssize_t len = read(fan_fd, buffer, sizeof(buffer));
        if (len <= 0) continue;

        struct fanotify_event_metadata *metadata;
        for (metadata = (struct fanotify_event_metadata *)buffer;
            FAN_EVENT_OK(metadata, len);
            metadata = FAN_EVENT_NEXT(metadata, len)) {

            if (metadata->mask & FAN_OPEN_EXEC_PERM) {

                struct fanotify_response response = {
                    .fd = metadata->fd,
                    .response = FAN_ALLOW  
                };
                
                char link_path[PATH_MAX];
                snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", metadata->fd);

                char real_path[PATH_MAX];
                ssize_t r = readlink(link_path, real_path, sizeof(real_path) - 1);
                
                if (r > 0) {
                    real_path[r] = '\0';
                    
   
                    if (strstr(real_path, "ld-linux") != NULL || 
                        strstr(real_path, "ld.so") != NULL ||
                        strcmp(real_path, "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2") == 0) {
                  
                        write(fan_fd, &response, sizeof(response));
                        close(metadata->fd);
                        continue;
                    }
                    
           
                    if (strncmp(real_path, "/usr/lib/", 9) == 0 ||
                        strncmp(real_path, "/lib/", 5) == 0 ||
                        strncmp(real_path, "/lib64/", 7) == 0 ||
                        strncmp(real_path, "/usr/libexec/", 13) == 0 ||
                        strncmp(real_path, "/proc/", 6) == 0 ||
                        strncmp(real_path, "/sys/", 5) == 0) {
              
                        write(fan_fd, &response, sizeof(response));
                        close(metadata->fd);
                        continue;
                    }
                    
                    if (strcmp(real_path, "/bin/bash") == 0 ||
                        strcmp(real_path, "/usr/bin/bash") == 0 ||
                        strcmp(real_path, "/bin/sh") == 0 ||
                        strcmp(real_path, "/usr/bin/sh") == 0 ||
                        strcmp(real_path, "/bin/dash") == 0) {
                     
                        write(fan_fd, &response, sizeof(response));
                        close(metadata->fd);
                        continue;
                    }
                    
               
                    // printf("/-----------------------/\n");
                    // printf("Checking executable: %s\n", real_path);
                    
              
                    try {
                        bool malicious = check_exe_malicious(real_path, ioc_db);
                        
                        if (malicious) {
                            printf("BLOCKED malicious file: %s\n", real_path);
                            response.response = FAN_DENY;
                        } else {
                      
                            response.response = FAN_ALLOW;
                        }
                    } catch (const std::exception& e) {
            
                        fprintf(stderr, "Error checking file %s: %s\n", real_path, e.what());
                        response.response = FAN_ALLOW;
                    }
                    // printf("/-----------------------/\n");
                } 
                else {
            
                    response.response = FAN_ALLOW;
                }
                
                
                if (write(fan_fd, &response, sizeof(response)) < 0) {
                    perror("Failed to send fanotify response");
                }
                
                close(metadata->fd);
            }
        }
    }
}