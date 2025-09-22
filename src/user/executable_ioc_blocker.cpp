#include "executable_ioc_blocker.h"
#include "ioc_database.h"


ExecutableIOCBlocker::ExecutableIOCBlocker(volatile sig_atomic_t* external_exit, IOCDatabase &db)
    : fan_fd(-1), exiting(external_exit), ioc_db(db) {}

ExecutableIOCBlocker::~ExecutableIOCBlocker() {
    stop();
}

// void ExecutableIOCBlocker::add_policy(const std::string &path) {
//     __u64 key = get_inode_key(path.c_str());
//     if (key != 0) {
//         {
//             std::lock_guard<std::mutex> lock(cache_inode_policy_map_not_malicious_mutex);
//             cache_inode_policy_map_not_malicious[key] = true;
//         }
//
//     }
// }
void ExecutableIOCBlocker::add_policy(const __u64 &inode, __u64 ctime_sec, __u64 ctime_nsec) {
    if (inode != 0) {
        {
            std::lock_guard<std::mutex> lock(cache_inode_policy_map_not_malicious_mutex);
            cache_inode_policy_map_not_malicious[inode] = std::pair<__u64,__u64>(ctime_sec, ctime_nsec);
        }
        
    }
}
void ExecutableIOCBlocker::remove_policy(const __u64 &inode) {
    if (inode != 0) {
        {
            std::lock_guard<std::mutex> lock(cache_inode_policy_map_not_malicious_mutex);
            auto it = cache_inode_policy_map_not_malicious.find(inode);
            if(it != cache_inode_policy_map_not_malicious.end()) {
                cache_inode_policy_map_not_malicious.erase(it);
            }
        }
        
    }
}
bool ExecutableIOCBlocker::start() {
    if (fan_fd >= 0) return false; // already started
    fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE);
    if (fan_fd < 0) return false;
    enumerate_mounts_and_mark();
    if (fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_OPEN_EXEC_PERM, AT_FDCWD, "/") < 0) {
        perror("fanotify_mark add /");
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
    // check cache file not malicious
    {
        std::lock_guard<std::mutex> lock(cache_inode_policy_map_not_malicious_mutex);
        if(cache_inode_policy_map_not_malicious.count(file_key) <= 0) {
            malicious = false;
        }
        else {
            auto it = cache_inode_policy_map_not_malicious.find(file_key);
            if(it != cache_inode_policy_map_not_malicious.end()) {
                __u64 ctime_sec = it->second.first;
                __u64 ctime_nsec = it->second.second;
                // std::cerr << "have: " << real_path << " " << ctime_sec << " " << ctime_nsec << "\n";
                struct stat st;
                if (stat(real_path, &st) == 0) {
                    if(st.st_ctim.tv_sec == ctime_sec && st.st_ctim.tv_nsec == ctime_nsec) {
                        std::cerr << "File not changed, skip hash check: " << real_path << "\n";
                        return false; // file not change, not malicious
                    }
                }
            }
        }
    }
    // check file size before hash
    __u64 file_size = get_file_size(real_path);
    if (file_size == 0 || file_size > LIMIT_FILE_SIZE) {
        std::cerr << "File size is zero or exceeds limit: " << real_path << "\n";
        return false; 
    }
    if(!malicious) {
        std::string hash_check = calculate_sha256_fast(real_path);   
        // check malicious
        IOCMeta result;
        malicious = ioc_db.get_file_hash(hash_check, result); 
        if(malicious) { // cache malicious
            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double, std::milli> elapsed = end - start;        
            printf("malicious file: %s and time to hash file: %.3f ms\n", real_path, elapsed.count());
            // get ctime_sec and ctime_nsec
            
        }
        else {
            struct stat st;
            if (stat(real_path, &st) == 0) {
                __u64 ctime_sec = st.st_ctim.tv_sec;
                __u64 ctime_nsec = st.st_ctim.tv_nsec;
                // std::cerr << "add key: " << real_path << " " << ctime_sec << " " << ctime_nsec << "\n";
                add_policy(file_key, ctime_sec, ctime_nsec);
            }
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;
    // printf("Time to hash file %s with size %.3f MB: %.3f ms\n", real_path, file_size / (1024.0 * 1024.0), elapsed.count());
    return malicious;
}
bool ExecutableIOCBlocker::add_mount(const std::string &path, const MountInfo& mount_info) {
    if (fan_fd < 0) return false;
    if (fanotify_mark(fan_fd,
                        FAN_MARK_ADD | FAN_MARK_MOUNT,
                        FAN_OPEN_EXEC_PERM,
                        AT_FDCWD,
                        path.c_str()) < 0) {
        perror(("fanotify_mark add " + path).c_str());
        return false;
    }
    mount_cache[path] = mount_info;
    // std::cerr << "[+] Add mount: " << path << "\n";
    return true;
}
bool ExecutableIOCBlocker::remove_mount(const std::string &path) {
    // return false;
    if (fan_fd < 0) return false;

    auto it = mount_cache.find(path);
    if(it != mount_cache.end()) {
        mount_cache.erase(it);
    }
    else {
        return false;
    }

    if (fanotify_mark(fan_fd, FAN_MARK_REMOVE | FAN_MARK_MOUNT,
                      FAN_OPEN_EXEC_PERM, AT_FDCWD, path.c_str()) < 0) {
        perror("fanotify_mark remove");
        return false;
    }
    // std::cerr << "[+] Remove mount: " << path << "\n";
    return true;
}
void ExecutableIOCBlocker::enumerate_mounts_and_mark() {
    std::ifstream mounts("/proc/self/mountinfo");
    if (!mounts.is_open()) {
        perror("open /proc/self/mountinfo");
        return;
    }

    std::string line;
    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string mount_id, parent_id, major_minor, root, mount_point;
        MountInfo mount_info = {};
        if (!(iss >> mount_id >> parent_id >> major_minor >> root >> mount_point)) {
            continue;
        }

        // int major = 0, minor = 0;
        // sscanf(major_minor.c_str(), "%d:%d", &major, &minor);
        // uint64_t dev = ((uint64_t)major << 32) | minor;

        std::string token;
        while (iss >> token && token != "-");

        std::string fstype, devname;
        if (!(iss >> fstype >> devname)) {
            devname = "unknown";
        }
        mount_info.dev_name = devname;
        mount_info.fs_type = fstype;
        add_mount(mount_point, mount_info);
    }
    // for(auto path: mount_cache) {
    //     std::cerr << "mountpoint: " << path.first << std::endl;
    // }
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
            // perror("poll");
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
                    try {
                        // bool malicious = check_exe_malicious(real_path, ioc_db);
                        bool malicious = check_with_timeout(real_path, ioc_db, TIME_OUT_CHECK_FILE_MS);
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
bool ExecutableIOCBlocker::check_with_timeout(const char* real_path, IOCDatabase& db, int timeout_ms) {
    auto fut = std::async(std::launch::async, [&]() {
        return check_exe_malicious(real_path, db);
    });

    if (fut.wait_for(std::chrono::milliseconds(timeout_ms)) == std::future_status::ready) {
        return fut.get();
    } else {
        fprintf(stderr, "[Timeout] Checking %s took too long, default ALLOW\n", real_path);
        return false; 
    }
}