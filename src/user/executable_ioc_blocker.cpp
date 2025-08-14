#include "executable_ioc_blocker.h"



ExecutableIOCBlocker::ExecutableIOCBlocker(volatile sig_atomic_t* external_exit)
    : fan_fd(-1), exiting(external_exit) {}

ExecutableIOCBlocker::~ExecutableIOCBlocker() {
    stop();
}

void ExecutableIOCBlocker::add_policy(const std::string &path) {
    __u64 key = get_inode_key(path.c_str());
    if (key != 0) inode_policy_map[key] = true;
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

void ExecutableIOCBlocker::loop() {
    struct pollfd fds[1];
    fds[0].fd = fan_fd;
    fds[0].events = POLLIN;
    const int POLL_TIMEOUT_MS = 50;    
    const size_t BUF_SIZE = 4096;      
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
                char link_path[PATH_MAX];
                snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", metadata->fd);

                char real_path[PATH_MAX];
                ssize_t r = readlink(link_path, real_path, sizeof(real_path) - 1);
                if (r > 0) {
                    real_path[r] = '\0';

                    bool malicious;
                    __u64 file_key = get_inode_key(real_path);
                    {
                        std::lock_guard<std::mutex> lock(inode_policy_map_mutex);
                        malicious = inode_policy_map.count(file_key) > 0;
                    }
                    /*
                        check hash 
                    */
                    if(malicious) {
                        auto start = std::chrono::high_resolution_clock::now();
                        std::string hash = calculate_sha256_fast(real_path);    
                        auto end = std::chrono::high_resolution_clock::now();
                        std::chrono::duration<double, std::milli> elapsed = end - start;
                        printf("hash file: %s\n", hash.c_str());
                        printf("Time to hash file: %.3f ms\n", elapsed.count());
                    }
                    struct fanotify_response response = {
                        .fd = metadata->fd,
                        .response = malicious ? (__u32)FAN_DENY : (__u32)FAN_ALLOW
                    };
                    write(fan_fd, &response, sizeof(response));
                }
                close(metadata->fd);
            }
        }
    }
}