#include "utils.h"
#include "common_user.h"
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/sysmacros.h>

char* get_local_ip() {
    struct ifaddrs *ifaddr, *ifa;
    static char ip[INET_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return NULL;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            const char* addr = inet_ntop(AF_INET, &sa->sin_addr, ip, INET_ADDRSTRLEN);

            if (addr && strncmp(ip, "127.", 4) != 0) {
                freeifaddrs(ifaddr);
                return ip;
            }
        }
    }

    freeifaddrs(ifaddr);
    return NULL;
}

int acquire_lock_and_write_pid(const char *path, int *out_fd) {
    // Create lock file (rw-------)
    int fd = open(path, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        perror("open lockfile");
        return -1;
    }

    // Get exclusive lock without blocking
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK) {
            close(fd);
            return 1; // Other instances are holding
        }
        perror("flock");
        close(fd);
        return -1;
    }

    // Write PID to file
    if (ftruncate(fd, 0) < 0) {
        perror("ftruncate");
    }
    char buf[32];
    int len = snprintf(buf, sizeof(buf), "%d\n", getpid());
    if (pwrite(fd, buf, len, 0) != len) {
        perror("pwrite pid");
    }
    fsync(fd);

    // Change file permissions to read-only for root
    if (chmod(path, 0400) < 0) {
        perror("chmod");
    }

    *out_fd = fd; // Keep fd open → keep lock
    return 0;
}

__u64 get_inode_key(const char* path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    unsigned int user_major = major(st.st_dev);
    unsigned int user_minor = minor(st.st_dev);
    __u64 kernel_dev = KERNEL_MKDEV(user_major, user_minor);
    return (kernel_dev << 32) | (__u64)st.st_ino;
}
std::string calculate_sha256_fast(const char* file_path) {

    using file_ptr = std::unique_ptr<FILE, FileCloser>;
    file_ptr file(fopen(file_path, "rb"));
    if (!file) return "";

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    constexpr size_t BUFFER_SIZE_HASH = 1024 * 1024;
    unsigned char* buffer = nullptr;
    if (posix_memalign(reinterpret_cast<void**>(&buffer), 32, BUFFER_SIZE_HASH) != 0) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    std::unique_ptr<unsigned char[], decltype(&free)> buf_guard(buffer, &free);

    size_t bytes_read = 0;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE_HASH, file.get())) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
            EVP_MD_CTX_free(ctx);
            return "";
        }
    }
    if (ferror(file.get())) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    EVP_MD_CTX_free(ctx);

    static const char hex_chars[] = "0123456789abcdef";
    char hex_output[EVP_MAX_MD_SIZE*2 + 1];
    for (unsigned int i = 0; i < hash_len; ++i) {
        hex_output[i*2]   = hex_chars[(hash[i] >> 4) & 0xF];
        hex_output[i*2+1] = hex_chars[hash[i] & 0xF];
    }
    hex_output[hash_len*2] = 0;

    return std::string(hex_output);
}

bool is_elf_fd(int fd) {
    unsigned char magic[4];
    if (pread(fd, magic, 4, 0) != 4) 
        return false;
    return magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F';
}
bool is_executable_fd(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0)
        return false;
    return (st.st_mode & S_IXUSR) || (st.st_mode & S_IXGRP) || (st.st_mode & S_IXOTH);
}
// const char *get_ioc_db_path() {

// }