#include "utils.h"
#include "common_user.h"
#include "ioc_database.h"
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


bool load_ioc_ip_into_kernel_map(struct ioc_block_bpf *skel, IOCDatabase &ioc_db) {
    int map_fd = bpf_map__fd(skel->maps.ioc_ip_map);
    if (map_fd < 0) {
        perror("bpf_map__fd");
        return false;
    }

    MDB_txn* txn;
    MDB_cursor* cursor;
    if (mdb_txn_begin(ioc_db.env, nullptr, MDB_RDONLY, &txn) != 0)
        return false;
    if (mdb_cursor_open(txn, ioc_db.ip_dbi, &cursor) != 0) {
        mdb_txn_abort(txn);
        return false;
    }

    MDB_val key, data;
    while (mdb_cursor_get(cursor, &key, &data, MDB_NEXT) == 0) {
        std::string ip_str((char*)key.mv_data, key.mv_size);

        struct ip_lpm_key lpm_key = {};
        __u32 verdict = 1; // block

        if (ip_str.find(':') != std::string::npos) {
            // IPv6
            lpm_key.prefixlen = 128;
            if (inet_pton(AF_INET6, ip_str.c_str(), lpm_key.data) != 1) {
                fprintf(stderr, "Invalid IPv6: %s\n", ip_str.c_str());
                continue;
            }
        } else {
            // IPv4
            lpm_key.prefixlen = 32;
            if (inet_pton(AF_INET, ip_str.c_str(), lpm_key.data) != 1) {
                fprintf(stderr, "Invalid IPv4: %s\n", ip_str.c_str());
                continue;
            }
        }

        if (bpf_map__update_elem(
                skel->maps.ioc_ip_map,
                &lpm_key, sizeof(lpm_key),
                &verdict, sizeof(verdict),
                BPF_ANY) != 0) {
            perror("bpf_map__update_elem false\n");
        }
    }

    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);
    return true;
}
// Check interface IPv4
int has_default_route4(const char *ifname) {
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return 0;

    char line[256];
    fgets(line, sizeof(line), f); // skip header
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        char iface[IFNAMSIZ];
        unsigned long dest;
        if (sscanf(line, "%s %lx", iface, &dest) != 2) continue;
        if (dest == 0 && strcmp(iface, ifname)==0) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

// Check interface IPv6
int has_default_route6(const char *ifname) {
    if (!ifname) return 0;

    // Get ifindex from /sys/class/net/<ifname>/ifindex
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/ifindex", ifname);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    int ifidx = -1;
    if (fscanf(f, "%d", &ifidx) != 1 || ifidx <= 0) {
        fclose(f);
        return 0;
    }
    fclose(f);

    // Open /proc/net/ipv6_route
    f = fopen("/proc/net/ipv6_route", "r");
    if (!f) {
        perror("open /proc/net/ipv6_route");
        return 0;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char dest[33], plen[3], src[33], splen[3], nexthop[33];
        unsigned long metric, refcnt, use, flags, route_ifidx;

        int n = sscanf(line,
                       "%32s %2s %32s %2s %32s %lx %lx %lx %lx %lx",
                       dest, plen, src, splen, nexthop,
                       &metric, &refcnt, &use, &flags, &route_ifidx);

        if (n == 10) {
            // check default route (dest = all zero, plen = 00)
            if (strcmp(dest, "00000000000000000000000000000000") == 0 &&
                strcmp(plen, "00") == 0) {
                if ((int)route_ifidx == ifidx) {
                    fclose(f);
                    return 1;
                }
            }
        }
    }

    fclose(f);
    return 0;
}

std::vector<unsigned int> get_all_default_ifindexes() {
    std::vector<unsigned int> res;
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return res;
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !(ifa->ifa_flags & IFF_UP)) continue;

        unsigned int idx = if_nametoindex(ifa->ifa_name);

        // check dup
        if (std::find(res.begin(), res.end(), idx) != res.end())
            continue;

        if (has_default_route4(ifa->ifa_name) || has_default_route6(ifa->ifa_name)) {
            res.push_back(idx);
            std::cout << "Found default route on " << ifa->ifa_name
                      << " (ifindex=" << idx << ")\n";
        }
    }

    freeifaddrs(ifaddr);
    return res;
}

std::string get_binary_dir() {
    char buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf)-1);
    if (len == -1) return ".";
    buf[len] = '\0';
    return std::string(dirname(buf));
}
__u64 get_file_size(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        return st.st_size;  
    }
    return 0; 
}