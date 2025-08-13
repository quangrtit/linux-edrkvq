#include "utils.h"
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