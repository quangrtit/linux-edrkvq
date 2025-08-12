#include "utils.h"
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

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