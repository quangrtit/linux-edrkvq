#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <string.h>

// syscall ioprio_set
#ifndef SYS_ioprio_set
#define SYS_ioprio_set 251
#endif

// ioprio helpers
#define IOPRIO_CLASS_SHIFT 13
#define IOPRIO_PRIO_VALUE(class, data) (((class) << IOPRIO_CLASS_SHIFT) | (data))
#define IOPRIO_CLASS_BE 2 // Best Effort

// Attack 1: Thay đổi CPU nice value
void attack_setnice(pid_t pid) {
    printf("[*] Trying to set nice value of PID %d to 19...\n", pid);
    if (setpriority(PRIO_PROCESS, pid, 19) == -1) {
        perror("setpriority failed");
    } else {
        printf("[+] setpriority succeeded (no protection?)\n");
    }
}

// Attack 2: Thay đổi I/O priority
void attack_setioprio(pid_t pid) {
    printf("[*] Trying to set I/O priority of PID %d to lowest...\n", pid);
    int prio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 7);
    if (syscall(SYS_ioprio_set, 1 /* process */, pid, prio) == -1) {
        perror("ioprio_set failed");
    } else {
        printf("[+] ioprio_set succeeded (no protection?)\n");
    }
}

// Attack 3: Giảm giới hạn tài nguyên
void attack_prlimit(pid_t pid) {
    printf("[*] Trying to set RLIMIT_NOFILE of PID %d to 1...\n", pid);
    struct rlimit new_lim = { .rlim_cur = 1, .rlim_max = 1 };
    if (prlimit(pid, RLIMIT_NOFILE, &new_lim, NULL) == -1) {
        perror("prlimit failed");
    } else {
        printf("[+] prlimit succeeded (no protection?)\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <target_pid>\n", argv[0]);
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);

    attack_setnice(target_pid);
    attack_setioprio(target_pid);
    attack_prlimit(target_pid);

    return 0;
}