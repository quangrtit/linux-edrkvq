#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>
#include <sched.h>

int main() {
    while(1) {
        
        sleep(1);
    }
    // pid_t pid = fork();
    // if (pid > 0) {
    //     printf("[Launcher] Started EDR process (PID Namespace)\n");
    //     exit(0); // Exit parent, systemd thinks service is running.
    // }

    // setsid(); // Detach from TTY

    // if (unshare(CLONE_NEWPID | CLONE_NEWNS) != 0) {
    //     perror("unshare failed");
    //     exit(1);
    // }

    // pid_t child = fork();
    // if (child == 0) {
    //     execl("/usr/local/sbin/edr_main", "edr_main", NULL);
    //     perror("exec failed");
    //     exit(1);
    // }
    // waitpid(child, NULL, 0); // Wait for child to exit
    return 0;
}
