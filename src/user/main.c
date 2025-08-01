#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <time.h>
#include "common_user.h"                    
#include "self_defense.skel.h"                  
#include "policy_manager.h"


static volatile sig_atomic_t exiting = 0;

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct log_debug *log = data;
    struct timespec ts;
    char timestamp_str[32];

    // Convert nanoseconds to a more readable format
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec = log->timestamp_ns / 1000000000ULL;
    ts.tv_nsec = log->timestamp_ns % 1000000000ULL;
    strftime(timestamp_str, sizeof(timestamp_str), "%H:%M:%S", localtime(&ts.tv_sec));
    snprintf(timestamp_str + strlen(timestamp_str), sizeof(timestamp_str) - strlen(timestamp_str),
             ".%06lu", ts.tv_nsec / 1000);


    const char *level_str = "UNKNOWN";
    switch (log->level) {
        case INFO: level_str = "INFO"; break;
        case WARNING: level_str = "WARNING"; break;
        case ERROR: level_str = "ERROR"; break;
        case BLOCKED_ACTION: level_str = "BLOCKED"; break;
    }

    printf("[%s] [%-7s] PID: %d, UID: %d, Comm: '%s' -> %s\n",
           timestamp_str, level_str, log->pid, log->uid, log->comm, log->msg);

    return 0;
}

static void sig_handler(int sig) {
    exiting = 1;
}

int main() {
    struct self_defense_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_handler);

    // Load and verify BPF program
    skel = self_defense_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[user space main.c] Failed to open and load BPF skeleton\n");
        return 1;
    }
    const char *policy_file = get_policy_path();
    err = load_and_apply_policies(skel, policy_file);
    // Attach tracepoints
    err = self_defense_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[user space main.c] Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.debug_events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[user space main.c] Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("[user space main.c] Watching for file deletes... Ctrl+C to stop.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    self_defense_bpf__destroy(skel);
    return 0;
}
