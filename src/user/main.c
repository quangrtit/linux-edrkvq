#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "self_defense.h"                    
#include "self_defense.skel.h"                  

static volatile sig_atomic_t exiting = 0;

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    printf("[DEL] PID_COMM: %s, FILE: %s\n", e->comm, e->filename);
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
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Attach tracepoints
    err = self_defense_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Watching for file deletes... Ctrl+C to stop.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 10);
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
