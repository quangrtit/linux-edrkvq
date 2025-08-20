#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "common_user.h"

extern "C" {
#include "ioc_block.skel.h"
#include "self_defense.skel.h"
}

#include "policy_manager.h"
#include "utils.h"
#include "executable_ioc_blocker.h"
#include "ioc_database.h"

static volatile sig_atomic_t exiting = 0;
static volatile int exit_code = 1;

// self defense 
static int handle_sd_event(void *ctx, void *data, size_t data_sz) {
    const struct log_debug *log = static_cast<const struct log_debug*>(data);
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
void *self_defense_thread(void *arg) {
    struct ring_buffer *rb = (struct ring_buffer*)arg;
    while (!exiting) {
        int err = ring_buffer__poll(rb, 100); 
        if (err < 0) {
            fprintf(stderr, "Error polling self_defense: %d\n", err);
            break;
        }
    }
    return NULL;
}

// ioc block
static int handle_ioc_event(void *ctx, void *data, size_t data_sz) {
    const struct ioc_event *evt = (const struct ioc_event *)data;
    CallbackContext *rb_ctx = (CallbackContext*)ctx;
    // Convert timestamp
    struct timespec ts;
    char timestamp_str[32];
    ts.tv_sec = evt->timestamp_ns / 1000000000ULL;
    ts.tv_nsec = evt->timestamp_ns % 1000000000ULL;
    strftime(timestamp_str, sizeof(timestamp_str), "%H:%M:%S", localtime(&ts.tv_sec));
    snprintf(timestamp_str + strlen(timestamp_str),
             sizeof(timestamp_str) - strlen(timestamp_str),
             ".%06lu", ts.tv_nsec / 1000);

    // IOC type
    const char *type_str = "UNKNOWN";
    if (evt->type == IOC_EVT_EXEC_FILE) type_str = "EXEC";
    else if (evt->type == IOC_EVT_CONNECT_IP) type_str = "NET";
    else if (evt->type == IOC_EVT_CMD_CONTROL) type_str = "CMD";
    else if (evt->type == IOC_EVT_MOUNT_EVENT) type_str = "MOUNT_EVENT";
    printf("[%s] [%-5s] PID:%d TGID:%d UID:%d GID:%d COMM:'%s' -> ",
           timestamp_str, type_str,
           evt->pid, evt->tgid, evt->uid, evt->gid, evt->type == IOC_EVT_EXEC_FILE ? evt->exec.file_path : "");
    MountInfo mount_info;
    switch (evt->type) {
        case IOC_EVT_EXEC_FILE:
            printf("File='%s' inode=0x%llx\n",
                   evt->exec.file_path, (unsigned long long)evt->exec.inode_id);
            break;
        case IOC_EVT_CONNECT_IP:
            printf("Connect %s:%u -> %s:%u\n",
                   inet_ntoa(*(struct in_addr*)&evt->net.saddr), ntohs(evt->net.sport),
                   inet_ntoa(*(struct in_addr*)&evt->net.daddr), ntohs(evt->net.dport));
            break;
        case IOC_EVT_CMD_CONTROL:
            printf("Command='%s'\n", evt->cmd.cmd);
            break;
        case IOC_EVT_MOUNT_EVENT: 
            printf("[MOUNT_EVENT] action=%s dev=%s fs=%s mnt=%s\n",
                evt->mnt.action == MOUNT_ADD ? "MOUNT_ADD" : "MOUNT_REMOVE",
                evt->mnt.dev_name,
                evt->mnt.fs_type,
                evt->mnt.mnt_point);
            if (evt->mnt.action == MOUNT_ADD) {
                rb_ctx->exe_ioc_blocker->add_mount(evt->mnt.mnt_point, mount_info);
            }
            else {
                rb_ctx->exe_ioc_blocker->remove_mount(evt->mnt.mnt_point);
            }
            break;
        default:
            printf("Unknown IOC type\n");
            break;
    }

    return 0;
}
void *ioc_block_thread(void *arg) {
    struct ring_buffer *rb = (struct ring_buffer*)arg;
    while (!exiting) {
        int err = ring_buffer__poll(rb, 5); 
        if (err < 0) {
            fprintf(stderr, "Error polling ioc_block: %d\n", err);
            break;
        }
    }
    return NULL;
}

static void sig_handler(int sig) {
    exiting = 1;
    printf("[Signal Handler] Received signal %d but ignoring.\n", sig);
}

void* socket_thread(void* arg) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    int opt = 1;
    // printf("Computer%s", get_local_ip());
    printf("[Server Thread] Starting to listen for incoming data...\n");
    char* SERVER_IP = get_local_ip();
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("[Server Thread] socket failed");
        return NULL;
    }
    
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("[Server Thread] setsockopt failed");
        close(server_fd);
        return NULL;
    }
    
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &address.sin_addr) <= 0) {
        perror("[Server Thread] Invalid address/ Address not supported");
        close(server_fd);
        return NULL;
    }
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("[Server Thread] bind failed");
        close(server_fd);
        return NULL;
    }
    
    if (listen(server_fd, 3) < 0) {
        perror("[Server Thread] listen failed");
        close(server_fd);
        return NULL;
    }
    
    printf("[Server Thread] Listening on %s:%d\n", SERVER_IP, PORT);
    int server_stop = 0;
    while (!server_stop) {
        fd_set fds;
        struct timeval tv;
        FD_ZERO(&fds);
        FD_SET(server_fd, &fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        if (select(server_fd + 1, &fds, NULL, NULL, &tv) > 0) {
            new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
            if (new_socket < 0) {
                if (errno != EINTR) {
                    perror("[Server Thread] accept failed");
                }
                continue;
            }
            
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &address.sin_addr, client_ip, INET_ADDRSTRLEN);
            printf("[Server Thread] Client connected from %s\n", client_ip);
            ssize_t valread;
            while ((valread = recv(new_socket, buffer, BUFFER_SIZE - 1, 0)) > 0) {
                buffer[valread] = '\0';
                printf("[Server Thread] Received %zd bytes: %s\n", valread, buffer);
                //stop service
                if(strcmp(buffer, "stop_service") == 0) {
                    printf("[Server Thread] Stop service");
                    server_stop = 1;
                    exit_code = 0;
                    break;
                }
            }
            
            if (valread == 0) {
                printf("[Server Thread] Client disconnected.\n");
            } else if (valread == -1) {
                if (errno != EINTR && errno != EWOULDBLOCK) {
                    perror("[Server Thread] recv failed");
                }
            }
            
            close(new_socket);
        }
        if(server_stop) {exiting = 1;}
        if(exiting) {server_stop = 1;}
    }
    
    close(server_fd);
    printf("[Server Thread] Server is shutting down.\n");
    return NULL;
}
int main() {
    // check singe instance 
    int lock_fd;
    int ret = acquire_lock_and_write_pid(LOCK_PATH, &lock_fd);
    if (ret != 0) {
        fprintf(stderr, "Another instance is already running.\n");
        return 0;
    }

    IOCDatabase ioc_db(IOC_DB_PATH);
    // update_database(ioc_db);
    // ioc_db.dump_database_info();
    // if(ioc_db.delete_file_hash(calculate_sha256_fast(FILE_TEST_BLOCK_EXE))){
    //     printf("deletet hash success!\n");
    // }
    ioc_db.add_file_hash(calculate_sha256_fast(FILE_TEST_BLOCK_EXE), IOCMeta());
    ExecutableIOCBlocker exe_ioc_blocker(&exiting, ioc_db);
    CallbackContext rb_ctx;
    rb_ctx.exe_ioc_blocker = &exe_ioc_blocker;
    pthread_t network_thread_id;
    pthread_t self_defense_id;
    pthread_t ioc_block_id;
    struct self_defense_bpf *skel_self_defense;
    struct ioc_block_bpf *skel_ioc_block;
    struct ring_buffer *rb_self_defense = NULL;
    struct ring_buffer *rb_ioc_block = NULL;
    int err_all;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP, sig_handler);
    signal(SIGQUIT, sig_handler);
    pid_t pid = getpid();         // Process ID
    pid_t ppid = getppid();       // Parent PID
    char process_name[17] = {0};
    prctl(PR_GET_NAME, (unsigned long)process_name);
    // Load and verify BPF program
    skel_self_defense = self_defense_bpf__open_and_load();
    skel_ioc_block = ioc_block_bpf__open_and_load();
    if (!skel_self_defense || !skel_ioc_block) {
        fprintf(stderr, "[user space main.c] Failed to open and load BPF skeleton\n");
        return 1;
    }
    const char *policy_file = get_policy_path();
    err_all = load_and_apply_policies(skel_self_defense, policy_file);
    // Attach tracepoints
    err_all = self_defense_bpf__attach(skel_self_defense);
    if (err_all) {
        fprintf(stderr, "[user space main.c] Failed to attach self-defense BPF skeleton: %d\n", err_all);
        goto cleanup;
    }
    err_all = ioc_block_bpf__attach(skel_ioc_block);
    if(err_all) {
        fprintf(stderr, "[user space main.c] Failed to attach ioc-block BPF skeleton: %d\n", err_all);
        goto cleanup;
    }
    // Set up ring buffer
    rb_self_defense = ring_buffer__new(bpf_map__fd(skel_self_defense->maps.debug_events), handle_sd_event, NULL, NULL);
    if (!rb_self_defense) {
        fprintf(stderr, "[user space main.c] Failed to create ring buffer\n");
        goto cleanup;
    }
    rb_ioc_block = ring_buffer__new(bpf_map__fd(skel_ioc_block->maps.ioc_events), handle_ioc_event, &rb_ctx, NULL);
    if (!rb_ioc_block) {
        fprintf(stderr, "[user space main.c] Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("PID: %d, Name: %s [user space main.c] Watching for file deletes... Ctrl+C to stop.\n", pid, process_name);

    if (pthread_create(&network_thread_id, NULL, socket_thread, NULL) != 0) {
        fprintf(stderr, "Failed to create socket thread.\n");
    }
    if (pthread_create(&self_defense_id, NULL, self_defense_thread, rb_self_defense) != 0) {
        fprintf(stderr, "Failed to create self_defense thread.\n");
    }
    if (pthread_create(&ioc_block_id, NULL, ioc_block_thread, rb_ioc_block) != 0) {
        fprintf(stderr, "Failed to create ioc_block thread.\n");
    }
    exe_ioc_blocker.start();
    
    while (!exiting) {
        sleep(1);
    }

    pthread_join(network_thread_id, NULL);
    pthread_join(self_defense_id, NULL);
    pthread_join(ioc_block_id, NULL);
    exe_ioc_blocker.stop();
cleanup:
    if (rb_self_defense) {
        ring_buffer__free(rb_self_defense);
    }
    if (skel_self_defense) {
        self_defense_bpf__destroy(skel_self_defense);
    }
    if(skel_ioc_block) {
        ioc_block_bpf__destroy(skel_ioc_block);
    }
    return exit_code;
}
