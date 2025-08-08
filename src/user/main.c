#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <time.h>
#include <pthread.h>
#include "common_user.h"                    
#include "self_defense.skel.h"                  
#include "policy_manager.h"


#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <ifaddrs.h>
// #define SERVER_IP "192.168.159.128"
#define PORT 8080
#define BUFFER_SIZE 1024


static volatile sig_atomic_t exiting = 0;
static volatile int exit_code = 1;

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
    if (sig == SIGTERM) {
        if (exiting) {
            printf("[Signal Handler] Received SIGTERM and stop_service command, exiting.\n");
            exit_code = 0;
            return;
        } else {
            printf("[Signal Handler] Received SIGTERM but no stop_service command, ignoring.\n");
            return;
        }
    }
    printf("[Signal Handler] Received signal %d but ignoring.\n", sig);
}

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
void* socket_thread(void* arg) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    int opt = 1;
    // printf("Computer%s", get_local_ip());
    printf("[Server Thread] Starting to listen for incoming data...\n");
    char* SERVER_IP = get_local_ip();
    // 1. Tạo socket
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
    pthread_t network_thread_id;
    struct self_defense_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP, sig_handler);
    signal(SIGQUIT, sig_handler);
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
    pid_t pid = getpid();         // Process ID
    pid_t ppid = getppid();       // Parent PID
    char process_name[17] = {0};
    prctl(PR_GET_NAME, (unsigned long)process_name);
    printf("PID: %d, Name: %s [user space main.c] Watching for file deletes... Ctrl+C to stop.\n", pid, process_name);
    // unsigned int seed;
    // seed = 1337;
    // int cnt = 0;
    // srand(seed);
    // printf("#: %d\n", rand());
    if (pthread_create(&network_thread_id, NULL, socket_thread, NULL) != 0) {
        fprintf(stderr, "Failed to create test thread.\n");
        // goto cleanup;
    }
    while (!exiting) {
        err = ring_buffer__poll(rb, 10);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
        // cnt += 1;
        // if(cnt % 100 == 0) {printf("#: %d\n", rand());}

    }
    pthread_join(network_thread_id, NULL);
cleanup:
    ring_buffer__free(rb);
    self_defense_bpf__destroy(skel);
    return exit_code;
}
